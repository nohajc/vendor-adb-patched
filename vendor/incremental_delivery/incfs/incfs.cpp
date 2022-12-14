/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "incfs"

#include "incfs.h"

#include <IncrementalProperties.sysprop.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/no_destructor.h>
#include <android-base/parsebool.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <openssl/sha.h>
#include <selinux/android.h>
#include <selinux/selinux.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <chrono>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <string_view>

#include "MountRegistry.h"
#include "path.h"

using namespace std::literals;

using android::base::StringPrintf;
using android::base::unique_fd;

struct IncFsControl final {
    IncFsFd cmd;
    IncFsFd pendingReads;
    IncFsFd logs;
    constexpr IncFsControl(IncFsFd cmd, IncFsFd pendingReads, IncFsFd logs)
          : cmd(cmd), pendingReads(pendingReads), logs(logs) {}
};

static android::incfs::MountRegistry& registry() {
    static android::base::NoDestructor<android::incfs::MountRegistry> instance{};
    return *instance;
}

static unique_fd openRaw(std::string_view file) {
    auto fd = unique_fd(::open(android::incfs::details::c_str(file), O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        return unique_fd{-errno};
    }
    return fd;
}

static unique_fd openRaw(std::string_view dir, std::string_view name) {
    return openRaw(android::incfs::path::join(dir, name));
}

static std::string rootForCmd(int fd) {
    auto cmdFile = android::incfs::path::fromFd(fd);
    if (cmdFile.empty()) {
        LOG(INFO) << __func__ << "(): name empty for " << fd;
        return {};
    }
    auto res = android::incfs::path::dirName(cmdFile);
    if (res.empty()) {
        LOG(INFO) << __func__ << "(): dirname empty for " << cmdFile;
        return {};
    }
    if (!android::incfs::path::endsWith(cmdFile, INCFS_PENDING_READS_FILENAME)) {
        LOG(INFO) << __func__ << "(): invalid file name " << cmdFile;
        return {};
    }
    if (cmdFile.data() == res.data() || cmdFile.starts_with(res)) {
        cmdFile.resize(res.size());
        return cmdFile;
    }
    return std::string(res);
}

static android::incfs::Features readIncFsFeatures() {
    static const char kSysfsFeaturesDir[] = "/sys/fs/" INCFS_NAME "/features";
    const auto dir = android::incfs::path::openDir(kSysfsFeaturesDir);
    if (!dir) {
        return android::incfs::Features::none;
    }

    int res = android::incfs::Features::none;
    while (auto entry = ::readdir(dir.get())) {
        if (entry->d_type != DT_REG) {
            continue;
        }
        if (entry->d_name == "corefs"sv) {
            res |= android::incfs::Features::core;
        }
    }

    return android::incfs::Features(res);
}

IncFsFeatures IncFs_Features() {
    return IncFsFeatures(readIncFsFeatures());
}

static bool isFsAvailable() {
    static const char kProcFilesystems[] = "/proc/filesystems";
    std::string filesystems;
    if (!android::base::ReadFileToString(kProcFilesystems, &filesystems)) {
        return false;
    }
    return filesystems.find("\t" INCFS_NAME "\n") != std::string::npos;
}

static std::string_view incFsPropertyValue() {
    static const android::base::NoDestructor<std::string> kValue{
            android::sysprop::IncrementalProperties::enable().value_or("")};
    return *kValue;
}

static std::pair<bool, std::string_view> parseProperty(std::string_view property) {
    auto boolVal = android::base::ParseBool(property);
    if (boolVal == android::base::ParseBoolResult::kTrue) {
        return {isFsAvailable(), {}};
    }
    if (boolVal == android::base::ParseBoolResult::kFalse) {
        return {false, {}};
    }

    // Don't load the module at once, but instead only check if it is loadable.
    static const auto kModulePrefix = "module:"sv;
    if (property.starts_with(kModulePrefix)) {
        const auto modulePath = property.substr(kModulePrefix.size());
        return {::access(android::incfs::details::c_str(modulePath), R_OK | X_OK), modulePath};
    }
    return {false, {}};
}

namespace {

class IncFsInit {
public:
    IncFsInit() {
        auto [featureEnabled, moduleName] = parseProperty(incFsPropertyValue());
        featureEnabled_ = featureEnabled;
        moduleName_ = moduleName;
        loaded_ = featureEnabled_ && isFsAvailable();
    }

    constexpr ~IncFsInit() = default;

    bool enabled() const { return featureEnabled_; }
    bool enabledAndReady() const {
        if (!featureEnabled_) {
            return false;
        }
        if (moduleName_.empty()) {
            return true;
        }
        if (loaded_) {
            return true;
        }
        std::call_once(loadedFlag_, [this] {
            const unique_fd fd(
                    TEMP_FAILURE_RETRY(::open(android::incfs::details::c_str(moduleName_),
                                              O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
            if (fd < 0) {
                PLOG(ERROR) << "could not open IncFs kernel module \"" << moduleName_ << '"';
                return;
            }

            const auto rc = syscall(__NR_finit_module, fd.get(), "", 0);
            if (rc < 0) {
                PLOG(ERROR) << "finit_module for IncFs \"" << moduleName_ << "\" failed";
                return;
            }
            if (!isFsAvailable()) {
                LOG(ERROR) << "loaded IncFs kernel module \"" << moduleName_
                           << "\" but incremental-fs is still not available";
            }
            loaded_ = true;
            LOG(INFO) << "successfully loaded IncFs kernel module \"" << moduleName_ << '"';
        });
        return loaded_;
    }

private:
    bool featureEnabled_;
    std::string_view moduleName_;
    mutable std::once_flag loadedFlag_;
    mutable bool loaded_;
};

} // namespace

static IncFsInit& init() {
    static IncFsInit initer;
    return initer;
}

bool IncFs_IsEnabled() {
    return init().enabled();
}

bool isIncFsFd(int fd) {
    struct statfs fs = {};
    if (::fstatfs(fd, &fs) != 0) {
        PLOG(WARNING) << __func__ << "(): could not fstatfs fd " << fd;
        return false;
    }

    return fs.f_type == (decltype(fs.f_type))INCFS_MAGIC_NUMBER;
}

bool isIncFsPath(const char* path) {
    struct statfs fs = {};
    if (::statfs(path, &fs) != 0) {
        PLOG(WARNING) << __func__ << "(): could not statfs " << path;
        return false;
    }

    return fs.f_type == (decltype(fs.f_type))INCFS_MAGIC_NUMBER;
}

static int isDir(const char* path) {
    struct stat st;
    if (::stat(path, &st) != 0) {
        return -errno;
    }
    if (!S_ISDIR(st.st_mode)) {
        return -ENOTDIR;
    }
    return 0;
}

static bool isAbsolute(const char* path) {
    return path && path[0] == '/';
}

static int isValidMountTarget(const char* path) {
    if (!isAbsolute(path)) {
        return -EINVAL;
    }
    if (isIncFsPath(path)) {
        LOG(ERROR) << "[incfs] mounting over existing incfs mount is not allowed";
        return -EINVAL;
    }
    if (const auto err = isDir(path); err != 0) {
        return err;
    }
    if (const auto err = android::incfs::path::isEmptyDir(path); err != 0) {
        return err;
    }
    return 0;
}

static int rmDirContent(const char* path) {
    auto dir = android::incfs::path::openDir(path);
    if (!dir) {
        return -EINVAL;
    }
    while (auto entry = ::readdir(dir.get())) {
        if (entry->d_name == "."sv || entry->d_name == ".."sv) {
            continue;
        }
        auto fullPath = StringPrintf("%s/%s", path, entry->d_name);
        if (entry->d_type == DT_DIR) {
            if (const auto err = rmDirContent(fullPath.c_str()); err != 0) {
                return err;
            }
            if (const auto err = ::rmdir(fullPath.c_str()); err != 0) {
                return err;
            }
        } else {
            if (const auto err = ::unlink(fullPath.c_str()); err != 0) {
                return err;
            }
        }
    }
    return 0;
}

static std::string makeMountOptionsString(IncFsMountOptions options) {
    return StringPrintf("read_timeout_ms=%u,readahead=0,rlog_pages=%u,rlog_wakeup_cnt=1",
                        unsigned(options.defaultReadTimeoutMs),
                        unsigned(options.readLogBufferPages < 0
                                         ? INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES
                                         : options.readLogBufferPages));
}

static IncFsControl* makeControl(const char* root) {
    auto cmd = openRaw(root, INCFS_PENDING_READS_FILENAME);
    if (!cmd.ok()) {
        return nullptr;
    }
    unique_fd pendingReads(fcntl(cmd.get(), F_DUPFD_CLOEXEC, cmd.get()));
    if (!pendingReads.ok()) {
        return nullptr;
    }
    auto logs = openRaw(root, INCFS_LOG_FILENAME);
    // logs may be absent, that's fine
    auto control = IncFs_CreateControl(cmd.get(), pendingReads.get(), logs.get());
    if (control) {
        (void)cmd.release();
        (void)pendingReads.release();
        (void)logs.release();
    }
    return control;
}

static std::string makeCommandPath(std::string_view root, std::string_view item) {
    auto [itemRoot, subpath] = registry().rootAndSubpathFor(item);
    if (itemRoot != root) {
        return {};
    }
    // TODO: add "/.cmd/" if we decide to use a separate control tree.
    return android::incfs::path::join(itemRoot, subpath);
}

static void toString(IncFsFileId id, char* out) {
    // Make sure this function matches the one in the kernel (e.g. same case for a-f digits).
    static constexpr char kHexChar[] = "0123456789abcdef";

    for (auto item = std::begin(id.data); item != std::end(id.data); ++item, out += 2) {
        out[0] = kHexChar[(*item & 0xf0) >> 4];
        out[1] = kHexChar[(*item & 0x0f)];
    }
}

static std::string toStringImpl(IncFsFileId id) {
    std::string res(kIncFsFileIdStringLength, '\0');
    toString(id, res.data());
    return res;
}

static IncFsFileId toFileIdImpl(std::string_view str) {
    if (str.size() != kIncFsFileIdStringLength) {
        return kIncFsInvalidFileId;
    }

    IncFsFileId res;
    auto out = (char*)&res;
    for (auto it = str.begin(); it != str.end(); it += 2, ++out) {
        static const auto fromChar = [](char src) -> int {
            if (src >= '0' && src <= '9') {
                return src - '0';
            }
            if (src >= 'a' && src <= 'f') {
                return src - 'a' + 10;
            }
            return -1;
        };

        const int c[2] = {fromChar(it[0]), fromChar(it[1])};
        if (c[0] == -1 || c[1] == -1) {
            errno = EINVAL;
            return kIncFsInvalidFileId;
        }
        *out = (c[0] << 4) | c[1];
    }
    return res;
}

int IncFs_FileIdToString(IncFsFileId id, char* out) {
    if (!out) {
        return -EINVAL;
    }
    toString(id, out);
    return 0;
}

IncFsFileId IncFs_FileIdFromString(const char* in) {
    return toFileIdImpl({in, kIncFsFileIdStringLength});
}

IncFsFileId IncFs_FileIdFromMetadata(IncFsSpan metadata) {
    IncFsFileId id = {};
    if (size_t(metadata.size) <= sizeof(id)) {
        memcpy(&id, metadata.data, metadata.size);
    } else {
        uint8_t buffer[SHA_DIGEST_LENGTH];
        static_assert(sizeof(buffer) >= sizeof(id));

        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, metadata.data, metadata.size);
        SHA1_Final(buffer, &ctx);
        memcpy(&id, buffer, sizeof(id));
    }
    return id;
}

static bool restoreconControlFiles(std::string_view targetDir) {
    const std::string controlFilePaths[] =
            {android::incfs::path::join(targetDir, INCFS_PENDING_READS_FILENAME),
             android::incfs::path::join(targetDir, INCFS_LOG_FILENAME)};
    for (size_t i = 0; i < std::size(controlFilePaths); i++) {
        if (const auto err = selinux_android_restorecon(controlFilePaths[i].c_str(),
                                                        SELINUX_ANDROID_RESTORECON_FORCE);
            err != 0) {
            PLOG(ERROR) << "[incfs] Failed to restorecon: " << controlFilePaths[i]
                        << " error code: " << err;
            errno = -err;
            return false;
        }
    }
    return true;
}

IncFsControl* IncFs_Mount(const char* backingPath, const char* targetDir,
                          IncFsMountOptions options) {
    if (!init().enabledAndReady()) {
        LOG(WARNING) << "[incfs] Feature is not enabled";
        errno = ENOTSUP;
        return nullptr;
    }

    if (auto err = isValidMountTarget(targetDir); err != 0) {
        errno = -err;
        return nullptr;
    }
    if (!isAbsolute(backingPath)) {
        errno = EINVAL;
        return nullptr;
    }

    if (options.flags & android::incfs::createOnly) {
        if (const auto err = android::incfs::path::isEmptyDir(backingPath); err != 0) {
            errno = -err;
            return nullptr;
        }
    } else if (options.flags & android::incfs::truncate) {
        if (const auto err = rmDirContent(backingPath); err != 0) {
            errno = -err;
            return nullptr;
        }
    }

    const auto opts = makeMountOptionsString(options);
    if (::mount(backingPath, targetDir, INCFS_NAME, MS_NOSUID | MS_NODEV | MS_NOATIME,
                opts.c_str())) {
        PLOG(ERROR) << "[incfs] Failed to mount IncFS filesystem: " << targetDir
                    << " errno: " << errno;
        return nullptr;
    }

    if (!restoreconControlFiles(targetDir)) {
        return nullptr;
    }

    auto control = makeControl(targetDir);
    if (control == nullptr) {
        return nullptr;
    }
    return control;
}

IncFsControl* IncFs_Open(const char* dir) {
    auto root = registry().rootFor(dir);
    if (root.empty()) {
        errno = EINVAL;
        return nullptr;
    }
    return makeControl(android::incfs::details::c_str(root));
}

IncFsFd IncFs_GetControlFd(const IncFsControl* control, IncFsFdType type) {
    if (!control) {
        return -EINVAL;
    }
    switch (type) {
        case CMD:
            return control->cmd;
        case PENDING_READS:
            return control->pendingReads;
        case LOGS:
            return control->logs;
        default:
            return -EINVAL;
    }
}

IncFsSize IncFs_ReleaseControlFds(IncFsControl* control, IncFsFd out[], IncFsSize outSize) {
    if (!control || !out) {
        return -EINVAL;
    }
    if (outSize < IncFsFdType::FDS_COUNT) {
        return -ERANGE;
    }
    out[CMD] = std::exchange(control->cmd, -1);
    out[PENDING_READS] = std::exchange(control->pendingReads, -1);
    out[LOGS] = std::exchange(control->logs, -1);
    return IncFsFdType::FDS_COUNT;
}

IncFsControl* IncFs_CreateControl(IncFsFd cmd, IncFsFd pendingReads, IncFsFd logs) {
    return new IncFsControl(cmd, pendingReads, logs);
}

void IncFs_DeleteControl(IncFsControl* control) {
    if (control) {
        if (control->cmd >= 0) {
            close(control->cmd);
        }
        if (control->pendingReads >= 0) {
            close(control->pendingReads);
        }
        if (control->logs >= 0) {
            close(control->logs);
        }
        delete control;
    }
}

IncFsErrorCode IncFs_SetOptions(const IncFsControl* control, IncFsMountOptions options) {
    if (!control) {
        return -EINVAL;
    }
    auto root = rootForCmd(control->cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto opts = makeMountOptionsString(options);
    if (::mount(nullptr, root.c_str(), nullptr, MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOATIME,
                opts.c_str()) != 0) {
        const auto error = errno;
        PLOG(ERROR) << "[incfs] Failed to remount IncFS filesystem: " << root;
        return -error;
    }
    return 0;
}

IncFsErrorCode IncFs_Root(const IncFsControl* control, char buffer[], size_t* bufferSize) {
    if (!control) {
        return -EINVAL;
    }
    std::string result = rootForCmd(control->cmd);
    if (*bufferSize <= result.size()) {
        *bufferSize = result.size() + 1;
        return -EOVERFLOW;
    }
    result.copy(buffer, result.size());
    buffer[result.size()] = '\0';
    *bufferSize = result.size();
    return 0;
}

template <class T>
std::optional<T> read(IncFsSpan& data) {
    if (data.size < (int32_t)sizeof(T)) {
        return {};
    }
    T res;
    memcpy(&res, data.data, sizeof(res));
    data.data += sizeof(res);
    data.size -= sizeof(res);
    return res;
}

static IncFsErrorCode validateSignatureFormat(IncFsSpan signature) {
    if (signature.data == nullptr && signature.size == 0) {
        return 0; // it's fine to have unverified files too
    }
    if ((signature.data == nullptr) != (signature.size == 0)) {
        return -EINVAL;
    }

    // These structs are here purely for checking the minimum size. Maybe will use them for
    // parsing later.
    struct __attribute__((packed)) Hashing {
        int32_t size;
        int32_t algorithm;
        int8_t log2_blocksize;
        int32_t salt_size;
        int32_t raw_root_hash_size;
    };
    struct __attribute__((packed)) Signing {
        int32_t size;
        int32_t apk_digest_size;
        int32_t certificate_size;
        int32_t addl_data_size;
        int32_t public_key_size;
        int32_t algorithm;
        int32_t signature_size;
    };
    struct __attribute__((packed)) MinSignature {
        int32_t version;
        Hashing hashing_info;
        Signing signing_info;
    };

    if (signature.size < (int32_t)sizeof(MinSignature)) {
        return -ERANGE;
    }
    if (signature.size > INCFS_MAX_SIGNATURE_SIZE) {
        return -ERANGE;
    }

    auto version = read<int32_t>(signature);
    if (version.value_or(-1) != INCFS_SIGNATURE_VERSION) {
        return -EINVAL;
    }
    auto hashSize = read<int32_t>(signature);
    if (!hashSize || signature.size < *hashSize) {
        return -EINVAL;
    }
    auto hashAlgo = read<int32_t>(signature);
    if (hashAlgo.value_or(-1) != INCFS_HASH_TREE_SHA256) {
        return -EINVAL;
    }
    auto logBlockSize = read<int8_t>(signature);
    if (logBlockSize.value_or(-1) != 12 /* 2^12 == 4096 */) {
        return -EINVAL;
    }
    auto saltSize = read<int32_t>(signature);
    if (saltSize.value_or(-1) != 0) {
        return -EINVAL;
    }
    auto rootHashSize = read<int32_t>(signature);
    if (rootHashSize.value_or(-1) != INCFS_MAX_HASH_SIZE) {
        return -EINVAL;
    }
    if (signature.size < *rootHashSize) {
        return -EINVAL;
    }
    signature.data += *rootHashSize;
    signature.size -= *rootHashSize;
    auto signingSize = read<int32_t>(signature);
    // everything remaining has to be in the signing info
    if (signingSize.value_or(-1) != signature.size) {
        return -EINVAL;
    }

    // TODO: validate the signature part too.
    return 0;
}

IncFsErrorCode IncFs_MakeFile(const IncFsControl* control, const char* path, int32_t mode,
                              IncFsFileId id, IncFsNewFileParams params) {
    if (!control) {
        return -EINVAL;
    }

    auto [root, subpath] = registry().rootAndSubpathFor(path);
    if (root.empty()) {
        PLOG(WARNING) << "[incfs] makeFile failed for path " << path << ", root is empty.";
        return -EINVAL;
    }
    if (params.size < 0) {
        LOG(WARNING) << "[incfs] makeFile failed for path " << path
                     << ", size is invalid: " << params.size;
        return -ERANGE;
    }

    const auto [subdir, name] = android::incfs::path::splitDirBase(subpath);
    incfs_new_file_args args = {
            .size = (uint64_t)params.size,
            .mode = (uint16_t)mode,
            .directory_path = (uint64_t)subdir.data(),
            .file_name = (uint64_t)name.data(),
            .file_attr = (uint64_t)params.metadata.data,
            .file_attr_len = (uint32_t)params.metadata.size,
    };
    static_assert(sizeof(args.file_id.bytes) == sizeof(id.data));
    memcpy(args.file_id.bytes, id.data, sizeof(args.file_id.bytes));

    if (auto err = validateSignatureFormat(params.signature)) {
        return err;
    }
    args.signature_info = (uint64_t)(uintptr_t)params.signature.data;
    args.signature_size = (uint64_t)params.signature.size;

    if (::ioctl(control->cmd, INCFS_IOC_CREATE_FILE, &args)) {
        PLOG(WARNING) << "[incfs] makeFile failed for " << root << " / " << subdir << " / " << name
                      << " of " << params.size << " bytes";
        return -errno;
    }
    if (::chmod(android::incfs::path::join(root, subpath).c_str(), mode)) {
        PLOG(WARNING) << "[incfs] couldn't change file mode to 0" << std::oct << mode;
    }

    return 0;
}

static IncFsErrorCode makeDir(const char* commandPath, int32_t mode, bool allowExisting) {
    if (!::mkdir(commandPath, mode)) {
        if (::chmod(commandPath, mode)) {
            PLOG(WARNING) << "[incfs] couldn't change directory mode to 0" << std::oct << mode;
        }
        return 0;
    }
    // don't touch the existing dir's mode - mkdir(1) works that way.
    return (allowExisting && errno == EEXIST) ? 0 : -errno;
}

static IncFsErrorCode makeDirs(std::string_view commandPath, std::string_view path,
                               std::string_view root, int32_t mode) {
    auto commandCPath = android::incfs::details::c_str(commandPath);
    const auto mkdirRes = makeDir(commandCPath, mode, true);
    if (!mkdirRes) {
        return 0;
    }
    if (mkdirRes != -ENOENT) {
        LOG(ERROR) << __func__ << "(): mkdir failed for " << path << " - " << mkdirRes;
        return mkdirRes;
    }

    const auto parent = android::incfs::path::dirName(commandPath);
    if (!android::incfs::path::startsWith(parent, root)) {
        // went too far, already out of the root mount
        return -EINVAL;
    }

    if (auto parentMkdirRes = makeDirs(parent, android::incfs::path::dirName(path), root, mode)) {
        return parentMkdirRes;
    }
    return makeDir(commandCPath, mode, true);
}

IncFsErrorCode IncFs_MakeDir(const IncFsControl* control, const char* path, int32_t mode) {
    if (!control) {
        return -EINVAL;
    }
    const auto root = rootForCmd(control->cmd);
    if (root.empty()) {
        LOG(ERROR) << __func__ << "(): root is empty for " << path;
        return -EINVAL;
    }
    auto commandPath = makeCommandPath(root, path);
    if (commandPath.empty()) {
        LOG(ERROR) << __func__ << "(): commandPath is empty for " << path;
        return -EINVAL;
    }
    if (auto res = makeDir(commandPath.c_str(), mode, false)) {
        LOG(ERROR) << __func__ << "(): mkdir failed for " << commandPath << " - " << res;
        return res;
    }
    return 0;
}

IncFsErrorCode IncFs_MakeDirs(const IncFsControl* control, const char* path, int32_t mode) {
    if (!control) {
        return -EINVAL;
    }
    const auto root = rootForCmd(control->cmd);
    if (root.empty()) {
        LOG(ERROR) << __func__ << "(): root is empty for " << path;
        return -EINVAL;
    }
    auto commandPath = makeCommandPath(root, path);
    if (commandPath.empty()) {
        LOG(ERROR) << __func__ << "(): commandPath is empty for " << path;
        return -EINVAL;
    }
    return makeDirs(commandPath, path, root, mode);
}

static IncFsErrorCode getMetadata(const char* path, char buffer[], size_t* bufferSize) {
    const auto res = ::getxattr(path, android::incfs::kMetadataAttrName, buffer, *bufferSize);
    if (res < 0) {
        if (errno == ERANGE) {
            auto neededSize = ::getxattr(path, android::incfs::kMetadataAttrName, buffer, 0);
            if (neededSize >= 0) {
                *bufferSize = neededSize;
                return 0;
            }
        }
        return -errno;
    }
    *bufferSize = res;
    return 0;
}

IncFsErrorCode IncFs_GetMetadataById(const IncFsControl* control, IncFsFileId fileId, char buffer[],
                                     size_t* bufferSize) {
    if (!control) {
        return -EINVAL;
    }

    const auto root = rootForCmd(control->cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto name = android::incfs::path::join(root, android::incfs::kIndexDir, toStringImpl(fileId));
    return getMetadata(android::incfs::details::c_str(name), buffer, bufferSize);
}

IncFsErrorCode IncFs_GetMetadataByPath(const IncFsControl* control, const char* path, char buffer[],
                                       size_t* bufferSize) {
    if (!control) {
        return -EINVAL;
    }
    const auto pathRoot = registry().rootFor(path);
    const auto root = rootForCmd(control->cmd);
    if (root.empty() || root != pathRoot) {
        return -EINVAL;
    }

    return getMetadata(path, buffer, bufferSize);
}

IncFsFileId IncFs_GetId(const IncFsControl* control, const char* path) {
    if (!control) {
        return kIncFsInvalidFileId;
    }
    const auto pathRoot = registry().rootFor(path);
    const auto root = rootForCmd(control->cmd);
    if (root.empty() || root != pathRoot) {
        errno = EINVAL;
        return kIncFsInvalidFileId;
    }
    char buffer[kIncFsFileIdStringLength];
    const auto res = ::getxattr(path, android::incfs::kIdAttrName, buffer, sizeof(buffer));
    if (res != sizeof(buffer)) {
        return kIncFsInvalidFileId;
    }
    return toFileIdImpl({buffer, std::size(buffer)});
}

static IncFsErrorCode getSignature(int fd, char buffer[], size_t* bufferSize) {
    incfs_get_file_sig_args args = {
            .file_signature = (uint64_t)buffer,
            .file_signature_buf_size = (uint32_t)*bufferSize,
    };

    auto res = ::ioctl(fd, INCFS_IOC_READ_FILE_SIGNATURE, &args);
    if (res < 0) {
        if (errno == E2BIG) {
            *bufferSize = INCFS_MAX_SIGNATURE_SIZE;
        }
        return -errno;
    }
    *bufferSize = args.file_signature_len_out;
    return 0;
}

IncFsErrorCode IncFs_GetSignatureById(const IncFsControl* control, IncFsFileId fileId,
                                      char buffer[], size_t* bufferSize) {
    if (!control) {
        return -EINVAL;
    }

    const auto root = rootForCmd(control->cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto file = android::incfs::path::join(root, android::incfs::kIndexDir, toStringImpl(fileId));
    auto fd = openRaw(file);
    if (fd < 0) {
        return fd.get();
    }
    return getSignature(fd, buffer, bufferSize);
}

IncFsErrorCode IncFs_GetSignatureByPath(const IncFsControl* control, const char* path,
                                        char buffer[], size_t* bufferSize) {
    if (!control) {
        return -EINVAL;
    }

    const auto pathRoot = registry().rootFor(path);
    const auto root = rootForCmd(control->cmd);
    if (root.empty() || root != pathRoot) {
        return -EINVAL;
    }
    return IncFs_UnsafeGetSignatureByPath(path, buffer, bufferSize);
}

IncFsErrorCode IncFs_UnsafeGetSignatureByPath(const char* path, char buffer[], size_t* bufferSize) {
    if (!isIncFsPath(path)) {
        return -EINVAL;
    }
    auto fd = openRaw(path);
    if (fd < 0) {
        return fd.get();
    }
    return getSignature(fd, buffer, bufferSize);
}

IncFsErrorCode IncFs_Link(const IncFsControl* control, const char* fromPath,
                          const char* wherePath) {
    if (!control) {
        return -EINVAL;
    }

    auto root = rootForCmd(control->cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto cmdFrom = makeCommandPath(root, fromPath);
    if (cmdFrom.empty()) {
        return -EINVAL;
    }
    auto cmdWhere = makeCommandPath(root, wherePath);
    if (cmdWhere.empty()) {
        return -EINVAL;
    }
    if (::link(cmdFrom.c_str(), cmdWhere.c_str())) {
        return -errno;
    }
    return 0;
}

IncFsErrorCode IncFs_Unlink(const IncFsControl* control, const char* path) {
    if (!control) {
        return -EINVAL;
    }

    auto root = rootForCmd(control->cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto cmdPath = makeCommandPath(root, path);
    if (cmdPath.empty()) {
        return -EINVAL;
    }
    if (::unlink(cmdPath.c_str())) {
        if (errno == EISDIR) {
            if (!::rmdir(cmdPath.c_str())) {
                return 0;
            }
        }
        return -errno;
    }
    return 0;
}

static int waitForReads(int fd, int32_t timeoutMs, incfs_pending_read_info pendingReadsBuffer[],
                        size_t* pendingReadsBufferSize) {
    auto hrTimeout = std::chrono::steady_clock::duration(std::chrono::milliseconds(timeoutMs));

    while (hrTimeout > hrTimeout.zero() || (!pendingReadsBuffer && hrTimeout == hrTimeout.zero())) {
        const auto startTs = std::chrono::steady_clock::now();

        pollfd pfd = {fd, POLLIN, 0};
        const auto res =
                ::poll(&pfd, 1, duration_cast<std::chrono::milliseconds>(hrTimeout).count());
        if (res > 0) {
            break;
        }
        if (res == 0) {
            if (pendingReadsBufferSize) {
                *pendingReadsBufferSize = 0;
            }
            return -ETIMEDOUT;
        }
        const auto error = errno;
        if (error != EINTR) {
            PLOG(ERROR) << "poll() failed";
            return -error;
        }
        hrTimeout -= std::chrono::steady_clock::now() - startTs;
    }
    if (!pendingReadsBuffer) {
        return hrTimeout < hrTimeout.zero() ? -ETIMEDOUT : 0;
    }

    auto res =
            ::read(fd, pendingReadsBuffer, *pendingReadsBufferSize * sizeof(*pendingReadsBuffer));
    if (res < 0) {
        const auto error = errno;
        PLOG(ERROR) << "read() failed";
        return -error;
    }
    if (res == 0) {
        *pendingReadsBufferSize = 0;
        return -ETIMEDOUT;
    }
    if ((res % sizeof(*pendingReadsBuffer)) != 0) {
        PLOG(ERROR) << "read() returned half of a struct??";
        return -EFAULT;
    }
    *pendingReadsBufferSize = res / sizeof(*pendingReadsBuffer);
    return 0;
}

IncFsErrorCode IncFs_WaitForPendingReads(const IncFsControl* control, int32_t timeoutMs,
                                         IncFsReadInfo buffer[], size_t* bufferSize) {
    if (!control || control->pendingReads < 0) {
        return -EINVAL;
    }

    std::vector<incfs_pending_read_info> pendingReads;
    pendingReads.resize(*bufferSize);
    if (const auto res =
                waitForReads(control->pendingReads, timeoutMs, pendingReads.data(), bufferSize)) {
        return res;
    }
    for (size_t i = 0; i != *bufferSize; ++i) {
        buffer[i] = IncFsReadInfo{
                .bootClockTsUs = pendingReads[i].timestamp_us,
                .block = (IncFsBlockIndex)pendingReads[i].block_index,
                .serialNo = pendingReads[i].serial_number,
        };
        memcpy(&buffer[i].id.data, pendingReads[i].file_id.bytes, sizeof(buffer[i].id.data));
    }
    return 0;
}

IncFsErrorCode IncFs_WaitForPageReads(const IncFsControl* control, int32_t timeoutMs,
                                      IncFsReadInfo buffer[], size_t* bufferSize) {
    if (!control) {
        return -EINVAL;
    }

    auto logsFd = control->logs;
    if (logsFd < 0) {
        return -EINVAL;
    }
    std::vector<incfs_pending_read_info> pendingReads;
    pendingReads.resize(*bufferSize);
    if (const auto res = waitForReads(logsFd, timeoutMs, pendingReads.data(), bufferSize)) {
        return res;
    }
    for (size_t i = 0; i != *bufferSize; ++i) {
        buffer[i] = IncFsReadInfo{
                .bootClockTsUs = pendingReads[i].timestamp_us,
                .block = (IncFsBlockIndex)pendingReads[i].block_index,
                .serialNo = pendingReads[i].serial_number,
        };
        memcpy(&buffer[i].id.data, pendingReads[i].file_id.bytes, sizeof(buffer[i].id.data));
    }
    return 0;
}

static IncFsFd openForSpecialOps(int cmd, const char* path) {
    unique_fd fd(::open(path, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        return -errno;
    }
    struct incfs_permit_fill args = {.file_descriptor = (uint32_t)fd.get()};
    auto err = ::ioctl(cmd, INCFS_IOC_PERMIT_FILL, &args);
    if (err < 0) {
        return -errno;
    }
    return fd.release();
}

IncFsFd IncFs_OpenForSpecialOpsByPath(const IncFsControl* control, const char* path) {
    if (!control) {
        return -EINVAL;
    }

    const auto pathRoot = registry().rootFor(path);
    const auto cmd = control->cmd;
    const auto root = rootForCmd(cmd);
    if (root.empty() || root != pathRoot) {
        return -EINVAL;
    }
    return openForSpecialOps(cmd, makeCommandPath(root, path).c_str());
}

IncFsFd IncFs_OpenForSpecialOpsById(const IncFsControl* control, IncFsFileId id) {
    if (!control) {
        return -EINVAL;
    }

    const auto cmd = control->cmd;
    const auto root = rootForCmd(cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto name = android::incfs::path::join(root, android::incfs::kIndexDir, toStringImpl(id));
    return openForSpecialOps(cmd, makeCommandPath(root, name).c_str());
}

static int writeBlocks(int fd, const incfs_fill_block blocks[], int blocksCount) {
    if (fd < 0 || blocksCount == 0) {
        return 0;
    }
    if (blocksCount < 0) {
        return -EINVAL;
    }

    auto ptr = blocks;
    const auto end = blocks + blocksCount;
    do {
        struct incfs_fill_blocks args = {.count = uint64_t(end - ptr),
                                         .fill_blocks = (uint64_t)(uintptr_t)ptr};
        const auto written = ::ioctl(fd, INCFS_IOC_FILL_BLOCKS, &args);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            const auto error = errno;
            PLOG(WARNING) << "writing IncFS blocks failed";
            if (ptr == blocks) {
                return -error;
            }
            // something has been written, return a success here and let the
            // next call handle the error.
            break;
        }
        ptr += written;
    } while (ptr < end);
    return ptr - blocks;
}

IncFsErrorCode IncFs_WriteBlocks(const IncFsDataBlock blocks[], size_t blocksCount) {
    incfs_fill_block incfsBlocks[128];
    int writtenCount = 0;
    int incfsBlocksUsed = 0;
    int lastBlockFd = -1;
    for (size_t i = 0; i < blocksCount; ++i) {
        if (lastBlockFd != blocks[i].fileFd || incfsBlocksUsed == std::size(incfsBlocks)) {
            auto count = writeBlocks(lastBlockFd, incfsBlocks, incfsBlocksUsed);
            if (count > 0) {
                writtenCount += count;
            }
            if (count != incfsBlocksUsed) {
                return writtenCount ? writtenCount : count;
            }
            lastBlockFd = blocks[i].fileFd;
            incfsBlocksUsed = 0;
        }
        incfsBlocks[incfsBlocksUsed] = incfs_fill_block{
                .block_index = (uint32_t)blocks[i].pageIndex,
                .data_len = blocks[i].dataSize,
                .data = (uint64_t)blocks[i].data,
                .compression = (uint8_t)blocks[i].compression,
                .flags = uint8_t(blocks[i].kind == INCFS_BLOCK_KIND_HASH ? INCFS_BLOCK_FLAGS_HASH
                                                                         : 0),
        };
        ++incfsBlocksUsed;
    }
    auto count = writeBlocks(lastBlockFd, incfsBlocks, incfsBlocksUsed);
    if (count > 0) {
        writtenCount += count;
    }
    return writtenCount ? writtenCount : count;
}

IncFsErrorCode IncFs_BindMount(const char* sourceDir, const char* targetDir) {
    if (!android::incfs::enabled()) {
        return -ENOTSUP;
    }

    auto [sourceRoot, subpath] = registry().rootAndSubpathFor(sourceDir);
    if (sourceRoot.empty()) {
        return -EINVAL;
    }
    if (subpath.empty()) {
        LOG(WARNING) << "[incfs] Binding the root mount '" << sourceRoot << "' is not allowed";
        return -EINVAL;
    }

    if (auto err = isValidMountTarget(targetDir); err != 0) {
        return err;
    }

    if (::mount(sourceDir, targetDir, nullptr, MS_BIND, nullptr)) {
        PLOG(ERROR) << "[incfs] Failed to bind mount '" << sourceDir << "' to '" << targetDir
                    << '\'';
        return -errno;
    }
    return 0;
}

IncFsErrorCode IncFs_Unmount(const char* dir) {
    if (!android::incfs::enabled()) {
        return -ENOTSUP;
    }

    errno = 0;
    if (::umount2(dir, MNT_FORCE) == 0 || errno == EINVAL || errno == ENOENT) {
        // EINVAL - not a mount point, ENOENT - doesn't exist at all
        return -errno;
    }
    PLOG(WARNING) << __func__ << ": umount(force) failed, detaching '" << dir << '\'';
    errno = 0;
    if (!::umount2(dir, MNT_DETACH)) {
        return 0;
    }
    PLOG(WARNING) << __func__ << ": umount(detach) returned non-zero for '" << dir << '\'';
    return 0;
}

bool IncFs_IsIncFsFd(int fd) {
    return isIncFsFd(fd);
}

bool IncFs_IsIncFsPath(const char* path) {
    return isIncFsPath(path);
}

IncFsErrorCode IncFs_GetFilledRanges(int fd, IncFsSpan outBuffer, IncFsFilledRanges* filledRanges) {
    return IncFs_GetFilledRangesStartingFrom(fd, 0, outBuffer, filledRanges);
}

IncFsErrorCode IncFs_GetFilledRangesStartingFrom(int fd, int startBlockIndex, IncFsSpan outBuffer,
                                                 IncFsFilledRanges* filledRanges) {
    if (fd < 0) {
        return -EBADF;
    }
    if (startBlockIndex < 0) {
        return -EINVAL;
    }
    if (!outBuffer.data && outBuffer.size > 0) {
        return -EINVAL;
    }
    if (!filledRanges) {
        return -EINVAL;
    }
    // Use this to optimize the incfs call and have the same buffer for both the incfs and the
    // public structs.
    static_assert(sizeof(IncFsBlockRange) == sizeof(incfs_filled_range));

    *filledRanges = {};

    auto outStart = (IncFsBlockRange*)outBuffer.data;
    auto outEnd = outStart + outBuffer.size / sizeof(*outStart);

    auto outPtr = outStart;
    int error = 0;
    int dataBlocks;
    incfs_get_filled_blocks_args args = {};
    for (;;) {
        auto start = args.index_out ? args.index_out : startBlockIndex;
        args = incfs_get_filled_blocks_args{
                .range_buffer = (uint64_t)(uintptr_t)outPtr,
                .range_buffer_size = uint32_t((outEnd - outPtr) * sizeof(*outPtr)),
                .start_index = start,
        };
        errno = 0;
        auto res = ::ioctl(fd, INCFS_IOC_GET_FILLED_BLOCKS, &args);
        error = errno;
        if (res && error != EINTR && error != ERANGE) {
            return -error;
        }

        dataBlocks = args.data_blocks_out;
        outPtr += args.range_buffer_size_out / sizeof(incfs_filled_range);
        if (!res || error == ERANGE) {
            break;
        }
        // in case of EINTR we want to continue calling the function
    }

    if (outPtr > outEnd) {
        outPtr = outEnd;
        error = ERANGE;
    }

    filledRanges->endIndex = args.index_out;
    auto hashStartPtr = outPtr;
    if (outPtr != outStart) {
        // figure out the ranges for data block and hash blocks in the output
        for (; hashStartPtr != outStart; --hashStartPtr) {
            if ((hashStartPtr - 1)->begin < dataBlocks) {
                break;
            }
        }
        auto lastDataPtr = hashStartPtr - 1;
        // here we go, this is the first block that's before or at the hashes
        if (lastDataPtr->end <= dataBlocks) {
            ; // we're good, the boundary is between the ranges - |hashStartPtr| is correct
        } else {
            // the hard part: split the |lastDataPtr| range into the data and the hash pieces
            if (outPtr == outEnd) {
                // the buffer turned out to be too small, even though it actually wasn't
                error = ERANGE;
                if (hashStartPtr == outEnd) {
                    // this is even worse: there's no room to put even a single hash block into.
                    filledRanges->endIndex = lastDataPtr->end = dataBlocks;
                } else {
                    std::copy_backward(lastDataPtr, outPtr - 1, outPtr);
                    lastDataPtr->end = hashStartPtr->begin = dataBlocks;
                    filledRanges->endIndex = (outPtr - 1)->end;
                }
            } else {
                std::copy_backward(lastDataPtr, outPtr, outPtr + 1);
                lastDataPtr->end = hashStartPtr->begin = dataBlocks;
                ++outPtr;
            }
        }
        // now fix the indices of all hash blocks - no one should know they're simply past the
        // regular data blocks in the file!
        for (auto ptr = hashStartPtr; ptr != outPtr; ++ptr) {
            ptr->begin -= dataBlocks;
            ptr->end -= dataBlocks;
        }
    }

    filledRanges->dataRanges = outStart;
    filledRanges->dataRangesCount = hashStartPtr - outStart;
    filledRanges->hashRanges = hashStartPtr;
    filledRanges->hashRangesCount = outPtr - hashStartPtr;

    return -error;
}

IncFsErrorCode IncFs_IsFullyLoaded(int fd) {
    char buffer[2 * sizeof(IncFsBlockRange)];
    IncFsFilledRanges ranges;
    auto res = IncFs_GetFilledRanges(fd, IncFsSpan{.data = buffer, .size = std::size(buffer)},
                                     &ranges);
    if (res == -ERANGE) {
        // need room for more than two ranges - definitely not fully loaded
        return -ENODATA;
    }
    if (res != 0) {
        return res;
    }
    // empty file
    if (ranges.endIndex == 0) {
        return 0;
    }
    // file with no hash tree
    if (ranges.dataRangesCount == 1 && ranges.hashRangesCount == 0) {
        return (ranges.dataRanges[0].begin == 0 && ranges.dataRanges[0].end == ranges.endIndex)
                ? 0
                : -ENODATA;
    }
    // file with a hash tree
    if (ranges.dataRangesCount == 1 && ranges.hashRangesCount == 1) {
        // calculate the expected data size from the size of the hash range and |endIndex|, which is
        // the total number of blocks in the file, both data and hash blocks together.
        if (ranges.hashRanges[0].begin != 0) {
            return -ENODATA;
        }
        const auto expectedDataBlocks =
                ranges.endIndex - (ranges.hashRanges[0].end - ranges.hashRanges[0].begin);
        return (ranges.dataRanges[0].begin == 0 && ranges.dataRanges[0].end == expectedDataBlocks)
                ? 0
                : -ENODATA;
    }
    return -ENODATA;
}

android::incfs::MountRegistry& android::incfs::defaultMountRegistry() {
    return registry();
}
