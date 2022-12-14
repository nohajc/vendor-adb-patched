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
#pragma once

#include <errno.h>

#include <optional>
#include <string>

#include "incfs.h"

namespace android::incfs {

constexpr char kIdAttrName[] = INCFS_XATTR_ID_NAME;
constexpr char kSizeAttrName[] = INCFS_XATTR_SIZE_NAME;
constexpr char kMetadataAttrName[] = INCFS_XATTR_METADATA_NAME;

constexpr char kIndexDir[] = ".index";

namespace details {

class CStrWrapper {
public:
    CStrWrapper(std::string_view sv) {
        if (sv[sv.size()] == '\0') {
            mCstr = sv.data();
        } else {
            mCopy.emplace(sv);
            mCstr = mCopy->c_str();
        }
    }

    CStrWrapper(const CStrWrapper&) = delete;
    void operator=(const CStrWrapper&) = delete;
    CStrWrapper(CStrWrapper&&) = delete;
    void operator=(CStrWrapper&&) = delete;

    const char* get() const { return mCstr; }
    operator const char*() const { return get(); }

private:
    const char* mCstr;
    std::optional<std::string> mCopy;
};

inline CStrWrapper c_str(std::string_view sv) {
    return {sv};
}

} // namespace details

inline bool enabled() {
    return IncFs_IsEnabled();
}

inline Features features() {
    return Features(IncFs_Features());
}

inline bool isIncFsFd(int fd) {
    return IncFs_IsIncFsFd(fd);
}

inline bool isIncFsPath(std::string_view path) {
    return IncFs_IsIncFsPath(details::c_str(path));
}

inline bool isValidFileId(FileId fileId) {
    return IncFs_IsValidFileId(fileId);
}

inline std::string toString(FileId fileId) {
    std::string res(kIncFsFileIdStringLength, '\0');
    auto err = IncFs_FileIdToString(fileId, res.data());
    if (err) {
        errno = err;
        return {};
    }
    return res;
}

inline IncFsFileId toFileId(std::string_view str) {
    if (str.size() != kIncFsFileIdStringLength) {
        return kIncFsInvalidFileId;
    }
    return IncFs_FileIdFromString(str.data());
}

inline void UniqueControl::close() {
    IncFs_DeleteControl(mControl);
    mControl = nullptr;
}

inline IncFsFd UniqueControl::cmd() const {
    return IncFs_GetControlFd(mControl, CMD);
}

inline IncFsFd UniqueControl::pendingReads() const {
    return IncFs_GetControlFd(mControl, PENDING_READS);
}

inline IncFsFd UniqueControl::logs() const {
    return IncFs_GetControlFd(mControl, LOGS);
}

inline UniqueControl::Fds UniqueControl::releaseFds() {
    Fds result;
    IncFsFd fds[result.size()];
    auto count = IncFs_ReleaseControlFds(mControl, fds, std::size(fds));
    for (auto i = 0; i < count; ++i) {
        result[i] = UniqueFd(fds[i]);
    }
    return result;
}

inline UniqueControl mount(std::string_view backingPath, std::string_view targetDir,
                           MountOptions options) {
    auto control = IncFs_Mount(details::c_str(backingPath), details::c_str(targetDir), options);
    return UniqueControl(control);
}

inline UniqueControl open(std::string_view dir) {
    auto control = IncFs_Open(details::c_str(dir));
    return UniqueControl(control);
}

inline UniqueControl createControl(IncFsFd cmd, IncFsFd pendingReads, IncFsFd logs) {
    return UniqueControl(IncFs_CreateControl(cmd, pendingReads, logs));
}

inline ErrorCode setOptions(const Control& control, MountOptions newOptions) {
    return IncFs_SetOptions(control, newOptions);
}

inline ErrorCode bindMount(std::string_view sourceDir, std::string_view targetDir) {
    return IncFs_BindMount(details::c_str(sourceDir), details::c_str(targetDir));
}

inline ErrorCode unmount(std::string_view dir) {
    return IncFs_Unmount(details::c_str(dir));
}

inline std::string root(const Control& control) {
    std::string result;
    result.resize(PATH_MAX);
    size_t size = result.size();
    if (auto err = IncFs_Root(control, result.data(), &size); err < 0) {
        errno = -err;
        return {};
    }
    result.resize(size);
    return result;
}

inline ErrorCode makeFile(const Control& control, std::string_view path, int mode, FileId fileId,
                          NewFileParams params) {
    return IncFs_MakeFile(control, details::c_str(path), mode, fileId, params);
}
inline ErrorCode makeDir(const Control& control, std::string_view path, int mode) {
    return IncFs_MakeDir(control, details::c_str(path), mode);
}
inline ErrorCode makeDirs(const Control& control, std::string_view path, int mode) {
    return IncFs_MakeDirs(control, details::c_str(path), mode);
}

inline RawMetadata getMetadata(const Control& control, FileId fileId) {
    RawMetadata metadata(INCFS_MAX_FILE_ATTR_SIZE);
    size_t size = metadata.size();
    if (IncFs_GetMetadataById(control, fileId, metadata.data(), &size) < 0) {
        return {};
    }
    metadata.resize(size);
    return metadata;
}

inline RawMetadata getMetadata(const Control& control, std::string_view path) {
    RawMetadata metadata(INCFS_MAX_FILE_ATTR_SIZE);
    size_t size = metadata.size();
    if (IncFs_GetMetadataByPath(control, details::c_str(path), metadata.data(), &size) < 0) {
        return {};
    }
    metadata.resize(size);
    return metadata;
}

inline RawSignature getSignature(const Control& control, FileId fileId) {
    RawSignature signature(INCFS_MAX_SIGNATURE_SIZE);
    size_t size = signature.size();
    if (IncFs_GetSignatureById(control, fileId, signature.data(), &size) < 0) {
        return {};
    }
    signature.resize(size);
    return signature;
}

inline RawSignature getSignature(const Control& control, std::string_view path) {
    RawSignature signature(INCFS_MAX_SIGNATURE_SIZE);
    size_t size = signature.size();
    if (IncFs_GetSignatureByPath(control, details::c_str(path), signature.data(), &size) < 0) {
        return {};
    }
    signature.resize(size);
    return signature;
}

inline FileId getFileId(const Control& control, std::string_view path) {
    return IncFs_GetId(control, details::c_str(path));
}

inline ErrorCode link(const Control& control, std::string_view sourcePath,
                      std::string_view targetPath) {
    return IncFs_Link(control, details::c_str(sourcePath), details::c_str(targetPath));
}

inline ErrorCode unlink(const Control& control, std::string_view path) {
    return IncFs_Unlink(control, details::c_str(path));
}

inline WaitResult waitForPendingReads(const Control& control, std::chrono::milliseconds timeout,
                                      std::vector<ReadInfo>* pendingReadsBuffer) {
    static constexpr auto kDefaultBufferSize = INCFS_DEFAULT_PENDING_READ_BUFFER_SIZE;
    if (pendingReadsBuffer->empty()) {
        pendingReadsBuffer->resize(kDefaultBufferSize);
    }
    size_t size = pendingReadsBuffer->size();
    IncFsErrorCode err =
            IncFs_WaitForPendingReads(control, timeout.count(), pendingReadsBuffer->data(), &size);
    pendingReadsBuffer->resize(size);
    switch (err) {
        case 0:
            return WaitResult::HaveData;
        case -ETIMEDOUT:
            return WaitResult::Timeout;
    }
    return WaitResult(err);
}

inline WaitResult waitForPageReads(const Control& control, std::chrono::milliseconds timeout,
                                   std::vector<ReadInfo>* pageReadsBuffer) {
    static constexpr auto kDefaultBufferSize =
            INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES * PAGE_SIZE / sizeof(ReadInfo);
    if (pageReadsBuffer->empty()) {
        pageReadsBuffer->resize(kDefaultBufferSize);
    }
    size_t size = pageReadsBuffer->size();
    IncFsErrorCode err =
            IncFs_WaitForPageReads(control, timeout.count(), pageReadsBuffer->data(), &size);
    pageReadsBuffer->resize(size);
    switch (err) {
        case 0:
            return WaitResult::HaveData;
        case -ETIMEDOUT:
            return WaitResult::Timeout;
    }
    return WaitResult(err);
}

inline UniqueFd openForSpecialOps(const Control& control, FileId fileId) {
    return UniqueFd(IncFs_OpenForSpecialOpsById(control, fileId));
}
inline UniqueFd openForSpecialOps(const Control& control, std::string_view path) {
    return UniqueFd(IncFs_OpenForSpecialOpsByPath(control, details::c_str(path)));
}

inline ErrorCode writeBlocks(Span<const DataBlock> blocks) {
    return IncFs_WriteBlocks(blocks.data(), blocks.size());
}

inline std::pair<ErrorCode, FilledRanges> getFilledRanges(int fd) {
    return getFilledRanges(fd, FilledRanges());
}

inline std::pair<ErrorCode, FilledRanges> getFilledRanges(int fd,
                                                          FilledRanges::RangeBuffer&& buffer) {
    return getFilledRanges(fd, FilledRanges(std::move(buffer), {}));
}

inline std::pair<ErrorCode, FilledRanges> getFilledRanges(int fd, FilledRanges&& resumeFrom) {
    auto rawRanges = resumeFrom.internalRawRanges();
    auto buffer = resumeFrom.extractInternalBufferAndClear();
    auto totalRanges = resumeFrom.dataRanges().size() + resumeFrom.hashRanges().size();
    auto remainingSpace = buffer.size() - totalRanges;
    const bool loadAll = remainingSpace == 0;
    int res;
    do {
        if (remainingSpace == 0) {
            remainingSpace = std::max<size_t>(32, buffer.size() / 2);
            buffer.resize(buffer.size() + remainingSpace);
        }
        auto outBuffer = IncFsSpan{(const char*)(buffer.data() + rawRanges.dataRangesCount +
                                                 rawRanges.hashRangesCount),
                                   IncFsSize(remainingSpace * sizeof(buffer[0]))};
        IncFsFilledRanges newRanges;
        res = IncFs_GetFilledRangesStartingFrom(fd, rawRanges.endIndex, outBuffer, &newRanges);
        if (res && res != -ERANGE) {
            return {res, FilledRanges(std::move(buffer), {})};
        }

        rawRanges.dataRangesCount += newRanges.dataRangesCount;
        rawRanges.hashRangesCount += newRanges.hashRangesCount;
        rawRanges.endIndex = newRanges.endIndex;
        remainingSpace = buffer.size() - rawRanges.dataRangesCount - rawRanges.hashRangesCount;
    } while (res && loadAll);

    rawRanges.dataRanges = buffer.data();
    rawRanges.hashRanges = buffer.data() + rawRanges.dataRangesCount;
    return {res, FilledRanges(std::move(buffer), rawRanges)};
}

inline LoadingState isFullyLoaded(int fd) {
    auto res = IncFs_IsFullyLoaded(fd);
    switch (res) {
        case 0:
            return LoadingState::Full;
        case -ENODATA:
            return LoadingState::MissingBlocks;
        default:
            return LoadingState(res);
    }
}

} // namespace android::incfs

inline bool operator==(const IncFsFileId& l, const IncFsFileId& r) {
    return memcmp(&l, &r, sizeof(l)) == 0;
}
