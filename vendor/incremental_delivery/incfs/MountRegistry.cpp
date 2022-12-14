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

#define LOG_TAG "incfs-mounts"

#include "MountRegistry.h"

#include "incfs.h"
#include "path.h"
#include "split.h"

#include <android-base/logging.h>

#include <charconv>
#include <unordered_map>

#include <poll.h>
#include <stdlib.h>

using namespace std::literals;

namespace android::incfs {

// /proc/self/mountinfo may have some special characters in paths replaced with their
// octal codes in the following pattern: '\xxx', e.g. \040 for space character.
// This function translates those patterns back into corresponding characters.
static void fixProcPath(std::string& path) {
    static const auto kPrefix = "\\"sv;
    static const auto kPatternLength = 4;
    auto pos = std::search(path.begin(), path.end(), kPrefix.begin(), kPrefix.end());
    if (pos == path.end()) {
        return;
    }
    auto dest = pos;
    do {
        if (path.end() - pos < kPatternLength || !std::equal(kPrefix.begin(), kPrefix.end(), pos)) {
            *dest++ = *pos++;
        } else {
            int charCode;
            auto res = std::from_chars(&*(pos + kPrefix.size()), &*(pos + kPatternLength), charCode,
                                       8);
            if (res.ec == std::errc{}) {
                *dest++ = char(charCode);
            } else {
                // Didn't convert, let's keep it as is.
                dest = std::copy(pos, pos + kPatternLength, dest);
                pos += kPatternLength;
            }
        }
    } while (pos != path.end());
    path.erase(dest, path.end());
}

std::vector<std::pair<std::string_view, std::string_view>> MountRegistry::Mounts::Mount::binds()
        const {
    std::vector<std::pair<std::string_view, std::string_view>> result;
    result.reserve(mBase->binds.size());
    for (auto it : mBase->binds) {
        result.emplace_back(it->second.first, it->first);
    }
    return result;
}

void MountRegistry::Mounts::swap(MountRegistry::Mounts& other) {
    roots.swap(other.roots);
    rootByBindPoint.swap(other.rootByBindPoint);
}

void MountRegistry::Mounts::clear() {
    roots.clear();
    rootByBindPoint.clear();
}

std::pair<int, MountRegistry::BindMap::const_iterator> MountRegistry::Mounts::rootIndex(
        std::string_view path) const {
    auto it = rootByBindPoint.lower_bound(path);
    if (it != rootByBindPoint.end() && it->first == path) {
        return {it->second.second, it};
    }
    if (it != rootByBindPoint.begin()) {
        --it;
        if (path::startsWith(path, it->first) && path.size() > it->first.size()) {
            const auto index = it->second.second;
            if (index >= int(roots.size()) || roots[index].empty()) {
                LOG(ERROR) << "[incfs] Root for path '" << path << "' #" << index
                           << " is not valid";
                return {-1, {}};
            }
            return {index, it};
        }
    }
    return {-1, {}};
}

std::string_view MountRegistry::Mounts::rootFor(std::string_view path) const {
    auto [index, _] = rootIndex(path::normalize(path));
    if (index < 0) {
        return {};
    }
    return roots[index].path;
}

std::pair<std::string_view, std::string> MountRegistry::Mounts::rootAndSubpathFor(
        std::string_view path) const {
    auto normalPath = path::normalize(path);
    auto [index, bindIt] = rootIndex(normalPath);
    if (index < 0) {
        return {};
    }

    const auto& bindSubdir = bindIt->second.first;
    const auto pastBindSubdir = path::relativize(bindIt->first, normalPath);
    const auto& root = roots[index];
    return {root.path, path::join(bindSubdir, pastBindSubdir)};
}

void MountRegistry::Mounts::addRoot(std::string_view root, std::string_view backingDir) {
    const auto index = roots.size();
    auto absolute = path::normalize(root);
    auto it = rootByBindPoint.insert_or_assign(absolute, std::pair{std::string(), index}).first;
    roots.push_back({std::move(absolute), path::normalize(backingDir), {it}});
}

void MountRegistry::Mounts::removeRoot(std::string_view root) {
    auto absolute = path::normalize(root);
    auto it = rootByBindPoint.find(absolute);
    if (it == rootByBindPoint.end()) {
        LOG(WARNING) << "[incfs] Trying to remove non-existent root '" << root << '\'';
        return;
    }
    const auto index = it->second.second;
    if (index >= int(roots.size())) {
        LOG(ERROR) << "[incfs] Root '" << root << "' has index " << index
                   << " out of bounds (total roots count is " << roots.size();
        return;
    }

    if (index + 1 == int(roots.size())) {
        roots.pop_back();
        // Run a small GC job here as we may be able to remove some obsolete
        // entries.
        while (roots.back().empty()) {
            roots.pop_back();
        }
    } else {
        roots[index].clear();
    }
    rootByBindPoint.erase(it);
}

void MountRegistry::Mounts::moveBind(std::string_view src, std::string_view dest) {
    auto srcAbsolute = path::normalize(src);
    auto destAbsolute = path::normalize(dest);
    if (srcAbsolute == destAbsolute) {
        return;
    }

    auto [root, rootIt] = rootIndex(srcAbsolute);
    if (root < 0) {
        LOG(ERROR) << "[incfs] No root found for bind move from " << src << " to " << dest;
        return;
    }

    if (roots[root].path == srcAbsolute) {
        // moving the whole root
        roots[root].path = destAbsolute;
    }

    // const_cast<> here is safe as we're erasing that element on the next line.
    const auto newRootIt = rootByBindPoint
                                   .insert_or_assign(std::move(destAbsolute),
                                                     std::pair{std::move(const_cast<std::string&>(
                                                                       rootIt->second.first)),
                                                               root})
                                   .first;
    rootByBindPoint.erase(rootIt);
    const auto bindIt = std::find(roots[root].binds.begin(), roots[root].binds.end(), rootIt);
    *bindIt = newRootIt;
}

void MountRegistry::Mounts::addBind(std::string_view what, std::string_view where) {
    auto whatAbsolute = path::normalize(what);
    auto [root, rootIt] = rootIndex(whatAbsolute);
    if (root < 0) {
        LOG(ERROR) << "[incfs] No root found for bind from " << what << " to " << where;
        return;
    }

    const auto& currentBind = rootIt->first;
    auto whatSubpath = path::relativize(currentBind, whatAbsolute);
    const auto& subdir = rootIt->second.first;
    auto realSubdir = path::join(subdir, whatSubpath);
    auto it = rootByBindPoint
                      .insert_or_assign(path::normalize(where),
                                        std::pair{std::move(realSubdir), root})
                      .first;
    roots[root].binds.push_back(it);
}

void MountRegistry::Mounts::removeBind(std::string_view what) {
    auto absolute = path::normalize(what);
    auto [root, rootIt] = rootIndex(absolute);
    if (root < 0) {
        LOG(WARNING) << "[incfs] Trying to remove non-existent bind point '" << what << '\'';
        return;
    }
    if (roots[root].path == absolute) {
        removeRoot(absolute);
        return;
    }

    rootByBindPoint.erase(rootIt);
    auto& binds = roots[root].binds;
    auto itBind = std::find(binds.begin(), binds.end(), rootIt);
    std::swap(binds.back(), *itBind);
    binds.pop_back();
}

MountRegistry::MountRegistry(std::string_view filesystem)
      : mFilesystem(filesystem.empty() ? INCFS_NAME : filesystem),
        mMountInfo(::open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC)) {
    if (!mMountInfo.ok()) {
        PLOG(FATAL) << "Failed to open the /proc/mounts file";
    }
    mMounts.loadFrom(mMountInfo, mFilesystem);
}

MountRegistry::~MountRegistry() = default;

std::string MountRegistry::rootFor(std::string_view path) {
    auto lock = ensureUpToDate();
    return std::string(mMounts.rootFor(path));
}
std::pair<std::string, std::string> MountRegistry::rootAndSubpathFor(std::string_view path) {
    auto lock = ensureUpToDate();
    auto [root, subpath] = mMounts.rootAndSubpathFor(path);
    return {std::string(root), std::move(subpath)};
}

MountRegistry::Mounts MountRegistry::copyMounts() {
    auto lock = ensureUpToDate();
    return mMounts;
}

void MountRegistry::reload() {
    (void)ensureUpToDate();
}

std::unique_lock<std::mutex> MountRegistry::ensureUpToDate() {
    pollfd pfd = {.fd = mMountInfo.get(), .events = POLLERR | POLLPRI};
    const auto res = TEMP_FAILURE_RETRY(poll(&pfd, 1, 0));
    if (res == 0) {
        // timeout - nothing to do, up to date
        return std::unique_lock{mDataMutex};
    }

    // reload even if poll() fails: (1) it usually doesn't and (2) it's better to be safe.
    std::unique_lock lock(mDataMutex);
    mMounts.loadFrom(mMountInfo, mFilesystem);
    return lock;
}

template <class Callback>
static bool forEachLine(base::borrowed_fd fd, Callback&& cb) {
    static constexpr auto kBufSize = 128 * 1024;
    char buffer[kBufSize];
    const char* nextLine = buffer;
    char* nextRead = buffer;
    int64_t pos = 0;
    for (;;) {
        const auto read = pread(fd.get(), nextRead, std::end(buffer) - nextRead, pos);
        if (read == 0) {
            break;
        }
        if (read < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }

        pos += read;
        const auto readEnd = nextRead + read;
        auto chunk = std::string_view{nextLine, size_t(readEnd - nextLine)};
        do {
            auto lineEnd = chunk.find('\n');
            if (lineEnd == chunk.npos) {
                break;
            }
            cb(chunk.substr(0, lineEnd));
            chunk.remove_prefix(lineEnd + 1);
        } while (!chunk.empty());

        const auto remainingSize = readEnd - chunk.end();
        memmove(buffer, chunk.end(), remainingSize);
        nextLine = buffer;
        nextRead = buffer + remainingSize;
    }

    if (nextLine < nextRead) {
        cb({nextLine, size_t(nextRead - nextLine)});
    }

    return true;
}

bool MountRegistry::Mounts::loadFrom(base::borrowed_fd fd, std::string_view filesystem) {
    struct MountInfo {
        std::string root;
        std::string backing;
        std::vector<std::pair<std::string, std::string>> bindPoints;
    };
    std::unordered_map<std::string, MountInfo> mountsByGroup(16);
    std::vector<std::string_view> items(12);
    const auto parsed = forEachLine(fd, [&](std::string_view line) {
        if (line.empty()) {
            return;
        }
        Split(line, ' ', &items);
        if (items.size() < 10) {
            LOG(WARNING) << "[incfs] bad line in mountinfo: '" << line << '\'';
            return;
        }
        // Note: there are optional fields in the line, starting at [6]. Anything after that should
        // be indexed from the end.
        const auto name = items.rbegin()[2];
        if (!name.starts_with(filesystem)) {
            return;
        }
        const auto groupId = items[2];
        auto subdir = items[3];
        auto mountPoint = std::string(items[4]);
        fixProcPath(mountPoint);
        mountPoint = path::normalize(mountPoint);
        auto& mount = mountsByGroup[std::string(groupId)];
        if (subdir == "/"sv) {
            if (mount.root.empty()) {
                mount.root.assign(mountPoint);
                mount.backing.assign(items.rbegin()[1]);
                fixProcPath(mount.backing);
            } else {
                LOG(WARNING) << "[incfs] incfs root '" << mount.root
                             << "' mounted in multiple places, ignoring later mount '" << mountPoint
                             << '\'';
            }
            subdir = ""sv;
        }
        mount.bindPoints.emplace_back(std::string(subdir), std::move(mountPoint));
    });

    if (!parsed) {
        return false;
    }

    rootByBindPoint.clear();
    // preserve the allocated capacity, but clean existing data
    roots.resize(mountsByGroup.size());
    for (auto& root : roots) {
        root.binds.clear();
    }

    int index = 0;
    for (auto& [_, mount] : mountsByGroup) {
        Root& root = roots[index];
        auto& binds = root.binds;
        binds.reserve(mount.bindPoints.size());
        for (auto& [subdir, bind] : mount.bindPoints) {
            auto it =
                    rootByBindPoint
                            .insert_or_assign(std::move(bind), std::pair(std::move(subdir), index))
                            .first;
            binds.push_back(it);
        }
        root.path = std::move(mount.root);
        root.backing = std::move(mount.backing);
        ++index;
    }

    LOG(INFO) << "[incfs] Loaded " << filesystem << " mount info: " << roots.size()
              << " instances, " << rootByBindPoint.size() << " mount points";
    if (base::VERBOSE >= base::GetMinimumLogSeverity()) {
        for (auto&& [root, backing, binds] : roots) {
            LOG(INFO) << "[incfs]  '" << root << '\'';
            LOG(INFO) << "[incfs]    backing: '" << backing << '\'';
            for (auto&& bind : binds) {
                LOG(INFO) << "[incfs]      bind : '" << bind->second.first << "'->'" << bind->first
                          << '\'';
            }
        }
    }
    return true;
}

auto MountRegistry::Mounts::load(base::borrowed_fd mountInfo, std::string_view filesystem)
        -> Mounts {
    Mounts res;
    res.loadFrom(mountInfo, filesystem);
    return res;
}

} // namespace android::incfs
