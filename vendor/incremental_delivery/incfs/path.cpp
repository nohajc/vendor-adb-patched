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

#include "path.h"

#include <android-base/logging.h>

#include <memory>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std::literals;

namespace android::incfs::path {

namespace {

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

} // namespace

bool isAbsolute(std::string_view path) {
    return !path.empty() && path[0] == '/';
}

std::string normalize(std::string_view path) {
    if (path.empty()) {
        return {};
    }
    if (path.starts_with("../"sv)) {
        return {};
    }

    std::string result;
    if (isAbsolute(path)) {
        path.remove_prefix(1);
    } else {
        char buffer[PATH_MAX];
        if (!::getcwd(buffer, sizeof(buffer))) {
            return {};
        }
        result += buffer;
    }

    size_t start = 0;
    size_t end = 0;
    for (; end != path.npos; start = end + 1) {
        end = path.find('/', start);
        // Next component, excluding the separator
        auto part = path.substr(start, end - start);
        if (part.empty() || part == "."sv) {
            continue;
        }
        if (part == ".."sv) {
            if (result.empty()) {
                return {};
            }
            auto lastPos = result.rfind('/');
            if (lastPos == result.npos) {
                result.clear();
            } else {
                result.resize(lastPos);
            }
            continue;
        }
        result += '/';
        result += part;
    }

    return result;
}

static constexpr char fdNameFormat[] = "/proc/self/fd/%d";

std::string procfsForFd(int fd) {
    char fdNameBuffer[std::size(fdNameFormat) + 11 + 1]; // max int length + '\0'
    snprintf(fdNameBuffer, std::size(fdNameBuffer), fdNameFormat, fd);
    return fdNameBuffer;
}

std::string fromFd(int fd) {
    char fdNameBuffer[std::size(fdNameFormat) + 11 + 1]; // max int length + '\0'
    snprintf(fdNameBuffer, std::size(fdNameBuffer), fdNameFormat, fd);

    return readlink(fdNameBuffer);
}

std::string readlink(std::string_view path) {
    static constexpr auto kDeletedSuffix = " (deleted)"sv;

    auto cPath = c_str(path);
    std::string res;
    // We used to call lstat() here to preallocate the buffer to the exact required size; turns out
    // that call is significantly more expensive than anything else, so doing a couple extra
    // iterations is worth the savings.
    auto bufSize = 256;
    for (;;) {
        res.resize(bufSize - 1, '\0');
        auto size = ::readlink(cPath, &res[0], res.size());
        if (size < 0) {
            PLOG(ERROR) << "readlink failed for " << path;
            return {};
        }
        if (size >= ssize_t(res.size())) {
            // can't tell if the name is exactly that long, or got truncated - just repeat the call.
            bufSize *= 2;
            continue;
        }
        res.resize(size);
        if (res.ends_with(kDeletedSuffix)) {
            res.resize(size - kDeletedSuffix.size());
        }
        return res;
    }
}

static void preparePathComponent(std::string_view& path, bool trimAll) {
    // need to check for double front slash as a single one has a separate meaning in front
    while (!path.empty() && path.front() == '/' &&
           (trimAll || (path.size() > 1 && path[1] == '/'))) {
        path.remove_prefix(1);
    }
    // for the back we don't care about double-vs-single slash difference
    while (path.size() > !trimAll && path.back() == '/') {
        path.remove_suffix(1);
    }
}

std::string_view relativize(std::string_view parent, std::string_view nested) {
    if (!nested.starts_with(parent)) {
        return nested;
    }
    if (nested.size() == parent.size()) {
        return {};
    }
    if (nested[parent.size()] != '/') {
        return nested;
    }
    auto relative = nested.substr(parent.size());
    while (relative.front() == '/') {
        relative.remove_prefix(1);
    }
    return relative;
}

void details::appendNextPath(std::string& res, std::string_view path) {
    preparePathComponent(path, !res.empty());
    if (path.empty()) {
        return;
    }
    if (!res.empty() && !res.ends_with('/')) {
        res.push_back('/');
    }
    res += path;
}

std::pair<std::string_view, std::string_view> splitDirBase(std::string& full) {
    auto res = std::pair(dirName(full), baseName(full));
    if (res.first.data() == full.data()) {
        full[res.first.size()] = 0;
    }
    return res;
}

int isEmptyDir(std::string_view dir) {
    const auto d = std::unique_ptr<DIR, decltype(&::closedir)>{::opendir(c_str(dir)), ::closedir};
    if (!d) {
        return -errno;
    }
    while (const auto entry = ::readdir(d.get())) {
        if (entry->d_type != DT_DIR) {
            return -ENOTEMPTY;
        }
        if (entry->d_name != "."sv && entry->d_name != ".."sv) {
            return -ENOTEMPTY;
        }
    }
    return 0;
}

bool startsWith(std::string_view path, std::string_view prefix) {
    if (!path.starts_with(prefix)) {
        return false;
    }
    return path.size() == prefix.size() || path[prefix.size()] == '/';
}

bool endsWith(std::string_view path, std::string_view suffix) {
    if (!path.ends_with(suffix)) {
        return false;
    }
    return path.size() == suffix.size() || path[path.size() - suffix.size() - 1] == '/';
}

} // namespace android::incfs::path
