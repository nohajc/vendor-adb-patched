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

std::string fromFd(int fd) {
    static constexpr auto kDeletedSuffix = " (deleted)"sv;
    static constexpr char fdNameFormat[] = "/proc/self/fd/%d";
    char fdNameBuffer[std::size(fdNameFormat) + 11 + 1]; // max int length + '\0'
    snprintf(fdNameBuffer, std::size(fdNameBuffer), fdNameFormat, fd);

    std::string res;
    // lstat() is supposed to return us exactly the needed buffer size, but
    // somehow it may also return a smaller (but still >0) st_size field.
    // That's why let's only use it for the initial estimate.
    struct stat st = {};
    if (::lstat(fdNameBuffer, &st) || st.st_size == 0) {
        st.st_size = PATH_MAX;
    }
    auto bufSize = st.st_size;
    for (;;) {
        res.resize(bufSize + 1, '\0');
        auto size = ::readlink(fdNameBuffer, &res[0], res.size());
        if (size < 0) {
            PLOG(ERROR) << "readlink failed for " << fdNameBuffer;
            return {};
        }
        if (size > bufSize) {
            // File got renamed in between lstat() and readlink() calls? Retry.
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

static void preparePathComponent(std::string_view& path, bool trimFront) {
    if (trimFront) {
        while (!path.empty() && path.front() == '/') {
            path.remove_prefix(1);
        }
    }
    while (!path.empty() && path.back() == '/') {
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
    preparePathComponent(path, true);
    if (path.empty()) {
        return;
    }
    if (!res.empty() && !res.ends_with('/')) {
        res.push_back('/');
    }
    res += path;
}

std::string_view baseName(std::string_view path) {
    if (path.empty()) {
        return {};
    }
    if (path == "/"sv) {
        return "/"sv;
    }
    auto pos = path.rfind('/');
    while (!path.empty() && pos == path.size() - 1) {
        path.remove_suffix(1);
        pos = path.rfind('/');
    }
    if (pos == path.npos) {
        return path.empty() ? "/"sv : path;
    }
    return path.substr(pos + 1);
}

std::string_view dirName(std::string_view path) {
    if (path.empty()) {
        return {};
    }
    if (path == "/"sv) {
        return "/"sv;
    }
    const auto pos = path.rfind('/');
    if (pos == 0) {
        return "/"sv;
    }
    if (pos == path.npos) {
        return "."sv;
    }
    return path.substr(0, pos);
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
