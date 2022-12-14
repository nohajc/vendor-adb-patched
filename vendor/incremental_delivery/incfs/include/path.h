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

#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include <dirent.h>

namespace android::incfs::path {

namespace details {
void appendNextPath(std::string& res, std::string_view c);
}

constexpr auto procfsFdDir = std::string_view("/proc/self/fd");

std::string fromFd(int fd);
std::string procfsForFd(int fd);
std::string readlink(std::string_view path);
bool isAbsolute(std::string_view path);
std::string normalize(std::string_view path);

std::string_view relativize(std::string_view parent, std::string_view nested);
inline std::string_view relativize(const char* parent, const char* nested) {
    return relativize(std::string_view(parent), std::string_view(nested));
}
inline std::string_view relativize(std::string_view parent, const char* nested) {
    return relativize(parent, std::string_view(nested));
}
inline std::string_view relativize(const char* parent, std::string_view nested) {
    return relativize(std::string_view(parent), nested);
}

std::string_view relativize(std::string&& parent, std::string_view nested) = delete;
std::string_view relativize(std::string_view parent, std::string&& nested) = delete;

// Note: some system headers #define 'dirname' and 'basename' as macros

inline std::string_view baseName(std::string_view path) {
    using namespace std::literals;
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

inline std::string_view dirName(std::string_view path) {
    using namespace std::literals;
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

// Split the |full| path into its directory and basename components.
// This modifies the input string to null-terminate the output directory
std::pair<std::string_view, std::string_view> splitDirBase(std::string& full);

int isEmptyDir(std::string_view dir);
bool startsWith(std::string_view path, std::string_view prefix);
bool endsWith(std::string_view path, std::string_view prefix);

struct PathDirCloser {
    void operator()(DIR* d) const { ::closedir(d); }
};

inline auto openDir(const char* path) {
    auto dir = std::unique_ptr<DIR, PathDirCloser>(::opendir(path));
    return dir;
}

inline auto openDir(int dirFd) {
    auto dir = std::unique_ptr<DIR, PathDirCloser>(::fdopendir(dirFd));
    return dir;
}

template <class... Paths>
std::string join(std::string&& first, std::string_view second, Paths&&... paths) {
    std::string& result = first;
    {
        using std::size;
        result.reserve(first.size() + second.size() + 1 + (sizeof...(paths) + ... + size(paths)));
    }
    (details::appendNextPath(result, second), ...,
     details::appendNextPath(result, std::forward<Paths>(paths)));
    return result;
}

template <class... Paths>
std::string join(std::string_view first, std::string_view second, Paths&&... paths) {
    return join(std::string(), first, second, std::forward<Paths>(paths)...);
}
template <class... Paths>
std::string join(const char* first, std::string_view second, Paths&&... paths) {
    return path::join(std::string_view(first), second, std::forward<Paths>(paths)...);
}

} // namespace android::incfs::path
