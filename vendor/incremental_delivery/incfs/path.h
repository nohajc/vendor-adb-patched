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

std::string fromFd(int fd);
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
std::string_view dirName(std::string_view path);
std::string_view baseName(std::string_view path);

// Split the |full| path into its directory and basename components.
// This modifies the input string to null-terminate the output directory
std::pair<std::string_view, std::string_view> splitDirBase(std::string& full);

int isEmptyDir(std::string_view dir);
bool startsWith(std::string_view path, std::string_view prefix);
bool endsWith(std::string_view path, std::string_view prefix);

inline auto openDir(const char* path) {
    auto dir = std::unique_ptr<DIR, decltype(&closedir)>(::opendir(path), &::closedir);
    return dir;
}

template <class... Paths>
std::string join(std::string_view first, std::string_view second, Paths&&... paths) {
    std::string result;
    {
        using std::size;
        result.reserve(first.size() + second.size() + 1 + (sizeof...(paths) + ... + size(paths)));
    }
    result.assign(first);
    (details::appendNextPath(result, second), ..., details::appendNextPath(result, paths));
    return result;
}

} // namespace android::incfs::path
