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

#include <string_view>
#include <vector>

namespace android::incfs {

// Splits a string and calls |onSplitCb| for each occurrence of a substring
// between delimiters (including empty ones for two delimiters in a row)
//
// |delimiters| can either be a list of delimiters in something string-like
// or a single character (which is more efficient).
//
// An empty string is not a valid delimiter.
//
template <class Callback, class Separator>
void Split(std::string_view s, Separator delimiters, Callback&& onSplitCb) {
    size_t base = 0;
    for (;;) {
        const auto found = s.find_first_of(delimiters, base);
        onSplitCb(s.substr(base, found - base));
        if (found == std::string_view::npos) {
            break;
        }
        base = found + 1;
    }
}

// Splits a string into a vector of string views.
//
// The string is split at each occurrence of a character in |delimiters|.
//
// The empty string is not a valid delimiter list.
//
template <class Separator>
void Split(std::string_view s, Separator delimiters, std::vector<std::string_view>* out) {
    out->clear();
    Split(s, delimiters, [out](std::string_view split) { out->emplace_back(split); });
}

template <class Separator>
std::vector<std::string_view> Split(std::string_view s, Separator delimiters) {
    std::vector<std::string_view> result;
    Split(s, delimiters, &result);
    return result;
}

} // namespace android::incfs
