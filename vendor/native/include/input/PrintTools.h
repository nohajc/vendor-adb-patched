/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <map>
#include <optional>
#include <set>
#include <string>

namespace android {

template <typename T>
std::string constToString(const T& v) {
    return std::to_string(v);
}

/**
 * Convert an optional type to string.
 */
template <typename T>
std::string toString(const std::optional<T>& optional,
                     std::string (*toString)(const T&) = constToString) {
    return optional ? toString(*optional) : "<not set>";
}

/**
 * Convert a set of integral types to string.
 */
template <typename T>
std::string dumpSet(const std::set<T>& v, std::string (*toString)(const T&) = constToString) {
    std::string out;
    for (const T& entry : v) {
        out += out.empty() ? "{" : ", ";
        out += toString(entry);
    }
    return out.empty() ? "{}" : (out + "}");
}

/**
 * Convert a map to string. Both keys and values of the map should be integral type.
 */
template <typename K, typename V>
std::string dumpMap(const std::map<K, V>& map, std::string (*keyToString)(const K&) = constToString,
                    std::string (*valueToString)(const V&) = constToString) {
    std::string out;
    for (const auto& [k, v] : map) {
        if (!out.empty()) {
            out += "\n";
        }
        out += keyToString(k) + ":" + valueToString(v);
    }
    return out;
}

const char* toString(bool value);

/**
 * Add "prefix" to the beginning of each line in the provided string
 * "str".
 * The string 'str' is typically multi-line.
 * The most common use case for this function is to add some padding
 * when dumping state.
 */
std::string addLinePrefix(std::string str, const std::string& prefix);

} // namespace android