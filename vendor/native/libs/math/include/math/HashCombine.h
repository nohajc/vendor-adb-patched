/*
 * Copyright 2021 The Android Open Source Project
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

#include <functional>

namespace android {
static inline void hashCombineSingleHashed(size_t& combinedHash, size_t hash) {
    combinedHash = 31 * combinedHash + hash;
}

template<typename T>
static inline void hashCombineSingle(size_t& combinedHash, const T& val) {
    hashCombineSingleHashed(combinedHash, std::hash<T>{}(val));
}

template<typename... Types>
static inline size_t hashCombine(const Types& ... args) {
    size_t hash = 0;
    ( hashCombineSingle(hash, args), ... );
    return hash;
}

} // namespace android