/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <stddef.h>
#include <sys/uio.h>
#include <cstdint>
#include <optional>

#include <log/log.h>
#include <utils/Errors.h>

#define TEST_AND_RETURN(value, expr)            \
    do {                                        \
        if (!(expr)) {                          \
            ALOGE("Failed to call: %s", #expr); \
            return value;                       \
        }                                       \
    } while (0)

namespace android {

// avoid optimizations
void zeroMemory(uint8_t* data, size_t size);

// View of contiguous sequence. Similar to std::span.
template <typename T>
struct Span {
    T* data = nullptr;
    size_t size = 0;

    size_t byteSize() { return size * sizeof(T); }

    iovec toIovec() { return {const_cast<std::remove_const_t<T>*>(data), byteSize()}; }

    // Truncates `this` to a length of `offset` and returns a span with the
    // remainder.
    //
    // `std::nullopt` iff offset > size.
    std::optional<Span<T>> splitOff(size_t offset) {
        if (offset > size) {
            return std::nullopt;
        }
        Span<T> rest = {data + offset, size - offset};
        size = offset;
        return rest;
    }

    // Returns nullopt if the byte size of `this` isn't evenly divisible by sizeof(U).
    template <typename U>
    std::optional<Span<U>> reinterpret() const {
        // Only allow casting from bytes for simplicity.
        static_assert(std::is_same_v<std::remove_const_t<T>, uint8_t>);
        if (size % sizeof(U) != 0) {
            return std::nullopt;
        }
        return Span<U>{reinterpret_cast<U*>(data), size / sizeof(U)};
    }
};

}   // namespace android
