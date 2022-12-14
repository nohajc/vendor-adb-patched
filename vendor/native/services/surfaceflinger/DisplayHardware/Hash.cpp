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

#undef LOG_TAG
#define LOG_TAG "DisplayIdentification"

#include <cstring>
#include <type_traits>

#include <log/log.h>

#include "Hash.h"

namespace android {
namespace {

template <class T>
inline T load(const void* p) {
    static_assert(std::is_integral<T>::value, "T must be integral");

    T r;
    std::memcpy(&r, p, sizeof(r));
    return r;
}

uint64_t rotateByAtLeast1(uint64_t val, uint8_t shift) {
    return (val >> shift) | (val << (64 - shift));
}

uint64_t shiftMix(uint64_t val) {
    return val ^ (val >> 47);
}

uint64_t hash64Len16(uint64_t u, uint64_t v) {
    constexpr uint64_t kMul = 0x9ddfea08eb382d69;
    uint64_t a = (u ^ v) * kMul;
    a ^= (a >> 47);
    uint64_t b = (v ^ a) * kMul;
    b ^= (b >> 47);
    b *= kMul;
    return b;
}

uint64_t hash64Len0To16(const char* s, uint64_t len) {
    constexpr uint64_t k2 = 0x9ae16a3b2f90404f;
    constexpr uint64_t k3 = 0xc949d7c7509e6557;

    if (len > 8) {
        const uint64_t a = load<uint64_t>(s);
        const uint64_t b = load<uint64_t>(s + len - 8);
        return hash64Len16(a, rotateByAtLeast1(b + len, static_cast<uint8_t>(len))) ^ b;
    }
    if (len >= 4) {
        const uint32_t a = load<uint32_t>(s);
        const uint32_t b = load<uint32_t>(s + len - 4);
        return hash64Len16(len + (a << 3), b);
    }
    if (len > 0) {
        const unsigned char a = static_cast<unsigned char>(s[0]);
        const unsigned char b = static_cast<unsigned char>(s[len >> 1]);
        const unsigned char c = static_cast<unsigned char>(s[len - 1]);
        const uint32_t y = static_cast<uint32_t>(a) + (static_cast<uint32_t>(b) << 8);
        const uint32_t z = static_cast<uint32_t>(len) + (static_cast<uint32_t>(c) << 2);
        return shiftMix(y * k2 ^ z * k3) * k2;
    }
    return k2;
}

} // namespace

uint64_t cityHash64Len0To16(std::string_view sv) {
    auto len = sv.length();
    if (len > 16) {
        ALOGE("%s called with length %zu. Only hashing the first 16 chars", __FUNCTION__, len);
        len = 16;
    }
    return hash64Len0To16(sv.data(), len);
}

} // namespace android