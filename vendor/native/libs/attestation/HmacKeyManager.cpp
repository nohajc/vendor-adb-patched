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

#include <attestation/HmacKeyManager.h>
#include <log/log.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace android {

static std::array<uint8_t, 128> getRandomKey() {
    std::array<uint8_t, 128> key;
    if (RAND_bytes(key.data(), key.size()) != 1) {
        LOG_ALWAYS_FATAL("Can't generate HMAC key");
    }
    return key;
}

HmacKeyManager::HmacKeyManager() : mHmacKey(getRandomKey()) {}

std::array<uint8_t, 32> HmacKeyManager::sign(const uint8_t* data, size_t size) const {
    // SHA256 always generates 32-bytes result
    std::array<uint8_t, 32> hash;
    unsigned int hashLen = 0;
    uint8_t* result =
            HMAC(EVP_sha256(), mHmacKey.data(), mHmacKey.size(), data, size, hash.data(), &hashLen);
    if (result == nullptr) {
        ALOGE("Could not sign the data using HMAC");
        return INVALID_HMAC;
    }

    if (hashLen != hash.size()) {
        ALOGE("HMAC-SHA256 has unexpected length");
        return INVALID_HMAC;
    }

    return hash;
}
} // namespace android