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

#ifndef ATTESTATION_HMACKEYMANAGER_H
#define ATTESTATION_HMACKEYMANAGER_H

#include <array>

namespace android {
/**
 * Invalid value of HMAC - SHA256. Any events with this HMAC value will be marked as not verified.
 */
constexpr std::array<uint8_t, 32> INVALID_HMAC = {0};

class HmacKeyManager {
public:
    HmacKeyManager();
    std::array<uint8_t, 32> sign(const uint8_t* data, size_t size) const;
private:
    const std::array<uint8_t, 128> mHmacKey;
};
} // namespace android

#endif // ATTESTATION_HMACKEYMANAGER_H