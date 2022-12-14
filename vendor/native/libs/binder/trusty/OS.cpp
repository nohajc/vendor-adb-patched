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

#include <openssl/rand.h>

#include "../OS.h"

using android::base::Result;

namespace android {

Result<void> setNonBlocking(android::base::borrowed_fd fd) {
    // Trusty IPC syscalls are all non-blocking by default.
    return {};
}

status_t getRandomBytes(uint8_t* data, size_t size) {
    int res = RAND_bytes(data, size);
    return res == 1 ? OK : UNKNOWN_ERROR;
}

} // namespace android
