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

#include "OS.h"

#include <android-base/file.h>
#include <string.h>

using android::base::ErrnoError;
using android::base::Result;

namespace android {

Result<void> setNonBlocking(android::base::borrowed_fd fd) {
    int flags = TEMP_FAILURE_RETRY(fcntl(fd.get(), F_GETFL));
    if (flags == -1) {
        return ErrnoError() << "Could not get flags for fd";
    }
    if (int ret = TEMP_FAILURE_RETRY(fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK)); ret == -1) {
        return ErrnoError() << "Could not set non-blocking flag for fd";
    }
    return {};
}

status_t getRandomBytes(uint8_t* data, size_t size) {
    int ret = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (ret == -1) {
        return -errno;
    }

    base::unique_fd fd(ret);
    if (!base::ReadFully(fd, data, size)) {
        return -errno;
    }
    return OK;
}

} // namespace android
