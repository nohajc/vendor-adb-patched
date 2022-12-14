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

#if defined(TRUSTY_USERSPACE)
#include <openssl/rand.h>
#include <trusty_ipc.h>
#else
#include <lib/rand/rand.h>
#endif

#include <binder/RpcTransportTipcTrusty.h>

#include "../OS.h"
#include "TrustyStatus.h"

using android::base::Result;

namespace android {

Result<void> setNonBlocking(android::base::borrowed_fd /*fd*/) {
    // Trusty IPC syscalls are all non-blocking by default.
    return {};
}

status_t getRandomBytes(uint8_t* data, size_t size) {
#if defined(TRUSTY_USERSPACE)
    int res = RAND_bytes(data, size);
    return res == 1 ? OK : UNKNOWN_ERROR;
#else
    int res = rand_get_bytes(data, size);
    return res == 0 ? OK : UNKNOWN_ERROR;
#endif // TRUSTY_USERSPACE
}

status_t dupFileDescriptor(int oldFd, int* newFd) {
    int res = dup(oldFd);
    if (res < 0) {
        return statusFromTrusty(res);
    }

    *newFd = res;
    return OK;
}

std::unique_ptr<RpcTransportCtxFactory> makeDefaultRpcTransportCtxFactory() {
    return RpcTransportCtxFactoryTipcTrusty::make();
}

ssize_t sendMessageOnSocket(
        const RpcTransportFd& /* socket */, iovec* /* iovs */, int /* niovs */,
        const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* /* ancillaryFds */) {
    errno = ENOTSUP;
    return -1;
}

ssize_t receiveMessageFromSocket(
        const RpcTransportFd& /* socket */, iovec* /* iovs */, int /* niovs */,
        std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* /* ancillaryFds */) {
    errno = ENOTSUP;
    return -1;
}

} // namespace android
