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

#include <stddef.h>
#include <cstdint>

#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <binder/RpcTransport.h>
#include <utils/Errors.h>

namespace android {

android::base::Result<void> setNonBlocking(android::base::borrowed_fd fd);

status_t getRandomBytes(uint8_t* data, size_t size);

status_t dupFileDescriptor(int oldFd, int* newFd);

std::unique_ptr<RpcTransportCtxFactory> makeDefaultRpcTransportCtxFactory();

ssize_t sendMessageOnSocket(
        const RpcTransportFd& socket, iovec* iovs, int niovs,
        const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds);

ssize_t receiveMessageFromSocket(
        const RpcTransportFd& socket, iovec* iovs, int niovs,
        std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds);

} // namespace android
