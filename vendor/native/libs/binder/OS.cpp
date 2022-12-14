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
#include <binder/RpcTransportRaw.h>
#include <log/log.h>
#include <string.h>

using android::base::ErrnoError;
using android::base::Result;

namespace android {

// Linux kernel supports up to 253 (from SCM_MAX_FD) for unix sockets.
constexpr size_t kMaxFdsPerMsg = 253;

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

status_t dupFileDescriptor(int oldFd, int* newFd) {
    int ret = fcntl(oldFd, F_DUPFD_CLOEXEC, 0);
    if (ret < 0) {
        return -errno;
    }

    *newFd = ret;
    return OK;
}

std::unique_ptr<RpcTransportCtxFactory> makeDefaultRpcTransportCtxFactory() {
    return RpcTransportCtxFactoryRaw::make();
}

ssize_t sendMessageOnSocket(
        const RpcTransportFd& socket, iovec* iovs, int niovs,
        const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds) {
    if (ancillaryFds != nullptr && !ancillaryFds->empty()) {
        if (ancillaryFds->size() > kMaxFdsPerMsg) {
            errno = EINVAL;
            return -1;
        }

        // CMSG_DATA is not necessarily aligned, so we copy the FDs into a buffer and then
        // use memcpy.
        int fds[kMaxFdsPerMsg];
        for (size_t i = 0; i < ancillaryFds->size(); i++) {
            fds[i] = std::visit([](const auto& fd) { return fd.get(); }, ancillaryFds->at(i));
        }
        const size_t fdsByteSize = sizeof(int) * ancillaryFds->size();

        alignas(struct cmsghdr) char msgControlBuf[CMSG_SPACE(sizeof(int) * kMaxFdsPerMsg)];

        msghdr msg{
                .msg_iov = iovs,
                .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
                .msg_control = msgControlBuf,
                .msg_controllen = sizeof(msgControlBuf),
        };

        cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(fdsByteSize);
        memcpy(CMSG_DATA(cmsg), fds, fdsByteSize);

        msg.msg_controllen = CMSG_SPACE(fdsByteSize);
        return TEMP_FAILURE_RETRY(sendmsg(socket.fd.get(), &msg, MSG_NOSIGNAL | MSG_CMSG_CLOEXEC));
    }

    msghdr msg{
            .msg_iov = iovs,
            // posix uses int, glibc uses size_t.  niovs is a
            // non-negative int and can be cast to either.
            .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
    };
    return TEMP_FAILURE_RETRY(sendmsg(socket.fd.get(), &msg, MSG_NOSIGNAL));
}

ssize_t receiveMessageFromSocket(
        const RpcTransportFd& socket, iovec* iovs, int niovs,
        std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds) {
    if (ancillaryFds != nullptr) {
        int fdBuffer[kMaxFdsPerMsg];
        alignas(struct cmsghdr) char msgControlBuf[CMSG_SPACE(sizeof(fdBuffer))];

        msghdr msg{
                .msg_iov = iovs,
                .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
                .msg_control = msgControlBuf,
                .msg_controllen = sizeof(msgControlBuf),
        };
        ssize_t processSize = TEMP_FAILURE_RETRY(recvmsg(socket.fd.get(), &msg, MSG_NOSIGNAL));
        if (processSize < 0) {
            return -1;
        }

        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                // NOTE: It is tempting to reinterpret_cast, but cmsg(3) explicitly asks
                // application devs to memcpy the data to ensure memory alignment.
                size_t dataLen = cmsg->cmsg_len - CMSG_LEN(0);
                LOG_ALWAYS_FATAL_IF(dataLen > sizeof(fdBuffer)); // validity check
                memcpy(fdBuffer, CMSG_DATA(cmsg), dataLen);
                size_t fdCount = dataLen / sizeof(int);
                ancillaryFds->reserve(ancillaryFds->size() + fdCount);
                for (size_t i = 0; i < fdCount; i++) {
                    ancillaryFds->emplace_back(base::unique_fd(fdBuffer[i]));
                }
                break;
            }
        }

        if (msg.msg_flags & MSG_CTRUNC) {
            errno = EPIPE;
            return -1;
        }
        return processSize;
    }
    msghdr msg{
            .msg_iov = iovs,
            // posix uses int, glibc uses size_t.  niovs is a
            // non-negative int and can be cast to either.
            .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
    };

    return TEMP_FAILURE_RETRY(recvmsg(socket.fd.get(), &msg, MSG_NOSIGNAL));
}

} // namespace android
