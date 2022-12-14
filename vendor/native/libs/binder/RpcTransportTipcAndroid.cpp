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

#define LOG_TAG "RpcTransportTipcAndroid"

#include <binder/RpcSession.h>
#include <binder/RpcTransportTipcAndroid.h>
#include <log/log.h>
#include <poll.h>
#include <trusty/tipc.h>

#include "FdTrigger.h"
#include "RpcState.h"
#include "RpcTransportUtils.h"

using android::base::Error;
using android::base::Result;

namespace android {

// RpcTransport for writing Trusty IPC clients in Android.
class RpcTransportTipcAndroid : public RpcTransport {
public:
    explicit RpcTransportTipcAndroid(android::RpcTransportFd socket) : mSocket(std::move(socket)) {}

    status_t pollRead() override {
        if (mReadBufferPos < mReadBufferSize) {
            // We have more data in the read buffer
            return OK;
        }

        // Trusty IPC device is not a socket, so MSG_PEEK is not available
        pollfd pfd{.fd = mSocket.fd.get(), .events = static_cast<int16_t>(POLLIN), .revents = 0};
        ssize_t ret = TEMP_FAILURE_RETRY(::poll(&pfd, 1, 0));
        if (ret < 0) {
            int savedErrno = errno;
            if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                return WOULD_BLOCK;
            }

            LOG_RPC_DETAIL("RpcTransport poll(): %s", strerror(savedErrno));
            return adjustStatus(-savedErrno);
        }

        if (pfd.revents & POLLNVAL) {
            return BAD_VALUE;
        }
        if (pfd.revents & POLLERR) {
            return DEAD_OBJECT;
        }
        if (pfd.revents & POLLIN) {
            // Copied from FdTrigger.cpp: Even though POLLHUP may also be set,
            // treat it as a success condition to ensure data is drained.
            return OK;
        }
        if (pfd.revents & POLLHUP) {
            return DEAD_OBJECT;
        }

        return WOULD_BLOCK;
    }

    status_t interruptableWriteFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll,
            const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds)
            override {
        auto writeFn = [&](iovec* iovs, size_t niovs) -> ssize_t {
            // TODO: send ancillaryFds. For now, we just abort if anyone tries
            // to send any.
            LOG_ALWAYS_FATAL_IF(ancillaryFds != nullptr && !ancillaryFds->empty(),
                                "File descriptors are not supported on Trusty yet");
            return TEMP_FAILURE_RETRY(tipc_send(mSocket.fd.get(), iovs, niovs, nullptr, 0));
        };

        status_t status = interruptableReadOrWrite(mSocket, fdTrigger, iovs, niovs, writeFn,
                                                   "tipc_send", POLLOUT, altPoll);
        return adjustStatus(status);
    }

    status_t interruptableReadFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll,
            std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* /*ancillaryFds*/)
            override {
        auto readFn = [&](iovec* iovs, size_t niovs) -> ssize_t {
            // Fill the read buffer at most once per readFn call, then try to
            // return as much of it as possible. If the input iovecs are spread
            // across multiple messages that require multiple fillReadBuffer
            // calls, we expect the caller to advance the iovecs past the first
            // read and call readFn as many times as needed to get all the data
            status_t ret = fillReadBuffer();
            if (ret != OK) {
                // We need to emulate a Linux read call, which sets errno on
                // error and returns -1
                errno = -ret;
                return -1;
            }

            ssize_t processSize = 0;
            for (size_t i = 0; i < niovs && mReadBufferPos < mReadBufferSize; i++) {
                auto& iov = iovs[i];
                size_t numBytes = std::min(iov.iov_len, mReadBufferSize - mReadBufferPos);
                memcpy(iov.iov_base, mReadBuffer.get() + mReadBufferPos, numBytes);
                mReadBufferPos += numBytes;
                processSize += numBytes;
            }

            return processSize;
        };

        status_t status = interruptableReadOrWrite(mSocket, fdTrigger, iovs, niovs, readFn, "read",
                                                   POLLIN, altPoll);
        return adjustStatus(status);
    }

    bool isWaiting() override { return mSocket.isInPollingState(); }

private:
    status_t adjustStatus(status_t status) {
        if (status == -ENOTCONN) {
            // TIPC returns ENOTCONN on disconnect, but that's basically
            // the same as DEAD_OBJECT and the latter is the common libbinder
            // error code for dead connections
            return DEAD_OBJECT;
        }

        return status;
    }

    status_t fillReadBuffer() {
        if (mReadBufferPos < mReadBufferSize) {
            return OK;
        }

        if (!mReadBuffer) {
            // Guarantee at least kDefaultBufferSize bytes
            mReadBufferCapacity = std::max(mReadBufferCapacity, kDefaultBufferSize);
            mReadBuffer.reset(new (std::nothrow) uint8_t[mReadBufferCapacity]);
            if (!mReadBuffer) {
                return NO_MEMORY;
            }
        }

        // Reset the size and position in case we have to exit with an error.
        // After we read a message into the buffer, we update the size
        // with the actual value.
        mReadBufferPos = 0;
        mReadBufferSize = 0;

        while (true) {
            ssize_t processSize = TEMP_FAILURE_RETRY(
                    read(mSocket.fd.get(), mReadBuffer.get(), mReadBufferCapacity));
            if (processSize == 0) {
                return DEAD_OBJECT;
            } else if (processSize < 0) {
                int savedErrno = errno;
                if (savedErrno == EMSGSIZE) {
                    // Buffer was too small, double it and retry
                    if (__builtin_mul_overflow(mReadBufferCapacity, 2, &mReadBufferCapacity)) {
                        return NO_MEMORY;
                    }
                    mReadBuffer.reset(new (std::nothrow) uint8_t[mReadBufferCapacity]);
                    if (!mReadBuffer) {
                        return NO_MEMORY;
                    }
                    continue;
                } else {
                    LOG_RPC_DETAIL("RpcTransport fillBuffer(): %s", strerror(savedErrno));
                    return adjustStatus(-savedErrno);
                }
            } else {
                mReadBufferSize = static_cast<size_t>(processSize);
                return OK;
            }
        }
    }

    RpcTransportFd mSocket;

    // For now, we copy all the input data into a temporary buffer because
    // we might get multiple interruptableReadFully calls per message, but
    // the tipc device only allows one read call. We read every message into
    // this temporary buffer, then return pieces of it from our method.
    //
    // The special transaction GET_MAX_THREADS takes 40 bytes, so the default
    // size should start pretty high.
    static constexpr size_t kDefaultBufferSize = 64;
    std::unique_ptr<uint8_t[]> mReadBuffer;
    size_t mReadBufferPos = 0;
    size_t mReadBufferSize = 0;
    size_t mReadBufferCapacity = 0;
};

// RpcTransportCtx for Trusty.
class RpcTransportCtxTipcAndroid : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::RpcTransportFd fd,
                                               FdTrigger*) const override {
        return std::make_unique<RpcTransportTipcAndroid>(std::move(fd));
    }
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override { return {}; }
};

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTipcAndroid::newServerCtx() const {
    return std::make_unique<RpcTransportCtxTipcAndroid>();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTipcAndroid::newClientCtx() const {
    return std::make_unique<RpcTransportCtxTipcAndroid>();
}

const char* RpcTransportCtxFactoryTipcAndroid::toCString() const {
    return "trusty";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryTipcAndroid::make() {
    return std::unique_ptr<RpcTransportCtxFactoryTipcAndroid>(
            new RpcTransportCtxFactoryTipcAndroid());
}

} // namespace android
