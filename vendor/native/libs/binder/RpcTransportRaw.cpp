/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "RpcRawTransport"
#include <log/log.h>

#include <poll.h>
#include <stddef.h>

#include <binder/RpcTransportRaw.h>

#include "FdTrigger.h"
#include "OS.h"
#include "RpcState.h"
#include "RpcTransportUtils.h"

namespace android {

// RpcTransport with TLS disabled.
class RpcTransportRaw : public RpcTransport {
public:
    explicit RpcTransportRaw(android::RpcTransportFd socket) : mSocket(std::move(socket)) {}
    status_t pollRead(void) override {
        uint8_t buf;
        ssize_t ret = TEMP_FAILURE_RETRY(
                ::recv(mSocket.fd.get(), &buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT));
        if (ret < 0) {
            int savedErrno = errno;
            if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                return WOULD_BLOCK;
            }

            LOG_RPC_DETAIL("RpcTransport poll(): %s", strerror(savedErrno));
            return -savedErrno;
        } else if (ret == 0) {
            return DEAD_OBJECT;
        }

        return OK;
    }

    status_t interruptableWriteFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll,
            const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds)
            override {
        bool sentFds = false;
        auto send = [&](iovec* iovs, int niovs) -> ssize_t {
            ssize_t ret =
                    sendMessageOnSocket(mSocket, iovs, niovs, sentFds ? nullptr : ancillaryFds);
            sentFds |= ret > 0;
            return ret;
        };
        return interruptableReadOrWrite(mSocket, fdTrigger, iovs, niovs, send, "sendmsg", POLLOUT,
                                        altPoll);
    }

    status_t interruptableReadFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll,
            std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds) override {
        auto recv = [&](iovec* iovs, int niovs) -> ssize_t {
            return receiveMessageFromSocket(mSocket, iovs, niovs, ancillaryFds);
        };
        return interruptableReadOrWrite(mSocket, fdTrigger, iovs, niovs, recv, "recvmsg", POLLIN,
                                        altPoll);
    }

    virtual bool isWaiting() { return mSocket.isInPollingState(); }

private:
    android::RpcTransportFd mSocket;
};

// RpcTransportCtx with TLS disabled.
class RpcTransportCtxRaw : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::RpcTransportFd socket, FdTrigger*) const {
        return std::make_unique<RpcTransportRaw>(std::move(socket));
    }
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override { return {}; }
};

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryRaw::newServerCtx() const {
    return std::make_unique<RpcTransportCtxRaw>();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryRaw::newClientCtx() const {
    return std::make_unique<RpcTransportCtxRaw>();
}

const char *RpcTransportCtxFactoryRaw::toCString() const {
    return "raw";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryRaw::make() {
    return std::unique_ptr<RpcTransportCtxFactoryRaw>(new RpcTransportCtxFactoryRaw());
}

} // namespace android
