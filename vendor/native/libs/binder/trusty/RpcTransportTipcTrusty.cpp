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

#define LOG_TAG "RpcTransportTipcTrusty"

#include <inttypes.h>
#include <trusty_ipc.h>

#include <binder/RpcSession.h>
#include <binder/RpcTransportTipcTrusty.h>
#include <log/log.h>

#include "../FdTrigger.h"
#include "../RpcState.h"
#include "TrustyStatus.h"

namespace android {

// RpcTransport for Trusty.
class RpcTransportTipcTrusty : public RpcTransport {
public:
    explicit RpcTransportTipcTrusty(android::RpcTransportFd socket) : mSocket(std::move(socket)) {}
    ~RpcTransportTipcTrusty() { releaseMessage(); }

    status_t pollRead() override {
        auto status = ensureMessage(false);
        if (status != OK) {
            return status;
        }
        return mHaveMessage ? OK : WOULD_BLOCK;
    }

    status_t interruptableWriteFully(
            FdTrigger* /*fdTrigger*/, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& /*altPoll*/,
            const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds)
            override {
        if (niovs < 0) {
            return BAD_VALUE;
        }

        size_t size = 0;
        for (int i = 0; i < niovs; i++) {
            size += iovs[i].iov_len;
        }

        handle_t msgHandles[IPC_MAX_MSG_HANDLES];
        ipc_msg_t msg{
                .num_iov = static_cast<uint32_t>(niovs),
                .iov = iovs,
                .num_handles = 0,
                .handles = nullptr,
        };

        if (ancillaryFds != nullptr && !ancillaryFds->empty()) {
            if (ancillaryFds->size() > IPC_MAX_MSG_HANDLES) {
                // This shouldn't happen because we check the FD count in RpcState.
                ALOGE("Saw too many file descriptors in RpcTransportCtxTipcTrusty: "
                      "%zu (max is %u). Aborting session.",
                      ancillaryFds->size(), IPC_MAX_MSG_HANDLES);
                return BAD_VALUE;
            }

            for (size_t i = 0; i < ancillaryFds->size(); i++) {
                msgHandles[i] =
                        std::visit([](const auto& fd) { return fd.get(); }, ancillaryFds->at(i));
            }

            msg.num_handles = ancillaryFds->size();
            msg.handles = msgHandles;
        }

        ssize_t rc = send_msg(mSocket.fd.get(), &msg);
        if (rc == ERR_NOT_ENOUGH_BUFFER) {
            // Peer is blocked, wait until it unblocks.
            // TODO: when tipc supports a send-unblocked handler,
            // save the message here in a queue and retry it asynchronously
            // when the handler gets called by the library
            uevent uevt;
            do {
                rc = ::wait(mSocket.fd.get(), &uevt, INFINITE_TIME);
                if (rc < 0) {
                    return statusFromTrusty(rc);
                }
                if (uevt.event & IPC_HANDLE_POLL_HUP) {
                    return DEAD_OBJECT;
                }
            } while (!(uevt.event & IPC_HANDLE_POLL_SEND_UNBLOCKED));

            // Retry the send, it should go through this time because
            // sending is now unblocked
            rc = send_msg(mSocket.fd.get(), &msg);
        }
        if (rc < 0) {
            return statusFromTrusty(rc);
        }
        LOG_ALWAYS_FATAL_IF(static_cast<size_t>(rc) != size,
                            "Sent the wrong number of bytes %zd!=%zu", rc, size);

        return OK;
    }

    status_t interruptableReadFully(
            FdTrigger* /*fdTrigger*/, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& /*altPoll*/,
            std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds) override {
        if (niovs < 0) {
            return BAD_VALUE;
        }

        // If iovs has one or more empty vectors at the end and
        // we somehow advance past all the preceding vectors and
        // pass some or all of the empty ones to sendmsg/recvmsg,
        // the call will return processSize == 0. In that case
        // we should be returning OK but instead return DEAD_OBJECT.
        // To avoid this problem, we make sure here that the last
        // vector at iovs[niovs - 1] has a non-zero length.
        while (niovs > 0 && iovs[niovs - 1].iov_len == 0) {
            niovs--;
        }
        if (niovs == 0) {
            // The vectors are all empty, so we have nothing to read.
            return OK;
        }

        while (true) {
            auto status = ensureMessage(true);
            if (status != OK) {
                return status;
            }

            LOG_ALWAYS_FATAL_IF(mMessageInfo.num_handles > IPC_MAX_MSG_HANDLES,
                                "Received too many handles %" PRIu32, mMessageInfo.num_handles);
            bool haveHandles = mMessageInfo.num_handles != 0;
            handle_t msgHandles[IPC_MAX_MSG_HANDLES];

            ipc_msg_t msg{
                    .num_iov = static_cast<uint32_t>(niovs),
                    .iov = iovs,
                    .num_handles = mMessageInfo.num_handles,
                    .handles = haveHandles ? msgHandles : 0,
            };
            ssize_t rc = read_msg(mSocket.fd.get(), mMessageInfo.id, mMessageOffset, &msg);
            if (rc < 0) {
                return statusFromTrusty(rc);
            }

            size_t processSize = static_cast<size_t>(rc);
            mMessageOffset += processSize;
            LOG_ALWAYS_FATAL_IF(mMessageOffset > mMessageInfo.len,
                                "Message offset exceeds length %zu/%zu", mMessageOffset,
                                mMessageInfo.len);

            if (haveHandles) {
                if (ancillaryFds != nullptr) {
                    ancillaryFds->reserve(ancillaryFds->size() + mMessageInfo.num_handles);
                    for (size_t i = 0; i < mMessageInfo.num_handles; i++) {
                        ancillaryFds->emplace_back(base::unique_fd(msgHandles[i]));
                    }

                    // Clear the saved number of handles so we don't accidentally
                    // read them multiple times
                    mMessageInfo.num_handles = 0;
                    haveHandles = false;
                } else {
                    ALOGE("Received unexpected handles %" PRIu32, mMessageInfo.num_handles);
                    // It should be safe to continue here. We could abort, but then
                    // peers could DoS us by sending messages with handles in them.
                    // Close the handles since we are ignoring them.
                    for (size_t i = 0; i < mMessageInfo.num_handles; i++) {
                        ::close(msgHandles[i]);
                    }
                }
            }

            // Release the message if all of it has been read
            if (mMessageOffset == mMessageInfo.len) {
                releaseMessage();
            }

            while (processSize > 0 && niovs > 0) {
                auto& iov = iovs[0];
                if (processSize < iov.iov_len) {
                    // Advance the base of the current iovec
                    iov.iov_base = reinterpret_cast<char*>(iov.iov_base) + processSize;
                    iov.iov_len -= processSize;
                    break;
                }

                // The current iovec was fully written
                processSize -= iov.iov_len;
                iovs++;
                niovs--;
            }
            if (niovs == 0) {
                LOG_ALWAYS_FATAL_IF(processSize > 0,
                                    "Reached the end of iovecs "
                                    "with %zd bytes remaining",
                                    processSize);
                return OK;
            }
        }
    }

    bool isWaiting() override { return mSocket.isInPollingState(); }

private:
    status_t ensureMessage(bool wait) {
        int rc;
        if (mHaveMessage) {
            LOG_ALWAYS_FATAL_IF(mMessageOffset >= mMessageInfo.len, "No data left in message");
            return OK;
        }

        /* TODO: interruptible wait, maybe with a timeout??? */
        uevent uevt;
        rc = ::wait(mSocket.fd.get(), &uevt, wait ? INFINITE_TIME : 0);
        if (rc < 0) {
            if (rc == ERR_TIMED_OUT && !wait) {
                // If we timed out with wait==false, then there's no message
                return OK;
            }
            return statusFromTrusty(rc);
        }
        if (!(uevt.event & IPC_HANDLE_POLL_MSG)) {
            /* No message, terminate here and leave mHaveMessage false */
            if (uevt.event & IPC_HANDLE_POLL_HUP) {
                // Peer closed the connection. We need to preserve the order
                // between MSG and HUP from FdTrigger.cpp, which means that
                // getting MSG&HUP should return OK instead of DEAD_OBJECT.
                return DEAD_OBJECT;
            }
            return OK;
        }

        rc = get_msg(mSocket.fd.get(), &mMessageInfo);
        if (rc < 0) {
            return statusFromTrusty(rc);
        }

        mHaveMessage = true;
        mMessageOffset = 0;
        return OK;
    }

    void releaseMessage() {
        if (mHaveMessage) {
            put_msg(mSocket.fd.get(), mMessageInfo.id);
            mHaveMessage = false;
        }
    }

    android::RpcTransportFd mSocket;

    bool mHaveMessage = false;
    ipc_msg_info mMessageInfo;
    size_t mMessageOffset;
};

// RpcTransportCtx for Trusty.
class RpcTransportCtxTipcTrusty : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::RpcTransportFd socket,
                                               FdTrigger*) const override {
        return std::make_unique<RpcTransportTipcTrusty>(std::move(socket));
    }
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override { return {}; }
};

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTipcTrusty::newServerCtx() const {
    return std::make_unique<RpcTransportCtxTipcTrusty>();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTipcTrusty::newClientCtx() const {
    return std::make_unique<RpcTransportCtxTipcTrusty>();
}

const char* RpcTransportCtxFactoryTipcTrusty::toCString() const {
    return "trusty";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryTipcTrusty::make() {
    return std::unique_ptr<RpcTransportCtxFactoryTipcTrusty>(
            new RpcTransportCtxFactoryTipcTrusty());
}

} // namespace android
