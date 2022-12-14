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

#include <android-base/unique_fd.h>
#include <poll.h>

#include "FdTrigger.h"
#include "RpcState.h"

namespace android {

template <typename SendOrReceive>
status_t interruptableReadOrWrite(
        const android::RpcTransportFd& socket, FdTrigger* fdTrigger, iovec* iovs, int niovs,
        SendOrReceive sendOrReceiveFun, const char* funName, int16_t event,
        const std::optional<android::base::function_ref<status_t()>>& altPoll) {
    MAYBE_WAIT_IN_FLAKE_MODE;

    if (niovs < 0) {
        return BAD_VALUE;
    }

    // Since we didn't poll, we need to manually check to see if it was triggered. Otherwise, we
    // may never know we should be shutting down.
    if (fdTrigger->isTriggered()) {
        return DEAD_OBJECT;
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
        // The vectors are all empty, so we have nothing to send.
        return OK;
    }

    bool havePolled = false;
    while (true) {
        ssize_t processSize = sendOrReceiveFun(iovs, niovs);
        if (processSize < 0) {
            int savedErrno = errno;

            // Still return the error on later passes, since it would expose
            // a problem with polling
            if (havePolled || (savedErrno != EAGAIN && savedErrno != EWOULDBLOCK)) {
                LOG_RPC_DETAIL("RpcTransport %s(): %s", funName, strerror(savedErrno));
                return -savedErrno;
            }
        } else if (processSize == 0) {
            return DEAD_OBJECT;
        } else {
            while (processSize > 0 && niovs > 0) {
                auto& iov = iovs[0];
                if (static_cast<size_t>(processSize) < iov.iov_len) {
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

        if (altPoll) {
            if (status_t status = (*altPoll)(); status != OK) return status;
            if (fdTrigger->isTriggered()) {
                return DEAD_OBJECT;
            }
        } else {
            if (status_t status = fdTrigger->triggerablePoll(socket, event); status != OK)
                return status;
            if (!havePolled) havePolled = true;
        }
    }
}

} // namespace android
