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

#define LOG_TAG "FdTrigger"
#include <log/log.h>

#include "FdTrigger.h"

#include <poll.h>

#include <android-base/macros.h>
#include <android-base/scopeguard.h>

#include "RpcState.h"
namespace android {

std::unique_ptr<FdTrigger> FdTrigger::make() {
    auto ret = std::make_unique<FdTrigger>();
#ifndef BINDER_RPC_SINGLE_THREADED
    if (!android::base::Pipe(&ret->mRead, &ret->mWrite)) {
        ALOGE("Could not create pipe %s", strerror(errno));
        return nullptr;
    }
#endif
    return ret;
}

void FdTrigger::trigger() {
#ifdef BINDER_RPC_SINGLE_THREADED
    mTriggered = true;
#else
    mWrite.reset();
#endif
}

bool FdTrigger::isTriggered() {
#ifdef BINDER_RPC_SINGLE_THREADED
    return mTriggered;
#else
    return mWrite == -1;
#endif
}

status_t FdTrigger::triggerablePoll(const android::RpcTransportFd& transportFd, int16_t event) {
#ifdef BINDER_RPC_SINGLE_THREADED
    if (mTriggered) {
        return DEAD_OBJECT;
    }
#endif

    LOG_ALWAYS_FATAL_IF(event == 0, "triggerablePoll %d with event 0 is not allowed",
                        transportFd.fd.get());
    pollfd pfd[]{
            {.fd = transportFd.fd.get(), .events = static_cast<int16_t>(event), .revents = 0},
#ifndef BINDER_RPC_SINGLE_THREADED
            {.fd = mRead.get(), .events = 0, .revents = 0},
#endif
    };

    LOG_ALWAYS_FATAL_IF(transportFd.isInPollingState() == true,
                        "Only one thread should be polling on Fd!");

    transportFd.setPollingState(true);
    auto pollingStateGuard =
            android::base::make_scope_guard([&]() { transportFd.setPollingState(false); });

    int ret = TEMP_FAILURE_RETRY(poll(pfd, arraysize(pfd), -1));
    if (ret < 0) {
        return -errno;
    }
    LOG_ALWAYS_FATAL_IF(ret == 0, "poll(%d) returns 0 with infinite timeout", transportFd.fd.get());

    // At least one FD has events. Check them.

#ifndef BINDER_RPC_SINGLE_THREADED
    // Detect explicit trigger(): DEAD_OBJECT
    if (pfd[1].revents & POLLHUP) {
        return DEAD_OBJECT;
    }
    // See unknown flags in trigger FD's revents (POLLERR / POLLNVAL).
    // Treat this error condition as UNKNOWN_ERROR.
    if (pfd[1].revents != 0) {
        ALOGE("Unknown revents on trigger FD %d: revents = %d", pfd[1].fd, pfd[1].revents);
        return UNKNOWN_ERROR;
    }

    // pfd[1].revents is 0, hence pfd[0].revents must be set, and only possible values are
    // a subset of event | POLLHUP | POLLERR | POLLNVAL.
#endif

    // POLLNVAL: invalid FD number, e.g. not opened.
    if (pfd[0].revents & POLLNVAL) {
        return BAD_VALUE;
    }

    // Error condition. It wouldn't be possible to do I/O on |fd| afterwards.
    // Note: If this is the write end of a pipe then POLLHUP may also be set simultaneously. We
    //   still want DEAD_OBJECT in this case.
    if (pfd[0].revents & POLLERR) {
        LOG_RPC_DETAIL("poll() incoming FD %d results in revents = %d", pfd[0].fd, pfd[0].revents);
        return DEAD_OBJECT;
    }

    // Success condition; event flag(s) set. Even though POLLHUP may also be set,
    // treat it as a success condition to ensure data is drained.
    if (pfd[0].revents & event) {
        return OK;
    }

    // POLLHUP: Peer closed connection. Treat as DEAD_OBJECT.
    // This is a very common case, so don't log.
    return DEAD_OBJECT;
}

} // namespace android
