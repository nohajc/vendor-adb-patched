/*
 * Copyright (C) 2009 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <binder/IPCThreadState.h>

#include <utils/Log.h>
#include <utils/Timers.h>
#include <utils/threads.h>

#include <gui/DisplayEventReceiver.h>

#include "EventThread.h"
#include "FrameTimeline.h"
#include "MessageQueue.h"
#include "SurfaceFlinger.h"

namespace android::impl {

void MessageQueue::Handler::dispatchRefresh() {
    if ((mEventMask.fetch_or(eventMaskRefresh) & eventMaskRefresh) == 0) {
        mQueue.mLooper->sendMessage(this, Message(MessageQueue::REFRESH));
    }
}

void MessageQueue::Handler::dispatchInvalidate(int64_t vsyncId, nsecs_t expectedVSyncTimestamp) {
    if ((mEventMask.fetch_or(eventMaskInvalidate) & eventMaskInvalidate) == 0) {
        mVsyncId = vsyncId;
        mExpectedVSyncTime = expectedVSyncTimestamp;
        mQueue.mLooper->sendMessage(this, Message(MessageQueue::INVALIDATE));
    }
}

bool MessageQueue::Handler::invalidatePending() {
    constexpr auto pendingMask = eventMaskInvalidate | eventMaskRefresh;
    return (mEventMask.load() & pendingMask) != 0;
}

void MessageQueue::Handler::handleMessage(const Message& message) {
    switch (message.what) {
        case INVALIDATE:
            mEventMask.fetch_and(~eventMaskInvalidate);
            mQueue.mFlinger->onMessageReceived(message.what, mVsyncId, mExpectedVSyncTime);
            break;
        case REFRESH:
            mEventMask.fetch_and(~eventMaskRefresh);
            mQueue.mFlinger->onMessageReceived(message.what, mVsyncId, mExpectedVSyncTime);
            break;
    }
}

// ---------------------------------------------------------------------------

void MessageQueue::init(const sp<SurfaceFlinger>& flinger) {
    mFlinger = flinger;
    mLooper = new Looper(true);
    mHandler = new Handler(*this);
}

// TODO(b/169865816): refactor VSyncInjections to use MessageQueue directly
// and remove the EventThread from MessageQueue
void MessageQueue::setInjector(sp<EventThreadConnection> connection) {
    auto& tube = mInjector.tube;

    if (const int fd = tube.getFd(); fd >= 0) {
        mLooper->removeFd(fd);
    }

    if (connection) {
        // The EventThreadConnection is retained when disabling injection, so avoid subsequently
        // stealing invalid FDs. Note that the stolen FDs are kept open.
        if (tube.getFd() < 0) {
            connection->stealReceiveChannel(&tube);
        } else {
            ALOGW("Recycling channel for VSYNC injection.");
        }

        mLooper->addFd(
                tube.getFd(), 0, Looper::EVENT_INPUT,
                [](int, int, void* data) {
                    reinterpret_cast<MessageQueue*>(data)->injectorCallback();
                    return 1; // Keep registration.
                },
                this);
    }

    std::lock_guard lock(mInjector.mutex);
    mInjector.connection = std::move(connection);
}

void MessageQueue::vsyncCallback(nsecs_t vsyncTime, nsecs_t targetWakeupTime, nsecs_t readyTime) {
    ATRACE_CALL();
    // Trace VSYNC-sf
    mVsync.value = (mVsync.value + 1) % 2;

    {
        std::lock_guard lock(mVsync.mutex);
        mVsync.lastCallbackTime = std::chrono::nanoseconds(vsyncTime);
        mVsync.scheduled = false;
    }
    mHandler->dispatchInvalidate(mVsync.tokenManager->generateTokenForPredictions(
                                         {targetWakeupTime, readyTime, vsyncTime}),
                                 vsyncTime);
}

void MessageQueue::initVsync(scheduler::VSyncDispatch& dispatch,
                             frametimeline::TokenManager& tokenManager,
                             std::chrono::nanoseconds workDuration) {
    setDuration(workDuration);
    mVsync.tokenManager = &tokenManager;
    mVsync.registration = std::make_unique<
            scheduler::VSyncCallbackRegistration>(dispatch,
                                                  std::bind(&MessageQueue::vsyncCallback, this,
                                                            std::placeholders::_1,
                                                            std::placeholders::_2,
                                                            std::placeholders::_3),
                                                  "sf");
}

void MessageQueue::setDuration(std::chrono::nanoseconds workDuration) {
    ATRACE_CALL();
    std::lock_guard lock(mVsync.mutex);
    mVsync.workDuration = workDuration;
    if (mVsync.scheduled) {
        mVsync.expectedWakeupTime = mVsync.registration->schedule(
                {mVsync.workDuration.get().count(),
                 /*readyDuration=*/0, mVsync.lastCallbackTime.count()});
    }
}

void MessageQueue::waitMessage() {
    do {
        IPCThreadState::self()->flushCommands();
        int32_t ret = mLooper->pollOnce(-1);
        switch (ret) {
            case Looper::POLL_WAKE:
            case Looper::POLL_CALLBACK:
                continue;
            case Looper::POLL_ERROR:
                ALOGE("Looper::POLL_ERROR");
                continue;
            case Looper::POLL_TIMEOUT:
                // timeout (should not happen)
                continue;
            default:
                // should not happen
                ALOGE("Looper::pollOnce() returned unknown status %d", ret);
                continue;
        }
    } while (true);
}

void MessageQueue::postMessage(sp<MessageHandler>&& handler) {
    mLooper->sendMessage(handler, Message());
}

void MessageQueue::invalidate() {
    ATRACE_CALL();

    {
        std::lock_guard lock(mInjector.mutex);
        if (CC_UNLIKELY(mInjector.connection)) {
            ALOGD("%s while injecting VSYNC", __FUNCTION__);
            mInjector.connection->requestNextVsync();
            return;
        }
    }

    std::lock_guard lock(mVsync.mutex);
    mVsync.scheduled = true;
    mVsync.expectedWakeupTime =
            mVsync.registration->schedule({.workDuration = mVsync.workDuration.get().count(),
                                           .readyDuration = 0,
                                           .earliestVsync = mVsync.lastCallbackTime.count()});
}

void MessageQueue::refresh() {
    mHandler->dispatchRefresh();
}

void MessageQueue::injectorCallback() {
    ssize_t n;
    DisplayEventReceiver::Event buffer[8];
    while ((n = DisplayEventReceiver::getEvents(&mInjector.tube, buffer, 8)) > 0) {
        for (int i = 0; i < n; i++) {
            if (buffer[i].header.type == DisplayEventReceiver::DISPLAY_EVENT_VSYNC) {
                mHandler->dispatchInvalidate(buffer[i].vsync.vsyncId,
                                             buffer[i].vsync.expectedVSyncTimestamp);
                break;
            }
        }
    }
}

std::optional<std::chrono::steady_clock::time_point> MessageQueue::nextExpectedInvalidate() {
    if (mHandler->invalidatePending()) {
        return std::chrono::steady_clock::now();
    }

    std::lock_guard lock(mVsync.mutex);
    if (mVsync.scheduled) {
        LOG_ALWAYS_FATAL_IF(!mVsync.expectedWakeupTime.has_value(), "callback was never scheduled");
        const auto expectedWakeupTime = std::chrono::nanoseconds(*mVsync.expectedWakeupTime);
        return std::optional<std::chrono::steady_clock::time_point>(expectedWakeupTime);
    }

    return std::nullopt;
}

} // namespace android::impl
