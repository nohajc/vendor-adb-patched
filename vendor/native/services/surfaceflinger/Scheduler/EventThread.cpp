/*
 * Copyright (C) 2011 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <pthread.h>
#include <sched.h>
#include <sys/types.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <type_traits>

#include <android-base/stringprintf.h>

#include <binder/IPCThreadState.h>

#include <cutils/compiler.h>
#include <cutils/sched_policy.h>

#include <gui/DisplayEventReceiver.h>

#include <utils/Errors.h>
#include <utils/Trace.h>

#include "DisplayHardware/DisplayMode.h"
#include "FrameTimeline.h"

#include "EventThread.h"

#undef LOG_TAG
#define LOG_TAG "EventThread"

using namespace std::chrono_literals;

namespace android {

using base::StringAppendF;
using base::StringPrintf;

namespace {

auto vsyncPeriod(VSyncRequest request) {
    return static_cast<std::underlying_type_t<VSyncRequest>>(request);
}

std::string toString(VSyncRequest request) {
    switch (request) {
        case VSyncRequest::None:
            return "VSyncRequest::None";
        case VSyncRequest::Single:
            return "VSyncRequest::Single";
        case VSyncRequest::SingleSuppressCallback:
            return "VSyncRequest::SingleSuppressCallback";
        default:
            return StringPrintf("VSyncRequest::Periodic{period=%d}", vsyncPeriod(request));
    }
}

std::string toString(const EventThreadConnection& connection) {
    return StringPrintf("Connection{%p, %s}", &connection,
                        toString(connection.vsyncRequest).c_str());
}

std::string toString(const DisplayEventReceiver::Event& event) {
    switch (event.header.type) {
        case DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG:
            return StringPrintf("Hotplug{displayId=%s, %s}",
                                to_string(event.header.displayId).c_str(),
                                event.hotplug.connected ? "connected" : "disconnected");
        case DisplayEventReceiver::DISPLAY_EVENT_VSYNC:
            return StringPrintf("VSync{displayId=%s, count=%u, expectedPresentationTime=%" PRId64
                                "}",
                                to_string(event.header.displayId).c_str(), event.vsync.count,
                                event.vsync.vsyncData.preferredExpectedPresentationTime());
        case DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE:
            return StringPrintf("ModeChanged{displayId=%s, modeId=%u}",
                                to_string(event.header.displayId).c_str(), event.modeChange.modeId);
        default:
            return "Event{}";
    }
}

DisplayEventReceiver::Event makeHotplug(PhysicalDisplayId displayId, nsecs_t timestamp,
                                        bool connected) {
    DisplayEventReceiver::Event event;
    event.header = {DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG, displayId, timestamp};
    event.hotplug.connected = connected;
    return event;
}

DisplayEventReceiver::Event makeVSync(PhysicalDisplayId displayId, nsecs_t timestamp,
                                      uint32_t count, nsecs_t expectedPresentationTime,
                                      nsecs_t deadlineTimestamp) {
    DisplayEventReceiver::Event event;
    event.header = {DisplayEventReceiver::DISPLAY_EVENT_VSYNC, displayId, timestamp};
    event.vsync.count = count;
    event.vsync.vsyncData.preferredFrameTimelineIndex = 0;
    // Temporarily store the current vsync information in frameTimelines[0], marked as
    // platform-preferred. When the event is dispatched later, the frame interval at that time is
    // used with this information to generate multiple frame timeline choices.
    event.vsync.vsyncData.frameTimelines[0] = {.vsyncId = FrameTimelineInfo::INVALID_VSYNC_ID,
                                               .deadlineTimestamp = deadlineTimestamp,
                                               .expectedPresentationTime =
                                                       expectedPresentationTime};
    return event;
}

DisplayEventReceiver::Event makeModeChanged(DisplayModePtr mode) {
    DisplayEventReceiver::Event event;
    event.header = {DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE, mode->getPhysicalDisplayId(),
                    systemTime()};
    event.modeChange.modeId = mode->getId().value();
    event.modeChange.vsyncPeriod = mode->getVsyncPeriod();
    return event;
}

DisplayEventReceiver::Event makeFrameRateOverrideEvent(PhysicalDisplayId displayId,
                                                       FrameRateOverride frameRateOverride) {
    return DisplayEventReceiver::Event{
            .header =
                    DisplayEventReceiver::Event::Header{
                            .type = DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE,
                            .displayId = displayId,
                            .timestamp = systemTime(),
                    },
            .frameRateOverride = frameRateOverride,
    };
}

DisplayEventReceiver::Event makeFrameRateOverrideFlushEvent(PhysicalDisplayId displayId) {
    return DisplayEventReceiver::Event{
            .header = DisplayEventReceiver::Event::Header{
                    .type = DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH,
                    .displayId = displayId,
                    .timestamp = systemTime(),
            }};
}

} // namespace

EventThreadConnection::EventThreadConnection(
        EventThread* eventThread, uid_t callingUid, ResyncCallback resyncCallback,
        ISurfaceComposer::EventRegistrationFlags eventRegistration)
      : resyncCallback(std::move(resyncCallback)),
        mOwnerUid(callingUid),
        mEventRegistration(eventRegistration),
        mEventThread(eventThread),
        mChannel(gui::BitTube::DefaultSize) {}

EventThreadConnection::~EventThreadConnection() {
    // do nothing here -- clean-up will happen automatically
    // when the main thread wakes up
}

void EventThreadConnection::onFirstRef() {
    // NOTE: mEventThread doesn't hold a strong reference on us
    mEventThread->registerDisplayEventConnection(this);
}

binder::Status EventThreadConnection::stealReceiveChannel(gui::BitTube* outChannel) {
    std::scoped_lock lock(mLock);
    if (mChannel.initCheck() != NO_ERROR) {
        return binder::Status::fromStatusT(NAME_NOT_FOUND);
    }

    outChannel->setReceiveFd(mChannel.moveReceiveFd());
    outChannel->setSendFd(base::unique_fd(dup(mChannel.getSendFd())));
    return binder::Status::ok();
}

binder::Status EventThreadConnection::setVsyncRate(int rate) {
    mEventThread->setVsyncRate(static_cast<uint32_t>(rate), this);
    return binder::Status::ok();
}

binder::Status EventThreadConnection::requestNextVsync() {
    ATRACE_CALL();
    mEventThread->requestNextVsync(this);
    return binder::Status::ok();
}

binder::Status EventThreadConnection::getLatestVsyncEventData(
        ParcelableVsyncEventData* outVsyncEventData) {
    ATRACE_CALL();
    outVsyncEventData->vsync = mEventThread->getLatestVsyncEventData(this);
    return binder::Status::ok();
}

status_t EventThreadConnection::postEvent(const DisplayEventReceiver::Event& event) {
    constexpr auto toStatus = [](ssize_t size) {
        return size < 0 ? status_t(size) : status_t(NO_ERROR);
    };

    if (event.header.type == DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE ||
        event.header.type == DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH) {
        mPendingEvents.emplace_back(event);
        if (event.header.type == DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE) {
            return status_t(NO_ERROR);
        }

        auto size = DisplayEventReceiver::sendEvents(&mChannel, mPendingEvents.data(),
                                                     mPendingEvents.size());
        mPendingEvents.clear();
        return toStatus(size);
    }

    auto size = DisplayEventReceiver::sendEvents(&mChannel, &event, 1);
    return toStatus(size);
}

// ---------------------------------------------------------------------------

EventThread::~EventThread() = default;

namespace impl {

EventThread::EventThread(std::unique_ptr<VSyncSource> vsyncSource,
                         android::frametimeline::TokenManager* tokenManager,
                         InterceptVSyncsCallback interceptVSyncsCallback,
                         ThrottleVsyncCallback throttleVsyncCallback,
                         GetVsyncPeriodFunction getVsyncPeriodFunction)
      : mVSyncSource(std::move(vsyncSource)),
        mTokenManager(tokenManager),
        mInterceptVSyncsCallback(std::move(interceptVSyncsCallback)),
        mThrottleVsyncCallback(std::move(throttleVsyncCallback)),
        mGetVsyncPeriodFunction(std::move(getVsyncPeriodFunction)),
        mThreadName(mVSyncSource->getName()) {

    LOG_ALWAYS_FATAL_IF(getVsyncPeriodFunction == nullptr,
            "getVsyncPeriodFunction must not be null");

    mVSyncSource->setCallback(this);

    mThread = std::thread([this]() NO_THREAD_SAFETY_ANALYSIS {
        std::unique_lock<std::mutex> lock(mMutex);
        threadMain(lock);
    });

    pthread_setname_np(mThread.native_handle(), mThreadName);

    pid_t tid = pthread_gettid_np(mThread.native_handle());

    // Use SCHED_FIFO to minimize jitter
    constexpr int EVENT_THREAD_PRIORITY = 2;
    struct sched_param param = {0};
    param.sched_priority = EVENT_THREAD_PRIORITY;
    if (pthread_setschedparam(mThread.native_handle(), SCHED_FIFO, &param) != 0) {
        ALOGE("Couldn't set SCHED_FIFO for EventThread");
    }

    set_sched_policy(tid, SP_FOREGROUND);
}

EventThread::~EventThread() {
    mVSyncSource->setCallback(nullptr);

    {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = State::Quit;
        mCondition.notify_all();
    }
    mThread.join();
}

void EventThread::setDuration(std::chrono::nanoseconds workDuration,
                              std::chrono::nanoseconds readyDuration) {
    std::lock_guard<std::mutex> lock(mMutex);
    mVSyncSource->setDuration(workDuration, readyDuration);
}

sp<EventThreadConnection> EventThread::createEventConnection(
        ResyncCallback resyncCallback,
        ISurfaceComposer::EventRegistrationFlags eventRegistration) const {
    return new EventThreadConnection(const_cast<EventThread*>(this),
                                     IPCThreadState::self()->getCallingUid(),
                                     std::move(resyncCallback), eventRegistration);
}

status_t EventThread::registerDisplayEventConnection(const sp<EventThreadConnection>& connection) {
    std::lock_guard<std::mutex> lock(mMutex);

    // this should never happen
    auto it = std::find(mDisplayEventConnections.cbegin(),
            mDisplayEventConnections.cend(), connection);
    if (it != mDisplayEventConnections.cend()) {
        ALOGW("DisplayEventConnection %p already exists", connection.get());
        mCondition.notify_all();
        return ALREADY_EXISTS;
    }

    mDisplayEventConnections.push_back(connection);
    mCondition.notify_all();
    return NO_ERROR;
}

void EventThread::removeDisplayEventConnectionLocked(const wp<EventThreadConnection>& connection) {
    auto it = std::find(mDisplayEventConnections.cbegin(),
            mDisplayEventConnections.cend(), connection);
    if (it != mDisplayEventConnections.cend()) {
        mDisplayEventConnections.erase(it);
    }
}

void EventThread::setVsyncRate(uint32_t rate, const sp<EventThreadConnection>& connection) {
    if (static_cast<std::underlying_type_t<VSyncRequest>>(rate) < 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(mMutex);

    const auto request = rate == 0 ? VSyncRequest::None : static_cast<VSyncRequest>(rate);
    if (connection->vsyncRequest != request) {
        connection->vsyncRequest = request;
        mCondition.notify_all();
    }
}

void EventThread::requestNextVsync(const sp<EventThreadConnection>& connection) {
    if (connection->resyncCallback) {
        connection->resyncCallback();
    }

    std::lock_guard<std::mutex> lock(mMutex);

    if (connection->vsyncRequest == VSyncRequest::None) {
        connection->vsyncRequest = VSyncRequest::Single;
        mCondition.notify_all();
    } else if (connection->vsyncRequest == VSyncRequest::SingleSuppressCallback) {
        connection->vsyncRequest = VSyncRequest::Single;
    }
}

VsyncEventData EventThread::getLatestVsyncEventData(
        const sp<EventThreadConnection>& connection) const {
    // Resync so that the vsync is accurate with hardware. getLatestVsyncEventData is an alternate
    // way to get vsync data (instead of posting callbacks to Choreographer).
    if (connection->resyncCallback) {
        connection->resyncCallback();
    }

    VsyncEventData vsyncEventData;
    nsecs_t frameInterval = mGetVsyncPeriodFunction(connection->mOwnerUid);
    vsyncEventData.frameInterval = frameInterval;
    VSyncSource::VSyncData vsyncData;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        vsyncData = mVSyncSource->getLatestVSyncData();
    }
    generateFrameTimeline(vsyncEventData, frameInterval, systemTime(SYSTEM_TIME_MONOTONIC),
                          vsyncData.expectedPresentationTime, vsyncData.deadlineTimestamp);
    return vsyncEventData;
}

void EventThread::onScreenReleased() {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mVSyncState || mVSyncState->synthetic) {
        return;
    }

    mVSyncState->synthetic = true;
    mCondition.notify_all();
}

void EventThread::onScreenAcquired() {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mVSyncState || !mVSyncState->synthetic) {
        return;
    }

    mVSyncState->synthetic = false;
    mCondition.notify_all();
}

void EventThread::onVSyncEvent(nsecs_t timestamp, VSyncSource::VSyncData vsyncData) {
    std::lock_guard<std::mutex> lock(mMutex);

    LOG_FATAL_IF(!mVSyncState);
    mPendingEvents.push_back(makeVSync(mVSyncState->displayId, timestamp, ++mVSyncState->count,
                                       vsyncData.expectedPresentationTime,
                                       vsyncData.deadlineTimestamp));
    mCondition.notify_all();
}

void EventThread::onHotplugReceived(PhysicalDisplayId displayId, bool connected) {
    std::lock_guard<std::mutex> lock(mMutex);

    mPendingEvents.push_back(makeHotplug(displayId, systemTime(), connected));
    mCondition.notify_all();
}

void EventThread::onModeChanged(DisplayModePtr mode) {
    std::lock_guard<std::mutex> lock(mMutex);

    mPendingEvents.push_back(makeModeChanged(mode));
    mCondition.notify_all();
}

void EventThread::onFrameRateOverridesChanged(PhysicalDisplayId displayId,
                                              std::vector<FrameRateOverride> overrides) {
    std::lock_guard<std::mutex> lock(mMutex);

    for (auto frameRateOverride : overrides) {
        mPendingEvents.push_back(makeFrameRateOverrideEvent(displayId, frameRateOverride));
    }
    mPendingEvents.push_back(makeFrameRateOverrideFlushEvent(displayId));

    mCondition.notify_all();
}

size_t EventThread::getEventThreadConnectionCount() {
    std::lock_guard<std::mutex> lock(mMutex);
    return mDisplayEventConnections.size();
}

void EventThread::threadMain(std::unique_lock<std::mutex>& lock) {
    DisplayEventConsumers consumers;

    while (mState != State::Quit) {
        std::optional<DisplayEventReceiver::Event> event;

        // Determine next event to dispatch.
        if (!mPendingEvents.empty()) {
            event = mPendingEvents.front();
            mPendingEvents.pop_front();

            switch (event->header.type) {
                case DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG:
                    if (event->hotplug.connected && !mVSyncState) {
                        mVSyncState.emplace(event->header.displayId);
                    } else if (!event->hotplug.connected && mVSyncState &&
                               mVSyncState->displayId == event->header.displayId) {
                        mVSyncState.reset();
                    }
                    break;

                case DisplayEventReceiver::DISPLAY_EVENT_VSYNC:
                    if (mInterceptVSyncsCallback) {
                        mInterceptVSyncsCallback(event->header.timestamp);
                    }
                    break;
            }
        }

        bool vsyncRequested = false;

        // Find connections that should consume this event.
        auto it = mDisplayEventConnections.begin();
        while (it != mDisplayEventConnections.end()) {
            if (const auto connection = it->promote()) {
                vsyncRequested |= connection->vsyncRequest != VSyncRequest::None;

                if (event && shouldConsumeEvent(*event, connection)) {
                    consumers.push_back(connection);
                }

                ++it;
            } else {
                it = mDisplayEventConnections.erase(it);
            }
        }

        if (!consumers.empty()) {
            dispatchEvent(*event, consumers);
            consumers.clear();
        }

        State nextState;
        if (mVSyncState && vsyncRequested) {
            nextState = mVSyncState->synthetic ? State::SyntheticVSync : State::VSync;
        } else {
            ALOGW_IF(!mVSyncState, "Ignoring VSYNC request while display is disconnected");
            nextState = State::Idle;
        }

        if (mState != nextState) {
            if (mState == State::VSync) {
                mVSyncSource->setVSyncEnabled(false);
            } else if (nextState == State::VSync) {
                mVSyncSource->setVSyncEnabled(true);
            }

            mState = nextState;
        }

        if (event) {
            continue;
        }

        // Wait for event or client registration/request.
        if (mState == State::Idle) {
            mCondition.wait(lock);
        } else {
            // Generate a fake VSYNC after a long timeout in case the driver stalls. When the
            // display is off, keep feeding clients at 60 Hz.
            const std::chrono::nanoseconds timeout =
                    mState == State::SyntheticVSync ? 16ms : 1000ms;
            if (mCondition.wait_for(lock, timeout) == std::cv_status::timeout) {
                if (mState == State::VSync) {
                    ALOGW("Faking VSYNC due to driver stall for thread %s", mThreadName);
                    std::string debugInfo = "VsyncSource debug info:\n";
                    mVSyncSource->dump(debugInfo);
                    // Log the debug info line-by-line to avoid logcat overflow
                    auto pos = debugInfo.find('\n');
                    while (pos != std::string::npos) {
                        ALOGW("%s", debugInfo.substr(0, pos).c_str());
                        debugInfo = debugInfo.substr(pos + 1);
                        pos = debugInfo.find('\n');
                    }
                }

                LOG_FATAL_IF(!mVSyncState);
                const auto now = systemTime(SYSTEM_TIME_MONOTONIC);
                const auto deadlineTimestamp = now + timeout.count();
                const auto expectedVSyncTime = deadlineTimestamp + timeout.count();
                mPendingEvents.push_back(makeVSync(mVSyncState->displayId, now,
                                                   ++mVSyncState->count, expectedVSyncTime,
                                                   deadlineTimestamp));
            }
        }
    }
}

bool EventThread::shouldConsumeEvent(const DisplayEventReceiver::Event& event,
                                     const sp<EventThreadConnection>& connection) const {
    const auto throttleVsync = [&] {
        return mThrottleVsyncCallback &&
                mThrottleVsyncCallback(event.vsync.vsyncData.preferredExpectedPresentationTime(),
                                       connection->mOwnerUid);
    };

    switch (event.header.type) {
        case DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG:
            return true;

        case DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE: {
            return connection->mEventRegistration.test(
                    ISurfaceComposer::EventRegistration::modeChanged);
        }

        case DisplayEventReceiver::DISPLAY_EVENT_VSYNC:
            switch (connection->vsyncRequest) {
                case VSyncRequest::None:
                    return false;
                case VSyncRequest::SingleSuppressCallback:
                    connection->vsyncRequest = VSyncRequest::None;
                    return false;
                case VSyncRequest::Single: {
                    if (throttleVsync()) {
                        return false;
                    }
                    connection->vsyncRequest = VSyncRequest::SingleSuppressCallback;
                    return true;
                }
                case VSyncRequest::Periodic:
                    if (throttleVsync()) {
                        return false;
                    }
                    return true;
                default:
                    // We don't throttle vsync if the app set a vsync request rate
                    // since there is no easy way to do that and this is a very
                    // rare case
                    return event.vsync.count % vsyncPeriod(connection->vsyncRequest) == 0;
            }

        case DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE:
            [[fallthrough]];
        case DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH:
            return connection->mEventRegistration.test(
                    ISurfaceComposer::EventRegistration::frameRateOverride);

        default:
            return false;
    }
}

int64_t EventThread::generateToken(nsecs_t timestamp, nsecs_t deadlineTimestamp,
                                   nsecs_t expectedPresentationTime) const {
    if (mTokenManager != nullptr) {
        return mTokenManager->generateTokenForPredictions(
                {timestamp, deadlineTimestamp, expectedPresentationTime});
    }
    return FrameTimelineInfo::INVALID_VSYNC_ID;
}

void EventThread::generateFrameTimeline(VsyncEventData& outVsyncEventData, nsecs_t frameInterval,
                                        nsecs_t timestamp,
                                        nsecs_t preferredExpectedPresentationTime,
                                        nsecs_t preferredDeadlineTimestamp) const {
    // Add 1 to ensure the preferredFrameTimelineIndex entry (when multiplier == 0) is included.
    for (int64_t multiplier = -VsyncEventData::kFrameTimelinesLength + 1, currentIndex = 0;
         currentIndex < VsyncEventData::kFrameTimelinesLength; multiplier++) {
        nsecs_t deadlineTimestamp = preferredDeadlineTimestamp + multiplier * frameInterval;
        // Valid possible frame timelines must have future values.
        if (deadlineTimestamp > timestamp) {
            if (multiplier == 0) {
                outVsyncEventData.preferredFrameTimelineIndex = currentIndex;
            }
            nsecs_t expectedPresentationTime =
                    preferredExpectedPresentationTime + multiplier * frameInterval;
            outVsyncEventData.frameTimelines[currentIndex] =
                    {.vsyncId =
                             generateToken(timestamp, deadlineTimestamp, expectedPresentationTime),
                     .deadlineTimestamp = deadlineTimestamp,
                     .expectedPresentationTime = expectedPresentationTime};
            currentIndex++;
        }
    }
}

void EventThread::dispatchEvent(const DisplayEventReceiver::Event& event,
                                const DisplayEventConsumers& consumers) {
    for (const auto& consumer : consumers) {
        DisplayEventReceiver::Event copy = event;
        if (event.header.type == DisplayEventReceiver::DISPLAY_EVENT_VSYNC) {
            const int64_t frameInterval = mGetVsyncPeriodFunction(consumer->mOwnerUid);
            copy.vsync.vsyncData.frameInterval = frameInterval;
            generateFrameTimeline(copy.vsync.vsyncData, frameInterval, copy.header.timestamp,
                                  event.vsync.vsyncData.preferredExpectedPresentationTime(),
                                  event.vsync.vsyncData.preferredDeadlineTimestamp());
        }
        switch (consumer->postEvent(copy)) {
            case NO_ERROR:
                break;

            case -EAGAIN:
                // TODO: Try again if pipe is full.
                ALOGW("Failed dispatching %s for %s", toString(event).c_str(),
                      toString(*consumer).c_str());
                break;

            default:
                // Treat EPIPE and other errors as fatal.
                removeDisplayEventConnectionLocked(consumer);
        }
    }
}

void EventThread::dump(std::string& result) const {
    std::lock_guard<std::mutex> lock(mMutex);

    StringAppendF(&result, "%s: state=%s VSyncState=", mThreadName, toCString(mState));
    if (mVSyncState) {
        StringAppendF(&result, "{displayId=%s, count=%u%s}\n",
                      to_string(mVSyncState->displayId).c_str(), mVSyncState->count,
                      mVSyncState->synthetic ? ", synthetic" : "");
    } else {
        StringAppendF(&result, "none\n");
    }

    StringAppendF(&result, "  pending events (count=%zu):\n", mPendingEvents.size());
    for (const auto& event : mPendingEvents) {
        StringAppendF(&result, "    %s\n", toString(event).c_str());
    }

    StringAppendF(&result, "  connections (count=%zu):\n", mDisplayEventConnections.size());
    for (const auto& ptr : mDisplayEventConnections) {
        if (const auto connection = ptr.promote()) {
            StringAppendF(&result, "    %s\n", toString(*connection).c_str());
        }
    }
}

const char* EventThread::toCString(State state) {
    switch (state) {
        case State::Idle:
            return "Idle";
        case State::Quit:
            return "Quit";
        case State::SyntheticVSync:
            return "SyntheticVSync";
        case State::VSync:
            return "VSync";
    }
}

} // namespace impl
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
