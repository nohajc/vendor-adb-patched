/*
 * Copyright 2019 The Android Open Source Project
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
#include <android-base/stringprintf.h>
#include <utils/Trace.h>
#include <vector>

#include "TimeKeeper.h"
#include "VSyncDispatchTimerQueue.h"
#include "VSyncTracker.h"

namespace android::scheduler {
using base::StringAppendF;

VSyncDispatch::~VSyncDispatch() = default;
VSyncTracker::~VSyncTracker() = default;
TimeKeeper::~TimeKeeper() = default;

VSyncDispatchTimerQueueEntry::VSyncDispatchTimerQueueEntry(std::string const& name,
                                                           VSyncDispatch::Callback const& cb,
                                                           nsecs_t minVsyncDistance)
      : mName(name),
        mCallback(cb),
        mWorkDuration(0),
        mEarliestVsync(0),
        mMinVsyncDistance(minVsyncDistance) {}

std::optional<nsecs_t> VSyncDispatchTimerQueueEntry::lastExecutedVsyncTarget() const {
    return mLastDispatchTime;
}

std::string_view VSyncDispatchTimerQueueEntry::name() const {
    return mName;
}

std::optional<nsecs_t> VSyncDispatchTimerQueueEntry::wakeupTime() const {
    if (!mArmedInfo) {
        return {};
    }
    return {mArmedInfo->mActualWakeupTime};
}

std::optional<nsecs_t> VSyncDispatchTimerQueueEntry::targetVsync() const {
    if (!mArmedInfo) {
        return {};
    }
    return {mArmedInfo->mActualVsyncTime};
}

ScheduleResult VSyncDispatchTimerQueueEntry::schedule(nsecs_t workDuration, nsecs_t earliestVsync,
                                                      VSyncTracker& tracker, nsecs_t now) {
    auto nextVsyncTime =
            tracker.nextAnticipatedVSyncTimeFrom(std::max(earliestVsync, now + workDuration));

    bool const wouldSkipAVsyncTarget =
            mArmedInfo && (nextVsyncTime > (mArmedInfo->mActualVsyncTime + mMinVsyncDistance));
    if (wouldSkipAVsyncTarget) {
        return ScheduleResult::Scheduled;
    }

    bool const alreadyDispatchedForVsync = mLastDispatchTime &&
            ((*mLastDispatchTime + mMinVsyncDistance) >= nextVsyncTime &&
             (*mLastDispatchTime - mMinVsyncDistance) <= nextVsyncTime);
    if (alreadyDispatchedForVsync) {
        nextVsyncTime =
                tracker.nextAnticipatedVSyncTimeFrom(*mLastDispatchTime + mMinVsyncDistance);
    }

    auto const nextWakeupTime = nextVsyncTime - workDuration;
    mWorkDuration = workDuration;
    mEarliestVsync = earliestVsync;
    mArmedInfo = {nextWakeupTime, nextVsyncTime};
    return ScheduleResult::Scheduled;
}

void VSyncDispatchTimerQueueEntry::addPendingWorkloadUpdate(nsecs_t workDuration,
                                                            nsecs_t earliestVsync) {
    mWorkloadUpdateInfo = {.earliestVsync = earliestVsync, .duration = workDuration};
}

bool VSyncDispatchTimerQueueEntry::hasPendingWorkloadUpdate() const {
    return mWorkloadUpdateInfo.has_value();
}

void VSyncDispatchTimerQueueEntry::update(VSyncTracker& tracker, nsecs_t now) {
    if (!mArmedInfo && !mWorkloadUpdateInfo) {
        return;
    }

    if (mWorkloadUpdateInfo) {
        mEarliestVsync = mWorkloadUpdateInfo->earliestVsync;
        mWorkDuration = mWorkloadUpdateInfo->duration;
        mWorkloadUpdateInfo.reset();
    }

    auto const nextVsyncTime =
            tracker.nextAnticipatedVSyncTimeFrom(std::max(mEarliestVsync, now + mWorkDuration));
    mArmedInfo = {nextVsyncTime - mWorkDuration, nextVsyncTime};
}

void VSyncDispatchTimerQueueEntry::disarm() {
    mArmedInfo.reset();
}

nsecs_t VSyncDispatchTimerQueueEntry::executing() {
    mLastDispatchTime = mArmedInfo->mActualVsyncTime;
    disarm();
    return *mLastDispatchTime;
}

void VSyncDispatchTimerQueueEntry::callback(nsecs_t vsyncTimestamp, nsecs_t wakeupTimestamp) {
    {
        std::lock_guard<std::mutex> lk(mRunningMutex);
        mRunning = true;
    }

    mCallback(vsyncTimestamp, wakeupTimestamp);

    std::lock_guard<std::mutex> lk(mRunningMutex);
    mRunning = false;
    mCv.notify_all();
}

void VSyncDispatchTimerQueueEntry::ensureNotRunning() {
    std::unique_lock<std::mutex> lk(mRunningMutex);
    mCv.wait(lk, [this]() REQUIRES(mRunningMutex) { return !mRunning; });
}

void VSyncDispatchTimerQueueEntry::dump(std::string& result) const {
    std::lock_guard<std::mutex> lk(mRunningMutex);
    std::string armedInfo;
    if (mArmedInfo) {
        StringAppendF(&armedInfo, "[wake up in %.2fms for vsync %.2fms from now]",
                      (mArmedInfo->mActualWakeupTime - systemTime()) / 1e6f,
                      (mArmedInfo->mActualVsyncTime - systemTime()) / 1e6f);
    }

    StringAppendF(&result, "\t\t%s: %s %s\n", mName.c_str(),
                  mRunning ? "(in callback function)" : "", armedInfo.c_str());
    StringAppendF(&result, "\t\t\tmWorkDuration: %.2fms mEarliestVsync: %.2fms relative to now\n",
                  mWorkDuration / 1e6f, (mEarliestVsync - systemTime()) / 1e6f);

    if (mLastDispatchTime) {
        StringAppendF(&result, "\t\t\tmLastDispatchTime: %.2fms ago\n",
                      (systemTime() - *mLastDispatchTime) / 1e6f);
    } else {
        StringAppendF(&result, "\t\t\tmLastDispatchTime unknown\n");
    }
}

VSyncDispatchTimerQueue::VSyncDispatchTimerQueue(std::unique_ptr<TimeKeeper> tk,
                                                 VSyncTracker& tracker, nsecs_t timerSlack,
                                                 nsecs_t minVsyncDistance)
      : mTimeKeeper(std::move(tk)),
        mTracker(tracker),
        mTimerSlack(timerSlack),
        mMinVsyncDistance(minVsyncDistance) {}

VSyncDispatchTimerQueue::~VSyncDispatchTimerQueue() {
    std::lock_guard<decltype(mMutex)> lk(mMutex);
    cancelTimer();
}

void VSyncDispatchTimerQueue::cancelTimer() {
    mIntendedWakeupTime = kInvalidTime;
    mTimeKeeper->alarmCancel();
}

void VSyncDispatchTimerQueue::setTimer(nsecs_t targetTime, nsecs_t /*now*/) {
    mIntendedWakeupTime = targetTime;
    mTimeKeeper->alarmAt(std::bind(&VSyncDispatchTimerQueue::timerCallback, this),
                         mIntendedWakeupTime);
    mLastTimerSchedule = mTimeKeeper->now();
}

void VSyncDispatchTimerQueue::rearmTimer(nsecs_t now) {
    rearmTimerSkippingUpdateFor(now, mCallbacks.end());
}

void VSyncDispatchTimerQueue::TraceBuffer::note(std::string_view name, nsecs_t alarmIn,
                                                nsecs_t vsFor) {
    if (ATRACE_ENABLED()) {
        snprintf(str_buffer.data(), str_buffer.size(), "%.4s%s%" PRId64 "%s%" PRId64,
                 name.substr(0, kMaxNamePrint).data(), kTraceNamePrefix, alarmIn,
                 kTraceNameSeparator, vsFor);
    }
    ATRACE_NAME(str_buffer.data());
}

void VSyncDispatchTimerQueue::rearmTimerSkippingUpdateFor(
        nsecs_t now, CallbackMap::iterator const& skipUpdateIt) {
    std::optional<nsecs_t> min;
    std::optional<nsecs_t> targetVsync;
    std::optional<std::string_view> nextWakeupName;
    for (auto it = mCallbacks.begin(); it != mCallbacks.end(); it++) {
        auto& callback = it->second;
        if (!callback->wakeupTime() && !callback->hasPendingWorkloadUpdate()) {
            continue;
        }

        if (it != skipUpdateIt) {
            callback->update(mTracker, now);
        }
        auto const wakeupTime = *callback->wakeupTime();
        if (!min || (min && *min > wakeupTime)) {
            nextWakeupName = callback->name();
            min = wakeupTime;
            targetVsync = callback->targetVsync();
        }
    }

    if (min && (min < mIntendedWakeupTime)) {
        if (targetVsync && nextWakeupName) {
            mTraceBuffer.note(*nextWakeupName, *min - now, *targetVsync - now);
        }
        setTimer(*min, now);
    } else {
        ATRACE_NAME("cancel timer");
        cancelTimer();
    }
}

void VSyncDispatchTimerQueue::timerCallback() {
    struct Invocation {
        std::shared_ptr<VSyncDispatchTimerQueueEntry> callback;
        nsecs_t vsyncTimestamp;
        nsecs_t wakeupTimestamp;
    };
    std::vector<Invocation> invocations;
    {
        std::lock_guard<decltype(mMutex)> lk(mMutex);
        auto const now = mTimeKeeper->now();
        mLastTimerCallback = now;
        for (auto it = mCallbacks.begin(); it != mCallbacks.end(); it++) {
            auto& callback = it->second;
            auto const wakeupTime = callback->wakeupTime();
            if (!wakeupTime) {
                continue;
            }

            auto const lagAllowance = std::max(now - mIntendedWakeupTime, static_cast<nsecs_t>(0));
            if (*wakeupTime < mIntendedWakeupTime + mTimerSlack + lagAllowance) {
                callback->executing();
                invocations.emplace_back(
                        Invocation{callback, *callback->lastExecutedVsyncTarget(), *wakeupTime});
            }
        }

        mIntendedWakeupTime = kInvalidTime;
        rearmTimer(mTimeKeeper->now());
    }

    for (auto const& invocation : invocations) {
        invocation.callback->callback(invocation.vsyncTimestamp, invocation.wakeupTimestamp);
    }
}

VSyncDispatchTimerQueue::CallbackToken VSyncDispatchTimerQueue::registerCallback(
        Callback const& callbackFn, std::string callbackName) {
    std::lock_guard<decltype(mMutex)> lk(mMutex);
    return CallbackToken{
            mCallbacks
                    .emplace(++mCallbackToken,
                             std::make_shared<VSyncDispatchTimerQueueEntry>(callbackName,
                                                                            callbackFn,
                                                                            mMinVsyncDistance))
                    .first->first};
}

void VSyncDispatchTimerQueue::unregisterCallback(CallbackToken token) {
    std::shared_ptr<VSyncDispatchTimerQueueEntry> entry = nullptr;
    {
        std::lock_guard<decltype(mMutex)> lk(mMutex);
        auto it = mCallbacks.find(token);
        if (it != mCallbacks.end()) {
            entry = it->second;
            mCallbacks.erase(it);
        }
    }

    if (entry) {
        entry->ensureNotRunning();
    }
}

ScheduleResult VSyncDispatchTimerQueue::schedule(CallbackToken token, nsecs_t workDuration,
                                                 nsecs_t earliestVsync) {
    auto result = ScheduleResult::Error;
    {
        std::lock_guard<decltype(mMutex)> lk(mMutex);

        auto it = mCallbacks.find(token);
        if (it == mCallbacks.end()) {
            return result;
        }
        auto& callback = it->second;
        auto const now = mTimeKeeper->now();

        /* If the timer thread will run soon, we'll apply this work update via the callback
         * timer recalculation to avoid cancelling a callback that is about to fire. */
        auto const rearmImminent = now > mIntendedWakeupTime;
        if (CC_UNLIKELY(rearmImminent)) {
            callback->addPendingWorkloadUpdate(workDuration, earliestVsync);
            return ScheduleResult::Scheduled;
        }

        result = callback->schedule(workDuration, earliestVsync, mTracker, now);
        if (result == ScheduleResult::CannotSchedule) {
            return result;
        }

        if (callback->wakeupTime() < mIntendedWakeupTime - mTimerSlack) {
            rearmTimerSkippingUpdateFor(now, it);
        }
    }

    return result;
}

CancelResult VSyncDispatchTimerQueue::cancel(CallbackToken token) {
    std::lock_guard<decltype(mMutex)> lk(mMutex);

    auto it = mCallbacks.find(token);
    if (it == mCallbacks.end()) {
        return CancelResult::Error;
    }
    auto& callback = it->second;

    auto const wakeupTime = callback->wakeupTime();
    if (wakeupTime) {
        callback->disarm();

        if (*wakeupTime == mIntendedWakeupTime) {
            mIntendedWakeupTime = kInvalidTime;
            rearmTimer(mTimeKeeper->now());
        }
        return CancelResult::Cancelled;
    }
    return CancelResult::TooLate;
}

void VSyncDispatchTimerQueue::dump(std::string& result) const {
    std::lock_guard<decltype(mMutex)> lk(mMutex);
    StringAppendF(&result, "\tTimer:\n");
    mTimeKeeper->dump(result);
    StringAppendF(&result, "\tmTimerSlack: %.2fms mMinVsyncDistance: %.2fms\n", mTimerSlack / 1e6f,
                  mMinVsyncDistance / 1e6f);
    StringAppendF(&result, "\tmIntendedWakeupTime: %.2fms from now\n",
                  (mIntendedWakeupTime - mTimeKeeper->now()) / 1e6f);
    StringAppendF(&result, "\tmLastTimerCallback: %.2fms ago mLastTimerSchedule: %.2fms ago\n",
                  (mTimeKeeper->now() - mLastTimerCallback) / 1e6f,
                  (mTimeKeeper->now() - mLastTimerSchedule) / 1e6f);
    StringAppendF(&result, "\tCallbacks:\n");
    for (const auto& [token, entry] : mCallbacks) {
        entry->dump(result);
    }
}

VSyncCallbackRegistration::VSyncCallbackRegistration(VSyncDispatch& dispatch,
                                                     VSyncDispatch::Callback const& callbackFn,
                                                     std::string const& callbackName)
      : mDispatch(dispatch),
        mToken(dispatch.registerCallback(callbackFn, callbackName)),
        mValidToken(true) {}

VSyncCallbackRegistration::VSyncCallbackRegistration(VSyncCallbackRegistration&& other)
      : mDispatch(other.mDispatch),
        mToken(std::move(other.mToken)),
        mValidToken(std::move(other.mValidToken)) {
    other.mValidToken = false;
}

VSyncCallbackRegistration& VSyncCallbackRegistration::operator=(VSyncCallbackRegistration&& other) {
    mDispatch = std::move(other.mDispatch);
    mToken = std::move(other.mToken);
    mValidToken = std::move(other.mValidToken);
    other.mValidToken = false;
    return *this;
}

VSyncCallbackRegistration::~VSyncCallbackRegistration() {
    if (mValidToken) mDispatch.get().unregisterCallback(mToken);
}

ScheduleResult VSyncCallbackRegistration::schedule(nsecs_t workDuration, nsecs_t earliestVsync) {
    if (!mValidToken) {
        return ScheduleResult::Error;
    }
    return mDispatch.get().schedule(mToken, workDuration, earliestVsync);
}

CancelResult VSyncCallbackRegistration::cancel() {
    if (!mValidToken) {
        return CancelResult::Error;
    }
    return mDispatch.get().cancel(mToken);
}

} // namespace android::scheduler
