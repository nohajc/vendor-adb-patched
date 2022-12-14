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
#undef LOG_TAG
#define LOG_TAG "VSyncReactor"
//#define LOG_NDEBUG 0
#include "VSyncReactor.h"
#include <cutils/properties.h>
#include <log/log.h>
#include <utils/Trace.h>
#include "../TracedOrdinal.h"
#include "TimeKeeper.h"
#include "VSyncDispatch.h"
#include "VSyncTracker.h"

namespace android::scheduler {
using base::StringAppendF;

Clock::~Clock() = default;
nsecs_t SystemClock::now() const {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

class PredictedVsyncTracer {
public:
    PredictedVsyncTracer(VSyncDispatch& dispatch)
          : mRegistration(dispatch,
                          std::bind(&PredictedVsyncTracer::callback, this, std::placeholders::_1,
                                    std::placeholders::_2),
                          "PredictedVsyncTracer") {
        mRegistration.schedule(0, 0);
    }

private:
    TracedOrdinal<bool> mParity = {"VSYNC-predicted", 0};
    VSyncCallbackRegistration mRegistration;

    void callback(nsecs_t /*vsyncTime*/, nsecs_t /*targetWakeupTim*/) {
        mParity = !mParity;
        mRegistration.schedule(0, 0);
    }
};

VSyncReactor::VSyncReactor(std::unique_ptr<Clock> clock, std::unique_ptr<VSyncDispatch> dispatch,
                           std::unique_ptr<VSyncTracker> tracker, size_t pendingFenceLimit,
                           bool supportKernelIdleTimer)
      : mClock(std::move(clock)),
        mTracker(std::move(tracker)),
        mDispatch(std::move(dispatch)),
        mPendingLimit(pendingFenceLimit),
        mPredictedVsyncTracer(property_get_bool("debug.sf.show_predicted_vsync", false)
                                      ? std::make_unique<PredictedVsyncTracer>(*mDispatch)
                                      : nullptr),
        mSupportKernelIdleTimer(supportKernelIdleTimer) {}

VSyncReactor::~VSyncReactor() = default;

// The DispSync interface has a 'repeat this callback at rate' semantic. This object adapts
// VSyncDispatch's individually-scheduled callbacks so as to meet DispSync's existing semantic
// for now.
class CallbackRepeater {
public:
    CallbackRepeater(VSyncDispatch& dispatch, DispSync::Callback* cb, const char* name,
                     nsecs_t period, nsecs_t offset, nsecs_t notBefore)
          : mName(name),
            mCallback(cb),
            mRegistration(dispatch,
                          std::bind(&CallbackRepeater::callback, this, std::placeholders::_1,
                                    std::placeholders::_2),
                          mName),
            mPeriod(period),
            mOffset(offset),
            mLastCallTime(notBefore) {}

    ~CallbackRepeater() {
        std::lock_guard<std::mutex> lk(mMutex);
        mRegistration.cancel();
    }

    void start(nsecs_t offset) {
        std::lock_guard<std::mutex> lk(mMutex);
        mStopped = false;
        mOffset = offset;

        auto const schedule_result = mRegistration.schedule(calculateWorkload(), mLastCallTime);
        LOG_ALWAYS_FATAL_IF((schedule_result != ScheduleResult::Scheduled),
                            "Error scheduling callback: rc %X", schedule_result);
    }

    void setPeriod(nsecs_t period) {
        std::lock_guard<std::mutex> lk(mMutex);
        if (period == mPeriod) {
            return;
        }
        mPeriod = period;
    }

    void stop() {
        std::lock_guard<std::mutex> lk(mMutex);
        LOG_ALWAYS_FATAL_IF(mStopped, "DispSyncInterface misuse: callback already stopped");
        mStopped = true;
        mRegistration.cancel();
    }

    void dump(std::string& result) const {
        std::lock_guard<std::mutex> lk(mMutex);
        StringAppendF(&result, "\t%s: mPeriod=%.2f last vsync time %.2fms relative to now (%s)\n",
                      mName.c_str(), mPeriod / 1e6f, (mLastCallTime - systemTime()) / 1e6f,
                      mStopped ? "stopped" : "running");
    }

private:
    void callback(nsecs_t vsynctime, nsecs_t wakeupTime) {
        {
            std::lock_guard<std::mutex> lk(mMutex);
            mLastCallTime = vsynctime;
        }

        mCallback->onDispSyncEvent(wakeupTime, vsynctime);

        {
            std::lock_guard<std::mutex> lk(mMutex);
            if (mStopped) {
                return;
            }
            auto const schedule_result = mRegistration.schedule(calculateWorkload(), vsynctime);
            LOG_ALWAYS_FATAL_IF((schedule_result != ScheduleResult::Scheduled),
                                "Error rescheduling callback: rc %X", schedule_result);
        }
    }

    // DispSync offsets are defined as time after the vsync before presentation.
    // VSyncReactor workloads are defined as time before the intended presentation vsync.
    // Note change in sign between the two defnitions.
    nsecs_t calculateWorkload() REQUIRES(mMutex) { return mPeriod - mOffset; }

    const std::string mName;
    DispSync::Callback* const mCallback;

    std::mutex mutable mMutex;
    VSyncCallbackRegistration mRegistration GUARDED_BY(mMutex);
    bool mStopped GUARDED_BY(mMutex) = false;
    nsecs_t mPeriod GUARDED_BY(mMutex);
    nsecs_t mOffset GUARDED_BY(mMutex);
    nsecs_t mLastCallTime GUARDED_BY(mMutex);
};

bool VSyncReactor::addPresentFence(const std::shared_ptr<FenceTime>& fence) {
    if (!fence) {
        return false;
    }

    nsecs_t const signalTime = fence->getCachedSignalTime();
    if (signalTime == Fence::SIGNAL_TIME_INVALID) {
        return true;
    }

    std::lock_guard<std::mutex> lk(mMutex);
    if (mExternalIgnoreFences || mInternalIgnoreFences) {
        return true;
    }

    bool timestampAccepted = true;
    for (auto it = mUnfiredFences.begin(); it != mUnfiredFences.end();) {
        auto const time = (*it)->getCachedSignalTime();
        if (time == Fence::SIGNAL_TIME_PENDING) {
            it++;
        } else if (time == Fence::SIGNAL_TIME_INVALID) {
            it = mUnfiredFences.erase(it);
        } else {
            timestampAccepted &= mTracker->addVsyncTimestamp(time);

            it = mUnfiredFences.erase(it);
        }
    }

    if (signalTime == Fence::SIGNAL_TIME_PENDING) {
        if (mPendingLimit == mUnfiredFences.size()) {
            mUnfiredFences.erase(mUnfiredFences.begin());
        }
        mUnfiredFences.push_back(fence);
    } else {
        timestampAccepted &= mTracker->addVsyncTimestamp(signalTime);
    }

    if (!timestampAccepted) {
        mMoreSamplesNeeded = true;
        setIgnorePresentFencesInternal(true);
        mPeriodConfirmationInProgress = true;
    }

    return mMoreSamplesNeeded;
}

void VSyncReactor::setIgnorePresentFences(bool ignoration) {
    std::lock_guard<std::mutex> lk(mMutex);
    mExternalIgnoreFences = ignoration;
    updateIgnorePresentFencesInternal();
}

void VSyncReactor::setIgnorePresentFencesInternal(bool ignoration) {
    mInternalIgnoreFences = ignoration;
    updateIgnorePresentFencesInternal();
}

void VSyncReactor::updateIgnorePresentFencesInternal() {
    if (mExternalIgnoreFences || mInternalIgnoreFences) {
        mUnfiredFences.clear();
    }
}

nsecs_t VSyncReactor::computeNextRefresh(int periodOffset, nsecs_t now) const {
    auto const currentPeriod = periodOffset ? mTracker->currentPeriod() : 0;
    return mTracker->nextAnticipatedVSyncTimeFrom(now + periodOffset * currentPeriod);
}

nsecs_t VSyncReactor::expectedPresentTime(nsecs_t now) {
    return mTracker->nextAnticipatedVSyncTimeFrom(now);
}

void VSyncReactor::startPeriodTransition(nsecs_t newPeriod) {
    ATRACE_CALL();
    mPeriodConfirmationInProgress = true;
    mPeriodTransitioningTo = newPeriod;
    mMoreSamplesNeeded = true;
    setIgnorePresentFencesInternal(true);
}

void VSyncReactor::endPeriodTransition() {
    ATRACE_CALL();
    mPeriodTransitioningTo.reset();
    mPeriodConfirmationInProgress = false;
    mLastHwVsync.reset();
}

void VSyncReactor::setPeriod(nsecs_t period) {
    ATRACE_INT64("VSR-setPeriod", period);
    std::lock_guard lk(mMutex);
    mLastHwVsync.reset();

    if (!mSupportKernelIdleTimer && period == getPeriod()) {
        endPeriodTransition();
        setIgnorePresentFencesInternal(false);
        mMoreSamplesNeeded = false;
    } else {
        startPeriodTransition(period);
    }
}

nsecs_t VSyncReactor::getPeriod() {
    return mTracker->currentPeriod();
}

void VSyncReactor::beginResync() {
    mTracker->resetModel();
}

void VSyncReactor::endResync() {}

bool VSyncReactor::periodConfirmed(nsecs_t vsync_timestamp, std::optional<nsecs_t> HwcVsyncPeriod) {
    if (!mPeriodConfirmationInProgress) {
        return false;
    }

    if (!mLastHwVsync && !HwcVsyncPeriod) {
        return false;
    }

    const bool periodIsChanging =
            mPeriodTransitioningTo && (*mPeriodTransitioningTo != getPeriod());
    if (mSupportKernelIdleTimer && !periodIsChanging) {
        // Clear out the Composer-provided period and use the allowance logic below
        HwcVsyncPeriod = {};
    }

    auto const period = mPeriodTransitioningTo ? *mPeriodTransitioningTo : getPeriod();
    static constexpr int allowancePercent = 10;
    static constexpr std::ratio<allowancePercent, 100> allowancePercentRatio;
    auto const allowance = period * allowancePercentRatio.num / allowancePercentRatio.den;
    if (HwcVsyncPeriod) {
        return std::abs(*HwcVsyncPeriod - period) < allowance;
    }

    auto const distance = vsync_timestamp - *mLastHwVsync;
    return std::abs(distance - period) < allowance;
}

bool VSyncReactor::addResyncSample(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                                   bool* periodFlushed) {
    assert(periodFlushed);

    std::lock_guard<std::mutex> lk(mMutex);
    if (periodConfirmed(timestamp, hwcVsyncPeriod)) {
        ATRACE_NAME("VSR: period confirmed");
        if (mPeriodTransitioningTo) {
            mTracker->setPeriod(*mPeriodTransitioningTo);
            for (auto& entry : mCallbacks) {
                entry.second->setPeriod(*mPeriodTransitioningTo);
            }
            *periodFlushed = true;
        }

        if (mLastHwVsync) {
            mTracker->addVsyncTimestamp(*mLastHwVsync);
        }
        mTracker->addVsyncTimestamp(timestamp);

        endPeriodTransition();
        mMoreSamplesNeeded = mTracker->needsMoreSamples();
    } else if (mPeriodConfirmationInProgress) {
        ATRACE_NAME("VSR: still confirming period");
        mLastHwVsync = timestamp;
        mMoreSamplesNeeded = true;
        *periodFlushed = false;
    } else {
        ATRACE_NAME("VSR: adding sample");
        *periodFlushed = false;
        mTracker->addVsyncTimestamp(timestamp);
        mMoreSamplesNeeded = mTracker->needsMoreSamples();
    }

    if (!mMoreSamplesNeeded) {
        setIgnorePresentFencesInternal(false);
    }
    return mMoreSamplesNeeded;
}

status_t VSyncReactor::addEventListener(const char* name, nsecs_t phase,
                                        DispSync::Callback* callback,
                                        nsecs_t /* lastCallbackTime */) {
    std::lock_guard<std::mutex> lk(mMutex);
    auto it = mCallbacks.find(callback);
    if (it == mCallbacks.end()) {
        // TODO (b/146557561): resolve lastCallbackTime semantics in DispSync i/f.
        static auto constexpr maxListeners = 4;
        if (mCallbacks.size() >= maxListeners) {
            ALOGE("callback %s not added, exceeded callback limit of %i (currently %zu)", name,
                  maxListeners, mCallbacks.size());
            return NO_MEMORY;
        }

        auto const period = mTracker->currentPeriod();
        auto repeater = std::make_unique<CallbackRepeater>(*mDispatch, callback, name, period,
                                                           phase, mClock->now());
        it = mCallbacks.emplace(std::pair(callback, std::move(repeater))).first;
    }

    it->second->start(phase);
    return NO_ERROR;
}

status_t VSyncReactor::removeEventListener(DispSync::Callback* callback,
                                           nsecs_t* /* outLastCallback */) {
    std::lock_guard<std::mutex> lk(mMutex);
    auto const it = mCallbacks.find(callback);
    LOG_ALWAYS_FATAL_IF(it == mCallbacks.end(), "callback %p not registered", callback);

    it->second->stop();
    return NO_ERROR;
}

status_t VSyncReactor::changePhaseOffset(DispSync::Callback* callback, nsecs_t phase) {
    std::lock_guard<std::mutex> lk(mMutex);
    auto const it = mCallbacks.find(callback);
    LOG_ALWAYS_FATAL_IF(it == mCallbacks.end(), "callback was %p not registered", callback);

    it->second->start(phase);
    return NO_ERROR;
}

void VSyncReactor::dump(std::string& result) const {
    std::lock_guard<std::mutex> lk(mMutex);
    StringAppendF(&result, "VsyncReactor in use\n");
    StringAppendF(&result, "Has %zu unfired fences\n", mUnfiredFences.size());
    StringAppendF(&result, "mInternalIgnoreFences=%d mExternalIgnoreFences=%d\n",
                  mInternalIgnoreFences, mExternalIgnoreFences);
    StringAppendF(&result, "mMoreSamplesNeeded=%d mPeriodConfirmationInProgress=%d\n",
                  mMoreSamplesNeeded, mPeriodConfirmationInProgress);
    if (mPeriodTransitioningTo) {
        StringAppendF(&result, "mPeriodTransitioningTo=%" PRId64 "\n", *mPeriodTransitioningTo);
    } else {
        StringAppendF(&result, "mPeriodTransitioningTo=nullptr\n");
    }

    if (mLastHwVsync) {
        StringAppendF(&result, "Last HW vsync was %.2fms ago\n",
                      (mClock->now() - *mLastHwVsync) / 1e6f);
    } else {
        StringAppendF(&result, "No Last HW vsync\n");
    }

    StringAppendF(&result, "CallbackRepeaters:\n");
    for (const auto& [callback, repeater] : mCallbacks) {
        repeater->dump(result);
    }

    StringAppendF(&result, "VSyncTracker:\n");
    mTracker->dump(result);
    StringAppendF(&result, "VSyncDispatch:\n");
    mDispatch->dump(result);
}

void VSyncReactor::reset() {}

} // namespace android::scheduler
