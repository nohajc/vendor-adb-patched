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

#pragma once

#include <android-base/thread_annotations.h>
#include <ui/FenceTime.h>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include "DispSync.h"
#include "TimeKeeper.h"
namespace android::scheduler {

class Clock;
class VSyncDispatch;
class VSyncTracker;
class CallbackRepeater;
class PredictedVsyncTracer;

// TODO (b/145217110): consider renaming.
class VSyncReactor : public android::DispSync {
public:
    VSyncReactor(std::unique_ptr<Clock> clock, std::unique_ptr<VSyncDispatch> dispatch,
                 std::unique_ptr<VSyncTracker> tracker, size_t pendingFenceLimit,
                 bool supportKernelIdleTimer);
    ~VSyncReactor();

    bool addPresentFence(const std::shared_ptr<FenceTime>& fence) final;
    void setIgnorePresentFences(bool ignoration) final;

    nsecs_t computeNextRefresh(int periodOffset, nsecs_t now) const final;
    nsecs_t expectedPresentTime(nsecs_t now) final;

    void setPeriod(nsecs_t period) final;
    nsecs_t getPeriod() final;

    // TODO: (b/145626181) remove begin,endResync functions from DispSync i/f when possible.
    void beginResync() final;
    bool addResyncSample(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                         bool* periodFlushed) final;
    void endResync() final;

    status_t addEventListener(const char* name, nsecs_t phase, DispSync::Callback* callback,
                              nsecs_t lastCallbackTime) final;
    status_t removeEventListener(DispSync::Callback* callback, nsecs_t* outLastCallback) final;
    status_t changePhaseOffset(DispSync::Callback* callback, nsecs_t phase) final;

    void dump(std::string& result) const final;
    void reset() final;

private:
    void setIgnorePresentFencesInternal(bool ignoration) REQUIRES(mMutex);
    void updateIgnorePresentFencesInternal() REQUIRES(mMutex);
    void startPeriodTransition(nsecs_t newPeriod) REQUIRES(mMutex);
    void endPeriodTransition() REQUIRES(mMutex);
    bool periodConfirmed(nsecs_t vsync_timestamp, std::optional<nsecs_t> hwcVsyncPeriod)
            REQUIRES(mMutex);

    std::unique_ptr<Clock> const mClock;
    std::unique_ptr<VSyncTracker> const mTracker;
    std::unique_ptr<VSyncDispatch> const mDispatch;
    size_t const mPendingLimit;

    mutable std::mutex mMutex;
    bool mInternalIgnoreFences GUARDED_BY(mMutex) = false;
    bool mExternalIgnoreFences GUARDED_BY(mMutex) = false;
    std::vector<std::shared_ptr<FenceTime>> mUnfiredFences GUARDED_BY(mMutex);

    bool mMoreSamplesNeeded GUARDED_BY(mMutex) = false;
    bool mPeriodConfirmationInProgress GUARDED_BY(mMutex) = false;
    std::optional<nsecs_t> mPeriodTransitioningTo GUARDED_BY(mMutex);
    std::optional<nsecs_t> mLastHwVsync GUARDED_BY(mMutex);

    std::unordered_map<DispSync::Callback*, std::unique_ptr<CallbackRepeater>> mCallbacks
            GUARDED_BY(mMutex);

    const std::unique_ptr<PredictedVsyncTracer> mPredictedVsyncTracer;
    const bool mSupportKernelIdleTimer = false;
};

class SystemClock : public Clock {
    nsecs_t now() const final;
};

} // namespace android::scheduler
