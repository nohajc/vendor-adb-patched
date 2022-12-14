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

#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <android-base/thread_annotations.h>
#include <ui/FenceTime.h>

#include <scheduler/TimeKeeper.h>

#include "VsyncController.h"

namespace android::scheduler {

class Clock;
class VSyncDispatch;
class VSyncTracker;

// TODO (b/145217110): consider renaming.
class VSyncReactor : public VsyncController {
public:
    VSyncReactor(std::unique_ptr<Clock> clock, VSyncTracker& tracker, size_t pendingFenceLimit,
                 bool supportKernelIdleTimer);
    ~VSyncReactor();

    bool addPresentFence(std::shared_ptr<FenceTime>) final;
    void setIgnorePresentFences(bool ignore) final;

    void startPeriodTransition(nsecs_t period) final;

    bool addHwVsyncTimestamp(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                             bool* periodFlushed) final;

    void setDisplayPowerMode(hal::PowerMode powerMode) final;

    void dump(std::string& result) const final;

private:
    void setIgnorePresentFencesInternal(bool ignore) REQUIRES(mMutex);
    void updateIgnorePresentFencesInternal() REQUIRES(mMutex);
    void startPeriodTransitionInternal(nsecs_t newPeriod) REQUIRES(mMutex);
    void endPeriodTransition() REQUIRES(mMutex);
    bool periodConfirmed(nsecs_t vsync_timestamp, std::optional<nsecs_t> hwcVsyncPeriod)
            REQUIRES(mMutex);

    std::unique_ptr<Clock> const mClock;
    VSyncTracker& mTracker;
    size_t const mPendingLimit;

    mutable std::mutex mMutex;
    bool mInternalIgnoreFences GUARDED_BY(mMutex) = false;
    bool mExternalIgnoreFences GUARDED_BY(mMutex) = false;
    std::vector<std::shared_ptr<android::FenceTime>> mUnfiredFences GUARDED_BY(mMutex);

    bool mMoreSamplesNeeded GUARDED_BY(mMutex) = false;
    bool mPeriodConfirmationInProgress GUARDED_BY(mMutex) = false;
    std::optional<nsecs_t> mPeriodTransitioningTo GUARDED_BY(mMutex);
    std::optional<nsecs_t> mLastHwVsync GUARDED_BY(mMutex);

    hal::PowerMode mDisplayPowerMode GUARDED_BY(mMutex) = hal::PowerMode::ON;

    const bool mSupportKernelIdleTimer = false;
};

class SystemClock : public Clock {
    nsecs_t now() const final;
};

} // namespace android::scheduler
