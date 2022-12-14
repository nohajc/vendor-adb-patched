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

#include <mutex>
#include <optional>
#include <string>

#include <ftl/small_map.h>
#include <utils/Timers.h>

#include <scheduler/Fps.h>

#include "VsyncModulator.h"

namespace android::scheduler {

/*
 * This class encapsulates vsync configurations for different refresh rates. Depending
 * on what refresh rate we are using, and wheter we are composing in GL,
 * different offsets will help us with latency. This class keeps track of
 * which mode the device is on, and returns approprate offsets when needed.
 */
class VsyncConfiguration {
public:
    using VsyncConfigSet = VsyncModulator::VsyncConfigSet;

    virtual ~VsyncConfiguration() = default;
    virtual VsyncConfigSet getCurrentConfigs() const = 0;
    virtual VsyncConfigSet getConfigsForRefreshRate(Fps fps) const = 0;
    virtual void reset() = 0;

    virtual void setRefreshRateFps(Fps fps) = 0;
    virtual void dump(std::string& result) const = 0;
};

namespace impl {

/*
 * This is a common implementation for both phase offsets and durations.
 * PhaseOffsets and WorkDuration derive from this class and implement the
 * constructOffsets method
 */
class VsyncConfiguration : public scheduler::VsyncConfiguration {
public:
    explicit VsyncConfiguration(Fps currentFps);

    // Returns early, early GL, and late offsets for Apps and SF for a given refresh rate.
    VsyncConfigSet getConfigsForRefreshRate(Fps fps) const override EXCLUDES(mLock);

    // Returns early, early GL, and late offsets for Apps and SF.
    VsyncConfigSet getCurrentConfigs() const override EXCLUDES(mLock) {
        std::lock_guard lock(mLock);
        return getConfigsForRefreshRateLocked(mRefreshRateFps);
    }

    // Cleans the internal cache.
    void reset() override EXCLUDES(mLock) {
        std::lock_guard lock(mLock);
        mOffsetsCache.clear();
    }

    // This function should be called when the device is switching between different
    // refresh rates, to properly update the offsets.
    void setRefreshRateFps(Fps fps) override EXCLUDES(mLock) {
        std::lock_guard lock(mLock);
        mRefreshRateFps = fps;
    }

    // Returns current offsets in human friendly format.
    void dump(std::string& result) const override;

protected:
    virtual VsyncConfiguration::VsyncConfigSet constructOffsets(nsecs_t vsyncDuration) const = 0;

    VsyncConfigSet getConfigsForRefreshRateLocked(Fps fps) const REQUIRES(mLock);

    mutable ftl::SmallMap<Fps, VsyncConfigSet, 2, FpsApproxEqual> mOffsetsCache GUARDED_BY(mLock);
    Fps mRefreshRateFps GUARDED_BY(mLock);
    mutable std::mutex mLock;
};

/*
 * This is the old implementation of phase offsets and considered as deprecated.
 * WorkDuration is the new implementation.
 */
class PhaseOffsets : public VsyncConfiguration {
public:
    explicit PhaseOffsets(Fps currentRefreshRate);

protected:
    // Used for unit tests
    PhaseOffsets(Fps currentRefreshRate, nsecs_t vsyncPhaseOffsetNs, nsecs_t sfVSyncPhaseOffsetNs,
                 std::optional<nsecs_t> earlySfOffsetNs, std::optional<nsecs_t> earlyGpuSfOffsetNs,
                 std::optional<nsecs_t> earlyAppOffsetNs,
                 std::optional<nsecs_t> earlyGpuAppOffsetNs, nsecs_t highFpsVsyncPhaseOffsetNs,
                 nsecs_t highFpsSfVSyncPhaseOffsetNs, std::optional<nsecs_t> highFpsEarlySfOffsetNs,
                 std::optional<nsecs_t> highFpsEarlyGpuSfOffsetNs,
                 std::optional<nsecs_t> highFpsEarlyAppOffsetNs,
                 std::optional<nsecs_t> highFpsEarlyGpuAppOffsetNs, nsecs_t thresholdForNextVsync,
                 nsecs_t hwcMinWorkDuration);

private:
    VsyncConfiguration::VsyncConfigSet constructOffsets(nsecs_t vsyncDuration) const override;

    VsyncConfigSet getDefaultOffsets(nsecs_t vsyncPeriod) const;
    VsyncConfigSet getHighFpsOffsets(nsecs_t vsyncPeriod) const;

    const nsecs_t mVSyncPhaseOffsetNs;
    const nsecs_t mSfVSyncPhaseOffsetNs;
    const std::optional<nsecs_t> mEarlySfOffsetNs;
    const std::optional<nsecs_t> mEarlyGpuSfOffsetNs;
    const std::optional<nsecs_t> mEarlyAppOffsetNs;
    const std::optional<nsecs_t> mEarlyGpuAppOffsetNs;

    const nsecs_t mHighFpsVSyncPhaseOffsetNs;
    const nsecs_t mHighFpsSfVSyncPhaseOffsetNs;
    const std::optional<nsecs_t> mHighFpsEarlySfOffsetNs;
    const std::optional<nsecs_t> mHighFpsEarlyGpuSfOffsetNs;
    const std::optional<nsecs_t> mHighFpsEarlyAppOffsetNs;
    const std::optional<nsecs_t> mHighFpsEarlyGpuAppOffsetNs;

    const nsecs_t mThresholdForNextVsync;
    const nsecs_t mHwcMinWorkDuration;
};

/*
 * Class that encapsulates the phase offsets for SurfaceFlinger and App.
 * The offsets are calculated from durations for each one of the (late, early, earlyGpu)
 * offset types.
 */
class WorkDuration : public VsyncConfiguration {
public:
    explicit WorkDuration(Fps currentRefrshRate);

protected:
    // Used for unit tests
    WorkDuration(Fps currentFps, nsecs_t sfDuration, nsecs_t appDuration, nsecs_t sfEarlyDuration,
                 nsecs_t appEarlyDuration, nsecs_t sfEarlyGpuDuration, nsecs_t appEarlyGpuDuration,
                 nsecs_t hwcMinWorkDuration);

private:
    VsyncConfiguration::VsyncConfigSet constructOffsets(nsecs_t vsyncDuration) const override;

    const nsecs_t mSfDuration;
    const nsecs_t mAppDuration;

    const nsecs_t mSfEarlyDuration;
    const nsecs_t mAppEarlyDuration;

    const nsecs_t mSfEarlyGpuDuration;
    const nsecs_t mAppEarlyGpuDuration;

    const nsecs_t mHwcMinWorkDuration;
};

} // namespace impl
} // namespace android::scheduler
