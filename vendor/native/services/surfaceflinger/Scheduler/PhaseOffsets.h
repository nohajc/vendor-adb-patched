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

#include <unordered_map>

#include "RefreshRateConfigs.h"
#include "VSyncModulator.h"

namespace android::scheduler {

/*
 * This class encapsulates offsets for different refresh rates. Depending
 * on what refresh rate we are using, and wheter we are composing in GL,
 * different offsets will help us with latency. This class keeps track of
 * which mode the device is on, and returns approprate offsets when needed.
 */
class PhaseConfiguration {
public:
    using Offsets = VSyncModulator::OffsetsConfig;

    virtual ~PhaseConfiguration();

    virtual Offsets getCurrentOffsets() const = 0;
    virtual Offsets getOffsetsForRefreshRate(float fps) const = 0;

    virtual void setRefreshRateFps(float fps) = 0;

    virtual void dump(std::string& result) const = 0;
};

namespace impl {

/*
 * This is the old implementation of phase offsets and considered as deprecated.
 * PhaseDurations is the new implementation.
 */
class PhaseOffsets : public scheduler::PhaseConfiguration {
public:
    PhaseOffsets(const scheduler::RefreshRateConfigs&);

    // Returns early, early GL, and late offsets for Apps and SF for a given refresh rate.
    Offsets getOffsetsForRefreshRate(float fps) const override;

    // Returns early, early GL, and late offsets for Apps and SF.
    Offsets getCurrentOffsets() const override { return getOffsetsForRefreshRate(mRefreshRateFps); }

    // This function should be called when the device is switching between different
    // refresh rates, to properly update the offsets.
    void setRefreshRateFps(float fps) override { mRefreshRateFps = fps; }

    // Returns current offsets in human friendly format.
    void dump(std::string& result) const override;

protected:
    // Used for unit tests
    PhaseOffsets(const std::vector<float>& refreshRates, float currentFps,
                 nsecs_t vsyncPhaseOffsetNs, nsecs_t sfVSyncPhaseOffsetNs,
                 std::optional<nsecs_t> earlySfOffsetNs, std::optional<nsecs_t> earlyGlSfOffsetNs,
                 std::optional<nsecs_t> earlyAppOffsetNs, std::optional<nsecs_t> earlyGlAppOffsetNs,
                 nsecs_t thresholdForNextVsync);
    std::unordered_map<float, Offsets> initializeOffsets(
            const std::vector<float>& refreshRates) const;
    Offsets getDefaultOffsets(nsecs_t vsyncPeriod) const;
    Offsets getHighFpsOffsets(nsecs_t vsyncPeriod) const;
    Offsets getPhaseOffsets(float fps, nsecs_t vsyncPeriod) const;

    const nsecs_t mVSyncPhaseOffsetNs;
    const nsecs_t mSfVSyncPhaseOffsetNs;
    const std::optional<nsecs_t> mEarlySfOffsetNs;
    const std::optional<nsecs_t> mEarlyGlSfOffsetNs;
    const std::optional<nsecs_t> mEarlyAppOffsetNs;
    const std::optional<nsecs_t> mEarlyGlAppOffsetNs;
    const nsecs_t mThresholdForNextVsync;
    const std::unordered_map<float, Offsets> mOffsets;

    std::atomic<float> mRefreshRateFps;
};

/*
 * Class that encapsulates the phase offsets for SurfaceFlinger and App.
 * The offsets are calculated from durations for each one of the (late, early, earlyGL)
 * offset types.
 */
class PhaseDurations : public scheduler::PhaseConfiguration {
public:
    PhaseDurations(const scheduler::RefreshRateConfigs&);

    // Returns early, early GL, and late offsets for Apps and SF for a given refresh rate.
    Offsets getOffsetsForRefreshRate(float fps) const override;

    // Returns early, early GL, and late offsets for Apps and SF.
    Offsets getCurrentOffsets() const override { return getOffsetsForRefreshRate(mRefreshRateFps); }

    // This function should be called when the device is switching between different
    // refresh rates, to properly update the offsets.
    void setRefreshRateFps(float fps) override { mRefreshRateFps = fps; }

    // Returns current offsets in human friendly format.
    void dump(std::string& result) const override;

protected:
    // Used for unit tests
    PhaseDurations(const std::vector<float>& refreshRates, float currentFps, nsecs_t sfDuration,
                   nsecs_t appDuration, nsecs_t sfEarlyDuration, nsecs_t appEarlyDuration,
                   nsecs_t sfEarlyGlDuration, nsecs_t appEarlyGlDuration);

private:
    std::unordered_map<float, Offsets> initializeOffsets(const std::vector<float>&) const;
    PhaseDurations::Offsets constructOffsets(nsecs_t vsyncDuration) const;

    const nsecs_t mSfDuration;
    const nsecs_t mAppDuration;

    const nsecs_t mSfEarlyDuration;
    const nsecs_t mAppEarlyDuration;

    const nsecs_t mSfEarlyGlDuration;
    const nsecs_t mAppEarlyGlDuration;

    const std::unordered_map<float, Offsets> mOffsets;

    std::atomic<float> mRefreshRateFps;
};

} // namespace impl
} // namespace android::scheduler
