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

#include "PhaseOffsets.h"

#include <cutils/properties.h>

#include <optional>

#include "SurfaceFlingerProperties.h"

namespace {

std::optional<nsecs_t> getProperty(const char* name) {
    char value[PROPERTY_VALUE_MAX];
    property_get(name, value, "-1");
    if (const int i = atoi(value); i != -1) return i;
    return std::nullopt;
}

bool fpsEqualsWithMargin(float fpsA, float fpsB) {
    static constexpr float MARGIN = 0.01f;
    return std::abs(fpsA - fpsB) <= MARGIN;
}

std::vector<float> getRefreshRatesFromConfigs(
        const android::scheduler::RefreshRateConfigs& refreshRateConfigs) {
    const auto& allRefreshRates = refreshRateConfigs.getAllRefreshRates();
    std::vector<float> refreshRates;
    refreshRates.reserve(allRefreshRates.size());

    for (const auto& [ignored, refreshRate] : allRefreshRates) {
        refreshRates.emplace_back(refreshRate->getFps());
    }

    return refreshRates;
}

} // namespace

namespace android::scheduler {

PhaseConfiguration::~PhaseConfiguration() = default;

namespace impl {

PhaseOffsets::PhaseOffsets(const scheduler::RefreshRateConfigs& refreshRateConfigs)
      : PhaseOffsets(getRefreshRatesFromConfigs(refreshRateConfigs),
                     refreshRateConfigs.getCurrentRefreshRate().getFps(),
                     sysprop::vsync_event_phase_offset_ns(1000000),
                     sysprop::vsync_sf_event_phase_offset_ns(1000000),
                     getProperty("debug.sf.early_phase_offset_ns"),
                     getProperty("debug.sf.early_gl_phase_offset_ns"),
                     getProperty("debug.sf.early_app_phase_offset_ns"),
                     getProperty("debug.sf.early_gl_app_phase_offset_ns"),
                     // Below defines the threshold when an offset is considered to be negative,
                     // i.e. targeting for the N+2 vsync instead of N+1. This means that: For offset
                     // < threshold, SF wake up (vsync_duration - offset) before HW vsync. For
                     // offset >= threshold, SF wake up (2 * vsync_duration - offset) before HW
                     // vsync.
                     getProperty("debug.sf.phase_offset_threshold_for_next_vsync_ns")
                             .value_or(std::numeric_limits<nsecs_t>::max())) {}

PhaseOffsets::PhaseOffsets(const std::vector<float>& refreshRates, float currentFps,
                           nsecs_t vsyncPhaseOffsetNs, nsecs_t sfVSyncPhaseOffsetNs,
                           std::optional<nsecs_t> earlySfOffsetNs,
                           std::optional<nsecs_t> earlyGlSfOffsetNs,
                           std::optional<nsecs_t> earlyAppOffsetNs,
                           std::optional<nsecs_t> earlyGlAppOffsetNs, nsecs_t thresholdForNextVsync)
      : mVSyncPhaseOffsetNs(vsyncPhaseOffsetNs),
        mSfVSyncPhaseOffsetNs(sfVSyncPhaseOffsetNs),
        mEarlySfOffsetNs(earlySfOffsetNs),
        mEarlyGlSfOffsetNs(earlyGlSfOffsetNs),
        mEarlyAppOffsetNs(earlyAppOffsetNs),
        mEarlyGlAppOffsetNs(earlyGlAppOffsetNs),
        mThresholdForNextVsync(thresholdForNextVsync),
        mOffsets(initializeOffsets(refreshRates)),
        mRefreshRateFps(currentFps) {}

void PhaseOffsets::dump(std::string& result) const {
    const auto [early, earlyGl, late] = getCurrentOffsets();
    using base::StringAppendF;
    StringAppendF(&result,
                  "           app phase: %9" PRId64 " ns\t         SF phase: %9" PRId64 " ns\n"
                  "     early app phase: %9" PRId64 " ns\t   early SF phase: %9" PRId64 " ns\n"
                  "  GL early app phase: %9" PRId64 " ns\tGL early SF phase: %9" PRId64 " ns\n"
                  "next VSYNC threshold: %9" PRId64 " ns\n",
                  late.app, late.sf, early.app, early.sf, earlyGl.app, earlyGl.sf,
                  mThresholdForNextVsync);
}

std::unordered_map<float, PhaseOffsets::Offsets> PhaseOffsets::initializeOffsets(
        const std::vector<float>& refreshRates) const {
    std::unordered_map<float, Offsets> offsets;

    for (const auto& refreshRate : refreshRates) {
        offsets.emplace(refreshRate,
                        getPhaseOffsets(refreshRate, static_cast<nsecs_t>(1e9f / refreshRate)));
    }
    return offsets;
}

PhaseOffsets::Offsets PhaseOffsets::getPhaseOffsets(float fps, nsecs_t vsyncPeriod) const {
    if (fps > 65.0f) {
        return getHighFpsOffsets(vsyncPeriod);
    } else {
        return getDefaultOffsets(vsyncPeriod);
    }
}

PhaseOffsets::Offsets PhaseOffsets::getDefaultOffsets(nsecs_t vsyncDuration) const {
    return {
            {
                    mEarlySfOffsetNs.value_or(mSfVSyncPhaseOffsetNs) < mThresholdForNextVsync
                            ? mEarlySfOffsetNs.value_or(mSfVSyncPhaseOffsetNs)
                            : mEarlySfOffsetNs.value_or(mSfVSyncPhaseOffsetNs) - vsyncDuration,

                    mEarlyAppOffsetNs.value_or(mVSyncPhaseOffsetNs),
            },
            {
                    mEarlyGlSfOffsetNs.value_or(mSfVSyncPhaseOffsetNs) < mThresholdForNextVsync
                            ? mEarlyGlSfOffsetNs.value_or(mSfVSyncPhaseOffsetNs)
                            : mEarlyGlSfOffsetNs.value_or(mSfVSyncPhaseOffsetNs) - vsyncDuration,

                    mEarlyGlAppOffsetNs.value_or(mVSyncPhaseOffsetNs),
            },
            {
                    mSfVSyncPhaseOffsetNs < mThresholdForNextVsync
                            ? mSfVSyncPhaseOffsetNs
                            : mSfVSyncPhaseOffsetNs - vsyncDuration,

                    mVSyncPhaseOffsetNs,
            },
    };
}

PhaseOffsets::Offsets PhaseOffsets::getHighFpsOffsets(nsecs_t vsyncDuration) const {
    const auto highFpsLateAppOffsetNs =
            getProperty("debug.sf.high_fps_late_app_phase_offset_ns").value_or(2000000);
    const auto highFpsLateSfOffsetNs =
            getProperty("debug.sf.high_fps_late_sf_phase_offset_ns").value_or(1000000);

    const auto highFpsEarlySfOffsetNs = getProperty("debug.sf.high_fps_early_phase_offset_ns");
    const auto highFpsEarlyGlSfOffsetNs = getProperty("debug.sf.high_fps_early_gl_phase_offset_ns");
    const auto highFpsEarlyAppOffsetNs = getProperty("debug.sf.high_fps_early_app_phase_offset_ns");
    const auto highFpsEarlyGlAppOffsetNs =
            getProperty("debug.sf.high_fps_early_gl_app_phase_offset_ns");

    return {
            {
                    highFpsEarlySfOffsetNs.value_or(highFpsLateSfOffsetNs) < mThresholdForNextVsync
                            ? highFpsEarlySfOffsetNs.value_or(highFpsLateSfOffsetNs)
                            : highFpsEarlySfOffsetNs.value_or(highFpsLateSfOffsetNs) -
                                    vsyncDuration,

                    highFpsEarlyAppOffsetNs.value_or(highFpsLateAppOffsetNs),
            },
            {
                    highFpsEarlyGlSfOffsetNs.value_or(highFpsLateSfOffsetNs) <
                                    mThresholdForNextVsync
                            ? highFpsEarlyGlSfOffsetNs.value_or(highFpsLateSfOffsetNs)
                            : highFpsEarlyGlSfOffsetNs.value_or(highFpsLateSfOffsetNs) -
                                    vsyncDuration,

                    highFpsEarlyGlAppOffsetNs.value_or(highFpsLateAppOffsetNs),
            },
            {
                    highFpsLateSfOffsetNs < mThresholdForNextVsync
                            ? highFpsLateSfOffsetNs
                            : highFpsLateSfOffsetNs - vsyncDuration,

                    highFpsLateAppOffsetNs,
            },
    };
}

PhaseOffsets::Offsets PhaseOffsets::getOffsetsForRefreshRate(float fps) const {
    const auto iter = std::find_if(mOffsets.begin(), mOffsets.end(),
                                   [&fps](const std::pair<float, Offsets>& candidateFps) {
                                       return fpsEqualsWithMargin(fps, candidateFps.first);
                                   });

    if (iter != mOffsets.end()) {
        return iter->second;
    }

    // Unknown refresh rate. This might happen if we get a hotplug event for an external display.
    // In this case just construct the offset.
    ALOGW("Can't find offset for %.2f fps", fps);
    return getPhaseOffsets(fps, static_cast<nsecs_t>(1e9f / fps));
}

static void validateSysprops() {
    const auto validatePropertyBool = [](const char* prop) {
        LOG_ALWAYS_FATAL_IF(!property_get_bool(prop, false), "%s is false", prop);
    };

    validatePropertyBool("debug.sf.use_phase_offsets_as_durations");

    LOG_ALWAYS_FATAL_IF(sysprop::vsync_event_phase_offset_ns(-1) != -1,
                        "ro.surface_flinger.vsync_event_phase_offset_ns is set but expecting "
                        "duration");

    LOG_ALWAYS_FATAL_IF(sysprop::vsync_sf_event_phase_offset_ns(-1) != -1,
                        "ro.surface_flinger.vsync_sf_event_phase_offset_ns is set but expecting "
                        "duration");

    const auto validateProperty = [](const char* prop) {
        LOG_ALWAYS_FATAL_IF(getProperty(prop).has_value(),
                            "%s is set to %" PRId64 " but expecting duration", prop,
                            getProperty(prop).value_or(-1));
    };

    validateProperty("debug.sf.early_phase_offset_ns");
    validateProperty("debug.sf.early_gl_phase_offset_ns");
    validateProperty("debug.sf.early_app_phase_offset_ns");
    validateProperty("debug.sf.early_gl_app_phase_offset_ns");
    validateProperty("debug.sf.high_fps_late_app_phase_offset_ns");
    validateProperty("debug.sf.high_fps_late_sf_phase_offset_ns");
    validateProperty("debug.sf.high_fps_early_phase_offset_ns");
    validateProperty("debug.sf.high_fps_early_gl_phase_offset_ns");
    validateProperty("debug.sf.high_fps_early_app_phase_offset_ns");
    validateProperty("debug.sf.high_fps_early_gl_app_phase_offset_ns");
}

static nsecs_t sfDurationToOffset(nsecs_t sfDuration, nsecs_t vsyncDuration) {
    return sfDuration == -1 ? 1'000'000 : vsyncDuration - sfDuration % vsyncDuration;
}

static nsecs_t appDurationToOffset(nsecs_t appDuration, nsecs_t sfDuration, nsecs_t vsyncDuration) {
    return sfDuration == -1 ? 1'000'000
                            : vsyncDuration - (appDuration + sfDuration) % vsyncDuration;
}

PhaseDurations::Offsets PhaseDurations::constructOffsets(nsecs_t vsyncDuration) const {
    return Offsets{
            {
                    mSfEarlyDuration < vsyncDuration
                            ? sfDurationToOffset(mSfEarlyDuration, vsyncDuration)
                            : sfDurationToOffset(mSfEarlyDuration, vsyncDuration) - vsyncDuration,

                    appDurationToOffset(mAppEarlyDuration, mSfEarlyDuration, vsyncDuration),
            },
            {
                    mSfEarlyGlDuration < vsyncDuration
                            ? sfDurationToOffset(mSfEarlyGlDuration, vsyncDuration)
                            : sfDurationToOffset(mSfEarlyGlDuration, vsyncDuration) - vsyncDuration,

                    appDurationToOffset(mAppEarlyGlDuration, mSfEarlyGlDuration, vsyncDuration),
            },
            {
                    mSfDuration < vsyncDuration
                            ? sfDurationToOffset(mSfDuration, vsyncDuration)
                            : sfDurationToOffset(mSfDuration, vsyncDuration) - vsyncDuration,

                    appDurationToOffset(mAppDuration, mSfDuration, vsyncDuration),
            },
    };
}

std::unordered_map<float, PhaseDurations::Offsets> PhaseDurations::initializeOffsets(
        const std::vector<float>& refreshRates) const {
    std::unordered_map<float, Offsets> offsets;

    for (const auto fps : refreshRates) {
        offsets.emplace(fps, constructOffsets(static_cast<nsecs_t>(1e9f / fps)));
    }
    return offsets;
}

PhaseDurations::PhaseDurations(const scheduler::RefreshRateConfigs& refreshRateConfigs)
      : PhaseDurations(getRefreshRatesFromConfigs(refreshRateConfigs),
                       refreshRateConfigs.getCurrentRefreshRate().getFps(),
                       getProperty("debug.sf.late.sf.duration").value_or(-1),
                       getProperty("debug.sf.late.app.duration").value_or(-1),
                       getProperty("debug.sf.early.sf.duration").value_or(mSfDuration),
                       getProperty("debug.sf.early.app.duration").value_or(mAppDuration),
                       getProperty("debug.sf.earlyGl.sf.duration").value_or(mSfDuration),
                       getProperty("debug.sf.earlyGl.app.duration").value_or(mAppDuration)) {
    validateSysprops();
}

PhaseDurations::PhaseDurations(const std::vector<float>& refreshRates, float currentFps,
                               nsecs_t sfDuration, nsecs_t appDuration, nsecs_t sfEarlyDuration,
                               nsecs_t appEarlyDuration, nsecs_t sfEarlyGlDuration,
                               nsecs_t appEarlyGlDuration)
      : mSfDuration(sfDuration),
        mAppDuration(appDuration),
        mSfEarlyDuration(sfEarlyDuration),
        mAppEarlyDuration(appEarlyDuration),
        mSfEarlyGlDuration(sfEarlyGlDuration),
        mAppEarlyGlDuration(appEarlyGlDuration),
        mOffsets(initializeOffsets(refreshRates)),
        mRefreshRateFps(currentFps) {}

PhaseOffsets::Offsets PhaseDurations::getOffsetsForRefreshRate(float fps) const {
    const auto iter = std::find_if(mOffsets.begin(), mOffsets.end(), [=](const auto& candidateFps) {
        return fpsEqualsWithMargin(fps, candidateFps.first);
    });

    if (iter != mOffsets.end()) {
        return iter->second;
    }

    // Unknown refresh rate. This might happen if we get a hotplug event for an external display.
    // In this case just construct the offset.
    ALOGW("Can't find offset for %.2f fps", fps);
    return constructOffsets(static_cast<nsecs_t>(1e9f / fps));
}

void PhaseDurations::dump(std::string& result) const {
    const auto [early, earlyGl, late] = getCurrentOffsets();
    using base::StringAppendF;
    StringAppendF(&result,
                  "           app phase:    %9" PRId64 " ns\t         SF phase:    %9" PRId64
                  " ns\n"
                  "           app duration: %9" PRId64 " ns\t         SF duration: %9" PRId64
                  " ns\n"
                  "     early app phase:    %9" PRId64 " ns\t   early SF phase:    %9" PRId64
                  " ns\n"
                  "     early app duration: %9" PRId64 " ns\t   early SF duration: %9" PRId64
                  " ns\n"
                  "  GL early app phase:    %9" PRId64 " ns\tGL early SF phase:    %9" PRId64
                  " ns\n"
                  "  GL early app duration: %9" PRId64 " ns\tGL early SF duration: %9" PRId64
                  " ns\n",
                  late.app,

                  late.sf,

                  mAppDuration, mSfDuration,

                  early.app, early.sf,

                  mAppEarlyDuration, mSfEarlyDuration,

                  earlyGl.app,

                  earlyGl.sf,

                  mAppEarlyGlDuration, mSfEarlyGlDuration);
}

} // namespace impl
} // namespace android::scheduler
