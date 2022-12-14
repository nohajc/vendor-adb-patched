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

#include "VsyncConfiguration.h"

#include <chrono>
#include <cinttypes>
#include <optional>

#include <cutils/properties.h>
#include <log/log.h>

#include "SurfaceFlingerProperties.h"

namespace {

using namespace std::chrono_literals;

std::optional<nsecs_t> getProperty(const char* name) {
    char value[PROPERTY_VALUE_MAX];
    property_get(name, value, "-1");
    if (const int i = atoi(value); i != -1) return i;
    return std::nullopt;
}

} // namespace

namespace android::scheduler::impl {

VsyncConfiguration::VsyncConfiguration(Fps currentFps) : mRefreshRateFps(currentFps) {}

PhaseOffsets::VsyncConfigSet VsyncConfiguration::getConfigsForRefreshRate(Fps fps) const {
    std::lock_guard lock(mLock);
    return getConfigsForRefreshRateLocked(fps);
}

PhaseOffsets::VsyncConfigSet VsyncConfiguration::getConfigsForRefreshRateLocked(Fps fps) const {
    if (const auto offsets = mOffsetsCache.get(fps)) {
        return offsets->get();
    }

    const auto [it, _] = mOffsetsCache.try_emplace(fps, constructOffsets(fps.getPeriodNsecs()));
    return it->second;
}

void VsyncConfiguration::dump(std::string& result) const {
    const auto [early, earlyGpu, late, hwcMinWorkDuration] = getCurrentConfigs();
    using base::StringAppendF;
    StringAppendF(&result,
                  "           app phase:    %9" PRId64 " ns\t         SF phase:    %9" PRId64
                  " ns\n"
                  "           app duration: %9lld ns\t         SF duration: %9lld ns\n"
                  "     early app phase:    %9" PRId64 " ns\t   early SF phase:    %9" PRId64
                  " ns\n"
                  "     early app duration: %9lld ns\t   early SF duration: %9lld ns\n"
                  "  GL early app phase:    %9" PRId64 " ns\tGL early SF phase:    %9" PRId64
                  " ns\n"
                  "  GL early app duration: %9lld ns\tGL early SF duration: %9lld ns\n"
                  "       HWC min duration: %9lld ns\n",
                  late.appOffset, late.sfOffset,

                  late.appWorkDuration.count(), late.sfWorkDuration.count(),

                  early.appOffset, early.sfOffset,

                  early.appWorkDuration.count(), early.sfWorkDuration.count(),

                  earlyGpu.appOffset, earlyGpu.sfOffset,

                  earlyGpu.appWorkDuration.count(), earlyGpu.sfWorkDuration.count(),

                  hwcMinWorkDuration.count());
}

PhaseOffsets::PhaseOffsets(Fps currentRefreshRate)
      : PhaseOffsets(currentRefreshRate, sysprop::vsync_event_phase_offset_ns(1000000),
                     sysprop::vsync_sf_event_phase_offset_ns(1000000),
                     getProperty("debug.sf.early_phase_offset_ns"),
                     getProperty("debug.sf.early_gl_phase_offset_ns"),
                     getProperty("debug.sf.early_app_phase_offset_ns"),
                     getProperty("debug.sf.early_gl_app_phase_offset_ns"),
                     getProperty("debug.sf.high_fps_late_app_phase_offset_ns").value_or(2000000),
                     getProperty("debug.sf.high_fps_late_sf_phase_offset_ns").value_or(1000000),
                     getProperty("debug.sf.high_fps_early_phase_offset_ns"),
                     getProperty("debug.sf.high_fps_early_gl_phase_offset_ns"),
                     getProperty("debug.sf.high_fps_early_app_phase_offset_ns"),
                     getProperty("debug.sf.high_fps_early_gl_app_phase_offset_ns"),
                     // Below defines the threshold when an offset is considered to be negative,
                     // i.e. targeting for the N+2 vsync instead of N+1. This means that: For offset
                     // < threshold, SF wake up (vsync_duration - offset) before HW vsync. For
                     // offset >= threshold, SF wake up (2 * vsync_duration - offset) before HW
                     // vsync.
                     getProperty("debug.sf.phase_offset_threshold_for_next_vsync_ns")
                             .value_or(std::numeric_limits<nsecs_t>::max()),
                     getProperty("debug.sf.hwc.min.duration").value_or(0)) {}

PhaseOffsets::PhaseOffsets(Fps currentFps, nsecs_t vsyncPhaseOffsetNs, nsecs_t sfVSyncPhaseOffsetNs,
                           std::optional<nsecs_t> earlySfOffsetNs,
                           std::optional<nsecs_t> earlyGpuSfOffsetNs,
                           std::optional<nsecs_t> earlyAppOffsetNs,
                           std::optional<nsecs_t> earlyGpuAppOffsetNs,
                           nsecs_t highFpsVsyncPhaseOffsetNs, nsecs_t highFpsSfVSyncPhaseOffsetNs,
                           std::optional<nsecs_t> highFpsEarlySfOffsetNs,
                           std::optional<nsecs_t> highFpsEarlyGpuSfOffsetNs,
                           std::optional<nsecs_t> highFpsEarlyAppOffsetNs,
                           std::optional<nsecs_t> highFpsEarlyGpuAppOffsetNs,
                           nsecs_t thresholdForNextVsync, nsecs_t hwcMinWorkDuration)
      : VsyncConfiguration(currentFps),
        mVSyncPhaseOffsetNs(vsyncPhaseOffsetNs),
        mSfVSyncPhaseOffsetNs(sfVSyncPhaseOffsetNs),
        mEarlySfOffsetNs(earlySfOffsetNs),
        mEarlyGpuSfOffsetNs(earlyGpuSfOffsetNs),
        mEarlyAppOffsetNs(earlyAppOffsetNs),
        mEarlyGpuAppOffsetNs(earlyGpuAppOffsetNs),
        mHighFpsVSyncPhaseOffsetNs(highFpsVsyncPhaseOffsetNs),
        mHighFpsSfVSyncPhaseOffsetNs(highFpsSfVSyncPhaseOffsetNs),
        mHighFpsEarlySfOffsetNs(highFpsEarlySfOffsetNs),
        mHighFpsEarlyGpuSfOffsetNs(highFpsEarlyGpuSfOffsetNs),
        mHighFpsEarlyAppOffsetNs(highFpsEarlyAppOffsetNs),
        mHighFpsEarlyGpuAppOffsetNs(highFpsEarlyGpuAppOffsetNs),
        mThresholdForNextVsync(thresholdForNextVsync),
        mHwcMinWorkDuration(hwcMinWorkDuration) {}

PhaseOffsets::VsyncConfigSet PhaseOffsets::constructOffsets(nsecs_t vsyncDuration) const {
    if (vsyncDuration < std::chrono::nanoseconds(15ms).count()) {
        return getHighFpsOffsets(vsyncDuration);
    } else {
        return getDefaultOffsets(vsyncDuration);
    }
}

namespace {
std::chrono::nanoseconds sfOffsetToDuration(nsecs_t sfOffset, nsecs_t vsyncDuration) {
    return std::chrono::nanoseconds(vsyncDuration - sfOffset);
}

std::chrono::nanoseconds appOffsetToDuration(nsecs_t appOffset, nsecs_t sfOffset,
                                             nsecs_t vsyncDuration) {
    auto duration = vsyncDuration + (sfOffset - appOffset);
    if (duration < vsyncDuration) {
        duration += vsyncDuration;
    }

    return std::chrono::nanoseconds(duration);
}
} // namespace

PhaseOffsets::VsyncConfigSet PhaseOffsets::getDefaultOffsets(nsecs_t vsyncDuration) const {
    const auto earlySfOffset =
            mEarlySfOffsetNs.value_or(mSfVSyncPhaseOffsetNs) < mThresholdForNextVsync

            ? mEarlySfOffsetNs.value_or(mSfVSyncPhaseOffsetNs)
            : mEarlySfOffsetNs.value_or(mSfVSyncPhaseOffsetNs) - vsyncDuration;
    const auto earlyAppOffset = mEarlyAppOffsetNs.value_or(mVSyncPhaseOffsetNs);
    const auto earlyGpuSfOffset =
            mEarlyGpuSfOffsetNs.value_or(mSfVSyncPhaseOffsetNs) < mThresholdForNextVsync

            ? mEarlyGpuSfOffsetNs.value_or(mSfVSyncPhaseOffsetNs)
            : mEarlyGpuSfOffsetNs.value_or(mSfVSyncPhaseOffsetNs) - vsyncDuration;
    const auto earlyGpuAppOffset = mEarlyGpuAppOffsetNs.value_or(mVSyncPhaseOffsetNs);
    const auto lateSfOffset = mSfVSyncPhaseOffsetNs < mThresholdForNextVsync
            ? mSfVSyncPhaseOffsetNs
            : mSfVSyncPhaseOffsetNs - vsyncDuration;
    const auto lateAppOffset = mVSyncPhaseOffsetNs;

    return {
            .early = {.sfOffset = earlySfOffset,
                      .appOffset = earlyAppOffset,
                      .sfWorkDuration = sfOffsetToDuration(earlySfOffset, vsyncDuration),
                      .appWorkDuration =
                              appOffsetToDuration(earlyAppOffset, earlySfOffset, vsyncDuration)},
            .earlyGpu = {.sfOffset = earlyGpuSfOffset,
                         .appOffset = earlyGpuAppOffset,
                         .sfWorkDuration = sfOffsetToDuration(earlyGpuSfOffset, vsyncDuration),
                         .appWorkDuration = appOffsetToDuration(earlyGpuAppOffset, earlyGpuSfOffset,
                                                                vsyncDuration)},
            .late = {.sfOffset = lateSfOffset,
                     .appOffset = lateAppOffset,
                     .sfWorkDuration = sfOffsetToDuration(lateSfOffset, vsyncDuration),
                     .appWorkDuration =
                             appOffsetToDuration(lateAppOffset, lateSfOffset, vsyncDuration)},
            .hwcMinWorkDuration = std::chrono::nanoseconds(mHwcMinWorkDuration),
    };
}

PhaseOffsets::VsyncConfigSet PhaseOffsets::getHighFpsOffsets(nsecs_t vsyncDuration) const {
    const auto earlySfOffset =
            mHighFpsEarlySfOffsetNs.value_or(mHighFpsSfVSyncPhaseOffsetNs) < mThresholdForNextVsync
            ? mHighFpsEarlySfOffsetNs.value_or(mHighFpsSfVSyncPhaseOffsetNs)
            : mHighFpsEarlySfOffsetNs.value_or(mHighFpsSfVSyncPhaseOffsetNs) - vsyncDuration;
    const auto earlyAppOffset = mHighFpsEarlyAppOffsetNs.value_or(mHighFpsVSyncPhaseOffsetNs);
    const auto earlyGpuSfOffset = mHighFpsEarlyGpuSfOffsetNs.value_or(
                                          mHighFpsSfVSyncPhaseOffsetNs) < mThresholdForNextVsync

            ? mHighFpsEarlyGpuSfOffsetNs.value_or(mHighFpsSfVSyncPhaseOffsetNs)
            : mHighFpsEarlyGpuSfOffsetNs.value_or(mHighFpsSfVSyncPhaseOffsetNs) - vsyncDuration;
    const auto earlyGpuAppOffset = mHighFpsEarlyGpuAppOffsetNs.value_or(mHighFpsVSyncPhaseOffsetNs);
    const auto lateSfOffset = mHighFpsSfVSyncPhaseOffsetNs < mThresholdForNextVsync
            ? mHighFpsSfVSyncPhaseOffsetNs
            : mHighFpsSfVSyncPhaseOffsetNs - vsyncDuration;
    const auto lateAppOffset = mHighFpsVSyncPhaseOffsetNs;

    return {
            .early =
                    {
                            .sfOffset = earlySfOffset,
                            .appOffset = earlyAppOffset,
                            .sfWorkDuration = sfOffsetToDuration(earlySfOffset, vsyncDuration),
                            .appWorkDuration = appOffsetToDuration(earlyAppOffset, earlySfOffset,
                                                                   vsyncDuration),
                    },
            .earlyGpu =
                    {
                            .sfOffset = earlyGpuSfOffset,
                            .appOffset = earlyGpuAppOffset,
                            .sfWorkDuration = sfOffsetToDuration(earlyGpuSfOffset, vsyncDuration),
                            .appWorkDuration = appOffsetToDuration(earlyGpuAppOffset,
                                                                   earlyGpuSfOffset, vsyncDuration),
                    },
            .late =
                    {
                            .sfOffset = lateSfOffset,
                            .appOffset = lateAppOffset,
                            .sfWorkDuration = sfOffsetToDuration(lateSfOffset, vsyncDuration),
                            .appWorkDuration =
                                    appOffsetToDuration(lateAppOffset, lateSfOffset, vsyncDuration),
                    },
            .hwcMinWorkDuration = std::chrono::nanoseconds(mHwcMinWorkDuration),
    };
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

namespace {
nsecs_t sfDurationToOffset(std::chrono::nanoseconds sfDuration, nsecs_t vsyncDuration) {
    return vsyncDuration - sfDuration.count() % vsyncDuration;
}

nsecs_t appDurationToOffset(std::chrono::nanoseconds appDuration,
                            std::chrono::nanoseconds sfDuration, nsecs_t vsyncDuration) {
    return vsyncDuration - (appDuration + sfDuration).count() % vsyncDuration;
}
} // namespace

WorkDuration::VsyncConfigSet WorkDuration::constructOffsets(nsecs_t vsyncDuration) const {
    const auto sfDurationFixup = [vsyncDuration](nsecs_t duration) {
        return duration == -1 ? std::chrono::nanoseconds(vsyncDuration) - 1ms
                              : std::chrono::nanoseconds(duration);
    };

    const auto appDurationFixup = [vsyncDuration](nsecs_t duration) {
        return duration == -1 ? std::chrono::nanoseconds(vsyncDuration)
                              : std::chrono::nanoseconds(duration);
    };

    const auto sfEarlyDuration = sfDurationFixup(mSfEarlyDuration);
    const auto appEarlyDuration = appDurationFixup(mAppEarlyDuration);
    const auto sfEarlyGpuDuration = sfDurationFixup(mSfEarlyGpuDuration);
    const auto appEarlyGpuDuration = appDurationFixup(mAppEarlyGpuDuration);
    const auto sfDuration = sfDurationFixup(mSfDuration);
    const auto appDuration = appDurationFixup(mAppDuration);

    return {
            .early =
                    {

                            .sfOffset = sfEarlyDuration.count() < vsyncDuration
                                    ? sfDurationToOffset(sfEarlyDuration, vsyncDuration)
                                    : sfDurationToOffset(sfEarlyDuration, vsyncDuration) -
                                            vsyncDuration,

                            .appOffset = appDurationToOffset(appEarlyDuration, sfEarlyDuration,
                                                             vsyncDuration),

                            .sfWorkDuration = sfEarlyDuration,
                            .appWorkDuration = appEarlyDuration,
                    },
            .earlyGpu =
                    {

                            .sfOffset = sfEarlyGpuDuration.count() < vsyncDuration

                                    ? sfDurationToOffset(sfEarlyGpuDuration, vsyncDuration)
                                    : sfDurationToOffset(sfEarlyGpuDuration, vsyncDuration) -
                                            vsyncDuration,

                            .appOffset = appDurationToOffset(appEarlyGpuDuration,
                                                             sfEarlyGpuDuration, vsyncDuration),
                            .sfWorkDuration = sfEarlyGpuDuration,
                            .appWorkDuration = appEarlyGpuDuration,
                    },
            .late =
                    {

                            .sfOffset = sfDuration.count() < vsyncDuration

                                    ? sfDurationToOffset(sfDuration, vsyncDuration)
                                    : sfDurationToOffset(sfDuration, vsyncDuration) - vsyncDuration,

                            .appOffset =
                                    appDurationToOffset(appDuration, sfDuration, vsyncDuration),

                            .sfWorkDuration = sfDuration,
                            .appWorkDuration = appDuration,
                    },
            .hwcMinWorkDuration = std::chrono::nanoseconds(mHwcMinWorkDuration),
    };
}

WorkDuration::WorkDuration(Fps currentRefreshRate)
      : WorkDuration(currentRefreshRate, getProperty("debug.sf.late.sf.duration").value_or(-1),
                     getProperty("debug.sf.late.app.duration").value_or(-1),
                     getProperty("debug.sf.early.sf.duration").value_or(mSfDuration),
                     getProperty("debug.sf.early.app.duration").value_or(mAppDuration),
                     getProperty("debug.sf.earlyGl.sf.duration").value_or(mSfDuration),
                     getProperty("debug.sf.earlyGl.app.duration").value_or(mAppDuration),
                     getProperty("debug.sf.hwc.min.duration").value_or(0)) {
    validateSysprops();
}

WorkDuration::WorkDuration(Fps currentRefreshRate, nsecs_t sfDuration, nsecs_t appDuration,
                           nsecs_t sfEarlyDuration, nsecs_t appEarlyDuration,
                           nsecs_t sfEarlyGpuDuration, nsecs_t appEarlyGpuDuration,
                           nsecs_t hwcMinWorkDuration)
      : VsyncConfiguration(currentRefreshRate),
        mSfDuration(sfDuration),
        mAppDuration(appDuration),
        mSfEarlyDuration(sfEarlyDuration),
        mAppEarlyDuration(appEarlyDuration),
        mSfEarlyGpuDuration(sfEarlyGpuDuration),
        mAppEarlyGpuDuration(appEarlyGpuDuration),
        mHwcMinWorkDuration(hwcMinWorkDuration) {}

} // namespace android::scheduler::impl
