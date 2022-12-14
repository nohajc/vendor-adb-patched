/*
 * Copyright 2018 The Android Open Source Project
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

//#define LOG_NDEBUG 0

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#undef LOG_TAG
#define LOG_TAG "PowerAdvisor"

#include <unistd.h>
#include <cinttypes>
#include <cstdint>
#include <optional>

#include <android-base/properties.h>
#include <utils/Log.h>
#include <utils/Mutex.h>
#include <utils/Trace.h>

#include <android/hardware/power/1.3/IPower.h>
#include <android/hardware/power/IPowerHintSession.h>
#include <android/hardware/power/WorkDuration.h>

#include <binder/IServiceManager.h>

#include "../SurfaceFlingerProperties.h"

#include "PowerAdvisor.h"
#include "SurfaceFlinger.h"

namespace android {
namespace Hwc2 {

PowerAdvisor::~PowerAdvisor() = default;

namespace impl {

namespace V1_0 = android::hardware::power::V1_0;
namespace V1_3 = android::hardware::power::V1_3;
using V1_3::PowerHint;

using android::hardware::power::Boost;
using android::hardware::power::IPower;
using android::hardware::power::IPowerHintSession;
using android::hardware::power::Mode;
using android::hardware::power::WorkDuration;

using scheduler::OneShotTimer;

PowerAdvisor::~PowerAdvisor() = default;

namespace {
std::chrono::milliseconds getUpdateTimeout() {
    // Default to a timeout of 80ms if nothing else is specified
    static std::chrono::milliseconds timeout =
            std::chrono::milliseconds(sysprop::display_update_imminent_timeout_ms(80));
    return timeout;
}

void traceExpensiveRendering(bool enabled) {
    if (enabled) {
        ATRACE_ASYNC_BEGIN("ExpensiveRendering", 0);
    } else {
        ATRACE_ASYNC_END("ExpensiveRendering", 0);
    }
}

} // namespace

PowerAdvisor::PowerAdvisor(SurfaceFlinger& flinger) : mFlinger(flinger) {
    if (getUpdateTimeout() > 0ms) {
        mScreenUpdateTimer.emplace("UpdateImminentTimer", getUpdateTimeout(),
                                   /* resetCallback */ nullptr,
                                   /* timeoutCallback */
                                   [this] {
                                       while (true) {
                                           auto timeSinceLastUpdate = std::chrono::nanoseconds(
                                                   systemTime() - mLastScreenUpdatedTime.load());
                                           if (timeSinceLastUpdate >= getUpdateTimeout()) {
                                               break;
                                           }
                                           // We may try to disable expensive rendering and allow
                                           // for sending DISPLAY_UPDATE_IMMINENT hints too early if
                                           // we idled very shortly after updating the screen, so
                                           // make sure we wait enough time.
                                           std::this_thread::sleep_for(getUpdateTimeout() -
                                                                       timeSinceLastUpdate);
                                       }
                                       mSendUpdateImminent.store(true);
                                       mFlinger.disableExpensiveRendering();
                                   });
    }
}

void PowerAdvisor::init() {
    // Defer starting the screen update timer until SurfaceFlinger finishes construction.
    if (mScreenUpdateTimer) {
        mScreenUpdateTimer->start();
    }
}

void PowerAdvisor::onBootFinished() {
    mBootFinished.store(true);
}

void PowerAdvisor::setExpensiveRenderingExpected(DisplayId displayId, bool expected) {
    if (expected) {
        mExpensiveDisplays.insert(displayId);
    } else {
        mExpensiveDisplays.erase(displayId);
    }

    const bool expectsExpensiveRendering = !mExpensiveDisplays.empty();
    if (mNotifiedExpensiveRendering != expectsExpensiveRendering) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper == nullptr) {
            return;
        }

        if (!halWrapper->setExpensiveRendering(expectsExpensiveRendering)) {
            // The HAL has become unavailable; attempt to reconnect later
            mReconnectPowerHal = true;
            return;
        }

        mNotifiedExpensiveRendering = expectsExpensiveRendering;
    }
}

void PowerAdvisor::notifyDisplayUpdateImminent() {
    // Only start sending this notification once the system has booted so we don't introduce an
    // early-boot dependency on Power HAL
    if (!mBootFinished.load()) {
        return;
    }

    if (mSendUpdateImminent.exchange(false)) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper == nullptr) {
            return;
        }

        if (!halWrapper->notifyDisplayUpdateImminent()) {
            // The HAL has become unavailable; attempt to reconnect later
            mReconnectPowerHal = true;
            return;
        }

        if (mScreenUpdateTimer) {
            mScreenUpdateTimer->reset();
        } else {
            // If we don't have a screen update timer, then we don't throttle power hal calls so
            // flip this bit back to allow for calling into power hal again.
            mSendUpdateImminent.store(true);
        }
    }

    if (mScreenUpdateTimer) {
        mLastScreenUpdatedTime.store(systemTime());
    }
}

// checks both if it supports and if it's enabled
bool PowerAdvisor::usePowerHintSession() {
    // uses cached value since the underlying support and flag are unlikely to change at runtime
    return mPowerHintEnabled.value_or(false) && supportsPowerHintSession();
}

bool PowerAdvisor::supportsPowerHintSession() {
    // cache to avoid needing lock every time
    if (!mSupportsPowerHint.has_value()) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        mSupportsPowerHint = halWrapper && halWrapper->supportsPowerHintSession();
    }
    return *mSupportsPowerHint;
}

bool PowerAdvisor::isPowerHintSessionRunning() {
    return mPowerHintSessionRunning;
}

void PowerAdvisor::setTargetWorkDuration(int64_t targetDuration) {
    if (!usePowerHintSession()) {
        ALOGV("Power hint session target duration cannot be set, skipping");
        return;
    }
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->setTargetWorkDuration(targetDuration);
        }
    }
}

void PowerAdvisor::sendActualWorkDuration() {
    if (!mBootFinished || !usePowerHintSession()) {
        ALOGV("Actual work duration power hint cannot be sent, skipping");
        return;
    }
    const std::optional<nsecs_t> actualDuration = estimateWorkDuration(false);
    if (actualDuration.has_value()) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->sendActualWorkDuration(*actualDuration + kTargetSafetyMargin.count(),
                                               systemTime());
        }
    }
}

void PowerAdvisor::sendPredictedWorkDuration() {
    if (!mBootFinished || !usePowerHintSession()) {
        ALOGV("Actual work duration power hint cannot be sent, skipping");
        return;
    }

    const std::optional<nsecs_t> predictedDuration = estimateWorkDuration(true);

    if (predictedDuration.has_value()) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper != nullptr) {
            halWrapper->sendActualWorkDuration(*predictedDuration + kTargetSafetyMargin.count(),
                                               systemTime());
        }
    }
}

void PowerAdvisor::enablePowerHint(bool enabled) {
    mPowerHintEnabled = enabled;
}

bool PowerAdvisor::startPowerHintSession(const std::vector<int32_t>& threadIds) {
    if (!usePowerHintSession()) {
        ALOGI("Power hint session cannot be started, skipping");
    }
    {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* halWrapper = getPowerHal();
        if (halWrapper != nullptr && usePowerHintSession()) {
            halWrapper->setPowerHintSessionThreadIds(threadIds);
            mPowerHintSessionRunning = halWrapper->startPowerHintSession();
        }
    }
    return mPowerHintSessionRunning;
}

void PowerAdvisor::setGpuFenceTime(DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime) {
    DisplayTimingData& displayData = mDisplayTimingData[displayId];
    if (displayData.gpuEndFenceTime) {
        nsecs_t signalTime = displayData.gpuEndFenceTime->getSignalTime();
        if (signalTime != Fence::SIGNAL_TIME_INVALID && signalTime != Fence::SIGNAL_TIME_PENDING) {
            for (auto&& [_, otherDisplayData] : mDisplayTimingData) {
                // If the previous display started before us but ended after we should have
                // started, then it likely delayed our start time and we must compensate for that.
                // Displays finishing earlier should have already made their way through this call
                // and swapped their timing into "lastValid" from "latest", so we check that here.
                if (!otherDisplayData.lastValidGpuStartTime.has_value()) continue;
                if ((*otherDisplayData.lastValidGpuStartTime < *displayData.gpuStartTime) &&
                    (*otherDisplayData.lastValidGpuEndTime > *displayData.gpuStartTime)) {
                    displayData.lastValidGpuStartTime = *otherDisplayData.lastValidGpuEndTime;
                    break;
                }
            }
            displayData.lastValidGpuStartTime = displayData.gpuStartTime;
            displayData.lastValidGpuEndTime = signalTime;
        }
    }
    displayData.gpuEndFenceTime = std::move(fenceTime);
    displayData.gpuStartTime = systemTime();
}

void PowerAdvisor::setHwcValidateTiming(DisplayId displayId, nsecs_t validateStartTime,
                                        nsecs_t validateEndTime) {
    DisplayTimingData& displayData = mDisplayTimingData[displayId];
    displayData.hwcValidateStartTime = validateStartTime;
    displayData.hwcValidateEndTime = validateEndTime;
}

void PowerAdvisor::setHwcPresentTiming(DisplayId displayId, nsecs_t presentStartTime,
                                       nsecs_t presentEndTime) {
    DisplayTimingData& displayData = mDisplayTimingData[displayId];
    displayData.hwcPresentStartTime = presentStartTime;
    displayData.hwcPresentEndTime = presentEndTime;
}

void PowerAdvisor::setSkippedValidate(DisplayId displayId, bool skipped) {
    mDisplayTimingData[displayId].skippedValidate = skipped;
}

void PowerAdvisor::setRequiresClientComposition(DisplayId displayId,
                                                bool requiresClientComposition) {
    mDisplayTimingData[displayId].usedClientComposition = requiresClientComposition;
}

void PowerAdvisor::setExpectedPresentTime(nsecs_t expectedPresentTime) {
    mExpectedPresentTimes.append(expectedPresentTime);
}

void PowerAdvisor::setSfPresentTiming(nsecs_t presentFenceTime, nsecs_t presentEndTime) {
    mLastSfPresentEndTime = presentEndTime;
    mLastPresentFenceTime = presentFenceTime;
}

void PowerAdvisor::setFrameDelay(nsecs_t frameDelayDuration) {
    mFrameDelayDuration = frameDelayDuration;
}

void PowerAdvisor::setHwcPresentDelayedTime(
        DisplayId displayId, std::chrono::steady_clock::time_point earliestFrameStartTime) {
    mDisplayTimingData[displayId].hwcPresentDelayedTime =
            (earliestFrameStartTime - std::chrono::steady_clock::now()).count() + systemTime();
}

void PowerAdvisor::setCommitStart(nsecs_t commitStartTime) {
    mCommitStartTimes.append(commitStartTime);
}

void PowerAdvisor::setCompositeEnd(nsecs_t compositeEnd) {
    mLastPostcompDuration = compositeEnd - mLastSfPresentEndTime;
}

void PowerAdvisor::setDisplays(std::vector<DisplayId>& displayIds) {
    mDisplayIds = displayIds;
}

void PowerAdvisor::setTotalFrameTargetWorkDuration(nsecs_t targetDuration) {
    mTotalFrameTargetDuration = targetDuration;
}

std::vector<DisplayId> PowerAdvisor::getOrderedDisplayIds(
        std::optional<nsecs_t> DisplayTimingData::*sortBy) {
    std::vector<DisplayId> sortedDisplays;
    std::copy_if(mDisplayIds.begin(), mDisplayIds.end(), std::back_inserter(sortedDisplays),
                 [&](DisplayId id) {
                     return mDisplayTimingData.count(id) &&
                             (mDisplayTimingData[id].*sortBy).has_value();
                 });
    std::sort(sortedDisplays.begin(), sortedDisplays.end(), [&](DisplayId idA, DisplayId idB) {
        return *(mDisplayTimingData[idA].*sortBy) < *(mDisplayTimingData[idB].*sortBy);
    });
    return sortedDisplays;
}

std::optional<nsecs_t> PowerAdvisor::estimateWorkDuration(bool earlyHint) {
    if (earlyHint && (!mExpectedPresentTimes.isFull() || !mCommitStartTimes.isFull())) {
        return std::nullopt;
    }

    // Tracks when we finish presenting to hwc
    nsecs_t estimatedEndTime = mCommitStartTimes[0];

    // How long we spent this frame not doing anything, waiting for fences or vsync
    nsecs_t idleDuration = 0;

    // Most recent previous gpu end time in the current frame, probably from a prior display, used
    // as the start time for the next gpu operation if it ran over time since it probably blocked
    std::optional<nsecs_t> previousValidGpuEndTime;

    // The currently estimated gpu end time for the frame,
    // used to accumulate gpu time as we iterate over the active displays
    std::optional<nsecs_t> estimatedGpuEndTime;

    // If we're predicting at the start of the frame, we use last frame as our reference point
    // If we're predicting at the end of the frame, we use the current frame as a reference point
    nsecs_t referenceFrameStartTime = (earlyHint ? mCommitStartTimes[-1] : mCommitStartTimes[0]);

    // When the prior frame should be presenting to the display
    // If we're predicting at the start of the frame, we use last frame's expected present time
    // If we're predicting at the end of the frame, the present fence time is already known
    nsecs_t lastFramePresentTime = (earlyHint ? mExpectedPresentTimes[-1] : mLastPresentFenceTime);

    // The timing info for the previously calculated display, if there was one
    std::optional<DisplayTimeline> previousDisplayReferenceTiming;
    std::vector<DisplayId>&& displayIds =
            getOrderedDisplayIds(&DisplayTimingData::hwcPresentStartTime);
    DisplayTimeline referenceTiming, estimatedTiming;

    // Iterate over the displays that use hwc in the same order they are presented
    for (DisplayId displayId : displayIds) {
        if (mDisplayTimingData.count(displayId) == 0) {
            continue;
        }

        auto& displayData = mDisplayTimingData.at(displayId);

        // mLastPresentFenceTime should always be the time of the reference frame, since it will be
        // the previous frame's present fence if called at the start, and current frame's if called
        // at the end
        referenceTiming = displayData.calculateDisplayTimeline(mLastPresentFenceTime);

        // If this is the first display, include the duration before hwc present starts
        if (!previousDisplayReferenceTiming.has_value()) {
            estimatedEndTime += referenceTiming.hwcPresentStartTime - referenceFrameStartTime;
        } else { // Otherwise add the time since last display's hwc present finished
            estimatedEndTime += referenceTiming.hwcPresentStartTime -
                    previousDisplayReferenceTiming->hwcPresentEndTime;
        }

        // Late hint can re-use reference timing here since it's estimating its own reference frame
        estimatedTiming = earlyHint
                ? referenceTiming.estimateTimelineFromReference(lastFramePresentTime,
                                                                estimatedEndTime)
                : referenceTiming;

        // Update predicted present finish time with this display's present time
        estimatedEndTime = estimatedTiming.hwcPresentEndTime;

        // Track how long we spent waiting for the fence, can be excluded from the timing estimate
        idleDuration += estimatedTiming.probablyWaitsForPresentFence
                ? lastFramePresentTime - estimatedTiming.presentFenceWaitStartTime
                : 0;

        // Track how long we spent waiting to present, can be excluded from the timing estimate
        idleDuration += earlyHint ? 0 : referenceTiming.hwcPresentDelayDuration;

        // Estimate the reference frame's gpu timing
        auto gpuTiming = displayData.estimateGpuTiming(previousValidGpuEndTime);
        if (gpuTiming.has_value()) {
            previousValidGpuEndTime = gpuTiming->startTime + gpuTiming->duration;

            // Estimate the prediction frame's gpu end time from the reference frame
            estimatedGpuEndTime =
                    std::max(estimatedTiming.hwcPresentStartTime, estimatedGpuEndTime.value_or(0)) +
                    gpuTiming->duration;
        }
        previousDisplayReferenceTiming = referenceTiming;
    }
    ATRACE_INT64("Idle duration", idleDuration);

    nsecs_t estimatedFlingerEndTime = earlyHint ? estimatedEndTime : mLastSfPresentEndTime;

    // Don't count time spent idly waiting in the estimate as we could do more work in that time
    estimatedEndTime -= idleDuration;
    estimatedFlingerEndTime -= idleDuration;

    // We finish the frame when both present and the gpu are done, so wait for the later of the two
    // Also add the frame delay duration since the target did not move while we were delayed
    nsecs_t totalDuration = mFrameDelayDuration +
            std::max(estimatedEndTime, estimatedGpuEndTime.value_or(0)) - mCommitStartTimes[0];

    // We finish SurfaceFlinger when post-composition finishes, so add that in here
    nsecs_t flingerDuration =
            estimatedFlingerEndTime + mLastPostcompDuration - mCommitStartTimes[0];

    // Combine the two timings into a single normalized one
    nsecs_t combinedDuration = combineTimingEstimates(totalDuration, flingerDuration);

    return std::make_optional(combinedDuration);
}

nsecs_t PowerAdvisor::combineTimingEstimates(nsecs_t totalDuration, nsecs_t flingerDuration) {
    nsecs_t targetDuration;
    {
        std::lock_guard lock(mPowerHalMutex);
        targetDuration = *getPowerHal()->getTargetWorkDuration();
    }
    if (!mTotalFrameTargetDuration.has_value()) return flingerDuration;

    // Normalize total to the flinger target (vsync period) since that's how often we actually send
    // hints
    nsecs_t normalizedTotalDuration = (targetDuration * totalDuration) / *mTotalFrameTargetDuration;
    return std::max(flingerDuration, normalizedTotalDuration);
}

PowerAdvisor::DisplayTimeline PowerAdvisor::DisplayTimeline::estimateTimelineFromReference(
        nsecs_t fenceTime, nsecs_t displayStartTime) {
    DisplayTimeline estimated;
    estimated.hwcPresentStartTime = displayStartTime;

    // We don't predict waiting for vsync alignment yet
    estimated.hwcPresentDelayDuration = 0;

    // How long we expect to run before we start waiting for the fence
    // For now just re-use last frame's post-present duration and assume it will not change much
    // Excludes time spent waiting for vsync since that's not going to be consistent
    estimated.presentFenceWaitStartTime = estimated.hwcPresentStartTime +
            (presentFenceWaitStartTime - (hwcPresentStartTime + hwcPresentDelayDuration));
    estimated.probablyWaitsForPresentFence = fenceTime > estimated.presentFenceWaitStartTime;
    estimated.hwcPresentEndTime = postPresentFenceHwcPresentDuration +
            (estimated.probablyWaitsForPresentFence ? fenceTime
                                                    : estimated.presentFenceWaitStartTime);
    return estimated;
}

PowerAdvisor::DisplayTimeline PowerAdvisor::DisplayTimingData::calculateDisplayTimeline(
        nsecs_t fenceTime) {
    DisplayTimeline timeline;
    // How long between calling hwc present and trying to wait on the fence
    const nsecs_t fenceWaitStartDelay =
            (skippedValidate ? kFenceWaitStartDelaySkippedValidate : kFenceWaitStartDelayValidated)
                    .count();

    // Did our reference frame wait for an appropriate vsync before calling into hwc
    const bool waitedOnHwcPresentTime = hwcPresentDelayedTime.has_value() &&
            *hwcPresentDelayedTime > *hwcPresentStartTime &&
            *hwcPresentDelayedTime < *hwcPresentEndTime;

    // Use validate start here if we skipped it because we did validate + present together
    timeline.hwcPresentStartTime = skippedValidate ? *hwcValidateStartTime : *hwcPresentStartTime;

    // Use validate end here if we skipped it because we did validate + present together
    timeline.hwcPresentEndTime = skippedValidate ? *hwcValidateEndTime : *hwcPresentEndTime;

    // How long hwc present was delayed waiting for the next appropriate vsync
    timeline.hwcPresentDelayDuration =
            (waitedOnHwcPresentTime ? *hwcPresentDelayedTime - *hwcPresentStartTime : 0);
    // When we started waiting for the present fence after calling into hwc present
    timeline.presentFenceWaitStartTime =
            timeline.hwcPresentStartTime + timeline.hwcPresentDelayDuration + fenceWaitStartDelay;
    timeline.probablyWaitsForPresentFence = fenceTime > timeline.presentFenceWaitStartTime &&
            fenceTime < timeline.hwcPresentEndTime;

    // How long we ran after we finished waiting for the fence but before hwc present finished
    timeline.postPresentFenceHwcPresentDuration = timeline.hwcPresentEndTime -
            (timeline.probablyWaitsForPresentFence ? fenceTime
                                                   : timeline.presentFenceWaitStartTime);
    return timeline;
}

std::optional<PowerAdvisor::GpuTimeline> PowerAdvisor::DisplayTimingData::estimateGpuTiming(
        std::optional<nsecs_t> previousEnd) {
    if (!(usedClientComposition && lastValidGpuStartTime.has_value() && gpuEndFenceTime)) {
        return std::nullopt;
    }
    const nsecs_t latestGpuStartTime = std::max(previousEnd.value_or(0), *gpuStartTime);
    const nsecs_t latestGpuEndTime = gpuEndFenceTime->getSignalTime();
    nsecs_t gpuDuration = 0;
    if (latestGpuEndTime != Fence::SIGNAL_TIME_INVALID &&
        latestGpuEndTime != Fence::SIGNAL_TIME_PENDING) {
        // If we know how long the most recent gpu duration was, use that
        gpuDuration = latestGpuEndTime - latestGpuStartTime;
    } else if (lastValidGpuEndTime.has_value()) {
        // If we don't have the fence data, use the most recent information we do have
        gpuDuration = *lastValidGpuEndTime - *lastValidGpuStartTime;
        if (latestGpuEndTime == Fence::SIGNAL_TIME_PENDING) {
            // If pending but went over the previous duration, use current time as the end
            gpuDuration = std::max(gpuDuration, systemTime() - latestGpuStartTime);
        }
    }
    return GpuTimeline{.duration = gpuDuration, .startTime = latestGpuStartTime};
}

class HidlPowerHalWrapper : public PowerAdvisor::HalWrapper {
public:
    HidlPowerHalWrapper(sp<V1_3::IPower> powerHal) : mPowerHal(std::move(powerHal)) {}

    ~HidlPowerHalWrapper() override = default;

    static std::unique_ptr<HalWrapper> connect() {
        // Power HAL 1.3 is not guaranteed to be available, thus we need to query
        // Power HAL 1.0 first and try to cast it to Power HAL 1.3.
        sp<V1_3::IPower> powerHal = nullptr;
        sp<V1_0::IPower> powerHal_1_0 = V1_0::IPower::getService();
        if (powerHal_1_0 != nullptr) {
            // Try to cast to Power HAL 1.3
            powerHal = V1_3::IPower::castFrom(powerHal_1_0);
            if (powerHal == nullptr) {
                ALOGW("No Power HAL 1.3 service in system, disabling PowerAdvisor");
            } else {
                ALOGI("Loaded Power HAL 1.3 service");
            }
        } else {
            ALOGW("No Power HAL found, disabling PowerAdvisor");
        }

        if (powerHal == nullptr) {
            return nullptr;
        }

        return std::make_unique<HidlPowerHalWrapper>(std::move(powerHal));
    }

    bool setExpensiveRendering(bool enabled) override {
        ALOGV("HIDL setExpensiveRendering %s", enabled ? "T" : "F");
        auto ret = mPowerHal->powerHintAsync_1_3(PowerHint::EXPENSIVE_RENDERING, enabled);
        if (ret.isOk()) {
            traceExpensiveRendering(enabled);
        }
        return ret.isOk();
    }

    bool notifyDisplayUpdateImminent() override {
        // Power HAL 1.x doesn't have a notification for this
        ALOGV("HIDL notifyUpdateImminent received but can't send");
        return true;
    }

    bool supportsPowerHintSession() override { return false; }

    bool isPowerHintSessionRunning() override { return false; }

    void restartPowerHintSession() override {}

    void setPowerHintSessionThreadIds(const std::vector<int32_t>&) override {}

    bool startPowerHintSession() override { return false; }

    void setTargetWorkDuration(int64_t) override {}

    void sendActualWorkDuration(int64_t, nsecs_t) override {}

    bool shouldReconnectHAL() override { return false; }

    std::vector<int32_t> getPowerHintSessionThreadIds() override { return std::vector<int32_t>{}; }

    std::optional<int64_t> getTargetWorkDuration() override { return std::nullopt; }

private:
    const sp<V1_3::IPower> mPowerHal = nullptr;
};

AidlPowerHalWrapper::AidlPowerHalWrapper(sp<IPower> powerHal) : mPowerHal(std::move(powerHal)) {
    auto ret = mPowerHal->isModeSupported(Mode::EXPENSIVE_RENDERING, &mHasExpensiveRendering);
    if (!ret.isOk()) {
        mHasExpensiveRendering = false;
    }

    ret = mPowerHal->isBoostSupported(Boost::DISPLAY_UPDATE_IMMINENT, &mHasDisplayUpdateImminent);
    if (!ret.isOk()) {
        mHasDisplayUpdateImminent = false;
    }

    mSupportsPowerHint = checkPowerHintSessionSupported();

    // Currently set to 0 to disable rate limiter by default
    mAllowedActualDeviation = base::GetIntProperty<nsecs_t>("debug.sf.allowed_actual_deviation", 0);
}

AidlPowerHalWrapper::~AidlPowerHalWrapper() {
    if (mPowerHintSession != nullptr) {
        mPowerHintSession->close();
        mPowerHintSession = nullptr;
    }
}

std::unique_ptr<PowerAdvisor::HalWrapper> AidlPowerHalWrapper::connect() {
    // This only waits if the service is actually declared
    sp<IPower> powerHal = waitForVintfService<IPower>();
    if (powerHal == nullptr) {
        return nullptr;
    }
    ALOGI("Loaded AIDL Power HAL service");

    return std::make_unique<AidlPowerHalWrapper>(std::move(powerHal));
}

bool AidlPowerHalWrapper::setExpensiveRendering(bool enabled) {
    ALOGV("AIDL setExpensiveRendering %s", enabled ? "T" : "F");
    if (!mHasExpensiveRendering) {
        ALOGV("Skipped sending EXPENSIVE_RENDERING because HAL doesn't support it");
        return true;
    }

    auto ret = mPowerHal->setMode(Mode::EXPENSIVE_RENDERING, enabled);
    if (ret.isOk()) {
        traceExpensiveRendering(enabled);
    }
    return ret.isOk();
}

bool AidlPowerHalWrapper::notifyDisplayUpdateImminent() {
    ALOGV("AIDL notifyDisplayUpdateImminent");
    if (!mHasDisplayUpdateImminent) {
        ALOGV("Skipped sending DISPLAY_UPDATE_IMMINENT because HAL doesn't support it");
        return true;
    }

    auto ret = mPowerHal->setBoost(Boost::DISPLAY_UPDATE_IMMINENT, 0);
    return ret.isOk();
}

// Only version 2+ of the aidl supports power hint sessions, hidl has no support
bool AidlPowerHalWrapper::supportsPowerHintSession() {
    return mSupportsPowerHint;
}

bool AidlPowerHalWrapper::checkPowerHintSessionSupported() {
    int64_t unused;
    // Try to get preferred rate to determine if hint sessions are supported
    // We check for isOk not EX_UNSUPPORTED_OPERATION to lump together errors
    return mPowerHal->getHintSessionPreferredRate(&unused).isOk();
}

bool AidlPowerHalWrapper::isPowerHintSessionRunning() {
    return mPowerHintSession != nullptr;
}

void AidlPowerHalWrapper::closePowerHintSession() {
    if (mPowerHintSession != nullptr) {
        mPowerHintSession->close();
        mPowerHintSession = nullptr;
    }
}

void AidlPowerHalWrapper::restartPowerHintSession() {
    closePowerHintSession();
    startPowerHintSession();
}

void AidlPowerHalWrapper::setPowerHintSessionThreadIds(const std::vector<int32_t>& threadIds) {
    if (threadIds != mPowerHintThreadIds) {
        mPowerHintThreadIds = threadIds;
        if (isPowerHintSessionRunning()) {
            restartPowerHintSession();
        }
    }
}

bool AidlPowerHalWrapper::startPowerHintSession() {
    if (mPowerHintSession != nullptr || mPowerHintThreadIds.empty()) {
        ALOGV("Cannot start power hint session, skipping");
        return false;
    }
    auto ret =
            mPowerHal->createHintSession(getpid(), static_cast<int32_t>(getuid()),
                                         mPowerHintThreadIds, mTargetDuration, &mPowerHintSession);
    if (!ret.isOk()) {
        ALOGW("Failed to start power hint session with error: %s",
              ret.exceptionToString(ret.exceptionCode()).c_str());
    } else {
        mLastTargetDurationSent = mTargetDuration;
    }
    return isPowerHintSessionRunning();
}

void AidlPowerHalWrapper::setTargetWorkDuration(int64_t targetDuration) {
    ATRACE_CALL();
    mTargetDuration = targetDuration;
    if (sTraceHintSessionData) ATRACE_INT64("Time target", targetDuration);
    if (isPowerHintSessionRunning() && (targetDuration != mLastTargetDurationSent)) {
        ALOGV("Sending target time: %" PRId64 "ns", targetDuration);
        mLastTargetDurationSent = targetDuration;
        auto ret = mPowerHintSession->updateTargetWorkDuration(targetDuration);
        if (!ret.isOk()) {
            ALOGW("Failed to set power hint target work duration with error: %s",
                  ret.exceptionMessage().c_str());
            mShouldReconnectHal = true;
        }
    }
}

bool AidlPowerHalWrapper::shouldReportActualDurations() {
    // Report if we have never reported before or are approaching a stale session
    if (!mLastActualDurationSent.has_value() ||
        (systemTime() - mLastActualReportTimestamp) > kStaleTimeout.count()) {
        return true;
    }

    if (!mActualDuration.has_value()) {
        return false;
    }
    // Report if the change in actual duration exceeds the threshold
    return abs(*mActualDuration - *mLastActualDurationSent) > mAllowedActualDeviation;
}

void AidlPowerHalWrapper::sendActualWorkDuration(int64_t actualDuration, nsecs_t timestamp) {
    ATRACE_CALL();

    if (actualDuration < 0 || !isPowerHintSessionRunning()) {
        ALOGV("Failed to send actual work duration, skipping");
        return;
    }
    const nsecs_t reportedDuration = actualDuration;

    mActualDuration = reportedDuration;
    WorkDuration duration;
    duration.durationNanos = reportedDuration;
    duration.timeStampNanos = timestamp;
    mPowerHintQueue.push_back(duration);

    if (sTraceHintSessionData) {
        ATRACE_INT64("Measured duration", actualDuration);
        ATRACE_INT64("Target error term", actualDuration - mTargetDuration);

        ATRACE_INT64("Reported duration", reportedDuration);
        ATRACE_INT64("Reported target", mLastTargetDurationSent);
        ATRACE_INT64("Reported target error term", reportedDuration - mLastTargetDurationSent);
    }

    ALOGV("Sending actual work duration of: %" PRId64 " on reported target: %" PRId64
          " with error: %" PRId64,
          reportedDuration, mLastTargetDurationSent, reportedDuration - mLastTargetDurationSent);

    // This rate limiter queues similar duration reports to the powerhal into
    // batches to avoid excessive binder calls. The criteria to send a given batch
    // are outlined in shouldReportActualDurationsNow()
    if (shouldReportActualDurations()) {
        ALOGV("Sending hint update batch");
        mLastActualReportTimestamp = systemTime();
        auto ret = mPowerHintSession->reportActualWorkDuration(mPowerHintQueue);
        if (!ret.isOk()) {
            ALOGW("Failed to report actual work durations with error: %s",
                  ret.exceptionMessage().c_str());
            mShouldReconnectHal = true;
        }
        mPowerHintQueue.clear();
        // We save the actual duration here for rate limiting
        mLastActualDurationSent = actualDuration;
    }
}

bool AidlPowerHalWrapper::shouldReconnectHAL() {
    return mShouldReconnectHal;
}

std::vector<int32_t> AidlPowerHalWrapper::getPowerHintSessionThreadIds() {
    return mPowerHintThreadIds;
}

std::optional<int64_t> AidlPowerHalWrapper::getTargetWorkDuration() {
    return mTargetDuration;
}

void AidlPowerHalWrapper::setAllowedActualDeviation(nsecs_t allowedDeviation) {
    mAllowedActualDeviation = allowedDeviation;
}

const bool AidlPowerHalWrapper::sTraceHintSessionData =
        base::GetBoolProperty(std::string("debug.sf.trace_hint_sessions"), false);

PowerAdvisor::HalWrapper* PowerAdvisor::getPowerHal() {
    if (!mHasHal) {
        return nullptr;
    }

    // Grab old hint session values before we destroy any existing wrapper
    std::vector<int32_t> oldPowerHintSessionThreadIds;
    std::optional<int64_t> oldTargetWorkDuration;

    if (mHalWrapper != nullptr) {
        oldPowerHintSessionThreadIds = mHalWrapper->getPowerHintSessionThreadIds();
        oldTargetWorkDuration = mHalWrapper->getTargetWorkDuration();
    }

    // If we used to have a HAL, but it stopped responding, attempt to reconnect
    if (mReconnectPowerHal) {
        mHalWrapper = nullptr;
        mReconnectPowerHal = false;
    }

    if (mHalWrapper != nullptr) {
        auto wrapper = mHalWrapper.get();
        // If the wrapper is fine, return it, but if it indicates a reconnect, remake it
        if (!wrapper->shouldReconnectHAL()) {
            return wrapper;
        }
        ALOGD("Reconnecting Power HAL");
        mHalWrapper = nullptr;
    }

    // At this point, we know for sure there is no running session
    mPowerHintSessionRunning = false;

    // First attempt to connect to the AIDL Power HAL
    mHalWrapper = AidlPowerHalWrapper::connect();

    // If that didn't succeed, attempt to connect to the HIDL Power HAL
    if (mHalWrapper == nullptr) {
        mHalWrapper = HidlPowerHalWrapper::connect();
    } else {
        ALOGD("Successfully connecting AIDL Power HAL");
        // If AIDL, pass on any existing hint session values
        mHalWrapper->setPowerHintSessionThreadIds(oldPowerHintSessionThreadIds);
        // Only set duration and start if duration is defined
        if (oldTargetWorkDuration.has_value()) {
            mHalWrapper->setTargetWorkDuration(*oldTargetWorkDuration);
            // Only start if possible to run and both threadids and duration are defined
            if (usePowerHintSession() && !oldPowerHintSessionThreadIds.empty()) {
                mPowerHintSessionRunning = mHalWrapper->startPowerHintSession();
            }
        }
    }

    // If we make it to this point and still don't have a HAL, it's unlikely we
    // will, so stop trying
    if (mHalWrapper == nullptr) {
        mHasHal = false;
    }

    return mHalWrapper.get();
}

} // namespace impl
} // namespace Hwc2
} // namespace android
