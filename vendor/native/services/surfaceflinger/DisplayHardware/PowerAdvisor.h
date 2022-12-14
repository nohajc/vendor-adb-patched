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

#pragma once

#include <atomic>
#include <chrono>
#include <unordered_map>
#include <unordered_set>

#include <ui/DisplayId.h>
#include <ui/FenceTime.h>
#include <utils/Mutex.h>

#include <android/hardware/power/IPower.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <ui/DisplayIdentification.h>
#include "../Scheduler/OneShotTimer.h"

using namespace std::chrono_literals;

namespace android {

class SurfaceFlinger;

namespace Hwc2 {

class PowerAdvisor {
public:
    virtual ~PowerAdvisor();

    // Initializes resources that cannot be initialized on construction
    virtual void init() = 0;
    virtual void onBootFinished() = 0;
    virtual void setExpensiveRenderingExpected(DisplayId displayId, bool expected) = 0;
    virtual bool isUsingExpensiveRendering() = 0;
    virtual void notifyDisplayUpdateImminent() = 0;
    // Checks both if it supports and if it's enabled
    virtual bool usePowerHintSession() = 0;
    virtual bool supportsPowerHintSession() = 0;
    virtual bool isPowerHintSessionRunning() = 0;
    // Sends a power hint that updates to the target work duration for the frame
    virtual void setTargetWorkDuration(nsecs_t targetDuration) = 0;
    // Sends a power hint for the actual known work duration at the end of the frame
    virtual void sendActualWorkDuration() = 0;
    // Sends a power hint for the upcoming frame predicted from previous frame timing
    virtual void sendPredictedWorkDuration() = 0;
    // Sets whether the power hint session is enabled
    virtual void enablePowerHint(bool enabled) = 0;
    // Initializes the power hint session
    virtual bool startPowerHintSession(const std::vector<int32_t>& threadIds) = 0;
    // Provides PowerAdvisor with a copy of the gpu fence so it can determine the gpu end time
    virtual void setGpuFenceTime(DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime) = 0;
    // Reports the start and end times of a hwc validate call this frame for a given display
    virtual void setHwcValidateTiming(DisplayId displayId, nsecs_t validateStartTime,
                                      nsecs_t validateEndTime) = 0;
    // Reports the start and end times of a hwc present call this frame for a given display
    virtual void setHwcPresentTiming(DisplayId displayId, nsecs_t presentStartTime,
                                     nsecs_t presentEndTime) = 0;
    // Reports the expected time that the current frame will present to the display
    virtual void setExpectedPresentTime(nsecs_t expectedPresentTime) = 0;
    // Reports the most recent present fence time and end time once known
    virtual void setSfPresentTiming(nsecs_t presentFenceTime, nsecs_t presentEndTime) = 0;
    // Reports whether a display used client composition this frame
    virtual void setRequiresClientComposition(DisplayId displayId,
                                              bool requiresClientComposition) = 0;
    // Reports whether a given display skipped validation this frame
    virtual void setSkippedValidate(DisplayId displayId, bool skipped) = 0;
    // Reports when a hwc present is delayed, and the time that it will resume
    virtual void setHwcPresentDelayedTime(
            DisplayId displayId, std::chrono::steady_clock::time_point earliestFrameStartTime) = 0;
    // Reports the start delay for SurfaceFlinger this frame
    virtual void setFrameDelay(nsecs_t frameDelayDuration) = 0;
    // Reports the SurfaceFlinger commit start time this frame
    virtual void setCommitStart(nsecs_t commitStartTime) = 0;
    // Reports the SurfaceFlinger composite end time this frame
    virtual void setCompositeEnd(nsecs_t compositeEndTime) = 0;
    // Reports the list of the currently active displays
    virtual void setDisplays(std::vector<DisplayId>& displayIds) = 0;
    // Sets the target duration for the entire pipeline including the gpu
    virtual void setTotalFrameTargetWorkDuration(nsecs_t targetDuration) = 0;
};

namespace impl {

// PowerAdvisor is a wrapper around IPower HAL which takes into account the
// full state of the system when sending out power hints to things like the GPU.
class PowerAdvisor final : public Hwc2::PowerAdvisor {
public:
    class HalWrapper {
    public:
        virtual ~HalWrapper() = default;

        virtual bool setExpensiveRendering(bool enabled) = 0;
        virtual bool notifyDisplayUpdateImminent() = 0;
        virtual bool supportsPowerHintSession() = 0;
        virtual bool isPowerHintSessionRunning() = 0;
        virtual void restartPowerHintSession() = 0;
        virtual void setPowerHintSessionThreadIds(const std::vector<int32_t>& threadIds) = 0;
        virtual bool startPowerHintSession() = 0;
        virtual void setTargetWorkDuration(nsecs_t targetDuration) = 0;
        virtual void sendActualWorkDuration(nsecs_t actualDuration, nsecs_t timestamp) = 0;
        virtual bool shouldReconnectHAL() = 0;
        virtual std::vector<int32_t> getPowerHintSessionThreadIds() = 0;
        virtual std::optional<nsecs_t> getTargetWorkDuration() = 0;
    };

    PowerAdvisor(SurfaceFlinger& flinger);
    ~PowerAdvisor() override;

    void init() override;
    void onBootFinished() override;
    void setExpensiveRenderingExpected(DisplayId displayId, bool expected) override;
    bool isUsingExpensiveRendering() override { return mNotifiedExpensiveRendering; };
    void notifyDisplayUpdateImminent() override;
    bool usePowerHintSession() override;
    bool supportsPowerHintSession() override;
    bool isPowerHintSessionRunning() override;
    void setTargetWorkDuration(nsecs_t targetDuration) override;
    void sendActualWorkDuration() override;
    void sendPredictedWorkDuration() override;
    void enablePowerHint(bool enabled) override;
    bool startPowerHintSession(const std::vector<int32_t>& threadIds) override;
    void setGpuFenceTime(DisplayId displayId, std::unique_ptr<FenceTime>&& fenceTime);
    void setHwcValidateTiming(DisplayId displayId, nsecs_t valiateStartTime,
                              nsecs_t validateEndTime) override;
    void setHwcPresentTiming(DisplayId displayId, nsecs_t presentStartTime,
                             nsecs_t presentEndTime) override;
    void setSkippedValidate(DisplayId displayId, bool skipped) override;
    void setRequiresClientComposition(DisplayId displayId, bool requiresClientComposition) override;
    void setExpectedPresentTime(nsecs_t expectedPresentTime) override;
    void setSfPresentTiming(nsecs_t presentFenceTime, nsecs_t presentEndTime) override;
    void setHwcPresentDelayedTime(
            DisplayId displayId,
            std::chrono::steady_clock::time_point earliestFrameStartTime) override;

    void setFrameDelay(nsecs_t frameDelayDuration) override;
    void setCommitStart(nsecs_t commitStartTime) override;
    void setCompositeEnd(nsecs_t compositeEndTime) override;
    void setDisplays(std::vector<DisplayId>& displayIds) override;
    void setTotalFrameTargetWorkDuration(nsecs_t targetDuration) override;

private:
    friend class PowerAdvisorTest;

    // Tracks if powerhal exists
    bool mHasHal = true;
    // Holds the hal wrapper for getPowerHal
    std::unique_ptr<HalWrapper> mHalWrapper GUARDED_BY(mPowerHalMutex) = nullptr;

    HalWrapper* getPowerHal() REQUIRES(mPowerHalMutex);
    bool mReconnectPowerHal GUARDED_BY(mPowerHalMutex) = false;
    std::mutex mPowerHalMutex;

    std::atomic_bool mBootFinished = false;

    std::unordered_set<DisplayId> mExpensiveDisplays;
    bool mNotifiedExpensiveRendering = false;

    SurfaceFlinger& mFlinger;
    std::atomic_bool mSendUpdateImminent = true;
    std::atomic<nsecs_t> mLastScreenUpdatedTime = 0;
    std::optional<scheduler::OneShotTimer> mScreenUpdateTimer;

    // Higher-level timing data used for estimation
    struct DisplayTimeline {
        // The start of hwc present, or the start of validate if it happened there instead
        nsecs_t hwcPresentStartTime = -1;
        // The end of hwc present or validate, whichever one actually presented
        nsecs_t hwcPresentEndTime = -1;
        // How long the actual hwc present was delayed after hwcPresentStartTime
        nsecs_t hwcPresentDelayDuration = 0;
        // When we think we started waiting for the present fence after calling into hwc present and
        // after potentially waiting for the earliest present time
        nsecs_t presentFenceWaitStartTime = -1;
        // How long we ran after we finished waiting for the fence but before hwc present finished
        nsecs_t postPresentFenceHwcPresentDuration = 0;
        // Are we likely to have waited for the present fence during composition
        bool probablyWaitsForPresentFence = false;
        // Estimate one frame's timeline from that of a previous frame
        DisplayTimeline estimateTimelineFromReference(nsecs_t fenceTime, nsecs_t displayStartTime);
    };

    struct GpuTimeline {
        nsecs_t duration = 0;
        nsecs_t startTime = -1;
    };

    // Power hint session data recorded from the pipeline
    struct DisplayTimingData {
        std::unique_ptr<FenceTime> gpuEndFenceTime;
        std::optional<nsecs_t> gpuStartTime;
        std::optional<nsecs_t> lastValidGpuEndTime;
        std::optional<nsecs_t> lastValidGpuStartTime;
        std::optional<nsecs_t> hwcPresentStartTime;
        std::optional<nsecs_t> hwcPresentEndTime;
        std::optional<nsecs_t> hwcValidateStartTime;
        std::optional<nsecs_t> hwcValidateEndTime;
        std::optional<nsecs_t> hwcPresentDelayedTime;
        bool usedClientComposition = false;
        bool skippedValidate = false;
        // Calculate high-level timing milestones from more granular display timing data
        DisplayTimeline calculateDisplayTimeline(nsecs_t fenceTime);
        // Estimate the gpu duration for a given display from previous gpu timing data
        std::optional<GpuTimeline> estimateGpuTiming(std::optional<nsecs_t> previousEnd);
    };

    template <class T, size_t N>
    class RingBuffer {
        std::array<T, N> elements = {};
        size_t mIndex = 0;
        size_t numElements = 0;

    public:
        void append(T item) {
            mIndex = (mIndex + 1) % N;
            numElements = std::min(N, numElements + 1);
            elements[mIndex] = item;
        }
        bool isFull() const { return numElements == N; }
        // Allows access like [0] == current, [-1] = previous, etc..
        T& operator[](int offset) {
            size_t positiveOffset =
                    static_cast<size_t>((offset % static_cast<int>(N)) + static_cast<int>(N));
            return elements[(mIndex + positiveOffset) % N];
        }
    };

    // Filter and sort the display ids by a given property
    std::vector<DisplayId> getOrderedDisplayIds(std::optional<nsecs_t> DisplayTimingData::*sortBy);
    // Estimates a frame's total work duration including gpu time.
    // Runs either at the beginning or end of a frame, using the most recent data available
    std::optional<nsecs_t> estimateWorkDuration(bool earlyHint);
    // There are two different targets and actual work durations we care about,
    // this normalizes them together and takes the max of the two
    nsecs_t combineTimingEstimates(nsecs_t totalDuration, nsecs_t flingerDuration);

    std::unordered_map<DisplayId, DisplayTimingData> mDisplayTimingData;

    // Current frame's delay
    nsecs_t mFrameDelayDuration = 0;
    // Last frame's post-composition duration
    nsecs_t mLastPostcompDuration = 0;
    // Buffer of recent commit start times
    RingBuffer<nsecs_t, 2> mCommitStartTimes;
    // Buffer of recent expected present times
    RingBuffer<nsecs_t, 2> mExpectedPresentTimes;
    // Most recent present fence time, set at the end of the frame once known
    nsecs_t mLastPresentFenceTime = -1;
    // Most recent present fence time, set at the end of the frame once known
    nsecs_t mLastSfPresentEndTime = -1;
    // Target for the entire pipeline including gpu
    std::optional<nsecs_t> mTotalFrameTargetDuration;
    // Updated list of display IDs
    std::vector<DisplayId> mDisplayIds;

    std::optional<bool> mPowerHintEnabled;
    std::optional<bool> mSupportsPowerHint;
    bool mPowerHintSessionRunning = false;

    // An adjustable safety margin which pads the "actual" value sent to PowerHAL,
    // encouraging more aggressive boosting to give SurfaceFlinger a larger margin for error
    static constexpr const std::chrono::nanoseconds kTargetSafetyMargin = 1ms;

    // How long we expect hwc to run after the present call until it waits for the fence
    static constexpr const std::chrono::nanoseconds kFenceWaitStartDelayValidated = 150us;
    static constexpr const std::chrono::nanoseconds kFenceWaitStartDelaySkippedValidate = 250us;
};

class AidlPowerHalWrapper : public PowerAdvisor::HalWrapper {
public:
    explicit AidlPowerHalWrapper(sp<hardware::power::IPower> powerHal);
    ~AidlPowerHalWrapper() override;

    static std::unique_ptr<HalWrapper> connect();

    bool setExpensiveRendering(bool enabled) override;
    bool notifyDisplayUpdateImminent() override;
    bool supportsPowerHintSession() override;
    bool isPowerHintSessionRunning() override;
    void restartPowerHintSession() override;
    void setPowerHintSessionThreadIds(const std::vector<int32_t>& threadIds) override;
    bool startPowerHintSession() override;
    void setTargetWorkDuration(nsecs_t targetDuration) override;
    void sendActualWorkDuration(nsecs_t actualDuration, nsecs_t timestamp) override;
    bool shouldReconnectHAL() override;
    std::vector<int32_t> getPowerHintSessionThreadIds() override;
    std::optional<nsecs_t> getTargetWorkDuration() override;

private:
    friend class AidlPowerHalWrapperTest;

    bool checkPowerHintSessionSupported();
    void closePowerHintSession();
    bool shouldReportActualDurations();

    // Used for testing
    void setAllowedActualDeviation(nsecs_t);

    const sp<hardware::power::IPower> mPowerHal = nullptr;
    bool mHasExpensiveRendering = false;
    bool mHasDisplayUpdateImminent = false;
    // Used to indicate an error state and need for reconstruction
    bool mShouldReconnectHal = false;

    // Power hint session data

    // Concurrent access for this is protected by mPowerHalMutex
    sp<hardware::power::IPowerHintSession> mPowerHintSession = nullptr;
    // Queue of actual durations saved to report
    std::vector<hardware::power::WorkDuration> mPowerHintQueue;
    // The latest values we have received for target and actual
    nsecs_t mTargetDuration = kDefaultTarget.count();
    std::optional<nsecs_t> mActualDuration;
    // The list of thread ids, stored so we can restart the session from this class if needed
    std::vector<int32_t> mPowerHintThreadIds;
    bool mSupportsPowerHint = false;
    // Keep track of the last messages sent for rate limiter change detection
    std::optional<nsecs_t> mLastActualDurationSent;
    // Timestamp of the last report we sent, used to avoid stale sessions
    nsecs_t mLastActualReportTimestamp = 0;
    nsecs_t mLastTargetDurationSent = kDefaultTarget.count();
    // Max amount the error term can vary without causing an actual value report
    nsecs_t mAllowedActualDeviation = -1;
    // Whether we should emit ATRACE_INT data for hint sessions
    static const bool sTraceHintSessionData;
    static constexpr const std::chrono::nanoseconds kDefaultTarget = 16ms;
    // Amount of time after the last message was sent before the session goes stale
    // actually 100ms but we use 80 here to ideally avoid going stale
    static constexpr const std::chrono::nanoseconds kStaleTimeout = 80ms;
};

} // namespace impl
} // namespace Hwc2
} // namespace android
