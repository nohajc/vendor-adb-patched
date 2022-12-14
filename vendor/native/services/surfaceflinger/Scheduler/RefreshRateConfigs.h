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

#include <android-base/stringprintf.h>
#include <gui/DisplayEventReceiver.h>

#include <algorithm>
#include <numeric>
#include <optional>
#include <type_traits>

#include "DisplayHardware/DisplayMode.h"
#include "DisplayHardware/HWComposer.h"
#include "Fps.h"
#include "Scheduler/OneShotTimer.h"
#include "Scheduler/SchedulerUtils.h"
#include "Scheduler/Seamlessness.h"
#include "Scheduler/StrongTyping.h"

namespace android::scheduler {

using namespace std::chrono_literals;

enum class RefreshRateConfigEvent : unsigned { None = 0b0, Changed = 0b1 };

inline RefreshRateConfigEvent operator|(RefreshRateConfigEvent lhs, RefreshRateConfigEvent rhs) {
    using T = std::underlying_type_t<RefreshRateConfigEvent>;
    return static_cast<RefreshRateConfigEvent>(static_cast<T>(lhs) | static_cast<T>(rhs));
}

using FrameRateOverride = DisplayEventReceiver::Event::FrameRateOverride;

/**
 * This class is used to encapsulate configuration for refresh rates. It holds information
 * about available refresh rates on the device, and the mapping between the numbers and human
 * readable names.
 */
class RefreshRateConfigs {
public:
    // Margin used when matching refresh rates to the content desired ones.
    static constexpr nsecs_t MARGIN_FOR_PERIOD_CALCULATION =
            std::chrono::nanoseconds(800us).count();

    class RefreshRate {
    private:
        // Effectively making the constructor private while allowing
        // std::make_unique to create the object
        struct ConstructorTag {
            explicit ConstructorTag(int) {}
        };

    public:
        RefreshRate(DisplayModePtr mode, ConstructorTag) : mode(mode) {}

        DisplayModeId getModeId() const { return mode->getId(); }
        nsecs_t getVsyncPeriod() const { return mode->getVsyncPeriod(); }
        int32_t getModeGroup() const { return mode->getGroup(); }
        std::string getName() const { return to_string(getFps()); }
        Fps getFps() const { return mode->getFps(); }
        DisplayModePtr getMode() const { return mode; }

        // Checks whether the fps of this RefreshRate struct is within a given min and max refresh
        // rate passed in. Margin of error is applied to the boundaries for approximation.
        bool inPolicy(Fps minRefreshRate, Fps maxRefreshRate) const {
            return minRefreshRate.lessThanOrEqualWithMargin(getFps()) &&
                    getFps().lessThanOrEqualWithMargin(maxRefreshRate);
        }

        bool operator!=(const RefreshRate& other) const { return mode != other.mode; }

        bool operator<(const RefreshRate& other) const {
            return getFps().getValue() < other.getFps().getValue();
        }

        bool operator==(const RefreshRate& other) const { return !(*this != other); }

        std::string toString() const;
        friend std::ostream& operator<<(std::ostream& os, const RefreshRate& refreshRate) {
            return os << refreshRate.toString();
        }

    private:
        friend RefreshRateConfigs;
        friend class RefreshRateConfigsTest;

        DisplayModePtr mode;
    };

    using AllRefreshRatesMapType =
            std::unordered_map<DisplayModeId, std::unique_ptr<const RefreshRate>>;

    struct FpsRange {
        Fps min{0.0f};
        Fps max{std::numeric_limits<float>::max()};

        bool operator==(const FpsRange& other) const {
            return min.equalsWithMargin(other.min) && max.equalsWithMargin(other.max);
        }

        bool operator!=(const FpsRange& other) const { return !(*this == other); }

        std::string toString() const {
            return base::StringPrintf("[%s %s]", to_string(min).c_str(), to_string(max).c_str());
        }
    };

    struct Policy {
    private:
        static constexpr int kAllowGroupSwitchingDefault = false;

    public:
        // The default mode, used to ensure we only initiate display mode switches within the
        // same mode group as defaultMode's group.
        DisplayModeId defaultMode;
        // Whether or not we switch mode groups to get the best frame rate.
        bool allowGroupSwitching = kAllowGroupSwitchingDefault;
        // The primary refresh rate range represents display manager's general guidance on the
        // display modes we'll consider when switching refresh rates. Unless we get an explicit
        // signal from an app, we should stay within this range.
        FpsRange primaryRange;
        // The app request refresh rate range allows us to consider more display modes when
        // switching refresh rates. Although we should generally stay within the primary range,
        // specific considerations, such as layer frame rate settings specified via the
        // setFrameRate() api, may cause us to go outside the primary range. We never go outside the
        // app request range. The app request range will be greater than or equal to the primary
        // refresh rate range, never smaller.
        FpsRange appRequestRange;

        Policy() = default;

        Policy(DisplayModeId defaultMode, const FpsRange& range)
              : Policy(defaultMode, kAllowGroupSwitchingDefault, range, range) {}

        Policy(DisplayModeId defaultMode, bool allowGroupSwitching, const FpsRange& range)
              : Policy(defaultMode, allowGroupSwitching, range, range) {}

        Policy(DisplayModeId defaultMode, const FpsRange& primaryRange,
               const FpsRange& appRequestRange)
              : Policy(defaultMode, kAllowGroupSwitchingDefault, primaryRange, appRequestRange) {}

        Policy(DisplayModeId defaultMode, bool allowGroupSwitching, const FpsRange& primaryRange,
               const FpsRange& appRequestRange)
              : defaultMode(defaultMode),
                allowGroupSwitching(allowGroupSwitching),
                primaryRange(primaryRange),
                appRequestRange(appRequestRange) {}

        bool operator==(const Policy& other) const {
            return defaultMode == other.defaultMode && primaryRange == other.primaryRange &&
                    appRequestRange == other.appRequestRange &&
                    allowGroupSwitching == other.allowGroupSwitching;
        }

        bool operator!=(const Policy& other) const { return !(*this == other); }
        std::string toString() const;
    };

    // Return code set*Policy() to indicate the current policy is unchanged.
    static constexpr int CURRENT_POLICY_UNCHANGED = 1;

    // We maintain the display manager policy and the override policy separately. The override
    // policy is used by CTS tests to get a consistent device state for testing. While the override
    // policy is set, it takes precedence over the display manager policy. Once the override policy
    // is cleared, we revert to using the display manager policy.

    // Sets the display manager policy to choose refresh rates. The return value will be:
    //   - A negative value if the policy is invalid or another error occurred.
    //   - NO_ERROR if the policy was successfully updated, and the current policy is different from
    //     what it was before the call.
    //   - CURRENT_POLICY_UNCHANGED if the policy was successfully updated, but the current policy
    //     is the same as it was before the call.
    status_t setDisplayManagerPolicy(const Policy& policy) EXCLUDES(mLock);
    // Sets the override policy. See setDisplayManagerPolicy() for the meaning of the return value.
    status_t setOverridePolicy(const std::optional<Policy>& policy) EXCLUDES(mLock);
    // Gets the current policy, which will be the override policy if active, and the display manager
    // policy otherwise.
    Policy getCurrentPolicy() const EXCLUDES(mLock);
    // Gets the display manager policy, regardless of whether an override policy is active.
    Policy getDisplayManagerPolicy() const EXCLUDES(mLock);

    // Returns true if mode is allowed by the current policy.
    bool isModeAllowed(DisplayModeId) const EXCLUDES(mLock);

    // Describes the different options the layer voted for refresh rate
    enum class LayerVoteType {
        NoVote,          // Doesn't care about the refresh rate
        Min,             // Minimal refresh rate available
        Max,             // Maximal refresh rate available
        Heuristic,       // Specific refresh rate that was calculated by platform using a heuristic
        ExplicitDefault, // Specific refresh rate that was provided by the app with Default
                         // compatibility
        ExplicitExactOrMultiple, // Specific refresh rate that was provided by the app with
                                 // ExactOrMultiple compatibility
        ExplicitExact,           // Specific refresh rate that was provided by the app with
                                 // Exact compatibility

    };

    // Captures the layer requirements for a refresh rate. This will be used to determine the
    // display refresh rate.
    struct LayerRequirement {
        // Layer's name. Used for debugging purposes.
        std::string name;
        // Layer's owner uid
        uid_t ownerUid = static_cast<uid_t>(-1);
        // Layer vote type.
        LayerVoteType vote = LayerVoteType::NoVote;
        // Layer's desired refresh rate, if applicable.
        Fps desiredRefreshRate{0.0f};
        // If a seamless mode switch is required.
        Seamlessness seamlessness = Seamlessness::Default;
        // Layer's weight in the range of [0, 1]. The higher the weight the more impact this layer
        // would have on choosing the refresh rate.
        float weight = 0.0f;
        // Whether layer is in focus or not based on WindowManager's state
        bool focused = false;

        bool operator==(const LayerRequirement& other) const {
            return name == other.name && vote == other.vote &&
                    desiredRefreshRate.equalsWithMargin(other.desiredRefreshRate) &&
                    seamlessness == other.seamlessness && weight == other.weight &&
                    focused == other.focused;
        }

        bool operator!=(const LayerRequirement& other) const { return !(*this == other); }
    };

    // Global state describing signals that affect refresh rate choice.
    struct GlobalSignals {
        // Whether the user touched the screen recently. Used to apply touch boost.
        bool touch = false;
        // True if the system hasn't seen any buffers posted to layers recently.
        bool idle = false;

        bool operator==(const GlobalSignals& other) const {
            return touch == other.touch && idle == other.idle;
        }
    };

    // Returns the refresh rate that fits best to the given layers.
    //   layers - The layer requirements to consider.
    //   globalSignals - global state of touch and idle
    //   outSignalsConsidered - An output param that tells the caller whether the refresh rate was
    //                          chosen based on touch boost and/or idle timer.
    RefreshRate getBestRefreshRate(const std::vector<LayerRequirement>& layers,
                                   const GlobalSignals& globalSignals,
                                   GlobalSignals* outSignalsConsidered = nullptr) const
            EXCLUDES(mLock);

    FpsRange getSupportedRefreshRateRange() const EXCLUDES(mLock) {
        std::lock_guard lock(mLock);
        return {mMinSupportedRefreshRate->getFps(), mMaxSupportedRefreshRate->getFps()};
    }

    std::optional<Fps> onKernelTimerChanged(std::optional<DisplayModeId> desiredActiveModeId,
                                            bool timerExpired) const EXCLUDES(mLock);

    // Returns the highest refresh rate according to the current policy. May change at runtime. Only
    // uses the primary range, not the app request range.
    RefreshRate getMaxRefreshRateByPolicy() const EXCLUDES(mLock);

    // Returns the current refresh rate
    RefreshRate getCurrentRefreshRate() const EXCLUDES(mLock);

    // Returns the current refresh rate, if allowed. Otherwise the default that is allowed by
    // the policy.
    RefreshRate getCurrentRefreshRateByPolicy() const;

    // Returns the refresh rate that corresponds to a DisplayModeId. This may change at
    // runtime.
    // TODO(b/159590486) An invalid mode id may be given here if the dipslay modes have changed.
    RefreshRate getRefreshRateFromModeId(DisplayModeId modeId) const EXCLUDES(mLock) {
        std::lock_guard lock(mLock);
        return *mRefreshRates.at(modeId);
    };

    // Stores the current modeId the device operates at
    void setCurrentModeId(DisplayModeId) EXCLUDES(mLock);

    // Returns a string that represents the layer vote type
    static std::string layerVoteTypeString(LayerVoteType vote);

    // Returns a known frame rate that is the closest to frameRate
    Fps findClosestKnownFrameRate(Fps frameRate) const;

    // Configuration flags.
    struct Config {
        bool enableFrameRateOverride = false;

        // Specifies the upper refresh rate threshold (inclusive) for layer vote types of multiple
        // or heuristic, such that refresh rates higher than this value will not be voted for. 0 if
        // no threshold is set.
        int frameRateMultipleThreshold = 0;

        // The Idle Timer timeout. 0 timeout means no idle timer.
        int32_t idleTimerTimeoutMs = 0;

        // Whether to use idle timer callbacks that support the kernel timer.
        bool supportKernelIdleTimer = false;
    };

    RefreshRateConfigs(const DisplayModes&, DisplayModeId,
                       Config config = {.enableFrameRateOverride = false,
                                        .frameRateMultipleThreshold = 0,
                                        .idleTimerTimeoutMs = 0,
                                        .supportKernelIdleTimer = false});

    // Returns whether switching modes (refresh rate or resolution) is possible.
    // TODO(b/158780872): Consider HAL support, and skip frame rate detection if the modes only
    // differ in resolution.
    bool canSwitch() const EXCLUDES(mLock) {
        std::lock_guard lock(mLock);
        return mRefreshRates.size() > 1;
    }

    // Class to enumerate options around toggling the kernel timer on and off.
    enum class KernelIdleTimerAction {
        TurnOff,  // Turn off the idle timer.
        TurnOn    // Turn on the idle timer.
    };
    // Checks whether kernel idle timer should be active depending the policy decisions around
    // refresh rates.
    KernelIdleTimerAction getIdleTimerAction() const;

    bool supportsFrameRateOverride() const { return mSupportsFrameRateOverride; }

    // Return the display refresh rate divider to match the layer
    // frame rate, or 0 if the display refresh rate is not a multiple of the
    // layer refresh rate.
    static int getFrameRateDivider(Fps displayFrameRate, Fps layerFrameRate);

    // Returns if the provided frame rates have a ratio t*1000/1001 or t*1001/1000
    // for an integer t.
    static bool isFractionalPairOrMultiple(Fps, Fps);

    using UidToFrameRateOverride = std::map<uid_t, Fps>;
    // Returns the frame rate override for each uid.
    //
    // @param layers list of visible layers
    // @param displayFrameRate the display frame rate
    // @param touch whether touch timer is active (i.e. user touched the screen recently)
    UidToFrameRateOverride getFrameRateOverrides(const std::vector<LayerRequirement>& layers,
                                                 Fps displayFrameRate, bool touch) const
            EXCLUDES(mLock);

    bool supportsKernelIdleTimer() const { return mConfig.supportKernelIdleTimer; }

    void setIdleTimerCallbacks(std::function<void()> platformTimerReset,
                               std::function<void()> platformTimerExpired,
                               std::function<void()> kernelTimerReset,
                               std::function<void()> kernelTimerExpired) {
        std::scoped_lock lock(mIdleTimerCallbacksMutex);
        mIdleTimerCallbacks.emplace();
        mIdleTimerCallbacks->platform.onReset = std::move(platformTimerReset);
        mIdleTimerCallbacks->platform.onExpired = std::move(platformTimerExpired);
        mIdleTimerCallbacks->kernel.onReset = std::move(kernelTimerReset);
        mIdleTimerCallbacks->kernel.onExpired = std::move(kernelTimerExpired);
    }

    void startIdleTimer() {
        if (mIdleTimer) {
            mIdleTimer->start();
        }
    }

    void stopIdleTimer() {
        if (mIdleTimer) {
            mIdleTimer->stop();
        }
    }

    void resetIdleTimer(bool kernelOnly) {
        if (!mIdleTimer) {
            return;
        }
        if (kernelOnly && !mConfig.supportKernelIdleTimer) {
            return;
        }
        mIdleTimer->reset();
    };

    void dump(std::string& result) const EXCLUDES(mLock);

    RefreshRateConfigs(const RefreshRateConfigs&) = delete;
    void operator=(const RefreshRateConfigs&) = delete;

private:
    friend class RefreshRateConfigsTest;

    void constructAvailableRefreshRates() REQUIRES(mLock);

    void getSortedRefreshRateListLocked(
            const std::function<bool(const RefreshRate&)>& shouldAddRefreshRate,
            std::vector<const RefreshRate*>* outRefreshRates) REQUIRES(mLock);

    std::optional<RefreshRate> getCachedBestRefreshRate(const std::vector<LayerRequirement>& layers,
                                                        const GlobalSignals& globalSignals,
                                                        GlobalSignals* outSignalsConsidered) const
            REQUIRES(mLock);

    RefreshRate getBestRefreshRateLocked(const std::vector<LayerRequirement>& layers,
                                         const GlobalSignals& globalSignals,
                                         GlobalSignals* outSignalsConsidered) const REQUIRES(mLock);

    // Returns the refresh rate with the highest score in the collection specified from begin
    // to end. If there are more than one with the same highest refresh rate, the first one is
    // returned.
    template <typename Iter>
    const RefreshRate* getBestRefreshRate(Iter begin, Iter end) const;

    // Returns number of display frames and remainder when dividing the layer refresh period by
    // display refresh period.
    std::pair<nsecs_t, nsecs_t> getDisplayFrames(nsecs_t layerPeriod, nsecs_t displayPeriod) const;

    // Returns the lowest refresh rate according to the current policy. May change at runtime. Only
    // uses the primary range, not the app request range.
    const RefreshRate& getMinRefreshRateByPolicyLocked() const REQUIRES(mLock);

    // Returns the highest refresh rate according to the current policy. May change at runtime. Only
    // uses the primary range, not the app request range.
    const RefreshRate& getMaxRefreshRateByPolicyLocked() const REQUIRES(mLock);

    // Returns the current refresh rate, if allowed. Otherwise the default that is allowed by
    // the policy.
    const RefreshRate& getCurrentRefreshRateByPolicyLocked() const REQUIRES(mLock);

    const Policy* getCurrentPolicyLocked() const REQUIRES(mLock);
    bool isPolicyValidLocked(const Policy& policy) const REQUIRES(mLock);

    // Returns whether the layer is allowed to vote for the given refresh rate.
    bool isVoteAllowed(const LayerRequirement&, const RefreshRate&) const;

    // calculates a score for a layer. Used to determine the display refresh rate
    // and the frame rate override for certains applications.
    float calculateLayerScoreLocked(const LayerRequirement&, const RefreshRate&,
                                    bool isSeamlessSwitch) const REQUIRES(mLock);

    float calculateNonExactMatchingLayerScoreLocked(const LayerRequirement&,
                                                    const RefreshRate&) const REQUIRES(mLock);

    void updateDisplayModes(const DisplayModes& mode, DisplayModeId currentModeId) EXCLUDES(mLock);

    void initializeIdleTimer();

    // The list of refresh rates, indexed by display modes ID. This may change after this
    // object is initialized.
    AllRefreshRatesMapType mRefreshRates GUARDED_BY(mLock);

    // The list of refresh rates in the primary range of the current policy, ordered by vsyncPeriod
    // (the first element is the lowest refresh rate).
    std::vector<const RefreshRate*> mPrimaryRefreshRates GUARDED_BY(mLock);

    // The list of refresh rates in the app request range of the current policy, ordered by
    // vsyncPeriod (the first element is the lowest refresh rate).
    std::vector<const RefreshRate*> mAppRequestRefreshRates GUARDED_BY(mLock);

    // The current display mode. This will change at runtime. This is set by SurfaceFlinger on
    // the main thread, and read by the Scheduler (and other objects) on other threads.
    const RefreshRate* mCurrentRefreshRate GUARDED_BY(mLock);

    // The policy values will change at runtime. They're set by SurfaceFlinger on the main thread,
    // and read by the Scheduler (and other objects) on other threads.
    Policy mDisplayManagerPolicy GUARDED_BY(mLock);
    std::optional<Policy> mOverridePolicy GUARDED_BY(mLock);

    // The min and max refresh rates supported by the device.
    // This may change at runtime.
    const RefreshRate* mMinSupportedRefreshRate GUARDED_BY(mLock);
    const RefreshRate* mMaxSupportedRefreshRate GUARDED_BY(mLock);

    mutable std::mutex mLock;

    // A sorted list of known frame rates that a Heuristic layer will choose
    // from based on the closest value.
    const std::vector<Fps> mKnownFrameRates;

    const Config mConfig;
    bool mSupportsFrameRateOverride;

    struct GetBestRefreshRateInvocation {
        std::vector<LayerRequirement> layerRequirements;
        GlobalSignals globalSignals;
        GlobalSignals outSignalsConsidered;
        RefreshRate resultingBestRefreshRate;
    };
    mutable std::optional<GetBestRefreshRateInvocation> lastBestRefreshRateInvocation
            GUARDED_BY(mLock);

    // Timer that records time between requests for next vsync.
    std::optional<scheduler::OneShotTimer> mIdleTimer;

    struct IdleTimerCallbacks {
        struct Callbacks {
            std::function<void()> onReset;
            std::function<void()> onExpired;
        };

        Callbacks platform;
        Callbacks kernel;
    };

    std::mutex mIdleTimerCallbacksMutex;
    std::optional<IdleTimerCallbacks> mIdleTimerCallbacks GUARDED_BY(mIdleTimerCallbacksMutex);
};

} // namespace android::scheduler
