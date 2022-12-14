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

#include <algorithm>
#include <numeric>
#include <optional>
#include <type_traits>

#include "DisplayHardware/HWComposer.h"
#include "HwcStrongTypes.h"
#include "Scheduler/SchedulerUtils.h"
#include "Scheduler/StrongTyping.h"

namespace android::scheduler {

using namespace std::chrono_literals;

enum class RefreshRateConfigEvent : unsigned { None = 0b0, Changed = 0b1 };

inline RefreshRateConfigEvent operator|(RefreshRateConfigEvent lhs, RefreshRateConfigEvent rhs) {
    using T = std::underlying_type_t<RefreshRateConfigEvent>;
    return static_cast<RefreshRateConfigEvent>(static_cast<T>(lhs) | static_cast<T>(rhs));
}

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
        RefreshRate(HwcConfigIndexType configId,
                    std::shared_ptr<const HWC2::Display::Config> config, std::string name,
                    float fps, ConstructorTag)
              : configId(configId), hwcConfig(config), name(std::move(name)), fps(fps) {}

        RefreshRate(const RefreshRate&) = delete;

        HwcConfigIndexType getConfigId() const { return configId; }
        nsecs_t getVsyncPeriod() const { return hwcConfig->getVsyncPeriod(); }
        int32_t getConfigGroup() const { return hwcConfig->getConfigGroup(); }
        const std::string& getName() const { return name; }
        float getFps() const { return fps; }

        // Checks whether the fps of this RefreshRate struct is within a given min and max refresh
        // rate passed in. FPS_EPSILON is applied to the boundaries for approximation.
        bool inPolicy(float minRefreshRate, float maxRefreshRate) const {
            return (fps >= (minRefreshRate - FPS_EPSILON) && fps <= (maxRefreshRate + FPS_EPSILON));
        }

        bool operator!=(const RefreshRate& other) const {
            return configId != other.configId || hwcConfig != other.hwcConfig;
        }

        bool operator<(const RefreshRate& other) const { return getFps() < other.getFps(); }

        bool operator==(const RefreshRate& other) const { return !(*this != other); }

    private:
        friend RefreshRateConfigs;
        friend class RefreshRateConfigsTest;

        // The tolerance within which we consider FPS approximately equals.
        static constexpr float FPS_EPSILON = 0.001f;

        // This config ID corresponds to the position of the config in the vector that is stored
        // on the device.
        const HwcConfigIndexType configId;
        // The config itself
        std::shared_ptr<const HWC2::Display::Config> hwcConfig;
        // Human readable name of the refresh rate.
        const std::string name;
        // Refresh rate in frames per second
        const float fps = 0;
    };

    using AllRefreshRatesMapType =
            std::unordered_map<HwcConfigIndexType, std::unique_ptr<const RefreshRate>>;

    struct Policy {
        struct Range {
            float min = 0;
            float max = std::numeric_limits<float>::max();

            bool operator==(const Range& other) const {
                return min == other.min && max == other.max;
            }

            bool operator!=(const Range& other) const { return !(*this == other); }
        };

        // The default config, used to ensure we only initiate display config switches within the
        // same config group as defaultConfigId's group.
        HwcConfigIndexType defaultConfig;
        // The primary refresh rate range represents display manager's general guidance on the
        // display configs we'll consider when switching refresh rates. Unless we get an explicit
        // signal from an app, we should stay within this range.
        Range primaryRange;
        // The app request refresh rate range allows us to consider more display configs when
        // switching refresh rates. Although we should generally stay within the primary range,
        // specific considerations, such as layer frame rate settings specified via the
        // setFrameRate() api, may cause us to go outside the primary range. We never go outside the
        // app request range. The app request range will be greater than or equal to the primary
        // refresh rate range, never smaller.
        Range appRequestRange;
        // Whether or not we switch config groups to get the best frame rate. Only used by tests.
        bool allowGroupSwitching = false;

        Policy() = default;
        Policy(HwcConfigIndexType defaultConfig, const Range& range)
              : Policy(defaultConfig, range, range) {}
        Policy(HwcConfigIndexType defaultConfig, const Range& primaryRange,
               const Range& appRequestRange)
              : defaultConfig(defaultConfig),
                primaryRange(primaryRange),
                appRequestRange(appRequestRange) {}

        bool operator==(const Policy& other) const {
            return defaultConfig == other.defaultConfig && primaryRange == other.primaryRange &&
                    appRequestRange == other.appRequestRange &&
                    allowGroupSwitching == other.allowGroupSwitching;
        }

        bool operator!=(const Policy& other) const { return !(*this == other); }
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

    // Returns true if config is allowed by the current policy.
    bool isConfigAllowed(HwcConfigIndexType config) const EXCLUDES(mLock);

    // Describes the different options the layer voted for refresh rate
    enum class LayerVoteType {
        NoVote,          // Doesn't care about the refresh rate
        Min,             // Minimal refresh rate available
        Max,             // Maximal refresh rate available
        Heuristic,       // Specific refresh rate that was calculated by platform using a heuristic
        ExplicitDefault, // Specific refresh rate that was provided by the app with Default
                         // compatibility
        ExplicitExactOrMultiple // Specific refresh rate that was provided by the app with
                                // ExactOrMultiple compatibility
    };

    // Captures the layer requirements for a refresh rate. This will be used to determine the
    // display refresh rate.
    struct LayerRequirement {
        // Layer's name. Used for debugging purposes.
        std::string name;
        // Layer vote type.
        LayerVoteType vote = LayerVoteType::NoVote;
        // Layer's desired refresh rate, if applicable.
        float desiredRefreshRate = 0.0f;
        // Layer's weight in the range of [0, 1]. The higher the weight the more impact this layer
        // would have on choosing the refresh rate.
        float weight = 0.0f;
        // Whether layer is in focus or not based on WindowManager's state
        bool focused = false;

        bool operator==(const LayerRequirement& other) const {
            return name == other.name && vote == other.vote &&
                    desiredRefreshRate == other.desiredRefreshRate && weight == other.weight &&
                    focused == other.focused;
        }

        bool operator!=(const LayerRequirement& other) const { return !(*this == other); }
    };

    // Returns the refresh rate that fits best to the given layers.
    const RefreshRate& getRefreshRateForContent(const std::vector<LayerRequirement>& layers) const
            EXCLUDES(mLock);

    // Global state describing signals that affect refresh rate choice.
    struct GlobalSignals {
        // Whether the user touched the screen recently. Used to apply touch boost.
        bool touch = false;
        // True if the system hasn't seen any buffers posted to layers recently.
        bool idle = false;
    };

    // Returns the refresh rate that fits best to the given layers.
    //   layers - The layer requirements to consider.
    //   globalSignals - global state of touch and idle
    //   outSignalsConsidered - An output param that tells the caller whether the refresh rate was
    //                          chosen based on touch boost and/or idle timer.
    const RefreshRate& getBestRefreshRate(const std::vector<LayerRequirement>& layers,
                                          const GlobalSignals& globalSignals,
                                          GlobalSignals* outSignalsConsidered = nullptr) const
            EXCLUDES(mLock);

    // Returns all the refresh rates supported by the device. This won't change at runtime.
    const AllRefreshRatesMapType& getAllRefreshRates() const EXCLUDES(mLock);

    // Returns the lowest refresh rate supported by the device. This won't change at runtime.
    const RefreshRate& getMinRefreshRate() const { return *mMinSupportedRefreshRate; }

    // Returns the lowest refresh rate according to the current policy. May change at runtime. Only
    // uses the primary range, not the app request range.
    const RefreshRate& getMinRefreshRateByPolicy() const EXCLUDES(mLock);

    // Returns the highest refresh rate supported by the device. This won't change at runtime.
    const RefreshRate& getMaxRefreshRate() const { return *mMaxSupportedRefreshRate; }

    // Returns the highest refresh rate according to the current policy. May change at runtime. Only
    // uses the primary range, not the app request range.
    const RefreshRate& getMaxRefreshRateByPolicy() const EXCLUDES(mLock);

    // Returns the current refresh rate
    const RefreshRate& getCurrentRefreshRate() const EXCLUDES(mLock);

    // Returns the current refresh rate, if allowed. Otherwise the default that is allowed by
    // the policy.
    const RefreshRate& getCurrentRefreshRateByPolicy() const;

    // Returns the refresh rate that corresponds to a HwcConfigIndexType. This won't change at
    // runtime.
    const RefreshRate& getRefreshRateFromConfigId(HwcConfigIndexType configId) const {
        return *mRefreshRates.at(configId);
    };

    // Stores the current configId the device operates at
    void setCurrentConfigId(HwcConfigIndexType configId) EXCLUDES(mLock);

    // Returns a string that represents the layer vote type
    static std::string layerVoteTypeString(LayerVoteType vote);

    // Returns a known frame rate that is the closest to frameRate
    float findClosestKnownFrameRate(float frameRate) const;

    RefreshRateConfigs(const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs,
                       HwcConfigIndexType currentConfigId);

    // Class to enumerate options around toggling the kernel timer on and off. We have an option
    // for no change to avoid extra calls to kernel.
    enum class KernelIdleTimerAction {
        NoChange, // Do not change the idle timer.
        TurnOff,  // Turn off the idle timer.
        TurnOn    // Turn on the idle timer.
    };
    // Checks whether kernel idle timer should be active depending the policy decisions around
    // refresh rates.
    KernelIdleTimerAction getIdleTimerAction() const;

private:
    friend class RefreshRateConfigsTest;

    void constructAvailableRefreshRates() REQUIRES(mLock);
    static std::vector<float> constructKnownFrameRates(
            const std::vector<std::shared_ptr<const HWC2::Display::Config>>& configs);

    void getSortedRefreshRateList(
            const std::function<bool(const RefreshRate&)>& shouldAddRefreshRate,
            std::vector<const RefreshRate*>* outRefreshRates);

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
    bool isPolicyValid(const Policy& policy);

    // The list of refresh rates, indexed by display config ID. This must not change after this
    // object is initialized.
    AllRefreshRatesMapType mRefreshRates;

    // The list of refresh rates in the primary range of the current policy, ordered by vsyncPeriod
    // (the first element is the lowest refresh rate).
    std::vector<const RefreshRate*> mPrimaryRefreshRates GUARDED_BY(mLock);

    // The list of refresh rates in the app request range of the current policy, ordered by
    // vsyncPeriod (the first element is the lowest refresh rate).
    std::vector<const RefreshRate*> mAppRequestRefreshRates GUARDED_BY(mLock);

    // The current config. This will change at runtime. This is set by SurfaceFlinger on
    // the main thread, and read by the Scheduler (and other objects) on other threads.
    const RefreshRate* mCurrentRefreshRate GUARDED_BY(mLock);

    // The policy values will change at runtime. They're set by SurfaceFlinger on the main thread,
    // and read by the Scheduler (and other objects) on other threads.
    Policy mDisplayManagerPolicy GUARDED_BY(mLock);
    std::optional<Policy> mOverridePolicy GUARDED_BY(mLock);

    // The min and max refresh rates supported by the device.
    // This will not change at runtime.
    const RefreshRate* mMinSupportedRefreshRate;
    const RefreshRate* mMaxSupportedRefreshRate;

    mutable std::mutex mLock;

    // A sorted list of known frame rates that a Heuristic layer will choose
    // from based on the closest value.
    const std::vector<float> mKnownFrameRates;
};

} // namespace android::scheduler
