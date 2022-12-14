/*
 * Copyright 2020 The Android Open Source Project
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

#include <chrono>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>

#include <ui/Transform.h>
#include <utils/Timers.h>

#include <scheduler/Seamlessness.h>

#include "LayerHistory.h"
#include "RefreshRateConfigs.h"

namespace android {

class Layer;

namespace scheduler {

using namespace std::chrono_literals;

// Maximum period between presents for a layer to be considered active.
constexpr std::chrono::nanoseconds MAX_ACTIVE_LAYER_PERIOD_NS = 1200ms;

// Earliest present time for a layer to be considered active.
constexpr nsecs_t getActiveLayerThreshold(nsecs_t now) {
    return now - MAX_ACTIVE_LAYER_PERIOD_NS.count();
}

// Stores history of present times and refresh rates for a layer.
class LayerInfo {
    using LayerUpdateType = LayerHistory::LayerUpdateType;

    // Layer is considered frequent if the earliest value in the window of most recent present times
    // is within a threshold. If a layer is infrequent, its average refresh rate is disregarded in
    // favor of a low refresh rate.
    static constexpr size_t kFrequentLayerWindowSize = 3;
    static constexpr Fps kMinFpsForFrequentLayer = 10_Hz;
    static constexpr auto kMaxPeriodForFrequentLayerNs =
            std::chrono::nanoseconds(kMinFpsForFrequentLayer.getPeriodNsecs()) + 1ms;

    friend class LayerHistoryTest;
    friend class LayerInfoTest;

public:
    // Holds information about the layer vote
    struct LayerVote {
        LayerHistory::LayerVoteType type = LayerHistory::LayerVoteType::Heuristic;
        Fps fps;
        Seamlessness seamlessness = Seamlessness::Default;
    };

    // FrameRateCompatibility specifies how we should interpret the frame rate associated with
    // the layer.
    enum class FrameRateCompatibility {
        Default, // Layer didn't specify any specific handling strategy

        Exact, // Layer needs the exact frame rate.

        ExactOrMultiple, // Layer needs the exact frame rate (or a multiple of it) to present the
                         // content properly. Any other value will result in a pull down.

        NoVote, // Layer doesn't have any requirements for the refresh rate and
                // should not be considered when the display refresh rate is determined.

        ftl_last = NoVote
    };

    // Encapsulates the frame rate and compatibility of the layer. This information will be used
    // when the display refresh rate is determined.
    struct FrameRate {
        using Seamlessness = scheduler::Seamlessness;

        Fps rate;
        FrameRateCompatibility type = FrameRateCompatibility::Default;
        Seamlessness seamlessness = Seamlessness::Default;

        FrameRate() = default;

        FrameRate(Fps rate, FrameRateCompatibility type,
                  Seamlessness seamlessness = Seamlessness::OnlySeamless)
              : rate(rate), type(type), seamlessness(getSeamlessness(rate, seamlessness)) {}

        bool operator==(const FrameRate& other) const {
            return isApproxEqual(rate, other.rate) && type == other.type &&
                    seamlessness == other.seamlessness;
        }

        bool operator!=(const FrameRate& other) const { return !(*this == other); }

        // Convert an ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_* value to a
        // Layer::FrameRateCompatibility. Logs fatal if the compatibility value is invalid.
        static FrameRateCompatibility convertCompatibility(int8_t compatibility);
        static scheduler::Seamlessness convertChangeFrameRateStrategy(int8_t strategy);

    private:
        static Seamlessness getSeamlessness(Fps rate, Seamlessness seamlessness) {
            if (!rate.isValid()) {
                // Refresh rate of 0 is a special value which should reset the vote to
                // its default value.
                return Seamlessness::Default;
            }
            return seamlessness;
        }
    };

    static void setTraceEnabled(bool enabled) { sTraceEnabled = enabled; }

    LayerInfo(const std::string& name, uid_t ownerUid, LayerHistory::LayerVoteType defaultVote);

    LayerInfo(const LayerInfo&) = delete;
    LayerInfo& operator=(const LayerInfo&) = delete;

    struct LayerProps {
        bool visible = false;
        FloatRect bounds;
        ui::Transform transform;
        FrameRate setFrameRateVote;
        int32_t frameRateSelectionPriority = -1;
    };

    // Records the last requested present time. It also stores information about when
    // the layer was last updated. If the present time is farther in the future than the
    // updated time, the updated time is the present time.
    void setLastPresentTime(nsecs_t lastPresentTime, nsecs_t now, LayerUpdateType updateType,
                            bool pendingModeChange, LayerProps props);

    // Sets an explicit layer vote. This usually comes directly from the application via
    // ANativeWindow_setFrameRate API
    void setLayerVote(LayerVote vote) { mLayerVote = vote; }

    // Sets the default layer vote. This will be the layer vote after calling to resetLayerVote().
    // This is used for layers that called to setLayerVote() and then removed the vote, so that the
    // layer can go back to whatever vote it had before the app voted for it.
    void setDefaultLayerVote(LayerHistory::LayerVoteType type) { mDefaultVote = type; }

    // Resets the layer vote to its default.
    void resetLayerVote() { mLayerVote = {mDefaultVote, Fps(), Seamlessness::Default}; }

    std::string getName() const { return mName; }

    uid_t getOwnerUid() const { return mOwnerUid; }

    LayerVote getRefreshRateVote(const RefreshRateConfigs&, nsecs_t now);

    // Return the last updated time. If the present time is farther in the future than the
    // updated time, the updated time is the present time.
    nsecs_t getLastUpdatedTime() const { return mLastUpdatedTime; }

    FrameRate getSetFrameRateVote() const { return mLayerProps.setFrameRateVote; }
    bool isVisible() const { return mLayerProps.visible; }
    int32_t getFrameRateSelectionPriority() const { return mLayerProps.frameRateSelectionPriority; }

    FloatRect getBounds() const { return mLayerProps.bounds; }

    ui::Transform getTransform() const { return mLayerProps.transform; }

    // Returns a C string for tracing a vote
    const char* getTraceTag(LayerHistory::LayerVoteType type) const;

    // Return the framerate of this layer.
    Fps getFps(nsecs_t now) const;

    void onLayerInactive(nsecs_t now) {
        // Mark mFrameTimeValidSince to now to ignore all previous frame times.
        // We are not deleting the old frame to keep track of whether we should treat the first
        // buffer as Max as we don't know anything about this layer or Min as this layer is
        // posting infrequent updates.
        const auto timePoint = std::chrono::nanoseconds(now);
        mFrameTimeValidSince = std::chrono::time_point<std::chrono::steady_clock>(timePoint);
        mLastRefreshRate = {};
        mRefreshRateHistory.clear();
    }

    void clearHistory(nsecs_t now) {
        onLayerInactive(now);
        mFrameTimes.clear();
    }

private:
    // Used to store the layer timestamps
    struct FrameTimeData {
        nsecs_t presentTime; // desiredPresentTime, if provided
        nsecs_t queueTime;  // buffer queue time
        bool pendingModeChange;
    };

    // Holds information about the calculated and reported refresh rate
    struct RefreshRateHeuristicData {
        // Rate calculated on the layer
        Fps calculated;
        // Last reported rate for LayerInfo::getRefreshRate()
        Fps reported;
        // Whether the last reported rate for LayerInfo::getRefreshRate()
        // was due to animation or infrequent updates
        bool animatingOrInfrequent = false;
    };

    // Class to store past calculated refresh rate and determine whether
    // the refresh rate calculated is consistent with past values
    class RefreshRateHistory {
    public:
        static constexpr auto HISTORY_SIZE = 90;
        static constexpr std::chrono::nanoseconds HISTORY_DURATION = 2s;

        RefreshRateHistory(const std::string& name) : mName(name) {}

        // Clears History
        void clear();

        // Adds a new refresh rate and returns true if it is consistent
        bool add(Fps refreshRate, nsecs_t now);

    private:
        friend class LayerHistoryTest;

        // Holds the refresh rate when it was calculated
        struct RefreshRateData {
            Fps refreshRate;
            nsecs_t timestamp = 0;
        };

        // Holds tracing strings
        struct HeuristicTraceTagData {
            std::string min;
            std::string max;
            std::string consistent;
            std::string average;
        };

        bool isConsistent() const;
        HeuristicTraceTagData makeHeuristicTraceTagData() const;

        const std::string mName;
        mutable std::optional<HeuristicTraceTagData> mHeuristicTraceTagData;
        std::deque<RefreshRateData> mRefreshRates;
        static constexpr float MARGIN_CONSISTENT_FPS = 1.0;
    };

    bool isFrequent(nsecs_t now) const;
    bool isAnimating(nsecs_t now) const;
    bool hasEnoughDataForHeuristic() const;
    std::optional<Fps> calculateRefreshRateIfPossible(const RefreshRateConfigs&, nsecs_t now);
    std::optional<nsecs_t> calculateAverageFrameTime() const;
    bool isFrameTimeValid(const FrameTimeData&) const;

    const std::string mName;
    const uid_t mOwnerUid;

    // Used for sanitizing the heuristic data. If two frames are less than
    // this period apart from each other they'll be considered as duplicates.
    static constexpr nsecs_t kMinPeriodBetweenFrames = (240_Hz).getPeriodNsecs();
    // Used for sanitizing the heuristic data. If two frames are more than
    // this period apart from each other, the interval between them won't be
    // taken into account when calculating average frame rate.
    static constexpr nsecs_t kMaxPeriodBetweenFrames = kMinFpsForFrequentLayer.getPeriodNsecs();
    LayerHistory::LayerVoteType mDefaultVote;

    LayerVote mLayerVote;

    nsecs_t mLastUpdatedTime = 0;

    nsecs_t mLastAnimationTime = 0;

    RefreshRateHeuristicData mLastRefreshRate;

    std::deque<FrameTimeData> mFrameTimes;
    std::chrono::time_point<std::chrono::steady_clock> mFrameTimeValidSince =
            std::chrono::steady_clock::now();
    static constexpr size_t HISTORY_SIZE = RefreshRateHistory::HISTORY_SIZE;
    static constexpr std::chrono::nanoseconds HISTORY_DURATION = 1s;

    LayerProps mLayerProps;

    RefreshRateHistory mRefreshRateHistory;

    mutable std::unordered_map<LayerHistory::LayerVoteType, std::string> mTraceTags;

    // Shared for all LayerInfo instances
    static bool sTraceEnabled;
};

} // namespace scheduler
} // namespace android
