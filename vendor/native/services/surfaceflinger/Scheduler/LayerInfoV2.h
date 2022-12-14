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

#include <utils/Timers.h>

#include <chrono>
#include <deque>

#include "LayerHistory.h"
#include "RefreshRateConfigs.h"
#include "SchedulerUtils.h"

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
class LayerInfoV2 {
    using LayerUpdateType = LayerHistory::LayerUpdateType;

    // Layer is considered frequent if the earliest value in the window of most recent present times
    // is within a threshold. If a layer is infrequent, its average refresh rate is disregarded in
    // favor of a low refresh rate.
    static constexpr size_t FREQUENT_LAYER_WINDOW_SIZE = 3;
    static constexpr float MIN_FPS_FOR_FREQUENT_LAYER = 10.0f;
    static constexpr auto MAX_FREQUENT_LAYER_PERIOD_NS =
            std::chrono::nanoseconds(static_cast<nsecs_t>(1e9f / MIN_FPS_FOR_FREQUENT_LAYER)) + 1ms;

    friend class LayerHistoryTestV2;

public:
    static void setTraceEnabled(bool enabled) { sTraceEnabled = enabled; }

    static void setRefreshRateConfigs(const RefreshRateConfigs& refreshRateConfigs) {
        sRefreshRateConfigs = &refreshRateConfigs;
    }

    LayerInfoV2(const std::string& name, nsecs_t highRefreshRatePeriod,
                LayerHistory::LayerVoteType defaultVote);

    LayerInfoV2(const LayerInfo&) = delete;
    LayerInfoV2& operator=(const LayerInfoV2&) = delete;

    // Records the last requested present time. It also stores information about when
    // the layer was last updated. If the present time is farther in the future than the
    // updated time, the updated time is the present time.
    void setLastPresentTime(nsecs_t lastPresentTime, nsecs_t now, LayerUpdateType updateType,
                            bool pendingConfigChange);

    // Sets an explicit layer vote. This usually comes directly from the application via
    // ANativeWindow_setFrameRate API
    void setLayerVote(LayerHistory::LayerVoteType type, float fps) { mLayerVote = {type, fps}; }

    // Sets the default layer vote. This will be the layer vote after calling to resetLayerVote().
    // This is used for layers that called to setLayerVote() and then removed the vote, so that the
    // layer can go back to whatever vote it had before the app voted for it.
    void setDefaultLayerVote(LayerHistory::LayerVoteType type) { mDefaultVote = type; }

    // Resets the layer vote to its default.
    void resetLayerVote() { mLayerVote = {mDefaultVote, 0.0f}; }

    std::pair<LayerHistory::LayerVoteType, float> getRefreshRate(nsecs_t now);

    // Return the last updated time. If the present time is farther in the future than the
    // updated time, the updated time is the present time.
    nsecs_t getLastUpdatedTime() const { return mLastUpdatedTime; }

    // Returns a C string for tracing a vote
    const char* getTraceTag(LayerHistory::LayerVoteType type) const;

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
        nsecs_t presetTime; // desiredPresentTime, if provided
        nsecs_t queueTime;  // buffer queue time
        bool pendingConfigChange;
    };

    // Holds information about the calculated and reported refresh rate
    struct RefreshRateHeuristicData {
        // Rate calculated on the layer
        float calculated = 0.0f;
        // Last reported rate for LayerInfoV2::getRefreshRate()
        float reported = 0.0f;
        // Whether the last reported rate for LayerInfoV2::getRefreshRate()
        // was due to animation or infrequent updates
        bool animatingOrInfrequent = false;
    };

    // Holds information about the layer vote
    struct LayerVote {
        LayerHistory::LayerVoteType type = LayerHistory::LayerVoteType::Heuristic;
        float fps = 0.0f;
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
        bool add(float refreshRate, nsecs_t now);

    private:
        friend class LayerHistoryTestV2;

        // Holds the refresh rate when it was calculated
        struct RefreshRateData {
            float refreshRate = 0.0f;
            nsecs_t timestamp = 0;

            bool operator<(const RefreshRateData& other) const {
                return refreshRate < other.refreshRate;
            }
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
        static constexpr float MARGIN_FPS = 1.0;
    };

    bool isFrequent(nsecs_t now) const;
    bool isAnimating(nsecs_t now) const;
    bool hasEnoughDataForHeuristic() const;
    std::optional<float> calculateRefreshRateIfPossible(nsecs_t now);
    std::optional<nsecs_t> calculateAverageFrameTime() const;
    bool isFrameTimeValid(const FrameTimeData&) const;

    const std::string mName;

    // Used for sanitizing the heuristic data
    const nsecs_t mHighRefreshRatePeriod;
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

    RefreshRateHistory mRefreshRateHistory;

    mutable std::unordered_map<LayerHistory::LayerVoteType, std::string> mTraceTags;

    // Shared for all LayerInfo instances
    static const RefreshRateConfigs* sRefreshRateConfigs;
    static bool sTraceEnabled;
};

} // namespace scheduler
} // namespace android
