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

#include <utils/Timers.h>

#include <chrono>
#include <deque>

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
class LayerInfo {
    // Layer is considered frequent if the earliest value in the window of most recent present times
    // is within a threshold. If a layer is infrequent, its average refresh rate is disregarded in
    // favor of a low refresh rate.
    static constexpr size_t FREQUENT_LAYER_WINDOW_SIZE = 3;
    static constexpr std::chrono::nanoseconds MAX_FREQUENT_LAYER_PERIOD_NS = 250ms;

    /**
     * Struct that keeps the information about the refresh rate for last
     * HISTORY_SIZE frames. This is used to better determine the refresh rate
     * for individual layers.
     */
    class RefreshRateHistory {
    public:
        explicit RefreshRateHistory(float highRefreshRate) : mHighRefreshRate(highRefreshRate) {}

        void insertRefreshRate(float refreshRate) {
            mElements.push_back(refreshRate);
            if (mElements.size() > HISTORY_SIZE) {
                mElements.pop_front();
            }
        }

        float getRefreshRateAvg() const {
            return mElements.empty() ? mHighRefreshRate : calculate_mean(mElements);
        }

        void clearHistory() { mElements.clear(); }

    private:
        const float mHighRefreshRate;

        static constexpr size_t HISTORY_SIZE = 30;
        std::deque<float> mElements;
    };

    /**
     * Struct that keeps the information about the present time for last
     * HISTORY_SIZE frames. This is used to better determine whether the given layer
     * is still relevant and it's refresh rate should be considered.
     */
    class PresentTimeHistory {
    public:
        static constexpr size_t HISTORY_SIZE = 90;

        void insertPresentTime(nsecs_t presentTime) {
            mElements.push_back(presentTime);
            if (mElements.size() > HISTORY_SIZE) {
                mElements.pop_front();
            }
        }

        // Returns whether the earliest present time is within the active threshold.
        bool isRecentlyActive(nsecs_t now) const {
            if (mElements.size() < 2) {
                return false;
            }

            // The layer had to publish at least HISTORY_SIZE or HISTORY_DURATION of updates
            if (mElements.size() < HISTORY_SIZE &&
                mElements.back() - mElements.front() < HISTORY_DURATION.count()) {
                return false;
            }

            return mElements.back() >= getActiveLayerThreshold(now);
        }

        bool isFrequent(nsecs_t now) const {
            // Assume layer is infrequent if too few present times have been recorded.
            if (mElements.size() < FREQUENT_LAYER_WINDOW_SIZE) {
                return false;
            }

            // Layer is frequent if the earliest value in the window of most recent present times is
            // within threshold.
            const auto it = mElements.end() - FREQUENT_LAYER_WINDOW_SIZE;
            const nsecs_t threshold = now - MAX_FREQUENT_LAYER_PERIOD_NS.count();
            return *it >= threshold;
        }

        void clearHistory() { mElements.clear(); }

    private:
        std::deque<nsecs_t> mElements;
        static constexpr std::chrono::nanoseconds HISTORY_DURATION = 1s;
    };

    friend class LayerHistoryTest;

public:
    LayerInfo(float lowRefreshRate, float highRefreshRate);

    LayerInfo(const LayerInfo&) = delete;
    LayerInfo& operator=(const LayerInfo&) = delete;

    // Records the last requested oresent time. It also stores information about when
    // the layer was last updated. If the present time is farther in the future than the
    // updated time, the updated time is the present time.
    void setLastPresentTime(nsecs_t lastPresentTime, nsecs_t now);

    bool isRecentlyActive(nsecs_t now) const { return mPresentTimeHistory.isRecentlyActive(now); }
    bool isFrequent(nsecs_t now) const { return mPresentTimeHistory.isFrequent(now); }

    float getRefreshRate(nsecs_t now) const {
        return isFrequent(now) ? mRefreshRateHistory.getRefreshRateAvg() : mLowRefreshRate;
    }

    // Return the last updated time. If the present time is farther in the future than the
    // updated time, the updated time is the present time.
    nsecs_t getLastUpdatedTime() const { return mLastUpdatedTime; }

    void clearHistory() {
        mRefreshRateHistory.clearHistory();
        mPresentTimeHistory.clearHistory();
    }

private:
    const float mLowRefreshRate;
    const float mHighRefreshRate;

    nsecs_t mLastUpdatedTime = 0;
    nsecs_t mLastPresentTime = 0;
    RefreshRateHistory mRefreshRateHistory{mHighRefreshRate};
    PresentTimeHistory mPresentTimeHistory;
};

} // namespace scheduler
} // namespace android
