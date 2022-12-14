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

#include <android-base/thread_annotations.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "RefreshRateConfigs.h"

namespace android {

class Layer;
class TestableScheduler;

namespace scheduler {

class LayerHistoryTest;
class LayerInfo;

class LayerHistory {
public:
    using LayerVoteType = RefreshRateConfigs::LayerVoteType;

    LayerHistory();
    ~LayerHistory();

    // Layers are unregistered when the weak reference expires.
    void registerLayer(Layer*, LayerVoteType type);

    // Sets the display size. Client is responsible for synchronization.
    void setDisplayArea(uint32_t displayArea) { mDisplayArea = displayArea; }

    // Sets whether a mode change is pending to be applied
    void setModeChangePending(bool pending) { mModeChangePending = pending; }

    // Represents which layer activity is recorded
    enum class LayerUpdateType {
        Buffer,       // a new buffer queued
        AnimationTX,  // a new transaction with eAnimation flag set
        SetFrameRate, // setFrameRate API was called
    };

    // Marks the layer as active, and records the given state to its history.
    void record(Layer*, nsecs_t presentTime, nsecs_t now, LayerUpdateType updateType);

    using Summary = std::vector<RefreshRateConfigs::LayerRequirement>;

    // Rebuilds sets of active/inactive layers, and accumulates stats for active layers.
    Summary summarize(const RefreshRateConfigs&, nsecs_t now);

    void clear();

    void deregisterLayer(Layer*);
    std::string dump() const;

private:
    friend LayerHistoryTest;
    friend TestableScheduler;

    using LayerPair = std::pair<Layer*, std::unique_ptr<LayerInfo>>;
    using LayerInfos = std::vector<LayerPair>;

    struct ActiveLayers {
        LayerInfos& infos;
        const size_t index;

        auto begin() { return infos.begin(); }
        auto end() { return begin() + static_cast<long>(index); }
    };

    ActiveLayers activeLayers() REQUIRES(mLock) { return {mLayerInfos, mActiveLayersEnd}; }

    // Iterates over layers in a single pass, swapping pairs such that active layers precede
    // inactive layers, and inactive layers precede expired layers. Removes expired layers by
    // truncating after inactive layers.
    void partitionLayers(nsecs_t now) REQUIRES(mLock);

    mutable std::mutex mLock;

    // Partitioned such that active layers precede inactive layers. For fast lookup, the few active
    // layers are at the front, and weak pointers are stored in contiguous memory to hit the cache.
    LayerInfos mLayerInfos GUARDED_BY(mLock);
    size_t mActiveLayersEnd GUARDED_BY(mLock) = 0;

    uint32_t mDisplayArea = 0;

    // Whether to emit systrace output and debug logs.
    const bool mTraceEnabled;

    // Whether to use priority sent from WindowManager to determine the relevancy of the layer.
    const bool mUseFrameRatePriority;

    // Whether a mode change is in progress or not
    std::atomic<bool> mModeChangePending = false;
};

} // namespace scheduler
} // namespace android
