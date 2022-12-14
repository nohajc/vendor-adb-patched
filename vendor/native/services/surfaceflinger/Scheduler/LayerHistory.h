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

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "RefreshRateConfigs.h"

namespace android {

class Layer;

namespace scheduler {

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

    // return the frames per second of the layer with the given sequence id.
    float getLayerFramerate(nsecs_t now, int32_t id) const;

private:
    friend class LayerHistoryTest;
    friend class TestableScheduler;

    using LayerPair = std::pair<Layer*, std::unique_ptr<LayerInfo>>;
    // keyed by id as returned from Layer::getSequence()
    using LayerInfos = std::unordered_map<int32_t, LayerPair>;

    // Iterates over layers maps moving all active layers to mActiveLayerInfos and all inactive
    // layers to mInactiveLayerInfos.
    // worst case time complexity is O(2 * inactive + active)
    void partitionLayers(nsecs_t now) REQUIRES(mLock);

    enum class LayerStatus {
        NotFound,
        LayerInActiveMap,
        LayerInInactiveMap,
    };

    // looks up a layer by sequence id in both layerInfo maps.
    // The first element indicates if and where the item was found
    std::pair<LayerStatus, LayerPair*> findLayer(int32_t id) REQUIRES(mLock);

    std::pair<LayerStatus, const LayerPair*> findLayer(int32_t id) const REQUIRES(mLock) {
        return const_cast<LayerHistory*>(this)->findLayer(id);
    }

    mutable std::mutex mLock;

    // Partitioned into two maps to facility two kinds of retrieval:
    // 1. retrieval of a layer by id (attempt lookup in both maps)
    // 2. retrieval of all active layers (iterate that map)
    // The partitioning is allowed to become out of date but calling partitionLayers refreshes the
    // validity of each map.
    LayerInfos mActiveLayerInfos GUARDED_BY(mLock);
    LayerInfos mInactiveLayerInfos GUARDED_BY(mLock);

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
