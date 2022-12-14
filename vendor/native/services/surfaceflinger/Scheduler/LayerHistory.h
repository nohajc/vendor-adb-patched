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
#include <utility>
#include <vector>

#include "RefreshRateConfigs.h"

namespace android {

class Layer;
class TestableScheduler;

namespace scheduler {

class LayerHistoryTest;
class LayerHistoryTestV2;
class LayerInfo;
class LayerInfoV2;

class LayerHistory {
public:
    using LayerVoteType = RefreshRateConfigs::LayerVoteType;

    virtual ~LayerHistory() = default;

    // Layers are unregistered when the weak reference expires.
    virtual void registerLayer(Layer*, float lowRefreshRate, float highRefreshRate,
                               LayerVoteType type) = 0;

    // Sets the display size. Client is responsible for synchronization.
    virtual void setDisplayArea(uint32_t displayArea) = 0;

    // Sets whether a config change is pending to be applied
    virtual void setConfigChangePending(bool pending) = 0;

    // Represents which layer activity is recorded
    enum class LayerUpdateType {
        Buffer,       // a new buffer queued
        AnimationTX,  // a new transaction with eAnimation flag set
        SetFrameRate, // setFrameRate API was called
    };

    // Marks the layer as active, and records the given state to its history.
    virtual void record(Layer*, nsecs_t presentTime, nsecs_t now, LayerUpdateType updateType) = 0;

    using Summary = std::vector<RefreshRateConfigs::LayerRequirement>;

    // Rebuilds sets of active/inactive layers, and accumulates stats for active layers.
    virtual Summary summarize(nsecs_t now) = 0;

    virtual void clear() = 0;
};

namespace impl {
// Records per-layer history of scheduling-related information (primarily present time),
// heuristically categorizes layers as active or inactive, and summarizes stats about
// active layers (primarily maximum refresh rate). See go/content-fps-detection-in-scheduler.
class LayerHistory : public android::scheduler::LayerHistory {
public:
    LayerHistory();
    virtual ~LayerHistory();

    // Layers are unregistered when the weak reference expires.
    void registerLayer(Layer*, float lowRefreshRate, float highRefreshRate,
                       LayerVoteType type) override;

    void setDisplayArea(uint32_t /*displayArea*/) override {}

    void setConfigChangePending(bool /*pending*/) override {}

    // Marks the layer as active, and records the given state to its history.
    void record(Layer*, nsecs_t presentTime, nsecs_t now, LayerUpdateType updateType) override;

    // Rebuilds sets of active/inactive layers, and accumulates stats for active layers.
    android::scheduler::LayerHistory::Summary summarize(nsecs_t now) override;

    void clear() override;

private:
    friend class android::scheduler::LayerHistoryTest;
    friend TestableScheduler;

    using LayerPair = std::pair<wp<Layer>, std::unique_ptr<LayerInfo>>;
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

    // Whether to emit systrace output and debug logs.
    const bool mTraceEnabled;

    // Whether to use priority sent from WindowManager to determine the relevancy of the layer.
    const bool mUseFrameRatePriority;
};

class LayerHistoryV2 : public android::scheduler::LayerHistory {
public:
    LayerHistoryV2(const scheduler::RefreshRateConfigs&);
    virtual ~LayerHistoryV2();

    // Layers are unregistered when the weak reference expires.
    void registerLayer(Layer*, float lowRefreshRate, float highRefreshRate,
                       LayerVoteType type) override;

    // Sets the display size. Client is responsible for synchronization.
    void setDisplayArea(uint32_t displayArea) override { mDisplayArea = displayArea; }

    void setConfigChangePending(bool pending) override { mConfigChangePending = pending; }

    // Marks the layer as active, and records the given state to its history.
    void record(Layer*, nsecs_t presentTime, nsecs_t now, LayerUpdateType updateType) override;

    // Rebuilds sets of active/inactive layers, and accumulates stats for active layers.
    android::scheduler::LayerHistory::Summary summarize(nsecs_t /*now*/) override;

    void clear() override;

private:
    friend android::scheduler::LayerHistoryTestV2;
    friend TestableScheduler;

    using LayerPair = std::pair<wp<Layer>, std::unique_ptr<LayerInfoV2>>;
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

    // Whether a config change is in progress or not
    std::atomic<bool> mConfigChangePending = false;
};

} // namespace impl
} // namespace scheduler
} // namespace android
