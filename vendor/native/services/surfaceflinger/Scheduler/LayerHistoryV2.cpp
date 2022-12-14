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

#undef LOG_TAG
#define LOG_TAG "LayerHistoryV2"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "LayerHistory.h"

#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <algorithm>
#include <cmath>
#include <string>
#include <utility>

#include "../Layer.h"
#include "SchedulerUtils.h"

#include "LayerInfoV2.h"

namespace android::scheduler::impl {

namespace {

bool isLayerActive(const Layer& layer, const LayerInfoV2& info, nsecs_t threshold) {
    // Layers with an explicit vote are always kept active
    if (layer.getFrameRateForLayerTree().rate > 0) {
        return true;
    }

    return layer.isVisible() && info.getLastUpdatedTime() >= threshold;
}

bool traceEnabled() {
    return property_get_bool("debug.sf.layer_history_trace", false);
}

bool useFrameRatePriority() {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.use_frame_rate_priority", value, "1");
    return atoi(value);
}

void trace(const wp<Layer>& weak, const LayerInfoV2& info, LayerHistory::LayerVoteType type,
           int fps) {
    const auto layer = weak.promote();
    if (!layer) return;

    const auto traceType = [&](LayerHistory::LayerVoteType checkedType, int value) {
        ATRACE_INT(info.getTraceTag(checkedType), type == checkedType ? value : 0);
    };

    traceType(LayerHistory::LayerVoteType::NoVote, 1);
    traceType(LayerHistory::LayerVoteType::Heuristic, fps);
    traceType(LayerHistory::LayerVoteType::ExplicitDefault, fps);
    traceType(LayerHistory::LayerVoteType::ExplicitExactOrMultiple, fps);
    traceType(LayerHistory::LayerVoteType::Min, 1);
    traceType(LayerHistory::LayerVoteType::Max, 1);

    ALOGD("%s: %s @ %d Hz", __FUNCTION__, layer->getName().c_str(), fps);
}
} // namespace

LayerHistoryV2::LayerHistoryV2(const scheduler::RefreshRateConfigs& refreshRateConfigs)
      : mTraceEnabled(traceEnabled()), mUseFrameRatePriority(useFrameRatePriority()) {
    LayerInfoV2::setTraceEnabled(mTraceEnabled);
    LayerInfoV2::setRefreshRateConfigs(refreshRateConfigs);
}

LayerHistoryV2::~LayerHistoryV2() = default;

void LayerHistoryV2::registerLayer(Layer* layer, float /*lowRefreshRate*/, float highRefreshRate,
                                   LayerVoteType type) {
    const nsecs_t highRefreshRatePeriod = static_cast<nsecs_t>(1e9f / highRefreshRate);
    auto info = std::make_unique<LayerInfoV2>(layer->getName(), highRefreshRatePeriod, type);
    std::lock_guard lock(mLock);
    mLayerInfos.emplace_back(layer, std::move(info));
}

void LayerHistoryV2::record(Layer* layer, nsecs_t presentTime, nsecs_t now,
                            LayerUpdateType updateType) {
    std::lock_guard lock(mLock);

    const auto it = std::find_if(mLayerInfos.begin(), mLayerInfos.end(),
                                 [layer](const auto& pair) { return pair.first == layer; });
    LOG_FATAL_IF(it == mLayerInfos.end(), "%s: unknown layer %p", __FUNCTION__, layer);

    const auto& info = it->second;
    info->setLastPresentTime(presentTime, now, updateType, mConfigChangePending);

    // Activate layer if inactive.
    if (const auto end = activeLayers().end(); it >= end) {
        std::iter_swap(it, end);
        mActiveLayersEnd++;
    }
}

LayerHistoryV2::Summary LayerHistoryV2::summarize(nsecs_t now) {
    LayerHistory::Summary summary;

    std::lock_guard lock(mLock);

    partitionLayers(now);

    for (const auto& [layer, info] : activeLayers()) {
        const auto strong = layer.promote();
        if (!strong) {
            continue;
        }

        const auto frameRateSelectionPriority = strong->getFrameRateSelectionPriority();
        const auto layerFocused = Layer::isLayerFocusedBasedOnPriority(frameRateSelectionPriority);
        ALOGV("%s has priority: %d %s focused", strong->getName().c_str(),
              frameRateSelectionPriority, layerFocused ? "" : "not");

        const auto [type, refreshRate] = info->getRefreshRate(now);
        // Skip NoVote layer as those don't have any requirements
        if (type == LayerHistory::LayerVoteType::NoVote) {
            continue;
        }

        // Compute the layer's position on the screen
        const Rect bounds = Rect(strong->getBounds());
        const ui::Transform transform = strong->getTransform();
        constexpr bool roundOutwards = true;
        Rect transformed = transform.transform(bounds, roundOutwards);

        const float layerArea = transformed.getWidth() * transformed.getHeight();
        float weight = mDisplayArea ? layerArea / mDisplayArea : 0.0f;
        summary.push_back({strong->getName(), type, refreshRate, weight, layerFocused});

        if (CC_UNLIKELY(mTraceEnabled)) {
            trace(layer, *info, type, static_cast<int>(std::round(refreshRate)));
        }
    }

    return summary;
}

void LayerHistoryV2::partitionLayers(nsecs_t now) {
    const nsecs_t threshold = getActiveLayerThreshold(now);

    // Collect expired and inactive layers after active layers.
    size_t i = 0;
    while (i < mActiveLayersEnd) {
        auto& [weak, info] = mLayerInfos[i];
        if (const auto layer = weak.promote(); layer && isLayerActive(*layer, *info, threshold)) {
            i++;
            // Set layer vote if set
            const auto frameRate = layer->getFrameRateForLayerTree();
            const auto voteType = [&]() {
                switch (frameRate.type) {
                    case Layer::FrameRateCompatibility::Default:
                        return LayerVoteType::ExplicitDefault;
                    case Layer::FrameRateCompatibility::ExactOrMultiple:
                        return LayerVoteType::ExplicitExactOrMultiple;
                    case Layer::FrameRateCompatibility::NoVote:
                        return LayerVoteType::NoVote;
                }
            }();

            if (frameRate.rate > 0 || voteType == LayerVoteType::NoVote) {
                const auto type = layer->isVisible() ? voteType : LayerVoteType::NoVote;
                info->setLayerVote(type, frameRate.rate);
            } else {
                info->resetLayerVote();
            }
            continue;
        }

        if (CC_UNLIKELY(mTraceEnabled)) {
            trace(weak, *info, LayerHistory::LayerVoteType::NoVote, 0);
        }

        info->onLayerInactive(now);
        std::swap(mLayerInfos[i], mLayerInfos[--mActiveLayersEnd]);
    }

    // Collect expired layers after inactive layers.
    size_t end = mLayerInfos.size();
    while (i < end) {
        if (mLayerInfos[i].first.promote()) {
            i++;
        } else {
            std::swap(mLayerInfos[i], mLayerInfos[--end]);
        }
    }

    mLayerInfos.erase(mLayerInfos.begin() + static_cast<long>(end), mLayerInfos.end());
}

void LayerHistoryV2::clear() {
    std::lock_guard lock(mLock);

    for (const auto& [layer, info] : activeLayers()) {
        info->clearHistory(systemTime());
    }
}

} // namespace android::scheduler::impl
