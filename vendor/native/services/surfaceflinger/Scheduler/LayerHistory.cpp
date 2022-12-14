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

#undef LOG_TAG
#define LOG_TAG "LayerHistory"
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
#include "LayerInfo.h"
#include "SchedulerUtils.h"

namespace android::scheduler::impl {

namespace {

bool isLayerActive(const Layer& layer, const LayerInfo& info, nsecs_t threshold) {
    if (layer.getFrameRateForLayerTree().rate > 0) {
        return layer.isVisible();
    }
    return layer.isVisible() && info.getLastUpdatedTime() >= threshold;
}

bool traceEnabled() {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.layer_history_trace", value, "0");
    return atoi(value);
}

bool useFrameRatePriority() {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.use_frame_rate_priority", value, "1");
    return atoi(value);
}

void trace(const wp<Layer>& weak, int fps) {
    const auto layer = weak.promote();
    if (!layer) return;

    const auto& name = layer->getName();
    const auto tag = "LFPS " + name;
    ATRACE_INT(tag.c_str(), fps);
    ALOGD("%s: %s @ %d Hz", __FUNCTION__, name.c_str(), fps);
}
} // namespace

LayerHistory::LayerHistory()
      : mTraceEnabled(traceEnabled()), mUseFrameRatePriority(useFrameRatePriority()) {}
LayerHistory::~LayerHistory() = default;

void LayerHistory::registerLayer(Layer* layer, float lowRefreshRate, float highRefreshRate,
                                 LayerVoteType /*type*/) {
    auto info = std::make_unique<LayerInfo>(lowRefreshRate, highRefreshRate);
    std::lock_guard lock(mLock);
    mLayerInfos.emplace_back(layer, std::move(info));
}

void LayerHistory::record(Layer* layer, nsecs_t presentTime, nsecs_t now,
                          LayerUpdateType /*updateType*/) {
    std::lock_guard lock(mLock);

    const auto it = std::find_if(mLayerInfos.begin(), mLayerInfos.end(),
                                 [layer](const auto& pair) { return pair.first == layer; });
    LOG_FATAL_IF(it == mLayerInfos.end(), "%s: unknown layer %p", __FUNCTION__, layer);

    const auto& info = it->second;
    info->setLastPresentTime(presentTime, now);

    // Activate layer if inactive.
    if (const auto end = activeLayers().end(); it >= end) {
        std::iter_swap(it, end);
        mActiveLayersEnd++;
    }
}

LayerHistory::Summary LayerHistory::summarize(nsecs_t now) {
    ATRACE_CALL();
    std::lock_guard lock(mLock);

    partitionLayers(now);

    LayerHistory::Summary summary;
    for (const auto& [weakLayer, info] : activeLayers()) {
        const bool recent = info->isRecentlyActive(now);
        auto layer = weakLayer.promote();
        // Only use the layer if the reference still exists.
        if (layer || CC_UNLIKELY(mTraceEnabled)) {
            const auto layerFocused =
                    Layer::isLayerFocusedBasedOnPriority(layer->getFrameRateSelectionPriority());
            // Check if frame rate was set on layer.
            const auto frameRate = layer->getFrameRateForLayerTree();
            if (frameRate.rate > 0.f) {
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
                summary.push_back({layer->getName(), voteType, frameRate.rate, /* weight */ 1.0f,
                                   layerFocused});
            } else if (recent) {
                summary.push_back({layer->getName(), LayerVoteType::Heuristic,
                                   info->getRefreshRate(now),
                                   /* weight */ 1.0f, layerFocused});
            }

            if (CC_UNLIKELY(mTraceEnabled)) {
                trace(weakLayer, round<int>(frameRate.rate));
            }
        }
    }

    return summary;
}

void LayerHistory::partitionLayers(nsecs_t now) {
    const nsecs_t threshold = getActiveLayerThreshold(now);

    // Collect expired and inactive layers after active layers.
    size_t i = 0;
    while (i < mActiveLayersEnd) {
        auto& [weak, info] = mLayerInfos[i];
        if (const auto layer = weak.promote(); layer && isLayerActive(*layer, *info, threshold)) {
            i++;
            continue;
        }

        if (CC_UNLIKELY(mTraceEnabled)) {
            trace(weak, 0);
        }

        info->clearHistory();
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

void LayerHistory::clear() {
    std::lock_guard lock(mLock);

    for (const auto& [layer, info] : activeLayers()) {
        info->clearHistory();
    }

    mActiveLayersEnd = 0;
}
} // namespace android::scheduler::impl
