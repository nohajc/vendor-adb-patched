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
#define LOG_TAG "LayerHistory"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "LayerHistory.h"

#include <android-base/stringprintf.h>
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

namespace android::scheduler {

namespace {

bool isLayerActive(const LayerInfo& info, nsecs_t threshold) {
    // Layers with an explicit vote are always kept active
    if (info.getSetFrameRateVote().rate.isValid()) {
        return true;
    }

    return info.isVisible() && info.getLastUpdatedTime() >= threshold;
}

bool traceEnabled() {
    return property_get_bool("debug.sf.layer_history_trace", false);
}

bool useFrameRatePriority() {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.use_frame_rate_priority", value, "1");
    return atoi(value);
}

void trace(const LayerInfo& info, LayerHistory::LayerVoteType type, int fps) {
    const auto traceType = [&](LayerHistory::LayerVoteType checkedType, int value) {
        ATRACE_INT(info.getTraceTag(checkedType), type == checkedType ? value : 0);
    };

    traceType(LayerHistory::LayerVoteType::NoVote, 1);
    traceType(LayerHistory::LayerVoteType::Heuristic, fps);
    traceType(LayerHistory::LayerVoteType::ExplicitDefault, fps);
    traceType(LayerHistory::LayerVoteType::ExplicitExactOrMultiple, fps);
    traceType(LayerHistory::LayerVoteType::ExplicitExact, fps);
    traceType(LayerHistory::LayerVoteType::Min, 1);
    traceType(LayerHistory::LayerVoteType::Max, 1);

    ALOGD("%s: %s @ %d Hz", __FUNCTION__, info.getName().c_str(), fps);
}
} // namespace

LayerHistory::LayerHistory()
      : mTraceEnabled(traceEnabled()), mUseFrameRatePriority(useFrameRatePriority()) {
    LayerInfo::setTraceEnabled(mTraceEnabled);
}

LayerHistory::~LayerHistory() = default;

void LayerHistory::registerLayer(Layer* layer, LayerVoteType type) {
    std::lock_guard lock(mLock);
    for (const auto& info : mLayerInfos) {
        LOG_ALWAYS_FATAL_IF(info.first == layer, "%s already registered", layer->getName().c_str());
    }
    auto info = std::make_unique<LayerInfo>(layer->getName(), layer->getOwnerUid(), type);
    mLayerInfos.emplace_back(layer, std::move(info));
}

void LayerHistory::deregisterLayer(Layer* layer) {
    std::lock_guard lock(mLock);

    const auto it = std::find_if(mLayerInfos.begin(), mLayerInfos.end(),
                                 [layer](const auto& pair) { return pair.first == layer; });
    LOG_ALWAYS_FATAL_IF(it == mLayerInfos.end(), "%s: unknown layer %p", __FUNCTION__, layer);

    const size_t i = static_cast<size_t>(it - mLayerInfos.begin());
    if (i < mActiveLayersEnd) {
        mActiveLayersEnd--;
    }
    const size_t last = mLayerInfos.size() - 1;
    std::swap(mLayerInfos[i], mLayerInfos[last]);
    mLayerInfos.erase(mLayerInfos.begin() + static_cast<long>(last));
}

void LayerHistory::record(Layer* layer, nsecs_t presentTime, nsecs_t now,
                          LayerUpdateType updateType) {
    std::lock_guard lock(mLock);

    const auto it = std::find_if(mLayerInfos.begin(), mLayerInfos.end(),
                                 [layer](const auto& pair) { return pair.first == layer; });
    if (it == mLayerInfos.end()) {
        // Offscreen layer
        ALOGV("LayerHistory::record: %s not registered", layer->getName().c_str());
        return;
    }

    const auto& info = it->second;
    const auto layerProps = LayerInfo::LayerProps{
            .visible = layer->isVisible(),
            .bounds = layer->getBounds(),
            .transform = layer->getTransform(),
            .setFrameRateVote = layer->getFrameRateForLayerTree(),
            .frameRateSelectionPriority = layer->getFrameRateSelectionPriority(),
    };

    info->setLastPresentTime(presentTime, now, updateType, mModeChangePending, layerProps);

    // Activate layer if inactive.
    if (const auto end = activeLayers().end(); it >= end) {
        std::iter_swap(it, end);
        mActiveLayersEnd++;
    }
}

LayerHistory::Summary LayerHistory::summarize(const RefreshRateConfigs& refreshRateConfigs,
                                              nsecs_t now) {
    LayerHistory::Summary summary;

    std::lock_guard lock(mLock);

    partitionLayers(now);

    for (const auto& [layer, info] : activeLayers()) {
        const auto frameRateSelectionPriority = info->getFrameRateSelectionPriority();
        const auto layerFocused = Layer::isLayerFocusedBasedOnPriority(frameRateSelectionPriority);
        ALOGV("%s has priority: %d %s focused", info->getName().c_str(), frameRateSelectionPriority,
              layerFocused ? "" : "not");

        const auto vote = info->getRefreshRateVote(refreshRateConfigs, now);
        // Skip NoVote layer as those don't have any requirements
        if (vote.type == LayerHistory::LayerVoteType::NoVote) {
            continue;
        }

        // Compute the layer's position on the screen
        const Rect bounds = Rect(info->getBounds());
        const ui::Transform transform = info->getTransform();
        constexpr bool roundOutwards = true;
        Rect transformed = transform.transform(bounds, roundOutwards);

        const float layerArea = transformed.getWidth() * transformed.getHeight();
        float weight = mDisplayArea ? layerArea / mDisplayArea : 0.0f;
        summary.push_back({info->getName(), info->getOwnerUid(), vote.type, vote.fps,
                           vote.seamlessness, weight, layerFocused});

        if (CC_UNLIKELY(mTraceEnabled)) {
            trace(*info, vote.type, vote.fps.getIntValue());
        }
    }

    return summary;
}

void LayerHistory::partitionLayers(nsecs_t now) {
    const nsecs_t threshold = getActiveLayerThreshold(now);

    // Collect expired and inactive layers after active layers.
    size_t i = 0;
    while (i < mActiveLayersEnd) {
        auto& [layerUnsafe, info] = mLayerInfos[i];
        if (isLayerActive(*info, threshold)) {
            i++;
            // Set layer vote if set
            const auto frameRate = info->getSetFrameRateVote();
            const auto voteType = [&]() {
                switch (frameRate.type) {
                    case Layer::FrameRateCompatibility::Default:
                        return LayerVoteType::ExplicitDefault;
                    case Layer::FrameRateCompatibility::ExactOrMultiple:
                        return LayerVoteType::ExplicitExactOrMultiple;
                    case Layer::FrameRateCompatibility::NoVote:
                        return LayerVoteType::NoVote;
                    case Layer::FrameRateCompatibility::Exact:
                        return LayerVoteType::ExplicitExact;
                }
            }();

            if (frameRate.rate.isValid() || voteType == LayerVoteType::NoVote) {
                const auto type = info->isVisible() ? voteType : LayerVoteType::NoVote;
                info->setLayerVote({type, frameRate.rate, frameRate.seamlessness});
            } else {
                info->resetLayerVote();
            }
            continue;
        }

        if (CC_UNLIKELY(mTraceEnabled)) {
            trace(*info, LayerHistory::LayerVoteType::NoVote, 0);
        }

        info->onLayerInactive(now);
        std::swap(mLayerInfos[i], mLayerInfos[--mActiveLayersEnd]);
    }
}

void LayerHistory::clear() {
    std::lock_guard lock(mLock);

    for (const auto& [layer, info] : activeLayers()) {
        info->clearHistory(systemTime());
    }
}

std::string LayerHistory::dump() const {
    std::lock_guard lock(mLock);
    return base::StringPrintf("LayerHistory{size=%zu, active=%zu}", mLayerInfos.size(),
                              mActiveLayersEnd);
}

} // namespace android::scheduler
