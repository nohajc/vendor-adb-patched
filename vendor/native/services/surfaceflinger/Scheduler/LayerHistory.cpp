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
    LOG_ALWAYS_FATAL_IF(findLayer(layer->getSequence()).first != LayerStatus::NotFound,
                        "%s already registered", layer->getName().c_str());
    auto info = std::make_unique<LayerInfo>(layer->getName(), layer->getOwnerUid(), type);

    // The layer can be placed on either map, it is assumed that partitionLayers() will be called
    // to correct them.
    mInactiveLayerInfos.insert({layer->getSequence(), std::make_pair(layer, std::move(info))});
}

void LayerHistory::deregisterLayer(Layer* layer) {
    std::lock_guard lock(mLock);
    if (!mActiveLayerInfos.erase(layer->getSequence())) {
        if (!mInactiveLayerInfos.erase(layer->getSequence())) {
            LOG_ALWAYS_FATAL("%s: unknown layer %p", __FUNCTION__, layer);
        }
    }
}

void LayerHistory::record(Layer* layer, nsecs_t presentTime, nsecs_t now,
                          LayerUpdateType updateType) {
    std::lock_guard lock(mLock);
    auto id = layer->getSequence();

    auto [found, layerPair] = findLayer(id);
    if (found == LayerStatus::NotFound) {
        // Offscreen layer
        ALOGV("%s: %s not registered", __func__, layer->getName().c_str());
        return;
    }

    const auto& info = layerPair->second;
    const auto layerProps = LayerInfo::LayerProps{
            .visible = layer->isVisible(),
            .bounds = layer->getBounds(),
            .transform = layer->getTransform(),
            .setFrameRateVote = layer->getFrameRateForLayerTree(),
            .frameRateSelectionPriority = layer->getFrameRateSelectionPriority(),
    };

    info->setLastPresentTime(presentTime, now, updateType, mModeChangePending, layerProps);

    // Activate layer if inactive.
    if (found == LayerStatus::LayerInInactiveMap) {
        mActiveLayerInfos.insert(
                {id, std::make_pair(layerPair->first, std::move(layerPair->second))});
        mInactiveLayerInfos.erase(id);
    }
}

auto LayerHistory::summarize(const RefreshRateConfigs& configs, nsecs_t now) -> Summary {
    Summary summary;

    std::lock_guard lock(mLock);

    partitionLayers(now);

    for (const auto& [key, value] : mActiveLayerInfos) {
        auto& info = value.second;
        const auto frameRateSelectionPriority = info->getFrameRateSelectionPriority();
        const auto layerFocused = Layer::isLayerFocusedBasedOnPriority(frameRateSelectionPriority);
        ALOGV("%s has priority: %d %s focused", info->getName().c_str(), frameRateSelectionPriority,
              layerFocused ? "" : "not");

        const auto vote = info->getRefreshRateVote(configs, now);
        // Skip NoVote layer as those don't have any requirements
        if (vote.type == LayerVoteType::NoVote) {
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

    // iterate over inactive map
    LayerInfos::iterator it = mInactiveLayerInfos.begin();
    while (it != mInactiveLayerInfos.end()) {
        auto& [layerUnsafe, info] = it->second;
        if (isLayerActive(*info, threshold)) {
            // move this to the active map

            mActiveLayerInfos.insert({it->first, std::move(it->second)});
            it = mInactiveLayerInfos.erase(it);
        } else {
            if (CC_UNLIKELY(mTraceEnabled)) {
                trace(*info, LayerVoteType::NoVote, 0);
            }
            info->onLayerInactive(now);
            it++;
        }
    }

    // iterate over active map
    it = mActiveLayerInfos.begin();
    while (it != mActiveLayerInfos.end()) {
        auto& [layerUnsafe, info] = it->second;
        if (isLayerActive(*info, threshold)) {
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

            it++;
        } else {
            if (CC_UNLIKELY(mTraceEnabled)) {
                trace(*info, LayerVoteType::NoVote, 0);
            }
            info->onLayerInactive(now);
            // move this to the inactive map
            mInactiveLayerInfos.insert({it->first, std::move(it->second)});
            it = mActiveLayerInfos.erase(it);
        }
    }
}

void LayerHistory::clear() {
    std::lock_guard lock(mLock);
    for (const auto& [key, value] : mActiveLayerInfos) {
        value.second->clearHistory(systemTime());
    }
}

std::string LayerHistory::dump() const {
    std::lock_guard lock(mLock);
    return base::StringPrintf("LayerHistory{size=%zu, active=%zu}",
                              mActiveLayerInfos.size() + mInactiveLayerInfos.size(),
                              mActiveLayerInfos.size());
}

float LayerHistory::getLayerFramerate(nsecs_t now, int32_t id) const {
    std::lock_guard lock(mLock);
    auto [found, layerPair] = findLayer(id);
    if (found != LayerStatus::NotFound) {
        return layerPair->second->getFps(now).getValue();
    }
    return 0.f;
}

auto LayerHistory::findLayer(int32_t id) -> std::pair<LayerStatus, LayerPair*> {
    // the layer could be in either the active or inactive map, try both
    auto it = mActiveLayerInfos.find(id);
    if (it != mActiveLayerInfos.end()) {
        return {LayerStatus::LayerInActiveMap, &(it->second)};
    }
    it = mInactiveLayerInfos.find(id);
    if (it != mInactiveLayerInfos.end()) {
        return {LayerStatus::LayerInInactiveMap, &(it->second)};
    }
    return {LayerStatus::NotFound, nullptr};
}

} // namespace android::scheduler
