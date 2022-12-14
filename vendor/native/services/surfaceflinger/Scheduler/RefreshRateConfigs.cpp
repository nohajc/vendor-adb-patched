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

// #define LOG_NDEBUG 0
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra"

#include "RefreshRateConfigs.h"
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <utils/Trace.h>
#include <chrono>
#include <cmath>
#include "../SurfaceFlingerProperties.h"

#undef LOG_TAG
#define LOG_TAG "RefreshRateConfigs"

namespace android::scheduler {
namespace {
std::string formatLayerInfo(const RefreshRateConfigs::LayerRequirement& layer, float weight) {
    return base::StringPrintf("%s (type=%s, weight=%.2f seamlessness=%s) %s", layer.name.c_str(),
                              RefreshRateConfigs::layerVoteTypeString(layer.vote).c_str(), weight,
                              toString(layer.seamlessness).c_str(),
                              to_string(layer.desiredRefreshRate).c_str());
}

std::vector<Fps> constructKnownFrameRates(const DisplayModes& modes) {
    std::vector<Fps> knownFrameRates = {Fps(24.0f), Fps(30.0f), Fps(45.0f), Fps(60.0f), Fps(72.0f)};
    knownFrameRates.reserve(knownFrameRates.size() + modes.size());

    // Add all supported refresh rates to the set
    for (const auto& mode : modes) {
        const auto refreshRate = Fps::fromPeriodNsecs(mode->getVsyncPeriod());
        knownFrameRates.emplace_back(refreshRate);
    }

    // Sort and remove duplicates
    std::sort(knownFrameRates.begin(), knownFrameRates.end(), Fps::comparesLess);
    knownFrameRates.erase(std::unique(knownFrameRates.begin(), knownFrameRates.end(),
                                      Fps::EqualsWithMargin()),
                          knownFrameRates.end());
    return knownFrameRates;
}

} // namespace

using AllRefreshRatesMapType = RefreshRateConfigs::AllRefreshRatesMapType;
using RefreshRate = RefreshRateConfigs::RefreshRate;

std::string RefreshRate::toString() const {
    return base::StringPrintf("{id=%d, hwcId=%d, fps=%.2f, width=%d, height=%d group=%d}",
                              getModeId().value(), mode->getHwcId(), getFps().getValue(),
                              mode->getWidth(), mode->getHeight(), getModeGroup());
}

std::string RefreshRateConfigs::layerVoteTypeString(LayerVoteType vote) {
    switch (vote) {
        case LayerVoteType::NoVote:
            return "NoVote";
        case LayerVoteType::Min:
            return "Min";
        case LayerVoteType::Max:
            return "Max";
        case LayerVoteType::Heuristic:
            return "Heuristic";
        case LayerVoteType::ExplicitDefault:
            return "ExplicitDefault";
        case LayerVoteType::ExplicitExactOrMultiple:
            return "ExplicitExactOrMultiple";
        case LayerVoteType::ExplicitExact:
            return "ExplicitExact";
    }
}

std::string RefreshRateConfigs::Policy::toString() const {
    return base::StringPrintf("default mode ID: %d, allowGroupSwitching = %d"
                              ", primary range: %s, app request range: %s",
                              defaultMode.value(), allowGroupSwitching,
                              primaryRange.toString().c_str(), appRequestRange.toString().c_str());
}

std::pair<nsecs_t, nsecs_t> RefreshRateConfigs::getDisplayFrames(nsecs_t layerPeriod,
                                                                 nsecs_t displayPeriod) const {
    auto [quotient, remainder] = std::div(layerPeriod, displayPeriod);
    if (remainder <= MARGIN_FOR_PERIOD_CALCULATION ||
        std::abs(remainder - displayPeriod) <= MARGIN_FOR_PERIOD_CALCULATION) {
        quotient++;
        remainder = 0;
    }

    return {quotient, remainder};
}

bool RefreshRateConfigs::isVoteAllowed(const LayerRequirement& layer,
                                       const RefreshRate& refreshRate) const {
    switch (layer.vote) {
        case LayerVoteType::ExplicitExactOrMultiple:
        case LayerVoteType::Heuristic:
            if (mConfig.frameRateMultipleThreshold != 0 &&
                refreshRate.getFps().greaterThanOrEqualWithMargin(
                        Fps(mConfig.frameRateMultipleThreshold)) &&
                layer.desiredRefreshRate.lessThanWithMargin(
                        Fps(mConfig.frameRateMultipleThreshold / 2))) {
                // Don't vote high refresh rates past the threshold for layers with a low desired
                // refresh rate. For example, desired 24 fps with 120 Hz threshold means no vote for
                // 120 Hz, but desired 60 fps should have a vote.
                return false;
            }
            break;
        case LayerVoteType::ExplicitDefault:
        case LayerVoteType::ExplicitExact:
        case LayerVoteType::Max:
        case LayerVoteType::Min:
        case LayerVoteType::NoVote:
            break;
    }
    return true;
}

float RefreshRateConfigs::calculateNonExactMatchingLayerScoreLocked(
        const LayerRequirement& layer, const RefreshRate& refreshRate) const {
    constexpr float kScoreForFractionalPairs = .8f;

    const auto displayPeriod = refreshRate.getVsyncPeriod();
    const auto layerPeriod = layer.desiredRefreshRate.getPeriodNsecs();
    if (layer.vote == LayerVoteType::ExplicitDefault) {
        // Find the actual rate the layer will render, assuming
        // that layerPeriod is the minimal period to render a frame.
        // For example if layerPeriod is 20ms and displayPeriod is 16ms,
        // then the actualLayerPeriod will be 32ms, because it is the
        // smallest multiple of the display period which is >= layerPeriod.
        auto actualLayerPeriod = displayPeriod;
        int multiplier = 1;
        while (layerPeriod > actualLayerPeriod + MARGIN_FOR_PERIOD_CALCULATION) {
            multiplier++;
            actualLayerPeriod = displayPeriod * multiplier;
        }

        // Because of the threshold we used above it's possible that score is slightly
        // above 1.
        return std::min(1.0f,
                        static_cast<float>(layerPeriod) / static_cast<float>(actualLayerPeriod));
    }

    if (layer.vote == LayerVoteType::ExplicitExactOrMultiple ||
        layer.vote == LayerVoteType::Heuristic) {
        if (isFractionalPairOrMultiple(refreshRate.getFps(), layer.desiredRefreshRate)) {
            return kScoreForFractionalPairs;
        }

        // Calculate how many display vsyncs we need to present a single frame for this
        // layer
        const auto [displayFramesQuotient, displayFramesRemainder] =
                getDisplayFrames(layerPeriod, displayPeriod);
        static constexpr size_t MAX_FRAMES_TO_FIT = 10; // Stop calculating when score < 0.1
        if (displayFramesRemainder == 0) {
            // Layer desired refresh rate matches the display rate.
            return 1.0f;
        }

        if (displayFramesQuotient == 0) {
            // Layer desired refresh rate is higher than the display rate.
            return (static_cast<float>(layerPeriod) / static_cast<float>(displayPeriod)) *
                    (1.0f / (MAX_FRAMES_TO_FIT + 1));
        }

        // Layer desired refresh rate is lower than the display rate. Check how well it fits
        // the cadence.
        auto diff = std::abs(displayFramesRemainder - (displayPeriod - displayFramesRemainder));
        int iter = 2;
        while (diff > MARGIN_FOR_PERIOD_CALCULATION && iter < MAX_FRAMES_TO_FIT) {
            diff = diff - (displayPeriod - diff);
            iter++;
        }

        return (1.0f / iter);
    }

    return 0;
}

float RefreshRateConfigs::calculateLayerScoreLocked(const LayerRequirement& layer,
                                                    const RefreshRate& refreshRate,
                                                    bool isSeamlessSwitch) const {
    if (!isVoteAllowed(layer, refreshRate)) {
        return 0;
    }

    // Slightly prefer seamless switches.
    constexpr float kSeamedSwitchPenalty = 0.95f;
    const float seamlessness = isSeamlessSwitch ? 1.0f : kSeamedSwitchPenalty;

    // If the layer wants Max, give higher score to the higher refresh rate
    if (layer.vote == LayerVoteType::Max) {
        const auto ratio = refreshRate.getFps().getValue() /
                mAppRequestRefreshRates.back()->getFps().getValue();
        // use ratio^2 to get a lower score the more we get further from peak
        return ratio * ratio;
    }

    if (layer.vote == LayerVoteType::ExplicitExact) {
        const int divider = getFrameRateDivider(refreshRate.getFps(), layer.desiredRefreshRate);
        if (mSupportsFrameRateOverride) {
            // Since we support frame rate override, allow refresh rates which are
            // multiples of the layer's request, as those apps would be throttled
            // down to run at the desired refresh rate.
            return divider > 0;
        }

        return divider == 1;
    }

    // If the layer frame rate is a divider of the refresh rate it should score
    // the highest score.
    if (getFrameRateDivider(refreshRate.getFps(), layer.desiredRefreshRate) > 0) {
        return 1.0f * seamlessness;
    }

    // The layer frame rate is not a divider of the refresh rate,
    // there is a small penalty attached to the score to favor the frame rates
    // the exactly matches the display refresh rate or a multiple.
    constexpr float kNonExactMatchingPenalty = 0.95f;
    return calculateNonExactMatchingLayerScoreLocked(layer, refreshRate) * seamlessness *
            kNonExactMatchingPenalty;
}

struct RefreshRateScore {
    const RefreshRate* refreshRate;
    float score;
};

RefreshRate RefreshRateConfigs::getBestRefreshRate(const std::vector<LayerRequirement>& layers,
                                                   const GlobalSignals& globalSignals,
                                                   GlobalSignals* outSignalsConsidered) const {
    std::lock_guard lock(mLock);

    if (auto cached = getCachedBestRefreshRate(layers, globalSignals, outSignalsConsidered)) {
        return *cached;
    }

    GlobalSignals signalsConsidered;
    RefreshRate result = getBestRefreshRateLocked(layers, globalSignals, &signalsConsidered);
    lastBestRefreshRateInvocation.emplace(
            GetBestRefreshRateInvocation{.layerRequirements = layers,
                                         .globalSignals = globalSignals,
                                         .outSignalsConsidered = signalsConsidered,
                                         .resultingBestRefreshRate = result});
    if (outSignalsConsidered) {
        *outSignalsConsidered = signalsConsidered;
    }
    return result;
}

std::optional<RefreshRate> RefreshRateConfigs::getCachedBestRefreshRate(
        const std::vector<LayerRequirement>& layers, const GlobalSignals& globalSignals,
        GlobalSignals* outSignalsConsidered) const {
    const bool sameAsLastCall = lastBestRefreshRateInvocation &&
            lastBestRefreshRateInvocation->layerRequirements == layers &&
            lastBestRefreshRateInvocation->globalSignals == globalSignals;

    if (sameAsLastCall) {
        if (outSignalsConsidered) {
            *outSignalsConsidered = lastBestRefreshRateInvocation->outSignalsConsidered;
        }
        return lastBestRefreshRateInvocation->resultingBestRefreshRate;
    }

    return {};
}

RefreshRate RefreshRateConfigs::getBestRefreshRateLocked(
        const std::vector<LayerRequirement>& layers, const GlobalSignals& globalSignals,
        GlobalSignals* outSignalsConsidered) const {
    ATRACE_CALL();
    ALOGV("getBestRefreshRate %zu layers", layers.size());

    if (outSignalsConsidered) *outSignalsConsidered = {};
    const auto setTouchConsidered = [&] {
        if (outSignalsConsidered) {
            outSignalsConsidered->touch = true;
        }
    };

    const auto setIdleConsidered = [&] {
        if (outSignalsConsidered) {
            outSignalsConsidered->idle = true;
        }
    };

    int noVoteLayers = 0;
    int minVoteLayers = 0;
    int maxVoteLayers = 0;
    int explicitDefaultVoteLayers = 0;
    int explicitExactOrMultipleVoteLayers = 0;
    int explicitExact = 0;
    float maxExplicitWeight = 0;
    int seamedFocusedLayers = 0;
    for (const auto& layer : layers) {
        switch (layer.vote) {
            case LayerVoteType::NoVote:
                noVoteLayers++;
                break;
            case LayerVoteType::Min:
                minVoteLayers++;
                break;
            case LayerVoteType::Max:
                maxVoteLayers++;
                break;
            case LayerVoteType::ExplicitDefault:
                explicitDefaultVoteLayers++;
                maxExplicitWeight = std::max(maxExplicitWeight, layer.weight);
                break;
            case LayerVoteType::ExplicitExactOrMultiple:
                explicitExactOrMultipleVoteLayers++;
                maxExplicitWeight = std::max(maxExplicitWeight, layer.weight);
                break;
            case LayerVoteType::ExplicitExact:
                explicitExact++;
                maxExplicitWeight = std::max(maxExplicitWeight, layer.weight);
                break;
            case LayerVoteType::Heuristic:
                break;
        }

        if (layer.seamlessness == Seamlessness::SeamedAndSeamless && layer.focused) {
            seamedFocusedLayers++;
        }
    }

    const bool hasExplicitVoteLayers = explicitDefaultVoteLayers > 0 ||
            explicitExactOrMultipleVoteLayers > 0 || explicitExact > 0;

    // Consider the touch event if there are no Explicit* layers. Otherwise wait until after we've
    // selected a refresh rate to see if we should apply touch boost.
    if (globalSignals.touch && !hasExplicitVoteLayers) {
        ALOGV("TouchBoost - choose %s", getMaxRefreshRateByPolicyLocked().getName().c_str());
        setTouchConsidered();
        return getMaxRefreshRateByPolicyLocked();
    }

    // If the primary range consists of a single refresh rate then we can only
    // move out the of range if layers explicitly request a different refresh
    // rate.
    const Policy* policy = getCurrentPolicyLocked();
    const bool primaryRangeIsSingleRate =
            policy->primaryRange.min.equalsWithMargin(policy->primaryRange.max);

    if (!globalSignals.touch && globalSignals.idle &&
        !(primaryRangeIsSingleRate && hasExplicitVoteLayers)) {
        ALOGV("Idle - choose %s", getMinRefreshRateByPolicyLocked().getName().c_str());
        setIdleConsidered();
        return getMinRefreshRateByPolicyLocked();
    }

    if (layers.empty() || noVoteLayers == layers.size()) {
        return getMaxRefreshRateByPolicyLocked();
    }

    // Only if all layers want Min we should return Min
    if (noVoteLayers + minVoteLayers == layers.size()) {
        ALOGV("all layers Min - choose %s", getMinRefreshRateByPolicyLocked().getName().c_str());
        return getMinRefreshRateByPolicyLocked();
    }

    // Find the best refresh rate based on score
    std::vector<RefreshRateScore> scores;
    scores.reserve(mAppRequestRefreshRates.size());

    for (const auto refreshRate : mAppRequestRefreshRates) {
        scores.emplace_back(RefreshRateScore{refreshRate, 0.0f});
    }

    const auto& defaultMode = mRefreshRates.at(policy->defaultMode);

    for (const auto& layer : layers) {
        ALOGV("Calculating score for %s (%s, weight %.2f, desired %.2f) ", layer.name.c_str(),
              layerVoteTypeString(layer.vote).c_str(), layer.weight,
              layer.desiredRefreshRate.getValue());
        if (layer.vote == LayerVoteType::NoVote || layer.vote == LayerVoteType::Min) {
            continue;
        }

        auto weight = layer.weight;

        for (auto i = 0u; i < scores.size(); i++) {
            const bool isSeamlessSwitch =
                    scores[i].refreshRate->getModeGroup() == mCurrentRefreshRate->getModeGroup();

            if (layer.seamlessness == Seamlessness::OnlySeamless && !isSeamlessSwitch) {
                ALOGV("%s ignores %s to avoid non-seamless switch. Current mode = %s",
                      formatLayerInfo(layer, weight).c_str(),
                      scores[i].refreshRate->toString().c_str(),
                      mCurrentRefreshRate->toString().c_str());
                continue;
            }

            if (layer.seamlessness == Seamlessness::SeamedAndSeamless && !isSeamlessSwitch &&
                !layer.focused) {
                ALOGV("%s ignores %s because it's not focused and the switch is going to be seamed."
                      " Current mode = %s",
                      formatLayerInfo(layer, weight).c_str(),
                      scores[i].refreshRate->toString().c_str(),
                      mCurrentRefreshRate->toString().c_str());
                continue;
            }

            // Layers with default seamlessness vote for the current mode group if
            // there are layers with seamlessness=SeamedAndSeamless and for the default
            // mode group otherwise. In second case, if the current mode group is different
            // from the default, this means a layer with seamlessness=SeamedAndSeamless has just
            // disappeared.
            const bool isInPolicyForDefault = seamedFocusedLayers > 0
                    ? scores[i].refreshRate->getModeGroup() == mCurrentRefreshRate->getModeGroup()
                    : scores[i].refreshRate->getModeGroup() == defaultMode->getModeGroup();

            if (layer.seamlessness == Seamlessness::Default && !isInPolicyForDefault) {
                ALOGV("%s ignores %s. Current mode = %s", formatLayerInfo(layer, weight).c_str(),
                      scores[i].refreshRate->toString().c_str(),
                      mCurrentRefreshRate->toString().c_str());
                continue;
            }

            bool inPrimaryRange = scores[i].refreshRate->inPolicy(policy->primaryRange.min,
                                                                  policy->primaryRange.max);
            if ((primaryRangeIsSingleRate || !inPrimaryRange) &&
                !(layer.focused &&
                  (layer.vote == LayerVoteType::ExplicitDefault ||
                   layer.vote == LayerVoteType::ExplicitExact))) {
                // Only focused layers with ExplicitDefault frame rate settings are allowed to score
                // refresh rates outside the primary range.
                continue;
            }

            const auto layerScore =
                    calculateLayerScoreLocked(layer, *scores[i].refreshRate, isSeamlessSwitch);
            ALOGV("%s gives %s score of %.4f", formatLayerInfo(layer, weight).c_str(),
                  scores[i].refreshRate->getName().c_str(), layerScore);
            scores[i].score += weight * layerScore;
        }
    }

    // Now that we scored all the refresh rates we need to pick the one that got the highest score.
    // In case of a tie we will pick the higher refresh rate if any of the layers wanted Max,
    // or the lower otherwise.
    const RefreshRate* bestRefreshRate = maxVoteLayers > 0
            ? getBestRefreshRate(scores.rbegin(), scores.rend())
            : getBestRefreshRate(scores.begin(), scores.end());

    if (primaryRangeIsSingleRate) {
        // If we never scored any layers, then choose the rate from the primary
        // range instead of picking a random score from the app range.
        if (std::all_of(scores.begin(), scores.end(),
                        [](RefreshRateScore score) { return score.score == 0; })) {
            ALOGV("layers not scored - choose %s",
                  getMaxRefreshRateByPolicyLocked().getName().c_str());
            return getMaxRefreshRateByPolicyLocked();
        } else {
            return *bestRefreshRate;
        }
    }

    // Consider the touch event if there are no ExplicitDefault layers. ExplicitDefault are mostly
    // interactive (as opposed to ExplicitExactOrMultiple) and therefore if those posted an explicit
    // vote we should not change it if we get a touch event. Only apply touch boost if it will
    // actually increase the refresh rate over the normal selection.
    const RefreshRate& touchRefreshRate = getMaxRefreshRateByPolicyLocked();

    const bool touchBoostForExplicitExact = [&] {
        if (mSupportsFrameRateOverride) {
            // Enable touch boost if there are other layers besides exact
            return explicitExact + noVoteLayers != layers.size();
        } else {
            // Enable touch boost if there are no exact layers
            return explicitExact == 0;
        }
    }();
    if (globalSignals.touch && explicitDefaultVoteLayers == 0 && touchBoostForExplicitExact &&
        bestRefreshRate->getFps().lessThanWithMargin(touchRefreshRate.getFps())) {
        setTouchConsidered();
        ALOGV("TouchBoost - choose %s", touchRefreshRate.getName().c_str());
        return touchRefreshRate;
    }

    return *bestRefreshRate;
}

std::unordered_map<uid_t, std::vector<const RefreshRateConfigs::LayerRequirement*>>
groupLayersByUid(const std::vector<RefreshRateConfigs::LayerRequirement>& layers) {
    std::unordered_map<uid_t, std::vector<const RefreshRateConfigs::LayerRequirement*>> layersByUid;
    for (const auto& layer : layers) {
        auto iter = layersByUid.emplace(layer.ownerUid,
                                        std::vector<const RefreshRateConfigs::LayerRequirement*>());
        auto& layersWithSameUid = iter.first->second;
        layersWithSameUid.push_back(&layer);
    }

    // Remove uids that can't have a frame rate override
    for (auto iter = layersByUid.begin(); iter != layersByUid.end();) {
        const auto& layersWithSameUid = iter->second;
        bool skipUid = false;
        for (const auto& layer : layersWithSameUid) {
            if (layer->vote == RefreshRateConfigs::LayerVoteType::Max ||
                layer->vote == RefreshRateConfigs::LayerVoteType::Heuristic) {
                skipUid = true;
                break;
            }
        }
        if (skipUid) {
            iter = layersByUid.erase(iter);
        } else {
            ++iter;
        }
    }

    return layersByUid;
}

std::vector<RefreshRateScore> initializeScoresForAllRefreshRates(
        const AllRefreshRatesMapType& refreshRates) {
    std::vector<RefreshRateScore> scores;
    scores.reserve(refreshRates.size());
    for (const auto& [ignored, refreshRate] : refreshRates) {
        scores.emplace_back(RefreshRateScore{refreshRate.get(), 0.0f});
    }
    std::sort(scores.begin(), scores.end(),
              [](const auto& a, const auto& b) { return *a.refreshRate < *b.refreshRate; });
    return scores;
}

RefreshRateConfigs::UidToFrameRateOverride RefreshRateConfigs::getFrameRateOverrides(
        const std::vector<LayerRequirement>& layers, Fps displayFrameRate, bool touch) const {
    ATRACE_CALL();
    if (!mSupportsFrameRateOverride) return {};

    ALOGV("getFrameRateOverrides %zu layers", layers.size());
    std::lock_guard lock(mLock);
    std::vector<RefreshRateScore> scores = initializeScoresForAllRefreshRates(mRefreshRates);
    std::unordered_map<uid_t, std::vector<const LayerRequirement*>> layersByUid =
            groupLayersByUid(layers);
    UidToFrameRateOverride frameRateOverrides;
    for (const auto& [uid, layersWithSameUid] : layersByUid) {
        // Layers with ExplicitExactOrMultiple expect touch boost
        const bool hasExplicitExactOrMultiple =
                std::any_of(layersWithSameUid.cbegin(), layersWithSameUid.cend(),
                            [](const auto& layer) {
                                return layer->vote == LayerVoteType::ExplicitExactOrMultiple;
                            });

        if (touch && hasExplicitExactOrMultiple) {
            continue;
        }

        for (auto& score : scores) {
            score.score = 0;
        }

        for (const auto& layer : layersWithSameUid) {
            if (layer->vote == LayerVoteType::NoVote || layer->vote == LayerVoteType::Min) {
                continue;
            }

            LOG_ALWAYS_FATAL_IF(layer->vote != LayerVoteType::ExplicitDefault &&
                                layer->vote != LayerVoteType::ExplicitExactOrMultiple &&
                                layer->vote != LayerVoteType::ExplicitExact);
            for (RefreshRateScore& score : scores) {
                const auto layerScore = calculateLayerScoreLocked(*layer, *score.refreshRate,
                                                                  /*isSeamlessSwitch*/ true);
                score.score += layer->weight * layerScore;
            }
        }

        // We just care about the refresh rates which are a divider of the
        // display refresh rate
        auto iter =
                std::remove_if(scores.begin(), scores.end(), [&](const RefreshRateScore& score) {
                    return getFrameRateDivider(displayFrameRate, score.refreshRate->getFps()) == 0;
                });
        scores.erase(iter, scores.end());

        // If we never scored any layers, we don't have a preferred frame rate
        if (std::all_of(scores.begin(), scores.end(),
                        [](const RefreshRateScore& score) { return score.score == 0; })) {
            continue;
        }

        // Now that we scored all the refresh rates we need to pick the one that got the highest
        // score.
        const RefreshRate* bestRefreshRate = getBestRefreshRate(scores.begin(), scores.end());
        frameRateOverrides.emplace(uid, bestRefreshRate->getFps());
    }

    return frameRateOverrides;
}

template <typename Iter>
const RefreshRate* RefreshRateConfigs::getBestRefreshRate(Iter begin, Iter end) const {
    constexpr auto kEpsilon = 0.0001f;
    const RefreshRate* bestRefreshRate = begin->refreshRate;
    float max = begin->score;
    for (auto i = begin; i != end; ++i) {
        const auto [refreshRate, score] = *i;
        ALOGV("%s scores %.2f", refreshRate->getName().c_str(), score);

        ATRACE_INT(refreshRate->getName().c_str(), round<int>(score * 100));

        if (score > max * (1 + kEpsilon)) {
            max = score;
            bestRefreshRate = refreshRate;
        }
    }

    return bestRefreshRate;
}

std::optional<Fps> RefreshRateConfigs::onKernelTimerChanged(
        std::optional<DisplayModeId> desiredActiveConfigId, bool timerExpired) const {
    std::lock_guard lock(mLock);

    const auto& current = desiredActiveConfigId ? *mRefreshRates.at(*desiredActiveConfigId)
                                                : *mCurrentRefreshRate;
    const auto& min = *mMinSupportedRefreshRate;

    if (current != min) {
        const auto& refreshRate = timerExpired ? min : current;
        return refreshRate.getFps();
    }

    return {};
}

const RefreshRate& RefreshRateConfigs::getMinRefreshRateByPolicyLocked() const {
    for (auto refreshRate : mPrimaryRefreshRates) {
        if (mCurrentRefreshRate->getModeGroup() == refreshRate->getModeGroup()) {
            return *refreshRate;
        }
    }
    ALOGE("Can't find min refresh rate by policy with the same mode group"
          " as the current mode %s",
          mCurrentRefreshRate->toString().c_str());
    // Defaulting to the lowest refresh rate
    return *mPrimaryRefreshRates.front();
}

RefreshRate RefreshRateConfigs::getMaxRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
    return getMaxRefreshRateByPolicyLocked();
}

const RefreshRate& RefreshRateConfigs::getMaxRefreshRateByPolicyLocked() const {
    for (auto it = mPrimaryRefreshRates.rbegin(); it != mPrimaryRefreshRates.rend(); it++) {
        const auto& refreshRate = (**it);
        if (mCurrentRefreshRate->getModeGroup() == refreshRate.getModeGroup()) {
            return refreshRate;
        }
    }
    ALOGE("Can't find max refresh rate by policy with the same mode group"
          " as the current mode %s",
          mCurrentRefreshRate->toString().c_str());
    // Defaulting to the highest refresh rate
    return *mPrimaryRefreshRates.back();
}

RefreshRate RefreshRateConfigs::getCurrentRefreshRate() const {
    std::lock_guard lock(mLock);
    return *mCurrentRefreshRate;
}

RefreshRate RefreshRateConfigs::getCurrentRefreshRateByPolicy() const {
    std::lock_guard lock(mLock);
    return getCurrentRefreshRateByPolicyLocked();
}

const RefreshRate& RefreshRateConfigs::getCurrentRefreshRateByPolicyLocked() const {
    if (std::find(mAppRequestRefreshRates.begin(), mAppRequestRefreshRates.end(),
                  mCurrentRefreshRate) != mAppRequestRefreshRates.end()) {
        return *mCurrentRefreshRate;
    }
    return *mRefreshRates.at(getCurrentPolicyLocked()->defaultMode);
}

void RefreshRateConfigs::setCurrentModeId(DisplayModeId modeId) {
    std::lock_guard lock(mLock);

    // Invalidate the cached invocation to getBestRefreshRate. This forces
    // the refresh rate to be recomputed on the next call to getBestRefreshRate.
    lastBestRefreshRateInvocation.reset();

    mCurrentRefreshRate = mRefreshRates.at(modeId).get();
}

RefreshRateConfigs::RefreshRateConfigs(const DisplayModes& modes, DisplayModeId currentModeId,
                                       Config config)
      : mKnownFrameRates(constructKnownFrameRates(modes)), mConfig(config) {
    initializeIdleTimer();
    updateDisplayModes(modes, currentModeId);
}

void RefreshRateConfigs::initializeIdleTimer() {
    if (mConfig.idleTimerTimeoutMs > 0) {
        const auto getCallback = [this]() -> std::optional<IdleTimerCallbacks::Callbacks> {
            std::scoped_lock lock(mIdleTimerCallbacksMutex);
            if (!mIdleTimerCallbacks.has_value()) return {};
            return mConfig.supportKernelIdleTimer ? mIdleTimerCallbacks->kernel
                                                  : mIdleTimerCallbacks->platform;
        };

        mIdleTimer.emplace(
                "IdleTimer", std::chrono::milliseconds(mConfig.idleTimerTimeoutMs),
                [getCallback] {
                    if (const auto callback = getCallback()) callback->onReset();
                },
                [getCallback] {
                    if (const auto callback = getCallback()) callback->onExpired();
                });
    }
}

void RefreshRateConfigs::updateDisplayModes(const DisplayModes& modes,
                                            DisplayModeId currentModeId) {
    std::lock_guard lock(mLock);

    // The current mode should be supported
    LOG_ALWAYS_FATAL_IF(std::none_of(modes.begin(), modes.end(), [&](DisplayModePtr mode) {
        return mode->getId() == currentModeId;
    }));

    // Invalidate the cached invocation to getBestRefreshRate. This forces
    // the refresh rate to be recomputed on the next call to getBestRefreshRate.
    lastBestRefreshRateInvocation.reset();

    mRefreshRates.clear();
    for (const auto& mode : modes) {
        const auto modeId = mode->getId();
        mRefreshRates.emplace(modeId,
                              std::make_unique<RefreshRate>(mode, RefreshRate::ConstructorTag(0)));
        if (modeId == currentModeId) {
            mCurrentRefreshRate = mRefreshRates.at(modeId).get();
        }
    }

    std::vector<const RefreshRate*> sortedModes;
    getSortedRefreshRateListLocked([](const RefreshRate&) { return true; }, &sortedModes);
    // Reset the policy because the old one may no longer be valid.
    mDisplayManagerPolicy = {};
    mDisplayManagerPolicy.defaultMode = currentModeId;
    mMinSupportedRefreshRate = sortedModes.front();
    mMaxSupportedRefreshRate = sortedModes.back();

    mSupportsFrameRateOverride = false;
    if (mConfig.enableFrameRateOverride) {
        for (const auto& mode1 : sortedModes) {
            for (const auto& mode2 : sortedModes) {
                if (getFrameRateDivider(mode1->getFps(), mode2->getFps()) >= 2) {
                    mSupportsFrameRateOverride = true;
                    break;
                }
            }
        }
    }

    constructAvailableRefreshRates();
}

bool RefreshRateConfigs::isPolicyValidLocked(const Policy& policy) const {
    // defaultMode must be a valid mode, and within the given refresh rate range.
    auto iter = mRefreshRates.find(policy.defaultMode);
    if (iter == mRefreshRates.end()) {
        ALOGE("Default mode is not found.");
        return false;
    }
    const RefreshRate& refreshRate = *iter->second;
    if (!refreshRate.inPolicy(policy.primaryRange.min, policy.primaryRange.max)) {
        ALOGE("Default mode is not in the primary range.");
        return false;
    }
    return policy.appRequestRange.min.lessThanOrEqualWithMargin(policy.primaryRange.min) &&
            policy.appRequestRange.max.greaterThanOrEqualWithMargin(policy.primaryRange.max);
}

status_t RefreshRateConfigs::setDisplayManagerPolicy(const Policy& policy) {
    std::lock_guard lock(mLock);
    if (!isPolicyValidLocked(policy)) {
        ALOGE("Invalid refresh rate policy: %s", policy.toString().c_str());
        return BAD_VALUE;
    }
    lastBestRefreshRateInvocation.reset();
    Policy previousPolicy = *getCurrentPolicyLocked();
    mDisplayManagerPolicy = policy;
    if (*getCurrentPolicyLocked() == previousPolicy) {
        return CURRENT_POLICY_UNCHANGED;
    }
    constructAvailableRefreshRates();
    return NO_ERROR;
}

status_t RefreshRateConfigs::setOverridePolicy(const std::optional<Policy>& policy) {
    std::lock_guard lock(mLock);
    if (policy && !isPolicyValidLocked(*policy)) {
        return BAD_VALUE;
    }
    lastBestRefreshRateInvocation.reset();
    Policy previousPolicy = *getCurrentPolicyLocked();
    mOverridePolicy = policy;
    if (*getCurrentPolicyLocked() == previousPolicy) {
        return CURRENT_POLICY_UNCHANGED;
    }
    constructAvailableRefreshRates();
    return NO_ERROR;
}

const RefreshRateConfigs::Policy* RefreshRateConfigs::getCurrentPolicyLocked() const {
    return mOverridePolicy ? &mOverridePolicy.value() : &mDisplayManagerPolicy;
}

RefreshRateConfigs::Policy RefreshRateConfigs::getCurrentPolicy() const {
    std::lock_guard lock(mLock);
    return *getCurrentPolicyLocked();
}

RefreshRateConfigs::Policy RefreshRateConfigs::getDisplayManagerPolicy() const {
    std::lock_guard lock(mLock);
    return mDisplayManagerPolicy;
}

bool RefreshRateConfigs::isModeAllowed(DisplayModeId modeId) const {
    std::lock_guard lock(mLock);
    for (const RefreshRate* refreshRate : mAppRequestRefreshRates) {
        if (refreshRate->getModeId() == modeId) {
            return true;
        }
    }
    return false;
}

void RefreshRateConfigs::getSortedRefreshRateListLocked(
        const std::function<bool(const RefreshRate&)>& shouldAddRefreshRate,
        std::vector<const RefreshRate*>* outRefreshRates) {
    outRefreshRates->clear();
    outRefreshRates->reserve(mRefreshRates.size());
    for (const auto& [type, refreshRate] : mRefreshRates) {
        if (shouldAddRefreshRate(*refreshRate)) {
            ALOGV("getSortedRefreshRateListLocked: mode %d added to list policy",
                  refreshRate->getModeId().value());
            outRefreshRates->push_back(refreshRate.get());
        }
    }

    std::sort(outRefreshRates->begin(), outRefreshRates->end(),
              [](const auto refreshRate1, const auto refreshRate2) {
                  if (refreshRate1->mode->getVsyncPeriod() !=
                      refreshRate2->mode->getVsyncPeriod()) {
                      return refreshRate1->mode->getVsyncPeriod() >
                              refreshRate2->mode->getVsyncPeriod();
                  } else {
                      return refreshRate1->mode->getGroup() > refreshRate2->mode->getGroup();
                  }
              });
}

void RefreshRateConfigs::constructAvailableRefreshRates() {
    // Filter modes based on current policy and sort based on vsync period
    const Policy* policy = getCurrentPolicyLocked();
    const auto& defaultMode = mRefreshRates.at(policy->defaultMode)->mode;
    ALOGV("constructAvailableRefreshRates: %s ", policy->toString().c_str());

    auto filterRefreshRates =
            [&](Fps min, Fps max, const char* listName,
                std::vector<const RefreshRate*>* outRefreshRates) REQUIRES(mLock) {
                getSortedRefreshRateListLocked(
                        [&](const RefreshRate& refreshRate) REQUIRES(mLock) {
                            const auto& mode = refreshRate.mode;

                            return mode->getHeight() == defaultMode->getHeight() &&
                                    mode->getWidth() == defaultMode->getWidth() &&
                                    mode->getDpiX() == defaultMode->getDpiX() &&
                                    mode->getDpiY() == defaultMode->getDpiY() &&
                                    (policy->allowGroupSwitching ||
                                     mode->getGroup() == defaultMode->getGroup()) &&
                                    refreshRate.inPolicy(min, max);
                        },
                        outRefreshRates);

                LOG_ALWAYS_FATAL_IF(outRefreshRates->empty(),
                                    "No matching modes for %s range: min=%s max=%s", listName,
                                    to_string(min).c_str(), to_string(max).c_str());
                auto stringifyRefreshRates = [&]() -> std::string {
                    std::string str;
                    for (auto refreshRate : *outRefreshRates) {
                        base::StringAppendF(&str, "%s ", refreshRate->getName().c_str());
                    }
                    return str;
                };
                ALOGV("%s refresh rates: %s", listName, stringifyRefreshRates().c_str());
            };

    filterRefreshRates(policy->primaryRange.min, policy->primaryRange.max, "primary",
                       &mPrimaryRefreshRates);
    filterRefreshRates(policy->appRequestRange.min, policy->appRequestRange.max, "app request",
                       &mAppRequestRefreshRates);
}

Fps RefreshRateConfigs::findClosestKnownFrameRate(Fps frameRate) const {
    if (frameRate.lessThanOrEqualWithMargin(*mKnownFrameRates.begin())) {
        return *mKnownFrameRates.begin();
    }

    if (frameRate.greaterThanOrEqualWithMargin(*std::prev(mKnownFrameRates.end()))) {
        return *std::prev(mKnownFrameRates.end());
    }

    auto lowerBound = std::lower_bound(mKnownFrameRates.begin(), mKnownFrameRates.end(), frameRate,
                                       Fps::comparesLess);

    const auto distance1 = std::abs((frameRate.getValue() - lowerBound->getValue()));
    const auto distance2 = std::abs((frameRate.getValue() - std::prev(lowerBound)->getValue()));
    return distance1 < distance2 ? *lowerBound : *std::prev(lowerBound);
}

RefreshRateConfigs::KernelIdleTimerAction RefreshRateConfigs::getIdleTimerAction() const {
    std::lock_guard lock(mLock);
    const auto& deviceMin = *mMinSupportedRefreshRate;
    const auto& minByPolicy = getMinRefreshRateByPolicyLocked();
    const auto& maxByPolicy = getMaxRefreshRateByPolicyLocked();
    const auto& currentPolicy = getCurrentPolicyLocked();

    // Kernel idle timer will set the refresh rate to the device min. If DisplayManager says that
    // the min allowed refresh rate is higher than the device min, we do not want to enable the
    // timer.
    if (deviceMin < minByPolicy) {
        return RefreshRateConfigs::KernelIdleTimerAction::TurnOff;
    }
    if (minByPolicy == maxByPolicy) {
        // when min primary range in display manager policy is below device min turn on the timer.
        if (currentPolicy->primaryRange.min.lessThanWithMargin(deviceMin.getFps())) {
            return RefreshRateConfigs::KernelIdleTimerAction::TurnOn;
        }
        return RefreshRateConfigs::KernelIdleTimerAction::TurnOff;
    }
    // Turn on the timer in all other cases.
    return RefreshRateConfigs::KernelIdleTimerAction::TurnOn;
}

int RefreshRateConfigs::getFrameRateDivider(Fps displayFrameRate, Fps layerFrameRate) {
    // This calculation needs to be in sync with the java code
    // in DisplayManagerService.getDisplayInfoForFrameRateOverride

    // The threshold must be smaller than 0.001 in order to differentiate
    // between the fractional pairs (e.g. 59.94 and 60).
    constexpr float kThreshold = 0.0009f;
    const auto numPeriods = displayFrameRate.getValue() / layerFrameRate.getValue();
    const auto numPeriodsRounded = std::round(numPeriods);
    if (std::abs(numPeriods - numPeriodsRounded) > kThreshold) {
        return 0;
    }

    return static_cast<int>(numPeriodsRounded);
}

bool RefreshRateConfigs::isFractionalPairOrMultiple(Fps smaller, Fps bigger) {
    if (smaller.getValue() > bigger.getValue()) {
        return isFractionalPairOrMultiple(bigger, smaller);
    }

    const auto multiplier = std::round(bigger.getValue() / smaller.getValue());
    constexpr float kCoef = 1000.f / 1001.f;
    return bigger.equalsWithMargin(Fps(smaller.getValue() * multiplier / kCoef)) ||
            bigger.equalsWithMargin(Fps(smaller.getValue() * multiplier * kCoef));
}

void RefreshRateConfigs::dump(std::string& result) const {
    std::lock_guard lock(mLock);
    base::StringAppendF(&result, "DesiredDisplayModeSpecs (DisplayManager): %s\n\n",
                        mDisplayManagerPolicy.toString().c_str());
    scheduler::RefreshRateConfigs::Policy currentPolicy = *getCurrentPolicyLocked();
    if (mOverridePolicy && currentPolicy != mDisplayManagerPolicy) {
        base::StringAppendF(&result, "DesiredDisplayModeSpecs (Override): %s\n\n",
                            currentPolicy.toString().c_str());
    }

    auto mode = mCurrentRefreshRate->mode;
    base::StringAppendF(&result, "Current mode: %s\n", mCurrentRefreshRate->toString().c_str());

    result.append("Refresh rates:\n");
    for (const auto& [id, refreshRate] : mRefreshRates) {
        mode = refreshRate->mode;
        base::StringAppendF(&result, "\t%s\n", refreshRate->toString().c_str());
    }

    base::StringAppendF(&result, "Supports Frame Rate Override: %s\n",
                        mSupportsFrameRateOverride ? "yes" : "no");
    base::StringAppendF(&result, "Idle timer: (%s) %s\n",
                        mConfig.supportKernelIdleTimer ? "kernel" : "platform",
                        mIdleTimer ? mIdleTimer->dump().c_str() : "off");
    result.append("\n");
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"
