/*
 * Copyright 2021 The Android Open Source Project
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
#define LOG_TAG "Planner"
// #define LOG_NDEBUG 0
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <android-base/properties.h>
#include <compositionengine/impl/planner/Flattener.h>
#include <compositionengine/impl/planner/LayerState.h>

#include <gui/TraceUtils.h>

using time_point = std::chrono::steady_clock::time_point;
using namespace std::chrono_literals;

namespace android::compositionengine::impl::planner {

namespace {

// True if the underlying layer stack is the same modulo state that would be expected to be
// different like specific buffers, false otherwise.
bool isSameStack(const std::vector<const LayerState*>& incomingLayers,
                 const std::vector<CachedSet>& cachedSets) {
    std::vector<const LayerState*> existingLayers;
    for (auto& cachedSet : cachedSets) {
        for (auto& layer : cachedSet.getConstituentLayers()) {
            existingLayers.push_back(layer.getState());
        }
    }

    if (incomingLayers.size() != existingLayers.size()) {
        return false;
    }

    for (size_t i = 0; i < incomingLayers.size(); i++) {
        // Checking the IDs here is very strict, but we do this as otherwise we may mistakenly try
        // to access destroyed OutputLayers later on.
        if (incomingLayers[i]->getId() != existingLayers[i]->getId() ||
            incomingLayers[i]->getDifferingFields(*(existingLayers[i])) != LayerStateField::None) {
            return false;
        }
    }
    return true;
}

} // namespace

Flattener::Flattener(renderengine::RenderEngine& renderEngine, const Tunables& tunables)
      : mRenderEngine(renderEngine), mTunables(tunables), mTexturePool(mRenderEngine) {}

NonBufferHash Flattener::flattenLayers(const std::vector<const LayerState*>& layers,
                                       NonBufferHash hash, time_point now) {
    ATRACE_CALL();
    const size_t unflattenedDisplayCost = calculateDisplayCost(layers);
    mUnflattenedDisplayCost += unflattenedDisplayCost;

    // We invalidate the layer cache if:
    // 1. We're not tracking any layers, or
    // 2. The last seen hashed geometry changed between frames, or
    // 3. A stricter equality check demonstrates that the layer stack really did change, since the
    // hashed geometry does not guarantee uniqueness.
    if (mCurrentGeometry != hash || (!mLayers.empty() && !isSameStack(layers, mLayers))) {
        resetActivities(hash, now);
        mFlattenedDisplayCost += unflattenedDisplayCost;
        return hash;
    }

    ++mInitialLayerCounts[layers.size()];

    // Only buildCachedSets if these layers are already stored in mLayers.
    // Otherwise (i.e. mergeWithCachedSets returns false), the time has not
    // changed, so buildCachedSets will never find any runs.
    const bool alreadyHadCachedSets = mergeWithCachedSets(layers, now);

    ++mFinalLayerCounts[mLayers.size()];

    if (alreadyHadCachedSets) {
        buildCachedSets(now);
        hash = computeLayersHash();
    }

    return hash;
}

void Flattener::renderCachedSets(
        const OutputCompositionState& outputState,
        std::optional<std::chrono::steady_clock::time_point> renderDeadline,
        bool deviceHandlesColorTransform) {
    ATRACE_CALL();

    if (!mNewCachedSet) {
        return;
    }

    // Ensure that a cached set has a valid buffer first
    if (mNewCachedSet->hasRenderedBuffer()) {
        ATRACE_NAME("mNewCachedSet->hasRenderedBuffer()");
        return;
    }

    const auto now = std::chrono::steady_clock::now();

    // If we have a render deadline, and the flattener is configured to skip rendering if we don't
    // have enough time, then we skip rendering the cached set if we think that we'll steal too much
    // time from the next frame.
    if (renderDeadline && mTunables.mRenderScheduling) {
        if (const auto estimatedRenderFinish =
                    now + mTunables.mRenderScheduling->cachedSetRenderDuration;
            estimatedRenderFinish > *renderDeadline) {
            mNewCachedSet->incrementSkipCount();

            if (mNewCachedSet->getSkipCount() <=
                mTunables.mRenderScheduling->maxDeferRenderAttempts) {
                ATRACE_FORMAT("DeadlinePassed: exceeded deadline by: %d us",
                              std::chrono::duration_cast<std::chrono::microseconds>(
                                      estimatedRenderFinish - *renderDeadline)
                                      .count());
                return;
            } else {
                ATRACE_NAME("DeadlinePassed: exceeded max skips");
            }
        }
    }

    mNewCachedSet->render(mRenderEngine, mTexturePool, outputState, deviceHandlesColorTransform);
}

void Flattener::dumpLayers(std::string& result) const {
    result.append("  Current layers:");
    for (const CachedSet& layer : mLayers) {
        result.append("\n");
        layer.dump(result);
    }
}

void Flattener::dump(std::string& result) const {
    const auto now = std::chrono::steady_clock::now();

    base::StringAppendF(&result, "Flattener state:\n");

    result.append("\n  Statistics:\n");

    result.append("    Display cost (in screen-size buffers):\n");
    const size_t displayArea = static_cast<size_t>(mDisplaySize.width * mDisplaySize.height);
    base::StringAppendF(&result, "      Unflattened: %.2f\n",
                        static_cast<float>(mUnflattenedDisplayCost) / displayArea);
    base::StringAppendF(&result, "      Flattened:   %.2f\n",
                        static_cast<float>(mFlattenedDisplayCost) / displayArea);

    const auto compareLayerCounts = [](const std::pair<size_t, size_t>& left,
                                       const std::pair<size_t, size_t>& right) {
        return left.first < right.first;
    };

    const size_t maxLayerCount = mInitialLayerCounts.empty()
            ? 0u
            : std::max_element(mInitialLayerCounts.cbegin(), mInitialLayerCounts.cend(),
                               compareLayerCounts)
                      ->first;

    result.append("\n    Initial counts:\n");
    for (size_t count = 1; count < maxLayerCount; ++count) {
        size_t initial = mInitialLayerCounts.count(count) > 0 ? mInitialLayerCounts.at(count) : 0;
        base::StringAppendF(&result, "      % 2zd: %zd\n", count, initial);
    }

    result.append("\n    Final counts:\n");
    for (size_t count = 1; count < maxLayerCount; ++count) {
        size_t final = mFinalLayerCounts.count(count) > 0 ? mFinalLayerCounts.at(count) : 0;
        base::StringAppendF(&result, "      % 2zd: %zd\n", count, final);
    }

    base::StringAppendF(&result, "\n    Cached sets created: %zd\n", mCachedSetCreationCount);
    base::StringAppendF(&result, "    Cost: %.2f\n",
                        static_cast<float>(mCachedSetCreationCost) / displayArea);

    const auto lastUpdate =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - mLastGeometryUpdate);
    base::StringAppendF(&result, "\n  Current hash %016zx, last update %sago\n\n", mCurrentGeometry,
                        durationString(lastUpdate).c_str());

    dumpLayers(result);

    base::StringAppendF(&result, "\n");
    mTexturePool.dump(result);
}

size_t Flattener::calculateDisplayCost(const std::vector<const LayerState*>& layers) const {
    Region coveredRegion;
    size_t displayCost = 0;
    bool hasClientComposition = false;

    for (const LayerState* layer : layers) {
        coveredRegion.orSelf(layer->getDisplayFrame());

        // Regardless of composition type, we always have to read each input once
        displayCost += static_cast<size_t>(layer->getDisplayFrame().width() *
                                           layer->getDisplayFrame().height());

        hasClientComposition |= layer->getCompositionType() ==
                aidl::android::hardware::graphics::composer3::Composition::CLIENT;
    }

    if (hasClientComposition) {
        // If there is client composition, the client target buffer has to be both written by the
        // GPU and read by the DPU, so we pay its cost twice
        displayCost += 2 *
                static_cast<size_t>(coveredRegion.bounds().width() *
                                    coveredRegion.bounds().height());
    }

    return displayCost;
}

void Flattener::resetActivities(NonBufferHash hash, time_point now) {
    ALOGV("[%s]", __func__);

    mCurrentGeometry = hash;
    mLastGeometryUpdate = now;

    for (const CachedSet& cachedSet : mLayers) {
        if (cachedSet.getLayerCount() > 1) {
            ++mInvalidatedCachedSetAges[cachedSet.getAge()];
        }
    }

    mLayers.clear();

    if (mNewCachedSet) {
        ++mInvalidatedCachedSetAges[mNewCachedSet->getAge()];
        mNewCachedSet = std::nullopt;
    }
}

NonBufferHash Flattener::computeLayersHash() const{
    size_t hash = 0;
    for (const auto& layer : mLayers) {
        android::hashCombineSingleHashed(hash, layer.getNonBufferHash());
    }
    return hash;
}

// Only called if the geometry matches the last frame. Return true if mLayers
// was already populated with these layers, i.e. on the second and following
// calls with the same geometry.
bool Flattener::mergeWithCachedSets(const std::vector<const LayerState*>& layers, time_point now) {
    ATRACE_CALL();
    std::vector<CachedSet> merged;

    if (mLayers.empty()) {
        merged.reserve(layers.size());
        for (const LayerState* layer : layers) {
            merged.emplace_back(layer, now);
            mFlattenedDisplayCost += merged.back().getDisplayCost();
        }
        mLayers = std::move(merged);
        return false;
    }

    // the compiler should strip out the following no-op loops when ALOGV is off
    ALOGV("[%s] Incoming layers:", __func__);
    for (const LayerState* layer : layers) {
        ALOGV("%s", layer->getName().c_str());
    }

    ALOGV("[%s] Current layers:", __func__);
    for (const CachedSet& layer : mLayers) {
        const auto dumper = [&] {
            std::string dump;
            layer.dump(dump);
            return dump;
        };
        ALOGV("%s", dumper().c_str());
    }

    auto currentLayerIter = mLayers.begin();
    auto incomingLayerIter = layers.begin();

    // If not null, this represents the layer that is blurring the layer before
    // currentLayerIter. The blurring was stored in the override buffer, so the
    // layer that requests the blur no longer needs to do any blurring.
    compositionengine::OutputLayer* priorBlurLayer = nullptr;

    while (incomingLayerIter != layers.end()) {
        if (mNewCachedSet &&
            mNewCachedSet->getFirstLayer().getState()->getId() == (*incomingLayerIter)->getId()) {
            if (mNewCachedSet->hasBufferUpdate()) {
                ALOGV("[%s] Dropping new cached set", __func__);
                ++mInvalidatedCachedSetAges[0];
                mNewCachedSet = std::nullopt;
            } else if (mNewCachedSet->hasReadyBuffer()) {
                ALOGV("[%s] Found ready buffer", __func__);
                size_t skipCount = mNewCachedSet->getLayerCount();
                while (skipCount != 0) {
                    auto* peekThroughLayer = mNewCachedSet->getHolePunchLayer();
                    const size_t layerCount = currentLayerIter->getLayerCount();
                    for (size_t i = 0; i < layerCount; ++i) {
                        bool disableBlur = priorBlurLayer &&
                                priorBlurLayer == (*incomingLayerIter)->getOutputLayer();
                        OutputLayer::CompositionState& state =
                                (*incomingLayerIter)->getOutputLayer()->editState();
                        state.overrideInfo = {
                                .buffer = mNewCachedSet->getBuffer(),
                                .acquireFence = mNewCachedSet->getDrawFence(),
                                .displayFrame = mNewCachedSet->getTextureBounds(),
                                .dataspace = mNewCachedSet->getOutputDataspace(),
                                .displaySpace = mNewCachedSet->getOutputSpace(),
                                .damageRegion = Region::INVALID_REGION,
                                .visibleRegion = mNewCachedSet->getVisibleRegion(),
                                .peekThroughLayer = peekThroughLayer,
                                .disableBackgroundBlur = disableBlur,
                        };
                        ++incomingLayerIter;
                    }

                    if (currentLayerIter->getLayerCount() > 1) {
                        ++mInvalidatedCachedSetAges[currentLayerIter->getAge()];
                    }
                    ++currentLayerIter;

                    skipCount -= layerCount;
                }
                priorBlurLayer = mNewCachedSet->getBlurLayer();
                merged.emplace_back(std::move(*mNewCachedSet));
                mNewCachedSet = std::nullopt;
                continue;
            }
        }

        if (!currentLayerIter->hasBufferUpdate()) {
            currentLayerIter->incrementAge();
            merged.emplace_back(*currentLayerIter);

            // Skip the incoming layers corresponding to this valid current layer
            const size_t layerCount = currentLayerIter->getLayerCount();
            auto* peekThroughLayer = currentLayerIter->getHolePunchLayer();
            for (size_t i = 0; i < layerCount; ++i) {
                bool disableBlur =
                        priorBlurLayer && priorBlurLayer == (*incomingLayerIter)->getOutputLayer();
                OutputLayer::CompositionState& state =
                        (*incomingLayerIter)->getOutputLayer()->editState();
                state.overrideInfo = {
                        .buffer = currentLayerIter->getBuffer(),
                        .acquireFence = currentLayerIter->getDrawFence(),
                        .displayFrame = currentLayerIter->getTextureBounds(),
                        .dataspace = currentLayerIter->getOutputDataspace(),
                        .displaySpace = currentLayerIter->getOutputSpace(),
                        .damageRegion = Region(),
                        .visibleRegion = currentLayerIter->getVisibleRegion(),
                        .peekThroughLayer = peekThroughLayer,
                        .disableBackgroundBlur = disableBlur,
                };
                ++incomingLayerIter;
            }
        } else if (currentLayerIter->getLayerCount() > 1) {
            // Break the current layer into its constituent layers
            ++mInvalidatedCachedSetAges[currentLayerIter->getAge()];
            for (CachedSet& layer : currentLayerIter->decompose()) {
                bool disableBlur =
                        priorBlurLayer && priorBlurLayer == (*incomingLayerIter)->getOutputLayer();
                OutputLayer::CompositionState& state =
                        (*incomingLayerIter)->getOutputLayer()->editState();
                state.overrideInfo.disableBackgroundBlur = disableBlur;
                layer.updateAge(now);
                merged.emplace_back(layer);
                ++incomingLayerIter;
            }
        } else {
            bool disableBlur =
                    priorBlurLayer && priorBlurLayer == (*incomingLayerIter)->getOutputLayer();
            OutputLayer::CompositionState& state =
                    (*incomingLayerIter)->getOutputLayer()->editState();
            state.overrideInfo.disableBackgroundBlur = disableBlur;
            currentLayerIter->updateAge(now);
            merged.emplace_back(*currentLayerIter);
            ++incomingLayerIter;
        }
        priorBlurLayer = currentLayerIter->getBlurLayer();
        ++currentLayerIter;
    }

    for (const CachedSet& layer : merged) {
        mFlattenedDisplayCost += layer.getDisplayCost();
    }

    mLayers = std::move(merged);
    return true;
}

std::vector<Flattener::Run> Flattener::findCandidateRuns(time_point now) const {
    ATRACE_CALL();
    std::vector<Run> runs;
    bool isPartOfRun = false;
    Run::Builder builder;
    bool firstLayer = true;
    bool runHasFirstLayer = false;

    for (auto currentSet = mLayers.cbegin(); currentSet != mLayers.cend(); ++currentSet) {
        bool layerIsInactive = now - currentSet->getLastUpdate() > mTunables.mActiveLayerTimeout;
        const bool layerHasBlur = currentSet->hasBlurBehind();

        // Layers should also be considered inactive whenever their framerate is lower than 1fps.
        if (!layerIsInactive && currentSet->getLayerCount() == kNumLayersFpsConsideration) {
            auto layerFps = currentSet->getFirstLayer().getState()->getFps();
            if (layerFps > 0 && layerFps <= kFpsActiveThreshold) {
                ATRACE_FORMAT("layer is considered inactive due to low FPS [%s] %f",
                              currentSet->getFirstLayer().getName().c_str(), layerFps);
                layerIsInactive = true;
            }
        }

        if (layerIsInactive && (firstLayer || runHasFirstLayer || !layerHasBlur) &&
            !currentSet->hasUnsupportedDataspace()) {
            if (isPartOfRun) {
                builder.increment();
            } else {
                builder.init(currentSet);
                if (firstLayer) {
                    runHasFirstLayer = true;
                }
                isPartOfRun = true;
            }
        } else if (isPartOfRun) {
            builder.setHolePunchCandidate(&(*currentSet));

            // If we're here then this blur layer recently had an active buffer updating, meaning
            // that there is exactly one layer. Blur radius currently is part of layer stack
            // geometry, so we're also guaranteed that the background blur radius hasn't changed for
            // at least as long as this new inactive cached set.
            if (runHasFirstLayer && layerHasBlur &&
                currentSet->getFirstLayer().getBackgroundBlurRadius() > 0) {
                builder.setBlurringLayer(&(*currentSet));
            }
            if (auto run = builder.validateAndBuild(); run) {
                runs.push_back(*run);
            }

            runHasFirstLayer = false;
            builder.reset();
            isPartOfRun = false;
        }

        firstLayer = false;
    }

    // If we're in the middle of a run at the end, we still need to validate and build it.
    if (isPartOfRun) {
        if (auto run = builder.validateAndBuild(); run) {
            runs.push_back(*run);
        }
    }

    ALOGV("[%s] Found %zu candidate runs", __func__, runs.size());

    return runs;
}

std::optional<Flattener::Run> Flattener::findBestRun(std::vector<Flattener::Run>& runs) const {
    if (runs.empty()) {
        return std::nullopt;
    }

    // TODO (b/181192467): Choose the best run, instead of just the first.
    return runs[0];
}

void Flattener::buildCachedSets(time_point now) {
    ATRACE_CALL();
    if (mLayers.empty()) {
        ALOGV("[%s] No layers found, returning", __func__);
        return;
    }

    // Don't try to build a new cached set if we already have a new one in progress
    if (mNewCachedSet) {
        return;
    }

    for (const CachedSet& layer : mLayers) {
        // TODO (b/191997217): make it less aggressive, and sync with findCandidateRuns
        if (layer.hasProtectedLayers()) {
            ATRACE_NAME("layer->hasProtectedLayers()");
            return;
        }
    }

    for (const CachedSet& layer : mLayers) {
        if (layer.hasSolidColorLayers()) {
            ATRACE_NAME("layer->hasSolidColorLayers()");
            return;
        }
    }

    std::vector<Run> runs = findCandidateRuns(now);

    std::optional<Run> bestRun = findBestRun(runs);

    if (!bestRun) {
        return;
    }

    mNewCachedSet.emplace(*bestRun->getStart());
    mNewCachedSet->setLastUpdate(now);
    auto currentSet = bestRun->getStart();
    while (mNewCachedSet->getLayerCount() < bestRun->getLayerLength()) {
        ++currentSet;
        mNewCachedSet->append(*currentSet);
    }

    if (bestRun->getBlurringLayer()) {
        mNewCachedSet->addBackgroundBlurLayer(*bestRun->getBlurringLayer());
    }

    if (mTunables.mEnableHolePunch && bestRun->getHolePunchCandidate() &&
        bestRun->getHolePunchCandidate()->requiresHolePunch()) {
        // Add the pip layer to mNewCachedSet, but in a special way - it should
        // replace the buffer with a clear round rect.
        mNewCachedSet->addHolePunchLayerIfFeasible(*bestRun->getHolePunchCandidate(),
                                                   bestRun->getStart() == mLayers.cbegin());
    }

    // TODO(b/181192467): Actually compute new LayerState vector and corresponding hash for each run
    // and feedback into the predictor

    ++mCachedSetCreationCount;
    mCachedSetCreationCost += mNewCachedSet->getCreationCost();

    // note the compiler should strip the follow no-op statements when ALOGV is off
    const auto dumper = [&] {
        std::string setDump;
        mNewCachedSet->dump(setDump);
        return setDump;
    };
    ALOGV("[%s] Added new cached set:\n%s", __func__, dumper().c_str());
}

} // namespace android::compositionengine::impl::planner
