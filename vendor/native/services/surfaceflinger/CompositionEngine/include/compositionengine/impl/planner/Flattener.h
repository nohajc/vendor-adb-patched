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

#pragma once

#include <compositionengine/Output.h>
#include <compositionengine/impl/planner/CachedSet.h>
#include <compositionengine/impl/planner/LayerState.h>

#include <chrono>
#include <numeric>
#include <vector>

namespace android {

namespace renderengine {
class RenderEngine;
} // namespace renderengine

namespace compositionengine::impl::planner {
using namespace std::chrono_literals;

class LayerState;
class Predictor;

class Flattener {
public:
    // Collection of tunables which are backed by sysprops
    struct Tunables {
        // Tunables that are specific to scheduling when a cached set should be rendered
        struct RenderScheduling {
            // This default assumes that rendering a cached set takes about 3ms. That time is then
            // cut in half - the next frame using the cached set would have the same workload,
            // meaning that composition cost is the same. This is best illustrated with the
            // following example:
            //
            // Suppose we're at a 120hz cadence so SurfaceFlinger is budgeted 8.3ms per-frame. If
            // renderCachedSets costs 3ms, then two consecutive frames have timings:
            //
            // First frame: Start at 0ms, end at 6.8ms.
            // renderCachedSets: Start at 6.8ms, end at 9.8ms.
            // Second frame: Start at 9.8ms, end at 16.6ms.
            //
            // Now the second frame won't render a cached set afterwards, but the first frame didn't
            // really steal time from the second frame.
            static const constexpr std::chrono::nanoseconds kDefaultCachedSetRenderDuration =
                    1500us;

            static const constexpr size_t kDefaultMaxDeferRenderAttempts = 240;

            // Duration allocated for rendering a cached set. If we don't have enough time for
            // rendering a cached set, then rendering is deferred to another frame.
            const std::chrono::nanoseconds cachedSetRenderDuration;
            // Maximum of times that we defer rendering a cached set. If we defer rendering a cached
            // set too many times, then render it anyways so that future frames would benefit from
            // the flattened cached set.
            const size_t maxDeferRenderAttempts;
        };

        static const constexpr std::chrono::milliseconds kDefaultActiveLayerTimeout = 150ms;

        static const constexpr bool kDefaultEnableHolePunch = true;

        // Threshold for determing whether a layer is active. A layer whose properties, including
        // the buffer, have not changed in at least this time is considered inactive and is
        // therefore a candidate for flattening.
        const std::chrono::milliseconds mActiveLayerTimeout;

        // Toggles for scheduling when it's safe to render a cached set.
        // See: RenderScheduling
        const std::optional<RenderScheduling> mRenderScheduling;

        // True if the hole punching feature should be enabled.
        const bool mEnableHolePunch;
    };

    // Constants not yet backed by a sysprop
    // CachedSets that contain no more than this many layers may be considered inactive on the basis
    // of FPS.
    static constexpr int kNumLayersFpsConsideration = 1;
    // Frames/Second threshold below which these CachedSets may be considered inactive.
    static constexpr float kFpsActiveThreshold = 1.f;

    Flattener(renderengine::RenderEngine& renderEngine, const Tunables& tunables);

    void setDisplaySize(ui::Size size) {
        mDisplaySize = size;
        mTexturePool.setDisplaySize(size);
    }

    NonBufferHash flattenLayers(const std::vector<const LayerState*>& layers, NonBufferHash,
                                std::chrono::steady_clock::time_point now);

    // Renders the newest cached sets with the supplied output composition state
    void renderCachedSets(const OutputCompositionState& outputState,
                          std::optional<std::chrono::steady_clock::time_point> renderDeadline,
                          bool deviceHandlesColorTransform);

    void setTexturePoolEnabled(bool enabled) { mTexturePool.setEnabled(enabled); }

    void dump(std::string& result) const;
    void dumpLayers(std::string& result) const;

    const std::optional<CachedSet>& getNewCachedSetForTesting() const { return mNewCachedSet; }

private:
    size_t calculateDisplayCost(const std::vector<const LayerState*>& layers) const;

    void resetActivities(NonBufferHash, std::chrono::steady_clock::time_point now);

    NonBufferHash computeLayersHash() const;

    bool mergeWithCachedSets(const std::vector<const LayerState*>& layers,
                             std::chrono::steady_clock::time_point now);

    // A Run is a sequence of CachedSets, which is a candidate for flattening into a single
    // CachedSet. Because it is wasteful to flatten 1 CachedSet, a run must contain more than
    // 1 CachedSet or be used for a hole punch.
    class Run {
    public:
        // A builder for a Run, to aid in construction
        class Builder {
        private:
            std::vector<CachedSet>::const_iterator mStart;
            int32_t mNumSets = 0;
            const CachedSet* mHolePunchCandidate = nullptr;
            const CachedSet* mBlurringLayer = nullptr;
            bool mBuilt = false;

        public:
            // Initializes a Builder a CachedSet to start from.
            // This start iterator must be an iterator for mLayers
            void init(const std::vector<CachedSet>::const_iterator& start) {
                mStart = start;
                mNumSets = 1;
            }

            // Appends a new CachedSet to the end of the run
            // The provided length must be the size of the next sequential CachedSet in layers
            void increment() { mNumSets++; }

            // Sets the hole punch candidate for the Run.
            void setHolePunchCandidate(const CachedSet* holePunchCandidate) {
                mHolePunchCandidate = holePunchCandidate;
            }

            void setBlurringLayer(const CachedSet* blurringLayer) {
                mBlurringLayer = blurringLayer;
            }

            // Builds a Run instance, if a valid Run may be built.
            std::optional<Run> validateAndBuild() {
                const bool built = mBuilt;
                mBuilt = true;
                if (mNumSets <= 0 || built) {
                    return std::nullopt;
                }

                const bool requiresHolePunch =
                        mHolePunchCandidate && mHolePunchCandidate->requiresHolePunch();

                if (!requiresHolePunch) {
                    // If we don't require a hole punch, then treat solid color layers at the front
                    // to be "cheap", so remove them from the candidate cached set.
                    while (mNumSets > 1 && mStart->getLayerCount() == 1 &&
                           mStart->getFirstLayer().getBuffer() == nullptr) {
                        mStart++;
                        mNumSets--;
                    }

                    // Only allow for single cached sets if a hole punch is required. If we're here,
                    // then we don't require a hole punch, so don't build a run.
                    if (mNumSets <= 1) {
                        return std::nullopt;
                    }
                }

                return Run(mStart,
                           std::reduce(mStart, mStart + mNumSets, 0u,
                                       [](size_t length, const CachedSet& set) {
                                           return length + set.getLayerCount();
                                       }),
                           mHolePunchCandidate, mBlurringLayer);
            }

            void reset() { *this = {}; }
        };

        // Gets the starting CachedSet of this run.
        // This is an iterator into mLayers
        const std::vector<CachedSet>::const_iterator& getStart() const { return mStart; }
        // Gets the total number of layers encompassing this Run.
        size_t getLayerLength() const { return mLength; }
        // Gets the hole punch candidate for this Run.
        const CachedSet* getHolePunchCandidate() const { return mHolePunchCandidate; }
        const CachedSet* getBlurringLayer() const { return mBlurringLayer; }

    private:
        Run(std::vector<CachedSet>::const_iterator start, size_t length,
            const CachedSet* holePunchCandidate, const CachedSet* blurringLayer)
              : mStart(start),
                mLength(length),
                mHolePunchCandidate(holePunchCandidate),
                mBlurringLayer(blurringLayer) {}
        const std::vector<CachedSet>::const_iterator mStart;
        const size_t mLength;
        const CachedSet* const mHolePunchCandidate;
        const CachedSet* const mBlurringLayer;

        friend class Builder;
    };

    std::vector<Run> findCandidateRuns(std::chrono::steady_clock::time_point now) const;

    std::optional<Run> findBestRun(std::vector<Run>& runs) const;

    void buildCachedSets(std::chrono::steady_clock::time_point now);

    renderengine::RenderEngine& mRenderEngine;
    const Tunables mTunables;

    TexturePool mTexturePool;

protected:
    // mNewCachedSet must be destroyed before mTexturePool is.
    std::optional<CachedSet> mNewCachedSet;

private:
    ui::Size mDisplaySize;

    NonBufferHash mCurrentGeometry;
    std::chrono::steady_clock::time_point mLastGeometryUpdate;

    std::vector<CachedSet> mLayers;

    // Statistics
    size_t mUnflattenedDisplayCost = 0;
    size_t mFlattenedDisplayCost = 0;
    std::unordered_map<size_t, size_t> mInitialLayerCounts;
    std::unordered_map<size_t, size_t> mFinalLayerCounts;
    size_t mCachedSetCreationCount = 0;
    size_t mCachedSetCreationCost = 0;
    std::unordered_map<size_t, size_t> mInvalidatedCachedSetAges;
};

} // namespace compositionengine::impl::planner
} // namespace android
