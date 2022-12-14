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

#pragma once

#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include <compositionengine/LayerFE.h>
#include <renderengine/LayerSettings.h>
#include <ui/Fence.h>
#include <ui/GraphicTypes.h>
#include <ui/Region.h>
#include <ui/Transform.h>
#include <utils/StrongPointer.h>

#include "DisplayHardware/DisplayIdentification.h"

namespace android {

namespace HWC2 {
class Layer;
} // namespace HWC2

namespace compositionengine {

class DisplayColorProfile;
class LayerFE;
class RenderSurface;
class OutputLayer;

struct CompositionRefreshArgs;
struct LayerFECompositionState;

namespace impl {
struct OutputCompositionState;
} // namespace impl

/**
 * Encapsulates all the state involved with composing layers for an output
 */
class Output {
public:
    using ReleasedLayers = std::vector<wp<LayerFE>>;
    using UniqueFELayerStateMap = std::unordered_map<LayerFE*, LayerFECompositionState*>;

    // A helper class for enumerating the output layers using a C++11 ranged-based for loop
    template <typename T>
    class OutputLayersEnumerator {
    public:
        // TODO(lpique): Consider turning this into a C++20 view when possible.
        template <bool IsConstIter>
        class IteratorImpl {
        public:
            // Required definitions to be considered an iterator
            using iterator_category = std::forward_iterator_tag;
            using value_type = decltype(std::declval<T>().getOutputLayerOrderedByZByIndex(0));
            using difference_type = std::ptrdiff_t;
            using pointer = std::conditional_t<IsConstIter, const value_type*, value_type*>;
            using reference = std::conditional_t<IsConstIter, const value_type&, value_type&>;

            IteratorImpl() = default;
            IteratorImpl(const T* output, size_t index) : mOutput(output), mIndex(index) {}

            value_type operator*() const {
                return mOutput->getOutputLayerOrderedByZByIndex(mIndex);
            }
            value_type operator->() const {
                return mOutput->getOutputLayerOrderedByZByIndex(mIndex);
            }

            bool operator==(const IteratorImpl& other) const {
                return mOutput == other.mOutput && mIndex == other.mIndex;
            }
            bool operator!=(const IteratorImpl& other) const { return !operator==(other); }

            IteratorImpl& operator++() {
                ++mIndex;
                return *this;
            }
            IteratorImpl operator++(int) {
                auto prev = *this;
                ++mIndex;
                return prev;
            }

        private:
            const T* mOutput{nullptr};
            size_t mIndex{0};
        };

        using iterator = IteratorImpl<false>;
        using const_iterator = IteratorImpl<true>;

        explicit OutputLayersEnumerator(const T& output) : mOutput(output) {}
        auto begin() const { return iterator(&mOutput, 0); }
        auto end() const { return iterator(&mOutput, mOutput.getOutputLayerCount()); }
        auto cbegin() const { return const_iterator(&mOutput, 0); }
        auto cend() const { return const_iterator(&mOutput, mOutput.getOutputLayerCount()); }

    private:
        const T& mOutput;
    };

    struct FrameFences {
        sp<Fence> presentFence{Fence::NO_FENCE};
        sp<Fence> clientTargetAcquireFence{Fence::NO_FENCE};
        std::unordered_map<HWC2::Layer*, sp<Fence>> layerFences;
    };

    struct ColorProfile {
        ui::ColorMode mode{ui::ColorMode::NATIVE};
        ui::Dataspace dataspace{ui::Dataspace::UNKNOWN};
        ui::RenderIntent renderIntent{ui::RenderIntent::COLORIMETRIC};
        ui::Dataspace colorSpaceAgnosticDataspace{ui::Dataspace::UNKNOWN};
    };

    // Use internally to incrementally compute visibility/coverage
    struct CoverageState {
        explicit CoverageState(LayerFESet& latchedLayers) : latchedLayers(latchedLayers) {}

        // The set of layers that had been latched for the coverage calls, to
        // avoid duplicate requests to obtain the same front-end layer state.
        LayerFESet& latchedLayers;

        // The region of the output which is covered by layers
        Region aboveCoveredLayers;
        // The region of the output which is opaquely covered by layers
        Region aboveOpaqueLayers;
        // The region of the output which should be considered dirty
        Region dirtyRegion;
    };

    virtual ~Output();

    // Returns true if the output is valid. This is meant to be checked post-
    // construction and prior to use, as not everything is set up by the
    // constructor.
    virtual bool isValid() const = 0;

    // Returns the DisplayId the output represents, if it has one
    virtual std::optional<DisplayId> getDisplayId() const = 0;

    // Enables (or disables) composition on this output
    virtual void setCompositionEnabled(bool) = 0;

    // Sets the projection state to use
    virtual void setProjection(const ui::Transform&, uint32_t orientation, const Rect& frame,
                               const Rect& viewport, const Rect& sourceClip,
                               const Rect& destinationClip, bool needsFiltering) = 0;
    // Sets the bounds to use
    virtual void setBounds(const ui::Size&) = 0;

    // Sets the layer stack filtering settings for this output. See
    // belongsInOutput for full details.
    virtual void setLayerStackFilter(uint32_t layerStackId, bool isInternal) = 0;

    // Sets the output color mode
    virtual void setColorProfile(const ColorProfile&) = 0;

    // Outputs a string with a state dump
    virtual void dump(std::string&) const = 0;

    // Gets the debug name for the output
    virtual const std::string& getName() const = 0;

    // Sets a debug name for the output
    virtual void setName(const std::string&) = 0;

    // Gets the current render color mode for the output
    virtual DisplayColorProfile* getDisplayColorProfile() const = 0;

    // Gets the current render surface for the output
    virtual RenderSurface* getRenderSurface() const = 0;

    using OutputCompositionState = compositionengine::impl::OutputCompositionState;

    // Gets the raw composition state data for the output
    // TODO(lpique): Make this protected once it is only internally called.
    virtual const OutputCompositionState& getState() const = 0;

    // Allows mutable access to the raw composition state data for the output.
    // This is meant to be used by the various functions that are part of the
    // composition process.
    // TODO(lpique): Make this protected once it is only internally called.
    virtual OutputCompositionState& editState() = 0;

    // Gets the dirty region in layer stack space.
    // If repaintEverything is true, this will be the full display bounds.
    virtual Region getDirtyRegion(bool repaintEverything) const = 0;

    // Tests whether a given layerStackId belongs in this output.
    // A layer belongs to the output if its layerStackId matches the of the output layerStackId,
    // unless the layer should display on the primary output only and this is not the primary output

    // A layer belongs to the output if its layerStackId matches. Additionally
    // if the layer should only show in the internal (primary) display only and
    // this output allows that.
    virtual bool belongsInOutput(std::optional<uint32_t> layerStackId, bool internalOnly) const = 0;

    // Determines if a layer belongs to the output.
    virtual bool belongsInOutput(const sp<LayerFE>&) const = 0;

    // Returns a pointer to the output layer corresponding to the given layer on
    // this output, or nullptr if the layer does not have one
    virtual OutputLayer* getOutputLayerForLayer(const sp<LayerFE>&) const = 0;

    // Immediately clears all layers from the output.
    virtual void clearOutputLayers() = 0;

    // For tests use only. Creates and appends an OutputLayer into the output.
    virtual OutputLayer* injectOutputLayerForTest(const sp<LayerFE>&) = 0;

    // Gets the count of output layers managed by this output
    virtual size_t getOutputLayerCount() const = 0;

    // Gets an output layer in Z order given its index
    virtual OutputLayer* getOutputLayerOrderedByZByIndex(size_t) const = 0;

    // A helper function for enumerating all the output layers in Z order using
    // a C++11 range-based for loop.
    auto getOutputLayersOrderedByZ() const { return OutputLayersEnumerator(*this); }

    // Sets the new set of layers being released this frame
    virtual void setReleasedLayers(ReleasedLayers&&) = 0;

    // Prepare the output, updating the OutputLayers used in the output
    virtual void prepare(const CompositionRefreshArgs&, LayerFESet&) = 0;

    // Presents the output, finalizing all composition details
    virtual void present(const CompositionRefreshArgs&) = 0;

    // Latches the front-end layer state for each output layer
    virtual void updateLayerStateFromFE(const CompositionRefreshArgs&) const = 0;

protected:
    virtual void setDisplayColorProfile(std::unique_ptr<DisplayColorProfile>) = 0;
    virtual void setRenderSurface(std::unique_ptr<RenderSurface>) = 0;

    virtual void rebuildLayerStacks(const CompositionRefreshArgs&, LayerFESet&) = 0;
    virtual void collectVisibleLayers(const CompositionRefreshArgs&, CoverageState&) = 0;
    virtual void ensureOutputLayerIfVisible(sp<LayerFE>&, CoverageState&) = 0;
    virtual void setReleasedLayers(const CompositionRefreshArgs&) = 0;

    virtual void updateAndWriteCompositionState(const CompositionRefreshArgs&) = 0;
    virtual void setColorTransform(const CompositionRefreshArgs&) = 0;
    virtual void updateColorProfile(const CompositionRefreshArgs&) = 0;
    virtual void beginFrame() = 0;
    virtual void prepareFrame() = 0;
    virtual void devOptRepaintFlash(const CompositionRefreshArgs&) = 0;
    virtual void finishFrame(const CompositionRefreshArgs&) = 0;
    virtual std::optional<base::unique_fd> composeSurfaces(
            const Region&, const compositionengine::CompositionRefreshArgs& refreshArgs) = 0;
    virtual void postFramebuffer() = 0;
    virtual void chooseCompositionStrategy() = 0;
    virtual bool getSkipColorTransform() const = 0;
    virtual FrameFences presentAndGetFrameFences() = 0;
    virtual std::vector<LayerFE::LayerSettings> generateClientCompositionRequests(
            bool supportsProtectedContent, Region& clearRegion, ui::Dataspace outputDataspace) = 0;
    virtual void appendRegionFlashRequests(
            const Region& flashRegion,
            std::vector<LayerFE::LayerSettings>& clientCompositionLayers) = 0;
    virtual void setExpensiveRenderingExpected(bool enabled) = 0;
    virtual void cacheClientCompositionRequests(uint32_t cacheSize) = 0;
};

} // namespace compositionengine
} // namespace android
