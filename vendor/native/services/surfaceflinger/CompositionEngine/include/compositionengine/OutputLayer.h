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
#include <optional>
#include <string>

#include <ui/Transform.h>
#include <utils/StrongPointer.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include "DisplayHardware/ComposerHal.h"
#include "DisplayHardware/DisplayIdentification.h"

#include "LayerFE.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

namespace android {

namespace HWC2 {
class Layer;
} // namespace HWC2

namespace compositionengine {

class CompositionEngine;
class Output;

namespace impl {
struct OutputLayerCompositionState;
} // namespace impl

/**
 * An output layer contains the output-dependent composition state for a layer
 */
class OutputLayer {
public:
    virtual ~OutputLayer();

    // Sets the HWC2::Layer associated with this layer
    virtual void setHwcLayer(std::shared_ptr<HWC2::Layer>) = 0;

    // Gets the output which owns this output layer
    virtual const Output& getOutput() const = 0;

    // Gets the front-end layer interface this output layer represents
    virtual LayerFE& getLayerFE() const = 0;

    using CompositionState = compositionengine::impl::OutputLayerCompositionState;

    // Gets the raw composition state data for the layer
    // TODO(lpique): Make this protected once it is only internally called.
    virtual const CompositionState& getState() const = 0;

    // Allows mutable access to the raw composition state data for the layer.
    // This is meant to be used by the various functions that are part of the
    // composition process.
    // TODO(lpique): Make this protected once it is only internally called.
    virtual CompositionState& editState() = 0;

    // Recalculates the state of the output layer from the output-independent
    // layer. If includeGeometry is false, the geometry state can be skipped.
    // internalDisplayRotationFlags must be set to the rotation flags for the
    // internal display, and is used to properly compute the inverse-display
    // transform, if needed.
    virtual void updateCompositionState(
            bool includeGeometry, bool forceClientComposition,
            ui::Transform::RotationFlags internalDisplayRotationFlags) = 0;

    // Writes the geometry state to the HWC, or does nothing if this layer does
    // not use the HWC. If includeGeometry is false, the geometry state can be
    // skipped. If skipLayer is true, then the alpha of the layer is forced to
    // 0 so that HWC will ignore it. z specifies the order to draw the layer in
    // (starting with 0 for the back layer, and increasing for each following
    // layer). zIsOverridden specifies whether the layer has been reordered.
    // isPeekingThrough specifies whether this layer will be shown through a
    // hole punch in a layer above it.
    virtual void writeStateToHWC(bool includeGeometry, bool skipLayer, uint32_t z,
                                 bool zIsOverridden, bool isPeekingThrough) = 0;

    // Updates the cursor position with the HWC
    virtual void writeCursorPositionToHWC() const = 0;

    // Returns the HWC2::Layer associated with this layer, if it exists
    virtual HWC2::Layer* getHwcLayer() const = 0;

    // Returns true if the current layer state requires client composition
    virtual bool requiresClientComposition() const = 0;

    // Returns true if the current layer should be treated as a cursor layer
    virtual bool isHardwareCursor() const = 0;

    // Applies a HWC device requested composition type change
    virtual void applyDeviceCompositionTypeChange(Hwc2::IComposerClient::Composition) = 0;

    // Prepares to apply any HWC device layer requests
    virtual void prepareForDeviceLayerRequests() = 0;

    // Applies a HWC device layer request
    virtual void applyDeviceLayerRequest(Hwc2::IComposerClient::LayerRequest request) = 0;

    // Returns true if the composition settings scale pixels
    virtual bool needsFiltering() const = 0;

    // Returns a composition list to be used by RenderEngine if the layer has been overridden
    // during the composition process
    virtual std::vector<LayerFE::LayerSettings> getOverrideCompositionList() const = 0;

    // Debugging
    virtual void dump(std::string& result) const = 0;
};

} // namespace compositionengine
} // namespace android
