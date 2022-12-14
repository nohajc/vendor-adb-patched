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

#include <gui/HdrMetadata.h>
#include <math/mat4.h>
#include <ui/BlurRegion.h>
#include <ui/FloatRect.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/Transform.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <gui/BufferQueue.h>
#include <ui/GraphicBuffer.h>
#include <ui/GraphicTypes.h>
#include <ui/StretchEffect.h>

#include "DisplayHardware/Hal.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

namespace android::compositionengine {

namespace hal = android::hardware::graphics::composer::hal;

// More complex metadata for this layer
struct GenericLayerMetadataEntry {
    // True if the metadata may affect the composed result.
    // See setLayerGenericMetadata in IComposerClient.hal
    bool mandatory;

    // Byte blob or parcel
    std::vector<uint8_t> value;

    std::string dumpAsString() const;

    struct Hasher {
        size_t operator()(const GenericLayerMetadataEntry& entry) const {
            size_t hash = 0;
            for (const auto value : entry.value) {
                hashCombineSingleHashed(hash, value);
            }
            return hash;
        }
    };
};

inline bool operator==(const GenericLayerMetadataEntry& lhs, const GenericLayerMetadataEntry& rhs) {
    return lhs.mandatory == rhs.mandatory && lhs.value == rhs.value;
}

// Defining PrintTo helps with Google Tests.
inline void PrintTo(const GenericLayerMetadataEntry& v, ::std::ostream* os) {
    *os << v.dumpAsString();
}

using GenericLayerMetadataMap = std::unordered_map<std::string, GenericLayerMetadataEntry>;

/*
 * Used by LayerFE::getCompositionState
 * Note that fields that affect HW composer state may need to be mirrored into
 * android::compositionengine::impl::planner::LayerState
 */
struct LayerFECompositionState {
    // If set to true, forces client composition on all output layers until
    // the next geometry change.
    bool forceClientComposition{false};

    // TODO(b/121291683): Reorganize and rename the contents of this structure

    /*
     * Visibility state
     */
    // the layer stack this layer belongs to
    std::optional<uint32_t> layerStackId;

    // If true, this layer should be only visible on the internal display
    bool internalOnly{false};

    // If false, this layer should not be considered visible
    bool isVisible{true};

    // True if the layer is completely opaque
    bool isOpaque{true};

    // If true, invalidates the entire visible region
    bool contentDirty{false};

    // The alpha value for this layer
    float alpha{1.f};

    // Background blur in pixels
    int backgroundBlurRadius{0};

    // The transform from layer local coordinates to composition coordinates
    ui::Transform geomLayerTransform;

    // The inverse of the layer transform
    ui::Transform geomInverseLayerTransform;

    // The hint from the layer producer as to what portion of the layer is
    // transparent.
    Region transparentRegionHint;

    // The blend mode for this layer
    hal::BlendMode blendMode{hal::BlendMode::INVALID};

    // The bounds of the layer in layer local coordinates
    FloatRect geomLayerBounds;

    // length of the shadow in screen space
    float shadowRadius{0.f};

    // List of regions that require blur
    std::vector<BlurRegion> blurRegions;

    StretchEffect stretchEffect;

    /*
     * Geometry state
     */

    bool isSecure{false};
    bool geomUsesSourceCrop{false};
    bool geomBufferUsesDisplayInverseTransform{false};
    uint32_t geomBufferTransform{0};
    Rect geomBufferSize;
    Rect geomContentCrop;
    Rect geomCrop;

    GenericLayerMetadataMap metadata;

    /*
     * Per-frame content
     */

    // The type of composition for this layer
    hal::Composition compositionType{hal::Composition::INVALID};

    // The buffer and related state
    sp<GraphicBuffer> buffer;
    int bufferSlot{BufferQueue::INVALID_BUFFER_SLOT};
    sp<Fence> acquireFence;
    Region surfaceDamage;

    // The handle to use for a sideband stream for this layer
    sp<NativeHandle> sidebandStream;

    // The color for this layer
    half4 color;

    /*
     * Per-frame presentation state
     */

    // If true, this layer will use the dataspace chosen for the output and
    // ignore the dataspace value just below
    bool isColorspaceAgnostic{false};

    // The dataspace for this layer
    ui::Dataspace dataspace{ui::Dataspace::UNKNOWN};

    // The metadata for this layer
    HdrMetadata hdrMetadata;

    // The color transform
    mat4 colorTransform;
    bool colorTransformIsIdentity{true};

    // True if the layer has protected content
    bool hasProtectedContent{false};

    /*
     * Cursor state
     */

    // The output-independent frame for the cursor
    Rect cursorFrame;

    virtual ~LayerFECompositionState();

    // Debugging
    virtual void dump(std::string& out) const;
};

} // namespace android::compositionengine
