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

#include <compositionengine/impl/HwcBufferCache.h>
#include <renderengine/Mesh.h>
#include <ui/FloatRect.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>
#include <ui/Region.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include "DisplayHardware/ComposerHal.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

namespace android {

namespace HWC2 {
class Layer;
} // namespace HWC2

class HWComposer;

namespace compositionengine::impl {

struct OutputLayerCompositionState {
    // The portion of the layer that is not obscured by opaque layers on top
    Region visibleRegion;

    // The portion of the layer that is not obscured and is also opaque
    Region visibleNonTransparentRegion;

    // The portion of the layer that is obscured by opaque layers on top
    Region coveredRegion;

    // The visibleRegion transformed to output space
    Region outputSpaceVisibleRegion;

    // Region cast by the layer's shadow
    Region shadowRegion;

    // If true, client composition will be used on this output
    bool forceClientComposition{false};

    // If true, when doing client composition, the target may need to be cleared
    bool clearClientTarget{false};

    // The display frame for this layer on this output
    Rect displayFrame;

    // The source crop for this layer on this output
    FloatRect sourceCrop;

    // The buffer transform to use for this layer o on this output.
    Hwc2::Transform bufferTransform{static_cast<Hwc2::Transform>(0)};

    // The dataspace for this layer
    ui::Dataspace dataspace{ui::Dataspace::UNKNOWN};

    // The Z order index of this layer on this output
    uint32_t z{0};

    /*
     * HWC state
     */

    struct Hwc {
        explicit Hwc(std::shared_ptr<HWC2::Layer> hwcLayer) : hwcLayer(hwcLayer) {}

        // The HWC Layer backing this layer
        std::shared_ptr<HWC2::Layer> hwcLayer;

        // The most recently set HWC composition type for this layer
        Hwc2::IComposerClient::Composition hwcCompositionType{
                Hwc2::IComposerClient::Composition::INVALID};

        // The buffer cache for this layer. This is used to lower the
        // cost of sending reused buffers to the HWC.
        HwcBufferCache hwcBufferCache;
    };

    // The HWC state is optional, and is only set up if there is any potential
    // HWC acceleration possible.
    std::optional<Hwc> hwc;

    // Debugging
    void dump(std::string& result) const;

    // Timestamp for when the layer is queued for client composition
    nsecs_t clientCompositionTimestamp{0};
};

} // namespace compositionengine::impl
} // namespace android
