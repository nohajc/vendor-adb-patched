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

#include <compositionengine/ProjectionSpace.h>
#include <compositionengine/impl/HwcBufferCache.h>
#include <renderengine/ExternalTexture.h>
#include <ui/FloatRect.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>
#include <ui/Region.h>

#include <cstdint>
#include <optional>
#include <string>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include "DisplayHardware/ComposerHal.h"

#include <aidl/android/hardware/graphics/composer3/Composition.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

namespace android {

namespace HWC2 {
class Layer;
} // namespace HWC2

class HWComposer;

namespace compositionengine {
class OutputLayer;
} // namespace compositionengine

namespace compositionengine::impl {

// Note that fields that affect HW composer state may need to be mirrored into
// android::compositionengine::impl::planner::LayerState
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

    // A hint to the HWC that this region is transparent and may be skipped in
    // order to save power.
    Region outputSpaceBlockingRegionHint;

    // Overrides the buffer, acquire fence, and display frame stored in LayerFECompositionState
    struct {
        std::shared_ptr<renderengine::ExternalTexture> buffer = nullptr;
        sp<Fence> acquireFence = nullptr;
        Rect displayFrame = {};
        ui::Dataspace dataspace{ui::Dataspace::UNKNOWN};
        ProjectionSpace displaySpace;
        Region damageRegion = Region::INVALID_REGION;
        Region visibleRegion;

        // The OutputLayer pointed to by this field will be rearranged to draw
        // behind the OutputLayer represented by this CompositionState and will
        // be visible through it. Unowned - the OutputLayer's lifetime will
        // outlast this.)
        compositionengine::OutputLayer* peekThroughLayer = nullptr;
        // True when this layer's blur has been cached with a previous layer, so that this layer
        // does not need to request blurring.
        // TODO(b/188816867): support blur regions too, which are less likely to be common if a
        // device supports cross-window blurs. Blur region support should be doable, but we would
        // need to make sure that layer caching works well with the blur region transform passed
        // into RenderEngine
        bool disableBackgroundBlur = false;
    } overrideInfo;

    /*
     * HWC state
     */

    struct Hwc {
        explicit Hwc(std::shared_ptr<HWC2::Layer> hwcLayer) : hwcLayer(hwcLayer) {}

        // The HWC Layer backing this layer
        std::shared_ptr<HWC2::Layer> hwcLayer;

        // The most recently set HWC composition type for this layer
        aidl::android::hardware::graphics::composer3::Composition hwcCompositionType{
                aidl::android::hardware::graphics::composer3::Composition::INVALID};

        // The buffer cache for this layer. This is used to lower the
        // cost of sending reused buffers to the HWC.
        HwcBufferCache hwcBufferCache;

        // Set to true when overridden info has been sent to HW composer
        bool stateOverridden = false;

        // True when this layer was skipped as part of SF-side layer caching.
        bool layerSkipped = false;
    };

    // The HWC state is optional, and is only set up if there is any potential
    // HWC acceleration possible.
    std::optional<Hwc> hwc;

    // Debugging
    void dump(std::string& result) const;

    // Timestamp for when the layer is queued for client composition
    nsecs_t clientCompositionTimestamp{0};

    static constexpr float kDefaultWhitePointNits = 200.f;
    float whitePointNits = kDefaultWhitePointNits;
    // Dimming ratio of the layer from [0, 1]
    static constexpr float kDefaultDimmingRatio = 1.f;
    float dimmingRatio = kDefaultDimmingRatio;
};

} // namespace compositionengine::impl
} // namespace android
