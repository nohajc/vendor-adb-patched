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

#include <optional>
#include <ostream>
#include <unordered_set>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <renderengine/LayerSettings.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

#include <utils/RefBase.h>
#include <utils/Timers.h>

namespace android {

class Fence;

namespace compositionengine {

struct LayerFECompositionState;

// Defines the interface used by the CompositionEngine to make requests
// of the front-end layer
class LayerFE : public virtual RefBase {
public:
    // Gets the raw front-end composition state data for the layer
    virtual const LayerFECompositionState* getCompositionState() const = 0;

    // Called before composition starts. Should return true if this layer has
    // pending updates which would require an extra display refresh cycle to
    // process.
    virtual bool onPreComposition(nsecs_t refreshStartTime) = 0;

    // Used with latchCompositionState()
    enum class StateSubset {
        // Gets the basic geometry (bounds, transparent region, visibility,
        // transforms, alpha) for the layer, for computing visibility and
        // coverage.
        BasicGeometry,

        // Gets the full geometry (crops, buffer transforms, metadata) and
        // content (buffer or color) state for the layer.
        GeometryAndContent,

        // Gets the per frame content (buffer or color) state for the layer.
        Content,

        // Gets the cursor state for the layer.
        Cursor,
    };

    // Prepares the output-independent composition state for the layer. The
    // StateSubset argument selects what portion of the state is actually needed
    // by the CompositionEngine code, since computing everything may be
    // expensive.
    virtual void prepareCompositionState(StateSubset) = 0;

    struct ClientCompositionTargetSettings {
        // The clip region, or visible region that is being rendered to
        const Region& clip;

        // If true, the layer should use an identity transform for its position
        // transform. Used only by the captureScreen API call.
        const bool useIdentityTransform;

        // If set to true, the layer should enable filtering when rendering.
        const bool needsFiltering;

        // If set to true, the buffer is being sent to a destination that is
        // expected to treat the buffer contents as secure.
        const bool isSecure;

        // If set to true, the target buffer has protected content support.
        const bool supportsProtectedContent;

        // Modified by each call to prepareClientComposition to indicate the
        // region of the target buffer that should be cleared.
        Region& clearRegion;

        // Viewport of the target being rendered to. This is used to determine
        // the shadow light position.
        const Rect& viewport;

        // Dataspace of the output so we can optimize how to render the shadow
        // by avoiding unnecessary color space conversions.
        const ui::Dataspace dataspace;

        // True if the region excluding the shadow is visible.
        const bool realContentIsVisible;

        // If set to true, change the layer settings to render a clear output.
        // This may be requested by the HWC
        const bool clearContent;
    };

    // A superset of LayerSettings required by RenderEngine to compose a layer
    // and buffer info to determine duplicate client composition requests.
    struct LayerSettings : renderengine::LayerSettings {
        // Currently latched buffer if, 0 if invalid.
        uint64_t bufferId = 0;

        // Currently latched frame number, 0 if invalid.
        uint64_t frameNumber = 0;
    };

    // Returns the z-ordered list of LayerSettings to pass to RenderEngine::drawLayers. The list
    // may contain shadows casted by the layer or the content of the layer itself.  If the layer
    // does not render then an empty list will be returned.
    virtual std::vector<LayerSettings> prepareClientCompositionList(
            ClientCompositionTargetSettings&) = 0;

    // Called after the layer is displayed to update the presentation fence
    virtual void onLayerDisplayed(const sp<Fence>&) = 0;

    // Gets some kind of identifier for the layer for debug purposes.
    virtual const char* getDebugName() const = 0;
};

// TODO(b/121291683): Specialize std::hash<> for sp<T> so these and others can
// be removed.
struct LayerFESpHash {
    size_t operator()(const sp<LayerFE>& p) const { return std::hash<LayerFE*>()(p.get()); }
};

using LayerFESet = std::unordered_set<sp<LayerFE>, LayerFESpHash>;

static inline bool operator==(const LayerFE::ClientCompositionTargetSettings& lhs,
                              const LayerFE::ClientCompositionTargetSettings& rhs) {
    return lhs.clip.hasSameRects(rhs.clip) &&
            lhs.useIdentityTransform == rhs.useIdentityTransform &&
            lhs.needsFiltering == rhs.needsFiltering && lhs.isSecure == rhs.isSecure &&
            lhs.supportsProtectedContent == rhs.supportsProtectedContent &&
            lhs.clearRegion.hasSameRects(rhs.clearRegion) && lhs.viewport == rhs.viewport &&
            lhs.dataspace == rhs.dataspace &&
            lhs.realContentIsVisible == rhs.realContentIsVisible &&
            lhs.clearContent == rhs.clearContent;
}

static inline bool operator==(const LayerFE::LayerSettings& lhs,
                              const LayerFE::LayerSettings& rhs) {
    return static_cast<const renderengine::LayerSettings&>(lhs) ==
            static_cast<const renderengine::LayerSettings&>(rhs) &&
            lhs.bufferId == rhs.bufferId && lhs.frameNumber == rhs.frameNumber;
}

// Defining PrintTo helps with Google Tests.
static inline void PrintTo(const LayerFE::ClientCompositionTargetSettings& settings,
                           ::std::ostream* os) {
    *os << "ClientCompositionTargetSettings{";
    *os << "\n    .clip = \n";
    PrintTo(settings.clip, os);
    *os << "\n    .useIdentityTransform = " << settings.useIdentityTransform;
    *os << "\n    .needsFiltering = " << settings.needsFiltering;
    *os << "\n    .isSecure = " << settings.isSecure;
    *os << "\n    .supportsProtectedContent = " << settings.supportsProtectedContent;
    *os << "\n    .clearRegion = ";
    PrintTo(settings.clearRegion, os);
    *os << "\n    .viewport = ";
    PrintTo(settings.viewport, os);
    *os << "\n    .dataspace = ";
    PrintTo(settings.dataspace, os);
    *os << "\n    .realContentIsVisible = " << settings.realContentIsVisible;
    *os << "\n    .clearContent = " << settings.clearContent;
    *os << "\n}";
}

static inline void PrintTo(const LayerFE::LayerSettings& settings, ::std::ostream* os) {
    *os << "LayerFE::LayerSettings{";
    PrintTo(static_cast<const renderengine::LayerSettings&>(settings), os);
    *os << "\n    .bufferId = " << settings.bufferId;
    *os << "\n    .frameNumber = " << settings.frameNumber;
    *os << "\n}";
}

} // namespace compositionengine
} // namespace android
