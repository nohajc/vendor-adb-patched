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

#include <compositionengine/FenceResult.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <renderengine/LayerSettings.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

#include <ftl/future.h>
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
        enum class BlurSetting {
            Disabled,
            BackgroundBlurOnly,
            BlurRegionsOnly,
            Enabled,
        };

        friend std::string toString(BlurSetting blurSetting) {
            switch (blurSetting) {
                case BlurSetting::Enabled:
                    return "Enabled";
                case BlurSetting::BlurRegionsOnly:
                    return "BlurRegionsOnly";
                case BlurSetting::BackgroundBlurOnly:
                    return "BackgroundBlurOnly";
                case BlurSetting::Disabled:
                    return "Disabled";
            }
        }

        friend std::ostream& operator<<(std::ostream& os, const BlurSetting& setting) {
            return os << toString(setting);
        }

        // The clip region, or visible region that is being rendered to
        const Region& clip;

        // If set to true, the layer should enable filtering when rendering.
        const bool needsFiltering;

        // If set to true, the buffer is being sent to a destination that is
        // expected to treat the buffer contents as secure.
        const bool isSecure;

        // If set to true, the target buffer has protected content support.
        const bool supportsProtectedContent;

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

        // Configure layer settings for using blurs
        BlurSetting blurSetting;

        // Requested white point of the layer in nits
        const float whitePointNits;
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
    virtual void onLayerDisplayed(ftl::SharedFuture<FenceResult>) = 0;

    // Gets some kind of identifier for the layer for debug purposes.
    virtual const char* getDebugName() const = 0;

    // Gets the sequence number: a serial number that uniquely identifies a Layer
    virtual int32_t getSequence() const = 0;

    // Whether the layer should be rendered with rounded corners.
    virtual bool hasRoundedCorners() const = 0;
    virtual void setWasClientComposed(const sp<Fence>&) {}
};

// TODO(b/121291683): Specialize std::hash<> for sp<T> so these and others can
// be removed.
struct LayerFESpHash {
    size_t operator()(const sp<LayerFE>& p) const { return std::hash<LayerFE*>()(p.get()); }
};

using LayerFESet = std::unordered_set<sp<LayerFE>, LayerFESpHash>;

static inline bool operator==(const LayerFE::ClientCompositionTargetSettings& lhs,
                              const LayerFE::ClientCompositionTargetSettings& rhs) {
    return lhs.clip.hasSameRects(rhs.clip) && lhs.needsFiltering == rhs.needsFiltering &&
            lhs.isSecure == rhs.isSecure &&
            lhs.supportsProtectedContent == rhs.supportsProtectedContent &&
            lhs.viewport == rhs.viewport && lhs.dataspace == rhs.dataspace &&
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
    *os << "\n    .needsFiltering = " << settings.needsFiltering;
    *os << "\n    .isSecure = " << settings.isSecure;
    *os << "\n    .supportsProtectedContent = " << settings.supportsProtectedContent;
    *os << "\n    .viewport = ";
    PrintTo(settings.viewport, os);
    *os << "\n    .dataspace = ";
    PrintTo(settings.dataspace, os);
    *os << "\n    .realContentIsVisible = " << settings.realContentIsVisible;
    *os << "\n    .clearContent = " << settings.clearContent;
    *os << "\n    .blurSetting = " << settings.blurSetting;
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
