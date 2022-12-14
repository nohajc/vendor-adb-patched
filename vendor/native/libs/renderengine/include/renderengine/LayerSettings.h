/*
 * Copyright 2018 The Android Open Source Project
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

#include <iosfwd>

#include <math/mat4.h>
#include <math/vec3.h>
#include <renderengine/Texture.h>
#include <ui/Fence.h>
#include <ui/FloatRect.h>
#include <ui/GraphicBuffer.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/Transform.h>

namespace android {
namespace renderengine {

// Metadata describing the input buffer to render from.
struct Buffer {
    // Buffer containing the image that we will render.
    // If buffer == nullptr, then the rest of the fields in this struct will be
    // ignored.
    sp<GraphicBuffer> buffer = nullptr;

    // Fence that will fire when the buffer is ready to be bound.
    sp<Fence> fence = nullptr;

    // Texture identifier to bind the external texture to.
    // TODO(alecmouri): This is GL-specific...make the type backend-agnostic.
    uint32_t textureName = 0;

    // Whether to use filtering when rendering the texture.
    bool useTextureFiltering = false;

    // Transform matrix to apply to texture coordinates.
    mat4 textureTransform = mat4();

    // Whether to use pre-multiplied alpha.
    bool usePremultipliedAlpha = true;

    // Override flag that alpha for each pixel in the buffer *must* be 1.0.
    // LayerSettings::alpha is still used if isOpaque==true - this flag only
    // overrides the alpha channel of the buffer.
    bool isOpaque = false;

    // HDR color-space setting for Y410.
    bool isY410BT2020 = false;
    float maxMasteringLuminance = 0.0;
    float maxContentLuminance = 0.0;
};

// Metadata describing the layer geometry.
struct Geometry {
    // Boundaries of the layer.
    FloatRect boundaries = FloatRect();

    // Transform matrix to apply to mesh coordinates.
    mat4 positionTransform = mat4();

    // Radius of rounded corners, if greater than 0. Otherwise, this layer's
    // corners are not rounded.
    // Having corner radius will force GPU composition on the layer and its children, drawing it
    // with a special shader. The shader will receive the radius and the crop rectangle as input,
    // modifying the opacity of the destination texture, multiplying it by a number between 0 and 1.
    // We query Layer#getRoundedCornerState() to retrieve the radius as well as the rounded crop
    // rectangle to figure out how to apply the radius for this layer. The crop rectangle will be
    // in local layer coordinate space, so we have to take the layer transform into account when
    // walking up the tree.
    float roundedCornersRadius = 0.0;

    // Rectangle within which corners will be rounded.
    FloatRect roundedCornersCrop = FloatRect();
};

// Descriptor of the source pixels for this layer.
struct PixelSource {
    // Source buffer
    Buffer buffer = Buffer();

    // The solid color with which to fill the layer.
    // This should only be populated if we don't render from an application
    // buffer.
    half3 solidColor = half3(0.0f, 0.0f, 0.0f);
};

/*
 * Contains the configuration for the shadows drawn by single layer. Shadow follows
 * material design guidelines.
 */
struct ShadowSettings {
    // Color to the ambient shadow. The alpha is premultiplied.
    vec4 ambientColor = vec4();

    // Color to the spot shadow. The alpha is premultiplied. The position of the spot shadow
    // depends on the light position.
    vec4 spotColor = vec4();

    // Position of the light source used to cast the spot shadow.
    vec3 lightPos = vec3();

    // Radius of the spot light source. Smaller radius will have sharper edges,
    // larger radius will have softer shadows
    float lightRadius = 0.f;

    // Length of the cast shadow. If length is <= 0.f no shadows will be drawn.
    float length = 0.f;

    // If true fill in the casting layer is translucent and the shadow needs to fill the bounds.
    // Otherwise the shadow will only be drawn around the edges of the casting layer.
    bool casterIsTranslucent = false;
};

// The settings that RenderEngine requires for correctly rendering a Layer.
struct LayerSettings {
    // Geometry information
    Geometry geometry = Geometry();

    // Source pixels for this layer.
    PixelSource source = PixelSource();

    // Alpha option to blend with the source pixels
    half alpha = half(0.0);

    // Color space describing how the source pixels should be interpreted.
    ui::Dataspace sourceDataspace = ui::Dataspace::UNKNOWN;

    // Additional layer-specific color transform to be applied before the global
    // transform.
    mat4 colorTransform = mat4();

    // True if blending will be forced to be disabled.
    bool disableBlending = false;

    ShadowSettings shadow;

    int backgroundBlurRadius = 0;
};

// Keep in sync with custom comparison function in
// compositionengine/impl/ClientCompositionRequestCache.cpp
static inline bool operator==(const Buffer& lhs, const Buffer& rhs) {
    return lhs.buffer == rhs.buffer && lhs.fence == rhs.fence &&
            lhs.textureName == rhs.textureName &&
            lhs.useTextureFiltering == rhs.useTextureFiltering &&
            lhs.textureTransform == rhs.textureTransform &&
            lhs.usePremultipliedAlpha == rhs.usePremultipliedAlpha &&
            lhs.isOpaque == rhs.isOpaque && lhs.isY410BT2020 == rhs.isY410BT2020 &&
            lhs.maxMasteringLuminance == rhs.maxMasteringLuminance &&
            lhs.maxContentLuminance == rhs.maxContentLuminance;
}

static inline bool operator==(const Geometry& lhs, const Geometry& rhs) {
    return lhs.boundaries == rhs.boundaries && lhs.positionTransform == rhs.positionTransform &&
            lhs.roundedCornersRadius == rhs.roundedCornersRadius &&
            lhs.roundedCornersCrop == rhs.roundedCornersCrop;
}

static inline bool operator==(const PixelSource& lhs, const PixelSource& rhs) {
    return lhs.buffer == rhs.buffer && lhs.solidColor == rhs.solidColor;
}

static inline bool operator==(const ShadowSettings& lhs, const ShadowSettings& rhs) {
    return lhs.ambientColor == rhs.ambientColor && lhs.spotColor == rhs.spotColor &&
            lhs.lightPos == rhs.lightPos && lhs.lightRadius == rhs.lightRadius &&
            lhs.length == rhs.length && lhs.casterIsTranslucent == rhs.casterIsTranslucent;
}

static inline bool operator==(const LayerSettings& lhs, const LayerSettings& rhs) {
    return lhs.geometry == rhs.geometry && lhs.source == rhs.source && lhs.alpha == rhs.alpha &&
            lhs.sourceDataspace == rhs.sourceDataspace &&
            lhs.colorTransform == rhs.colorTransform &&
            lhs.disableBlending == rhs.disableBlending && lhs.shadow == rhs.shadow &&
            lhs.backgroundBlurRadius == rhs.backgroundBlurRadius;
}

// Defining PrintTo helps with Google Tests.

static inline void PrintTo(const Buffer& settings, ::std::ostream* os) {
    *os << "Buffer {";
    *os << "\n    .buffer = " << settings.buffer.get();
    *os << "\n    .fence = " << settings.fence.get();
    *os << "\n    .textureName = " << settings.textureName;
    *os << "\n    .useTextureFiltering = " << settings.useTextureFiltering;
    *os << "\n    .textureTransform = " << settings.textureTransform;
    *os << "\n    .usePremultipliedAlpha = " << settings.usePremultipliedAlpha;
    *os << "\n    .isOpaque = " << settings.isOpaque;
    *os << "\n    .isY410BT2020 = " << settings.isY410BT2020;
    *os << "\n    .maxMasteringLuminance = " << settings.maxMasteringLuminance;
    *os << "\n    .maxContentLuminance = " << settings.maxContentLuminance;
    *os << "\n}";
}

static inline void PrintTo(const Geometry& settings, ::std::ostream* os) {
    *os << "Geometry {";
    *os << "\n    .boundaries = ";
    PrintTo(settings.boundaries, os);
    *os << "\n    .positionTransform = " << settings.positionTransform;
    *os << "\n    .roundedCornersRadius = " << settings.roundedCornersRadius;
    *os << "\n    .roundedCornersCrop = ";
    PrintTo(settings.roundedCornersCrop, os);
    *os << "\n}";
}

static inline void PrintTo(const PixelSource& settings, ::std::ostream* os) {
    *os << "PixelSource {";
    *os << "\n    .buffer = ";
    PrintTo(settings.buffer, os);
    *os << "\n    .solidColor = " << settings.solidColor;
    *os << "\n}";
}

static inline void PrintTo(const ShadowSettings& settings, ::std::ostream* os) {
    *os << "ShadowSettings {";
    *os << "\n    .ambientColor = " << settings.ambientColor;
    *os << "\n    .spotColor = " << settings.spotColor;
    *os << "\n    .lightPos = " << settings.lightPos;
    *os << "\n    .lightRadius = " << settings.lightRadius;
    *os << "\n    .length = " << settings.length;
    *os << "\n    .casterIsTranslucent = " << settings.casterIsTranslucent;
    *os << "\n}";
}

static inline void PrintTo(const LayerSettings& settings, ::std::ostream* os) {
    *os << "LayerSettings {";
    *os << "\n    .geometry = ";
    PrintTo(settings.geometry, os);
    *os << "\n    .source = ";
    PrintTo(settings.source, os);
    *os << "\n    .alpha = " << settings.alpha;
    *os << "\n    .sourceDataspace = ";
    PrintTo(settings.sourceDataspace, os);
    *os << "\n    .colorTransform = " << settings.colorTransform;
    *os << "\n    .disableBlending = " << settings.disableBlending;
    *os << "\n    .backgroundBlurRadius = " << settings.backgroundBlurRadius;
    *os << "\n    .shadow = ";
    PrintTo(settings.shadow, os);
    *os << "\n}";
}

} // namespace renderengine
} // namespace android
