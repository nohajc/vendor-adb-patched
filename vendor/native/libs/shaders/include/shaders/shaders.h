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

#include <math/mat4.h>
#include <tonemap/tonemap.h>
#include <ui/GraphicTypes.h>
#include <cstddef>

namespace android::shaders {

/**
 * Arguments for creating an effect that applies color transformations in linear XYZ space.
 * A linear effect is decomposed into the following steps when operating on an image:
 * 1. Electrical-Optical Transfer Function (EOTF) maps the input RGB signal into the intended
 * relative display brightness of the scene in nits for each RGB channel
 * 2. Transformation matrix from linear RGB brightness to linear XYZ, to operate on display
 * luminance.
 * 3. Opto-Optical Transfer Function (OOTF) applies a "rendering intent". This can include tone
 * mapping to display SDR content alongside HDR content, or any number of subjective transformations
 * 4. Transformation matrix from linear XYZ back to linear RGB brightness.
 * 5. Opto-Electronic Transfer Function (OETF) maps the display brightness of the scene back to
 * output RGB colors.
 *
 * For further reading, consult the recommendation in ITU-R BT.2390-4:
 * https://www.itu.int/dms_pub/itu-r/opb/rep/R-REP-BT.2390-4-2018-PDF-E.pdf
 *
 * Skia normally attempts to do its own simple tone mapping, i.e., the working color space is
 * intended to be the output surface. However, Skia does not support complex tone mapping such as
 * polynomial interpolation. As such, this filter assumes that tone mapping has not yet been applied
 * to the source colors. so that the tone mapping process is only applied once by this effect. Tone
 * mapping is applied when presenting HDR content (content with HLG or PQ transfer functions)
 * alongside other content, whereby maximum input luminance is mapped to maximum output luminance
 * and intermediate values are interpolated.
 */
struct LinearEffect {
    // Input dataspace of the source colors.
    const ui::Dataspace inputDataspace = ui::Dataspace::SRGB;

    // Working dataspace for the output surface, for conversion from linear space.
    const ui::Dataspace outputDataspace = ui::Dataspace::SRGB;

    // Sets whether alpha premultiplication must be undone.
    // This is required if the source colors use premultiplied alpha and is not opaque.
    const bool undoPremultipliedAlpha = false;

    // "Fake" dataspace of the source colors. This is used for applying an EOTF to compute linear
    // RGB. This is used when Skia is expected to color manage the input image based on the
    // dataspace of the provided source image and destination surface. SkRuntimeEffects use the
    // destination color space as the working color space. RenderEngine deliberately sets the color
    // space for input images and destination surfaces to be the same whenever LinearEffects are
    // expected to be used so that color-management is controlled by RenderEngine, but other users
    // of a LinearEffect may not be able to control the color space of the images and surfaces. So
    // fakeInputDataspace is used to essentially masquerade the input dataspace to be the output
    // dataspace for correct conversion to linear colors.
    ui::Dataspace fakeInputDataspace = ui::Dataspace::UNKNOWN;
};

static inline bool operator==(const LinearEffect& lhs, const LinearEffect& rhs) {
    return lhs.inputDataspace == rhs.inputDataspace && lhs.outputDataspace == rhs.outputDataspace &&
            lhs.undoPremultipliedAlpha == rhs.undoPremultipliedAlpha &&
            lhs.fakeInputDataspace == rhs.fakeInputDataspace;
}

struct LinearEffectHasher {
    // Inspired by art/runtime/class_linker.cc
    // Also this is what boost:hash_combine does
    static size_t HashCombine(size_t seed, size_t val) {
        return seed ^ (val + 0x9e3779b9 + (seed << 6) + (seed >> 2));
    }
    size_t operator()(const LinearEffect& le) const {
        size_t result = std::hash<ui::Dataspace>{}(le.inputDataspace);
        result = HashCombine(result, std::hash<ui::Dataspace>{}(le.outputDataspace));
        result = HashCombine(result, std::hash<bool>{}(le.undoPremultipliedAlpha));
        return HashCombine(result, std::hash<ui::Dataspace>{}(le.fakeInputDataspace));
    }
};

// Generates a shader string that applies color transforms in linear space.
// Typical use-cases supported:
// 1. Apply tone-mapping
// 2. Apply color transform matrices in linear space
std::string buildLinearEffectSkSL(const LinearEffect& linearEffect);

// Generates a list of uniforms to set on the LinearEffect shader above.
std::vector<tonemap::ShaderUniform> buildLinearEffectUniforms(
        const LinearEffect& linearEffect, const mat4& colorTransform, float maxDisplayLuminance,
        float currentDisplayLuminanceNits, float maxLuminance, AHardwareBuffer* buffer = nullptr,
        aidl::android::hardware::graphics::composer3::RenderIntent renderIntent =
                aidl::android::hardware::graphics::composer3::RenderIntent::TONE_MAP_COLORIMETRIC);

} // namespace android::shaders
