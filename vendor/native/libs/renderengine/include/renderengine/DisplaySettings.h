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

#include <aidl/android/hardware/graphics/composer3/DimmingStage.h>
#include <aidl/android/hardware/graphics/composer3/RenderIntent.h>
#include <iosfwd>

#include <math/mat4.h>
#include <renderengine/PrintMatrix.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <ui/Transform.h>

namespace android {
namespace renderengine {

// DisplaySettings contains the settings that are applicable when drawing all
// layers for a given display.
struct DisplaySettings {
    // Rectangle describing the physical display. We will project from the
    // logical clip onto this rectangle.
    Rect physicalDisplay = Rect::INVALID_RECT;

    // Rectangle bounded by the x,y- clipping planes in the logical display, so
    // that the orthographic projection matrix can be computed. When
    // constructing this matrix, z-coordinate bound are assumed to be at z=0 and
    // z=1.
    Rect clip = Rect::INVALID_RECT;

    // Maximum luminance pulled from the display's HDR capabilities.
    float maxLuminance = 1.0f;

    // Current luminance of the display
    float currentLuminanceNits = -1.f;

    // Output dataspace that will be populated if wide color gamut is used, or
    // DataSpace::UNKNOWN otherwise.
    ui::Dataspace outputDataspace = ui::Dataspace::UNKNOWN;

    // Additional color transform to apply after transforming to the output
    // dataspace, in non-linear space.
    mat4 colorTransform = mat4();

    // If true, and colorTransform is non-identity, most client draw calls can
    // ignore it. Some draws (e.g. screen decorations) may need it, though.
    bool deviceHandlesColorTransform = false;

    // An additional orientation flag to be applied after clipping the output.
    // By way of example, this may be used for supporting fullscreen screenshot
    // capture of a device in landscape while the buffer is in portrait
    // orientation.
    uint32_t orientation = ui::Transform::ROT_0;

    // Target luminance of the display. -1f if unknown.
    // All layers will be dimmed by (max(layer white points) / targetLuminanceNits).
    // If the target luminance is unknown, then no display-level dimming occurs.
    float targetLuminanceNits = -1.f;

    // Configures when dimming should be applied for each layer.
    aidl::android::hardware::graphics::composer3::DimmingStage dimmingStage =
            aidl::android::hardware::graphics::composer3::DimmingStage::NONE;

    // Configures the rendering intent of the output display. This is used for tonemapping.
    aidl::android::hardware::graphics::composer3::RenderIntent renderIntent =
            aidl::android::hardware::graphics::composer3::RenderIntent::TONE_MAP_COLORIMETRIC;
};

static inline bool operator==(const DisplaySettings& lhs, const DisplaySettings& rhs) {
    return lhs.physicalDisplay == rhs.physicalDisplay && lhs.clip == rhs.clip &&
            lhs.maxLuminance == rhs.maxLuminance &&
            lhs.currentLuminanceNits == rhs.currentLuminanceNits &&
            lhs.outputDataspace == rhs.outputDataspace &&
            lhs.colorTransform == rhs.colorTransform &&
            lhs.deviceHandlesColorTransform == rhs.deviceHandlesColorTransform &&
            lhs.orientation == rhs.orientation &&
            lhs.targetLuminanceNits == rhs.targetLuminanceNits &&
            lhs.dimmingStage == rhs.dimmingStage && lhs.renderIntent == rhs.renderIntent;
}

static const char* orientation_to_string(uint32_t orientation) {
    switch (orientation) {
        case ui::Transform::ROT_0:
            return "ROT_0";
        case ui::Transform::FLIP_H:
            return "FLIP_H";
        case ui::Transform::FLIP_V:
            return "FLIP_V";
        case ui::Transform::ROT_90:
            return "ROT_90";
        case ui::Transform::ROT_180:
            return "ROT_180";
        case ui::Transform::ROT_270:
            return "ROT_270";
        case ui::Transform::ROT_INVALID:
            return "ROT_INVALID";
        default:
            ALOGE("invalid orientation!");
            return "invalid orientation";
    }
}

static inline void PrintTo(const DisplaySettings& settings, ::std::ostream* os) {
    *os << "DisplaySettings {";
    *os << "\n    .physicalDisplay = ";
    PrintTo(settings.physicalDisplay, os);
    *os << "\n    .clip = ";
    PrintTo(settings.clip, os);
    *os << "\n    .maxLuminance = " << settings.maxLuminance;
    *os << "\n    .currentLuminanceNits = " << settings.currentLuminanceNits;
    *os << "\n    .outputDataspace = ";
    PrintTo(settings.outputDataspace, os);
    *os << "\n    .colorTransform = ";
    PrintMatrix(settings.colorTransform, os);
    *os << "\n    .deviceHandlesColorTransform = " << settings.deviceHandlesColorTransform;
    *os << "\n    .orientation = " << orientation_to_string(settings.orientation);
    *os << "\n    .targetLuminanceNits = " << settings.targetLuminanceNits;
    *os << "\n    .dimmingStage = "
        << aidl::android::hardware::graphics::composer3::toString(settings.dimmingStage).c_str();
    *os << "\n    .renderIntent = "
        << aidl::android::hardware::graphics::composer3::toString(settings.renderIntent).c_str();
    *os << "\n}";
}

} // namespace renderengine
} // namespace android
