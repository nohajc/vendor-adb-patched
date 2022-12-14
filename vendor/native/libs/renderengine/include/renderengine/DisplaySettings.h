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

    // Output dataspace that will be populated if wide color gamut is used, or
    // DataSpace::UNKNOWN otherwise.
    ui::Dataspace outputDataspace = ui::Dataspace::UNKNOWN;

    // Additional color transform to apply in linear space after transforming
    // to the output dataspace.
    mat4 colorTransform = mat4();

    // Region that will be cleared to (0, 0, 0, 1) prior to rendering.
    // This is specified in layer-stack space.
    Region clearRegion = Region::INVALID_REGION;

    // An additional orientation flag to be applied after clipping the output.
    // By way of example, this may be used for supporting fullscreen screenshot
    // capture of a device in landscape while the buffer is in portrait
    // orientation.
    uint32_t orientation = ui::Transform::ROT_0;
};

static inline bool operator==(const DisplaySettings& lhs, const DisplaySettings& rhs) {
    return lhs.physicalDisplay == rhs.physicalDisplay && lhs.clip == rhs.clip &&
            lhs.maxLuminance == rhs.maxLuminance && lhs.outputDataspace == rhs.outputDataspace &&
            lhs.colorTransform == rhs.colorTransform &&
            lhs.clearRegion.hasSameRects(rhs.clearRegion) && lhs.orientation == rhs.orientation;
}

// Defining PrintTo helps with Google Tests.
static inline void PrintTo(const DisplaySettings& settings, ::std::ostream* os) {
    *os << "DisplaySettings {";
    *os << "\n    .physicalDisplay = ";
    PrintTo(settings.physicalDisplay, os);
    *os << "\n    .clip = ";
    PrintTo(settings.clip, os);
    *os << "\n    .maxLuminance = " << settings.maxLuminance;
    *os << "\n    .outputDataspace = ";
    PrintTo(settings.outputDataspace, os);
    *os << "\n    .colorTransform = " << settings.colorTransform;
    *os << "\n    .clearRegion = ";
    PrintTo(settings.clearRegion, os);
    *os << "\n    .orientation = " << settings.orientation;
    *os << "\n}";
}

} // namespace renderengine
} // namespace android
