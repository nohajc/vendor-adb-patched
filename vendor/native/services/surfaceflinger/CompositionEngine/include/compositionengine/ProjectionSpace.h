/*
 * Copyright 2020 The Android Open Source Project
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

#include <ostream>

#include <android-base/stringprintf.h>
#include <ui/Rect.h>
#include <ui/Rotation.h>
#include <ui/Transform.h>

namespace android {
namespace compositionengine {

// Geometrical space to which content is projected.
// For example, this can be the layer space or the physical display space.
struct ProjectionSpace {
    ProjectionSpace() = default;
    ProjectionSpace(ui::Size size, Rect content)
          : bounds(std::move(size)), content(std::move(content)) {}

    // Bounds of this space. Always starts at (0,0).
    Rect bounds;

    // Rect onto which content is projected.
    Rect content;

    // The orientation of this space. This value is meaningful only in relation to the rotation
    // of another projection space and it's used to determine the rotating transformation when
    // mapping between the two.
    // As a convention when using this struct orientation = 0 for the "oriented*" projection
    // spaces. For example when the display is rotated 90 degress counterclockwise, the orientation
    // of the display space will become 90, while  the orientation of the layer stack space will
    // remain the same.
    ui::Rotation orientation = ui::ROTATION_0;

    // Returns a transform which maps this.content into destination.content
    // and also rotates according to this.orientation and destination.orientation
    ui::Transform getTransform(const ProjectionSpace& destination) const {
        ui::Rotation rotation = destination.orientation - orientation;

        // Compute a transformation which rotates the destination in a way it has the same
        // orientation as us.
        const uint32_t inverseRotationFlags = ui::Transform::toRotationFlags(-rotation);
        ui::Transform inverseRotatingTransform;
        inverseRotatingTransform.set(inverseRotationFlags, destination.bounds.width(),
                                     destination.bounds.height());
        // The destination content rotated so it has the same orientation as us.
        Rect orientedDestContent = inverseRotatingTransform.transform(destination.content);

        // Compute translation from the source content to (0, 0).
        const float sourceX = content.left;
        const float sourceY = content.top;
        ui::Transform sourceTranslation;
        sourceTranslation.set(-sourceX, -sourceY);

        // Compute scaling transform which maps source content to destination content, assuming
        // they are both at (0, 0).
        ui::Transform scale;
        const float scaleX = static_cast<float>(orientedDestContent.width()) / content.width();
        const float scaleY = static_cast<float>(orientedDestContent.height()) / content.height();
        scale.set(scaleX, 0, 0, scaleY);

        // Compute translation from (0, 0) to the orientated destination content.
        const float destX = orientedDestContent.left;
        const float destY = orientedDestContent.top;
        ui::Transform destTranslation;
        destTranslation.set(destX, destY);

        // Compute rotation transform.
        const uint32_t orientationFlags = ui::Transform::toRotationFlags(rotation);
        auto orientedDestWidth = destination.bounds.width();
        auto orientedDestHeight = destination.bounds.height();
        if (rotation == ui::ROTATION_90 || rotation == ui::ROTATION_270) {
            std::swap(orientedDestWidth, orientedDestHeight);
        }
        ui::Transform rotationTransform;
        rotationTransform.set(orientationFlags, orientedDestWidth, orientedDestHeight);

        // The layerStackSpaceRect and orientedDisplaySpaceRect are both in the logical orientation.
        // Apply the logical translation, scale to physical size, apply the
        // physical translation and finally rotate to the physical orientation.
        return rotationTransform * destTranslation * scale * sourceTranslation;
    }

    bool operator==(const ProjectionSpace& other) const {
        return bounds == other.bounds && content == other.content &&
                orientation == other.orientation;
    }
};

} // namespace compositionengine

inline std::string to_string(const android::compositionengine::ProjectionSpace& space) {
    return android::base::
            StringPrintf("ProjectionSpace(bounds = %s, content = %s, orientation = %s)",
                         to_string(space.bounds).c_str(), to_string(space.content).c_str(),
                         toCString(space.orientation));
}

// Defining PrintTo helps with Google Tests.
inline void PrintTo(const android::compositionengine::ProjectionSpace& space, ::std::ostream* os) {
    *os << to_string(space);
}

} // namespace android