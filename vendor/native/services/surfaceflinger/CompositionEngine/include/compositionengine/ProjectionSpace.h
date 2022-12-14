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
class ProjectionSpace {
public:
    ProjectionSpace() = default;
    ProjectionSpace(ui::Size size, Rect content) : mBounds(size), mContent(std::move(content)) {}

    // Returns a transform which maps this.content into destination.content
    // and also rotates according to this.orientation and destination.orientation
    ui::Transform getTransform(const ProjectionSpace& destination) const {
        ui::Rotation rotation = destination.getOrientation() - mOrientation;

        // Compute a transformation which rotates the destination in a way it has the same
        // orientation as us.
        const uint32_t inverseRotationFlags = ui::Transform::toRotationFlags(-rotation);
        ui::Transform inverseRotatingTransform;
        inverseRotatingTransform.set(inverseRotationFlags, destination.getBounds().width,
                                     destination.getBounds().height);
        // The destination content rotated so it has the same orientation as us.
        Rect orientedDestContent = inverseRotatingTransform.transform(destination.getContent());

        // Compute translation from the source content to (0, 0).
        const float sourceX = mContent.left;
        const float sourceY = mContent.top;
        ui::Transform sourceTranslation;
        sourceTranslation.set(-sourceX, -sourceY);

        // Compute scaling transform which maps source content to destination content, assuming
        // they are both at (0, 0).
        ui::Transform scale;
        const float scaleX = static_cast<float>(orientedDestContent.width()) / mContent.width();
        const float scaleY = static_cast<float>(orientedDestContent.height()) / mContent.height();
        scale.set(scaleX, 0, 0, scaleY);

        // Compute translation from (0, 0) to the orientated destination content.
        const float destX = orientedDestContent.left;
        const float destY = orientedDestContent.top;
        ui::Transform destTranslation;
        destTranslation.set(destX, destY);

        // Compute rotation transform.
        const uint32_t orientationFlags = ui::Transform::toRotationFlags(rotation);
        auto orientedDestWidth = destination.getBounds().width;
        auto orientedDestHeight = destination.getBounds().height;
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
        return mBounds == other.mBounds && mContent == other.mContent &&
                mOrientation == other.mOrientation;
    }

    void setBounds(ui::Size newBounds) { mBounds = std::move(newBounds); }

    void setContent(Rect newContent) { mContent = std::move(newContent); }

    void setOrientation(ui::Rotation newOrientation) { mOrientation = newOrientation; }

    Rect getBoundsAsRect() const { return Rect(mBounds.getWidth(), mBounds.getHeight()); }

    const ui::Size& getBounds() const { return mBounds; }

    const Rect& getContent() const { return mContent; }

    ui::Rotation getOrientation() const { return mOrientation; }

private:
    // Bounds of this space. Always starts at (0,0).
    ui::Size mBounds = ui::Size();

    // Rect onto which content is projected.
    Rect mContent = Rect();

    // The orientation of this space. This value is meaningful only in relation to the rotation
    // of another projection space and it's used to determine the rotating transformation when
    // mapping between the two.
    // As a convention when using this struct orientation = 0 for the "oriented*" projection
    // spaces. For example when the display is rotated 90 degress counterclockwise, the orientation
    // of the display space will become 90, while  the orientation of the layer stack space will
    // remain the same.
    ui::Rotation mOrientation = ui::ROTATION_0;
};

} // namespace compositionengine

inline std::string to_string(const compositionengine::ProjectionSpace& space) {
    return base::StringPrintf("ProjectionSpace{bounds=%s, content=%s, orientation=%s}",
                              to_string(space.getBoundsAsRect()).c_str(),
                              to_string(space.getContent()).c_str(),
                              toCString(space.getOrientation()));
}

// Defining PrintTo helps with Google Tests.
inline void PrintTo(const compositionengine::ProjectionSpace& space, std::ostream* os) {
    *os << to_string(space);
}

} // namespace android
