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

#include "DisplayRenderArea.h"
#include "DisplayDevice.h"

namespace android {
namespace {

RenderArea::RotationFlags applyDeviceOrientation(bool useIdentityTransform,
                                                 const DisplayDevice& display) {
    if (!useIdentityTransform) {
        return RenderArea::RotationFlags::ROT_0;
    }

    return ui::Transform::toRotationFlags(display.getOrientation());
}

} // namespace

std::unique_ptr<RenderArea> DisplayRenderArea::create(wp<const DisplayDevice> displayWeak,
                                                      const Rect& sourceCrop, ui::Size reqSize,
                                                      ui::Dataspace reqDataSpace,
                                                      bool useIdentityTransform,
                                                      bool allowSecureLayers) {
    if (auto display = displayWeak.promote()) {
        // Using new to access a private constructor.
        return std::unique_ptr<DisplayRenderArea>(
                new DisplayRenderArea(std::move(display), sourceCrop, reqSize, reqDataSpace,
                                      useIdentityTransform, allowSecureLayers));
    }
    return nullptr;
}

DisplayRenderArea::DisplayRenderArea(sp<const DisplayDevice> display, const Rect& sourceCrop,
                                     ui::Size reqSize, ui::Dataspace reqDataSpace,
                                     bool useIdentityTransform, bool allowSecureLayers)
      : RenderArea(reqSize, CaptureFill::OPAQUE, reqDataSpace, display->getLayerStackSpaceRect(),
                   allowSecureLayers, applyDeviceOrientation(useIdentityTransform, *display)),
        mDisplay(std::move(display)),
        mSourceCrop(sourceCrop) {}

const ui::Transform& DisplayRenderArea::getTransform() const {
    return mTransform;
}

Rect DisplayRenderArea::getBounds() const {
    return mDisplay->getBounds();
}

int DisplayRenderArea::getHeight() const {
    return mDisplay->getHeight();
}

int DisplayRenderArea::getWidth() const {
    return mDisplay->getWidth();
}

bool DisplayRenderArea::isSecure() const {
    return mAllowSecureLayers && mDisplay->isSecure();
}

sp<const DisplayDevice> DisplayRenderArea::getDisplayDevice() const {
    return mDisplay;
}

bool DisplayRenderArea::needsFiltering() const {
    // check if the projection from the logical render area
    // to the physical render area requires filtering
    const Rect& sourceCrop = getSourceCrop();
    int width = sourceCrop.width();
    int height = sourceCrop.height();
    if (getRotationFlags() & ui::Transform::ROT_90) {
        std::swap(width, height);
    }
    return width != getReqWidth() || height != getReqHeight();
}

Rect DisplayRenderArea::getSourceCrop() const {
    // use the projected display viewport by default.
    if (mSourceCrop.isEmpty()) {
        return mDisplay->getLayerStackSpaceRect();
    }

    // Correct for the orientation when the screen capture request contained
    // useIdentityTransform. This will cause the rotation flag to be non 0 since
    // it needs to rotate based on the screen orientation to allow the screenshot
    // to be taken in the ROT_0 orientation
    const auto flags = getRotationFlags();
    int width = mDisplay->getLayerStackSpaceRect().getWidth();
    int height = mDisplay->getLayerStackSpaceRect().getHeight();
    ui::Transform rotation;
    rotation.set(flags, width, height);
    return rotation.transform(mSourceCrop);
}

} // namespace android