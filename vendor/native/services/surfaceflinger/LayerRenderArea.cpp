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

#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

#include "ContainerLayer.h"
#include "DisplayDevice.h"
#include "Layer.h"
#include "LayerRenderArea.h"
#include "SurfaceFlinger.h"

namespace android {
namespace {

void reparentForDrawing(const sp<Layer>& oldParent, const sp<Layer>& newParent,
                   const Rect& drawingBounds) {
        // Compute and cache the bounds for the new parent layer.
        newParent->computeBounds(drawingBounds.toFloatRect(), ui::Transform(),
            0.f /* shadowRadius */);
        oldParent->setChildrenDrawingParent(newParent);
};

} // namespace

LayerRenderArea::LayerRenderArea(SurfaceFlinger& flinger, sp<Layer> layer, const Rect& crop,
                                 ui::Size reqSize, ui::Dataspace reqDataSpace, bool childrenOnly,
                                 const Rect& layerStackRect, bool allowSecureLayers)
      : RenderArea(reqSize, CaptureFill::CLEAR, reqDataSpace, layerStackRect, allowSecureLayers),
        mLayer(std::move(layer)),
        mCrop(crop),
        mFlinger(flinger),
        mChildrenOnly(childrenOnly) {}

const ui::Transform& LayerRenderArea::getTransform() const {
    return mTransform;
}

Rect LayerRenderArea::getBounds() const {
    return mLayer->getBufferSize(mLayer->getDrawingState());
}

int LayerRenderArea::getHeight() const {
    return mLayer->getBufferSize(mLayer->getDrawingState()).getHeight();
}

int LayerRenderArea::getWidth() const {
    return mLayer->getBufferSize(mLayer->getDrawingState()).getWidth();
}

bool LayerRenderArea::isSecure() const {
    return mAllowSecureLayers;
}

bool LayerRenderArea::needsFiltering() const {
    return mNeedsFiltering;
}

sp<const DisplayDevice> LayerRenderArea::getDisplayDevice() const {
    return nullptr;
}

Rect LayerRenderArea::getSourceCrop() const {
    if (mCrop.isEmpty()) {
        return getBounds();
    } else {
        return mCrop;
    }
}

void LayerRenderArea::render(std::function<void()> drawLayers) {
    using namespace std::string_literals;

    const Rect sourceCrop = getSourceCrop();
    // no need to check rotation because there is none
    mNeedsFiltering = sourceCrop.width() != getReqWidth() || sourceCrop.height() != getReqHeight();

    // If layer is offscreen, update mirroring info if it exists
    if (mLayer->isRemovedFromCurrentState()) {
        mLayer->traverse(LayerVector::StateSet::Drawing,
                         [&](Layer* layer) { layer->updateMirrorInfo(); });
        mLayer->traverse(LayerVector::StateSet::Drawing,
                         [&](Layer* layer) { layer->updateCloneBufferInfo(); });
    }

    if (!mChildrenOnly) {
        mTransform = mLayer->getTransform().inverse();
        // If the layer is offscreen, compute bounds since we don't compute bounds for offscreen
        // layers in a regular cycles.
        if (mLayer->isRemovedFromCurrentState()) {
            FloatRect maxBounds = mFlinger.getMaxDisplayBounds();
            mLayer->computeBounds(maxBounds, ui::Transform(), 0.f /* shadowRadius */);
        }
        drawLayers();
    } else {
        // In the "childrenOnly" case we reparent the children to a screenshot
        // layer which has no properties set and which does not draw.
        //  We hold the statelock as the reparent-for-drawing operation modifies the
        //  hierarchy and there could be readers on Binder threads, like dump.
        sp<ContainerLayer> screenshotParentLayer = mFlinger.getFactory().createContainerLayer(
                  {&mFlinger, nullptr, "Screenshot Parent"s, 0, LayerMetadata()});
        {
            Mutex::Autolock _l(mFlinger.mStateLock);
            reparentForDrawing(mLayer, screenshotParentLayer, sourceCrop);
        }
        drawLayers();
        {
            Mutex::Autolock _l(mFlinger.mStateLock);
            mLayer->setChildrenDrawingParent(mLayer);
        }
    }
}

} // namespace android
