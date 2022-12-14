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

#include <string>

#include <ui/GraphicTypes.h>
#include <ui/Transform.h>
#include <utils/StrongPointer.h>

#include "RenderArea.h"

namespace android {

class DisplayDevice;
class Layer;
class SurfaceFlinger;

class LayerRenderArea : public RenderArea {
public:
    LayerRenderArea(SurfaceFlinger& flinger, sp<Layer> layer, const Rect& crop, ui::Size reqSize,
                    ui::Dataspace reqDataSpace, bool childrenOnly, const Rect& layerStackRect,
                    bool allowSecureLayers);

    const ui::Transform& getTransform() const override;
    Rect getBounds() const override;
    int getHeight() const override;
    int getWidth() const override;
    bool isSecure() const override;
    bool needsFiltering() const override;
    sp<const DisplayDevice> getDisplayDevice() const override;
    Rect getSourceCrop() const override;

    void render(std::function<void()> drawLayers) override;
    virtual sp<Layer> getParentLayer() const { return mLayer; }

private:
    const sp<Layer> mLayer;
    const Rect mCrop;

    ui::Transform mTransform;
    bool mNeedsFiltering = false;

    SurfaceFlinger& mFlinger;
    const bool mChildrenOnly;
};

} // namespace android
