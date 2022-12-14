/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <sys/types.h>

#include <cstdint>

#include "Layer.h"

namespace android {

// A layer that can render a combination of the following effects.
//   * fill the bounds of the layer with a color
//   * render a shadow cast by the bounds of the layer
// If no effects are enabled, the layer is considered to be invisible.
class EffectLayer : public Layer {
public:
    explicit EffectLayer(const LayerCreationArgs&);
    ~EffectLayer() override;

    sp<compositionengine::LayerFE> getCompositionEngineLayerFE() const override;
    compositionengine::LayerFECompositionState* editCompositionState() override;

    const char* getType() const override { return "EffectLayer"; }
    bool isVisible() const override;

    bool setColor(const half3& color) override;

    bool setDataspace(ui::Dataspace dataspace) override;

    ui::Dataspace getDataSpace() const override;

    bool isOpaque(const Layer::State& s) const override;

protected:
    /*
     * compositionengine::LayerFE overrides
     */
    const compositionengine::LayerFECompositionState* getCompositionState() const override;
    void preparePerFrameCompositionState() override;
    std::vector<compositionengine::LayerFE::LayerSettings> prepareClientCompositionList(
            compositionengine::LayerFE::ClientCompositionTargetSettings& targetSettings) override;

    std::unique_ptr<compositionengine::LayerFECompositionState> mCompositionState;

    sp<Layer> createClone() override;

private:
    // Returns true if there is a valid color to fill.
    bool fillsColor() const;
    // Returns true if this layer has a blur value.
    bool hasBlur() const;
    bool hasSomethingToDraw() const { return fillsColor() || drawShadows() || hasBlur(); }
};

} // namespace android
