/*
 * Copyright 2019 The Android Open Source Project
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

#include <compositionengine/CompositionRefreshArgs.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/Output.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/impl/GpuCompositionResult.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <gmock/gmock.h>

namespace android::compositionengine::mock {

class Output : public virtual compositionengine::Output {
public:
    Output();
    virtual ~Output();

    MOCK_CONST_METHOD0(isValid, bool());
    MOCK_CONST_METHOD0(getDisplayId, std::optional<DisplayId>());

    MOCK_METHOD1(setCompositionEnabled, void(bool));
    MOCK_METHOD1(setLayerCachingEnabled, void(bool));
    MOCK_METHOD1(setLayerCachingTexturePoolEnabled, void(bool));
    MOCK_METHOD3(setProjection, void(ui::Rotation, const Rect&, const Rect&));
    MOCK_METHOD1(setNextBrightness, void(float));
    MOCK_METHOD1(setDisplaySize, void(const ui::Size&));
    MOCK_CONST_METHOD0(getTransformHint, ui::Transform::RotationFlags());

    MOCK_METHOD(void, setLayerFilter, (ui::LayerFilter));
    MOCK_METHOD(bool, includesLayer, (ui::LayerFilter), (const));
    MOCK_METHOD(bool, includesLayer, (const sp<compositionengine::LayerFE>&), (const));

    MOCK_METHOD1(setColorTransform, void(const compositionengine::CompositionRefreshArgs&));
    MOCK_METHOD1(setColorProfile, void(const ColorProfile&));
    MOCK_METHOD2(setDisplayBrightness, void(float, float));

    MOCK_CONST_METHOD1(dump, void(std::string&));
    MOCK_CONST_METHOD2(dumpPlannerInfo, void(const Vector<String16>&, std::string&));
    MOCK_CONST_METHOD0(getName, const std::string&());
    MOCK_METHOD1(setName, void(const std::string&));

    MOCK_CONST_METHOD0(getDisplayColorProfile, compositionengine::DisplayColorProfile*());
    MOCK_METHOD1(setDisplayColorProfile,
                 void(std::unique_ptr<compositionengine::DisplayColorProfile>));

    MOCK_CONST_METHOD0(getRenderSurface, compositionengine::RenderSurface*());
    MOCK_METHOD1(setRenderSurface, void(std::unique_ptr<compositionengine::RenderSurface>));

    MOCK_CONST_METHOD0(getState, const OutputCompositionState&());
    MOCK_METHOD0(editState, OutputCompositionState&());

    MOCK_METHOD(Region, getDirtyRegion, (), (const));

    MOCK_CONST_METHOD1(getOutputLayerForLayer,
                       compositionengine::OutputLayer*(const sp<compositionengine::LayerFE>&));
    MOCK_METHOD0(clearOutputLayers, void());
    MOCK_METHOD1(injectOutputLayerForTest,
                 compositionengine::OutputLayer*(const sp<compositionengine::LayerFE>&));
    MOCK_CONST_METHOD0(getOutputLayerCount, size_t());
    MOCK_CONST_METHOD1(getOutputLayerOrderedByZByIndex, OutputLayer*(size_t));

    MOCK_METHOD1(setReleasedLayers, void(ReleasedLayers&&));

    MOCK_METHOD2(prepare, void(const compositionengine::CompositionRefreshArgs&, LayerFESet&));
    MOCK_METHOD1(present, void(const compositionengine::CompositionRefreshArgs&));

    MOCK_METHOD2(rebuildLayerStacks,
                 void(const compositionengine::CompositionRefreshArgs&, LayerFESet&));
    MOCK_METHOD2(collectVisibleLayers,
                 void(const compositionengine::CompositionRefreshArgs&,
                      compositionengine::Output::CoverageState&));
    MOCK_METHOD2(ensureOutputLayerIfVisible,
                 void(sp<compositionengine::LayerFE>&, compositionengine::Output::CoverageState&));
    MOCK_METHOD1(setReleasedLayers, void(const compositionengine::CompositionRefreshArgs&));

    MOCK_CONST_METHOD1(updateLayerStateFromFE, void(const CompositionRefreshArgs&));
    MOCK_METHOD1(updateCompositionState, void(const CompositionRefreshArgs&));
    MOCK_METHOD0(planComposition, void());
    MOCK_METHOD1(writeCompositionState, void(const CompositionRefreshArgs&));
    MOCK_METHOD1(updateColorProfile, void(const compositionengine::CompositionRefreshArgs&));

    MOCK_METHOD0(beginFrame, void());

    MOCK_METHOD0(prepareFrame, void());
    MOCK_METHOD1(prepareFrameAsync, GpuCompositionResult(const CompositionRefreshArgs&));
    MOCK_METHOD1(chooseCompositionStrategy,
                 bool(std::optional<android::HWComposer::DeviceRequestedChanges>*));
    MOCK_METHOD1(chooseCompositionStrategyAsync,
                 std::future<bool>(std::optional<android::HWComposer::DeviceRequestedChanges>*));
    MOCK_METHOD1(applyCompositionStrategy,
                 void(const std::optional<android::HWComposer::DeviceRequestedChanges>&));

    MOCK_METHOD1(devOptRepaintFlash, void(const compositionengine::CompositionRefreshArgs&));

    MOCK_METHOD2(finishFrame,
                 void(const compositionengine::CompositionRefreshArgs&, GpuCompositionResult&&));

    MOCK_METHOD4(composeSurfaces,
                 std::optional<base::unique_fd>(
                         const Region&,
                         const compositionengine::CompositionRefreshArgs& refreshArgs,
                         std::shared_ptr<renderengine::ExternalTexture>, base::unique_fd&));
    MOCK_CONST_METHOD0(getSkipColorTransform, bool());

    MOCK_METHOD0(postFramebuffer, void());
    MOCK_METHOD1(renderCachedSets, void(const CompositionRefreshArgs&));
    MOCK_METHOD0(presentAndGetFrameFences, compositionengine::Output::FrameFences());

    MOCK_METHOD3(generateClientCompositionRequests,
                 std::vector<LayerFE::LayerSettings>(bool, ui::Dataspace, std::vector<compositionengine::LayerFE*>&));
    MOCK_METHOD2(appendRegionFlashRequests,
                 void(const Region&, std::vector<LayerFE::LayerSettings>&));
    MOCK_METHOD1(setExpensiveRenderingExpected, void(bool));
    MOCK_METHOD1(cacheClientCompositionRequests, void(uint32_t));
    MOCK_METHOD1(canPredictCompositionStrategy, bool(const CompositionRefreshArgs&));
    MOCK_METHOD1(setPredictCompositionStrategy, void(bool));
    MOCK_METHOD1(setTreat170mAsSrgb, void(bool));
    MOCK_METHOD(void, setHintSessionGpuFence, (std::unique_ptr<FenceTime> && gpuFence));
    MOCK_METHOD(bool, isPowerHintSessionEnabled, ());
};

} // namespace android::compositionengine::mock
