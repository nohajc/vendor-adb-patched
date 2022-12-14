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

#include <compositionengine/CompositionEngine.h>

namespace android::compositionengine::impl {

class CompositionEngine : public compositionengine::CompositionEngine {
public:
    CompositionEngine();
    ~CompositionEngine() override;

    std::shared_ptr<compositionengine::Display> createDisplay(
            const compositionengine::DisplayCreationArgs&) override;
    std::unique_ptr<compositionengine::LayerFECompositionState> createLayerFECompositionState()
            override;

    HWComposer& getHwComposer() const override;
    void setHwComposer(std::unique_ptr<HWComposer>) override;

    renderengine::RenderEngine& getRenderEngine() const override;
    void setRenderEngine(std::unique_ptr<renderengine::RenderEngine>) override;

    TimeStats& getTimeStats() const override;
    void setTimeStats(const std::shared_ptr<TimeStats>&) override;

    bool needsAnotherUpdate() const override;
    nsecs_t getLastFrameRefreshTimestamp() const override;

    void present(CompositionRefreshArgs&) override;

    void updateCursorAsync(CompositionRefreshArgs&) override;

    void preComposition(CompositionRefreshArgs&) override;

    // Debugging
    void dump(std::string&) const override;

    void updateLayerStateFromFE(CompositionRefreshArgs& args);

    // Testing
    void setNeedsAnotherUpdateForTest(bool);

private:
    std::unique_ptr<HWComposer> mHwComposer;
    std::unique_ptr<renderengine::RenderEngine> mRenderEngine;
    std::shared_ptr<TimeStats> mTimeStats;
    bool mNeedsAnotherUpdate = false;
    nsecs_t mRefreshStartTime = 0;
};

std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine();

} // namespace android::compositionengine::impl
