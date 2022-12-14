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

#include <gmock/gmock.h>
#include <renderengine/DisplaySettings.h>
#include <renderengine/LayerSettings.h>
#include <renderengine/Mesh.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/Texture.h>
#include <ui/Fence.h>
#include <ui/GraphicBuffer.h>
#include <ui/Region.h>

namespace android {
namespace renderengine {
namespace mock {

class RenderEngine : public renderengine::RenderEngine {
public:
    RenderEngine();
    ~RenderEngine() override;

    MOCK_METHOD0(primeCache, std::future<void>());
    MOCK_METHOD1(dump, void(std::string&));
    MOCK_METHOD2(genTextures, void(size_t, uint32_t*));
    MOCK_METHOD2(deleteTextures, void(size_t, uint32_t const*));
    MOCK_METHOD1(drawMesh, void(const renderengine::Mesh&));
    MOCK_CONST_METHOD0(getMaxTextureSize, size_t());
    MOCK_CONST_METHOD0(getMaxViewportDims, size_t());
    MOCK_CONST_METHOD0(isProtected, bool());
    MOCK_CONST_METHOD0(supportsProtectedContent, bool());
    MOCK_METHOD1(useProtectedContext, void(bool));
    MOCK_METHOD0(cleanupPostRender, void());
    MOCK_CONST_METHOD0(canSkipPostRenderCleanup, bool());
    MOCK_METHOD5(drawLayers,
                 std::future<RenderEngineResult>(const DisplaySettings&,
                                                 const std::vector<LayerSettings>&,
                                                 const std::shared_ptr<ExternalTexture>&,
                                                 const bool, base::unique_fd&&));
    MOCK_METHOD6(drawLayersInternal,
                 void(const std::shared_ptr<std::promise<RenderEngineResult>>&&,
                      const DisplaySettings&, const std::vector<LayerSettings>&,
                      const std::shared_ptr<ExternalTexture>&, const bool, base::unique_fd&&));
    MOCK_METHOD0(cleanFramebufferCache, void());
    MOCK_METHOD0(getContextPriority, int());
    MOCK_METHOD0(supportsBackgroundBlur, bool());
    MOCK_METHOD1(onActiveDisplaySizeChanged, void(ui::Size));

protected:
    // mock renderengine still needs to implement these, but callers should never need to call them.
    void mapExternalTextureBuffer(const sp<GraphicBuffer>&, bool) {}
    void unmapExternalTextureBuffer(const sp<GraphicBuffer>&) {}
};

} // namespace mock
} // namespace renderengine
} // namespace android
