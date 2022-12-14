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

    MOCK_METHOD0(getFramebufferForDrawing, Framebuffer*());
    MOCK_CONST_METHOD0(primeCache, void());
    MOCK_METHOD1(dump, void(std::string&));
    MOCK_CONST_METHOD0(useNativeFenceSync, bool());
    MOCK_CONST_METHOD0(useWaitSync, bool());
    MOCK_CONST_METHOD0(isCurrent, bool());
    MOCK_METHOD2(genTextures, void(size_t, uint32_t*));
    MOCK_METHOD2(deleteTextures, void(size_t, uint32_t const*));
    MOCK_METHOD2(bindExternalTextureImage, void(uint32_t, const renderengine::Image&));
    MOCK_METHOD1(cacheExternalTextureBuffer, void(const sp<GraphicBuffer>&));
    MOCK_METHOD3(bindExternalTextureBuffer,
                 status_t(uint32_t, const sp<GraphicBuffer>&, const sp<Fence>&));
    MOCK_METHOD1(unbindExternalTextureBuffer, void(uint64_t));
    MOCK_METHOD1(bindFrameBuffer, status_t(renderengine::Framebuffer*));
    MOCK_METHOD1(unbindFrameBuffer, void(renderengine::Framebuffer*));
    MOCK_METHOD1(drawMesh, void(const renderengine::Mesh&));
    MOCK_CONST_METHOD0(getMaxTextureSize, size_t());
    MOCK_CONST_METHOD0(getMaxViewportDims, size_t());
    MOCK_CONST_METHOD0(isProtected, bool());
    MOCK_CONST_METHOD0(supportsProtectedContent, bool());
    MOCK_METHOD1(useProtectedContext, bool(bool));
    MOCK_METHOD1(cleanupPostRender, bool(CleanupMode mode));
    MOCK_METHOD6(drawLayers,
                 status_t(const DisplaySettings&, const std::vector<const LayerSettings*>&,
                          ANativeWindowBuffer*, const bool, base::unique_fd&&, base::unique_fd*));
};

} // namespace mock
} // namespace renderengine
} // namespace android
