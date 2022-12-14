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

#ifndef SF_SKIARENDERENGINE_H_
#define SF_SKIARENDERENGINE_H_

#include <renderengine/RenderEngine.h>
#include <sys/types.h>

namespace android {

namespace renderengine {

class Mesh;
class Texture;

namespace skia {

class BlurFilter;

// TODO: Put common skia stuff here that can be shared between the GL & Vulkan backends
// Currently mostly just handles all the no-op / missing APIs
class SkiaRenderEngine : public RenderEngine {
public:
    static std::unique_ptr<SkiaRenderEngine> create(const RenderEngineCreationArgs& args);
    SkiaRenderEngine(RenderEngineType type);
    ~SkiaRenderEngine() override {}

    virtual std::future<void> primeCache() override { return {}; };
    virtual void genTextures(size_t /*count*/, uint32_t* /*names*/) override{};
    virtual void deleteTextures(size_t /*count*/, uint32_t const* /*names*/) override{};
    virtual bool isProtected() const override { return false; } // mInProtectedContext; }
    virtual bool supportsProtectedContent() const override { return false; };
    virtual int getContextPriority() override { return 0; }
    virtual int reportShadersCompiled() { return 0; }
    virtual void setEnableTracing(bool tracingEnabled) override;

protected:
    virtual void mapExternalTextureBuffer(const sp<GraphicBuffer>& /*buffer*/,
                                          bool /*isRenderable*/) override = 0;
    virtual void unmapExternalTextureBuffer(const sp<GraphicBuffer>& /*buffer*/) override = 0;

    virtual void drawLayersInternal(
            const std::shared_ptr<std::promise<RenderEngineResult>>&& resultPromise,
            const DisplaySettings& display, const std::vector<LayerSettings>& layers,
            const std::shared_ptr<ExternalTexture>& buffer, const bool useFramebufferCache,
            base::unique_fd&& bufferFence) override {
        resultPromise->set_value({NO_ERROR, base::unique_fd()});
    };
};

} // namespace skia
} // namespace renderengine
} // namespace android

#endif /* SF_GLESRENDERENGINE_H_ */
