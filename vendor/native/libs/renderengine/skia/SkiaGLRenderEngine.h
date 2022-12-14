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

#ifndef SF_SKIAGLRENDERENGINE_H_
#define SF_SKIAGLRENDERENGINE_H_

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GrDirectContext.h>
#include <SkSurface.h>
#include <android-base/thread_annotations.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/RenderEngine.h>
#include <sys/types.h>

#include <mutex>
#include <unordered_map>

#include "AutoBackendTexture.h"
#include "EGL/egl.h"
#include "GrContextOptions.h"
#include "SkImageInfo.h"
#include "SkiaRenderEngine.h"
#include "android-base/macros.h"
#include "debug/SkiaCapture.h"
#include "filters/BlurFilter.h"
#include "filters/LinearEffect.h"
#include "filters/StretchShaderFactory.h"

namespace android {
namespace renderengine {
namespace skia {

class SkiaGLRenderEngine : public skia::SkiaRenderEngine {
public:
    static std::unique_ptr<SkiaGLRenderEngine> create(const RenderEngineCreationArgs& args);
    SkiaGLRenderEngine(const RenderEngineCreationArgs& args, EGLDisplay display, EGLContext ctxt,
                       EGLSurface placeholder, EGLContext protectedContext,
                       EGLSurface protectedPlaceholder);
    ~SkiaGLRenderEngine() override EXCLUDES(mRenderingMutex);

    std::future<void> primeCache() override;
    void cleanupPostRender() override;
    void cleanFramebufferCache() override{};
    int getContextPriority() override;
    bool isProtected() const override { return mInProtectedContext; }
    bool supportsProtectedContent() const override;
    void useProtectedContext(bool useProtectedContext) override;
    bool supportsBackgroundBlur() override { return mBlurFilter != nullptr; }
    void onActiveDisplaySizeChanged(ui::Size size) override;
    int reportShadersCompiled() override;

protected:
    void dump(std::string& result) override;
    size_t getMaxTextureSize() const override;
    size_t getMaxViewportDims() const override;
    void mapExternalTextureBuffer(const sp<GraphicBuffer>& buffer, bool isRenderable) override;
    void unmapExternalTextureBuffer(const sp<GraphicBuffer>& buffer) override;
    bool canSkipPostRenderCleanup() const override;
    void drawLayersInternal(const std::shared_ptr<std::promise<RenderEngineResult>>&& resultPromise,
                            const DisplaySettings& display,
                            const std::vector<LayerSettings>& layers,
                            const std::shared_ptr<ExternalTexture>& buffer,
                            const bool useFramebufferCache, base::unique_fd&& bufferFence) override;

private:
    static EGLConfig chooseEglConfig(EGLDisplay display, int format, bool logConfig);
    static EGLContext createEglContext(EGLDisplay display, EGLConfig config,
                                       EGLContext shareContext,
                                       std::optional<ContextPriority> contextPriority,
                                       Protection protection);
    static std::optional<RenderEngine::ContextPriority> createContextPriority(
            const RenderEngineCreationArgs& args);
    static EGLSurface createPlaceholderEglPbufferSurface(EGLDisplay display, EGLConfig config,
                                                         int hwcFormat, Protection protection);
    inline SkRect getSkRect(const FloatRect& layer);
    inline SkRect getSkRect(const Rect& layer);
    inline std::pair<SkRRect, SkRRect> getBoundsAndClip(const FloatRect& bounds,
                                                        const FloatRect& crop,
                                                        const vec2& cornerRadius);
    inline bool layerHasBlur(const LayerSettings& layer, bool colorTransformModifiesAlpha);
    inline SkColor getSkColor(const vec4& color);
    inline SkM44 getSkM44(const mat4& matrix);
    inline SkPoint3 getSkPoint3(const vec3& vector);
    inline GrDirectContext* getActiveGrContext() const;

    base::unique_fd flush();
    // waitFence attempts to wait in the GPU, and if unable to waits on the CPU instead.
    void waitFence(base::borrowed_fd fenceFd);
    bool waitGpuFence(base::borrowed_fd fenceFd);

    void initCanvas(SkCanvas* canvas, const DisplaySettings& display);
    void drawShadow(SkCanvas* canvas, const SkRRect& casterRRect,
                    const ShadowSettings& shadowSettings);

    // If requiresLinearEffect is true or the layer has a stretchEffect a new shader is returned.
    // Otherwise it returns the input shader.
    struct RuntimeEffectShaderParameters {
        sk_sp<SkShader> shader;
        const LayerSettings& layer;
        const DisplaySettings& display;
        bool undoPremultipliedAlpha;
        bool requiresLinearEffect;
        float layerDimmingRatio;
    };
    sk_sp<SkShader> createRuntimeEffectShader(const RuntimeEffectShaderParameters&);

    EGLDisplay mEGLDisplay;
    EGLContext mEGLContext;
    EGLSurface mPlaceholderSurface;
    EGLContext mProtectedEGLContext;
    EGLSurface mProtectedPlaceholderSurface;
    BlurFilter* mBlurFilter = nullptr;

    const PixelFormat mDefaultPixelFormat;
    const bool mUseColorManagement;

    // Identifier used or various mappings of layers to various
    // textures or shaders
    using GraphicBufferId = uint64_t;

    // Number of external holders of ExternalTexture references, per GraphicBuffer ID.
    std::unordered_map<GraphicBufferId, int32_t> mGraphicBufferExternalRefs
            GUARDED_BY(mRenderingMutex);
    // Cache of GL textures that we'll store per GraphicBuffer ID, shared between GPU contexts.
    std::unordered_map<GraphicBufferId, std::shared_ptr<AutoBackendTexture::LocalRef>> mTextureCache
            GUARDED_BY(mRenderingMutex);
    std::unordered_map<shaders::LinearEffect, sk_sp<SkRuntimeEffect>, shaders::LinearEffectHasher>
            mRuntimeEffects;
    AutoBackendTexture::CleanupManager mTextureCleanupMgr GUARDED_BY(mRenderingMutex);

    StretchShaderFactory mStretchShaderFactory;
    // Mutex guarding rendering operations, so that:
    // 1. GL operations aren't interleaved, and
    // 2. Internal state related to rendering that is potentially modified by
    // multiple threads is guaranteed thread-safe.
    mutable std::mutex mRenderingMutex;

    sp<Fence> mLastDrawFence;

    // Graphics context used for creating surfaces and submitting commands
    sk_sp<GrDirectContext> mGrContext;
    // Same as above, but for protected content (eg. DRM)
    sk_sp<GrDirectContext> mProtectedGrContext;

    bool mInProtectedContext = false;
    // Object to capture commands send to Skia.
    std::unique_ptr<SkiaCapture> mCapture;

    // Implements PersistentCache as a way to monitor what SkSL shaders Skia has
    // cached.
    class SkSLCacheMonitor : public GrContextOptions::PersistentCache {
    public:
        SkSLCacheMonitor() = default;
        ~SkSLCacheMonitor() override = default;

        sk_sp<SkData> load(const SkData& key) override;

        void store(const SkData& key, const SkData& data, const SkString& description) override;

        int shadersCachedSinceLastCall() {
            const int shadersCachedSinceLastCall = mShadersCachedSinceLastCall;
            mShadersCachedSinceLastCall = 0;
            return shadersCachedSinceLastCall;
        }

        int totalShadersCompiled() const { return mTotalShadersCompiled; }

    private:
        int mShadersCachedSinceLastCall = 0;
        int mTotalShadersCompiled = 0;
    };

    SkSLCacheMonitor mSkSLCacheMonitor;
};

} // namespace skia
} // namespace renderengine
} // namespace android

#endif /* SF_GLESRENDERENGINE_H_ */
