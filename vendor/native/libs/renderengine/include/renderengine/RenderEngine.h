/*
 * Copyright 2013 The Android Open Source Project
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

#ifndef SF_RENDERENGINE_H_
#define SF_RENDERENGINE_H_

#include <android-base/unique_fd.h>
#include <math/mat4.h>
#include <renderengine/DisplaySettings.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/Framebuffer.h>
#include <renderengine/Image.h>
#include <renderengine/LayerSettings.h>
#include <stdint.h>
#include <sys/types.h>
#include <ui/GraphicTypes.h>
#include <ui/Transform.h>

#include <future>
#include <memory>

/**
 * Allows to set RenderEngine backend to GLES (default) or SkiaGL (NOT yet supported).
 */
#define PROPERTY_DEBUG_RENDERENGINE_BACKEND "debug.renderengine.backend"

/**
 * Turns on recording of skia commands in SkiaGL version of the RE. This property
 * defines number of milliseconds for the recording to take place. A non zero value
 * turns on the recording.
 */
#define PROPERTY_DEBUG_RENDERENGINE_CAPTURE_SKIA_MS "debug.renderengine.capture_skia_ms"

/**
 * Set to the most recently saved file once the capture is finished.
 */
#define PROPERTY_DEBUG_RENDERENGINE_CAPTURE_FILENAME "debug.renderengine.capture_filename"

/**
 * Allows recording of Skia drawing commands with systrace.
 */
#define PROPERTY_SKIA_ATRACE_ENABLED "debug.renderengine.skia_atrace_enabled"

struct ANativeWindowBuffer;

namespace android {

class Rect;
class Region;

namespace renderengine {

class ExternalTexture;
class Image;
class Mesh;
class Texture;
struct RenderEngineCreationArgs;

namespace threaded {
class RenderEngineThreaded;
}

namespace impl {
class RenderEngine;
}

enum class Protection {
    UNPROTECTED = 1,
    PROTECTED = 2,
};

class RenderEngine {
public:
    enum class ContextPriority {
        LOW = 1,
        MEDIUM = 2,
        HIGH = 3,
        REALTIME = 4,
    };

    enum class RenderEngineType {
        GLES = 1,
        THREADED = 2,
        SKIA_GL = 3,
        SKIA_GL_THREADED = 4,
    };

    static std::unique_ptr<RenderEngine> create(RenderEngineCreationArgs args);

    virtual ~RenderEngine() = 0;

    // ----- BEGIN DEPRECATED INTERFACE -----
    // This interface, while still in use until a suitable replacement is built,
    // should be considered deprecated, minus some methods which still may be
    // used to support legacy behavior.
    virtual std::future<void> primeCache() = 0;

    // dump the extension strings. always call the base class.
    virtual void dump(std::string& result) = 0;

    virtual void genTextures(size_t count, uint32_t* names) = 0;
    virtual void deleteTextures(size_t count, uint32_t const* names) = 0;

    // queries that are required to be thread safe
    virtual size_t getMaxTextureSize() const = 0;
    virtual size_t getMaxViewportDims() const = 0;

    // ----- END DEPRECATED INTERFACE -----

    // ----- BEGIN NEW INTERFACE -----

    // queries that are required to be thread safe
    virtual bool isProtected() const = 0;
    virtual bool supportsProtectedContent() const = 0;

    // Attempt to switch RenderEngine into and out of protectedContext mode
    virtual void useProtectedContext(bool useProtectedContext) = 0;

    // Notify RenderEngine of changes to the dimensions of the active display
    // so that it can configure its internal caches accordingly.
    virtual void onActiveDisplaySizeChanged(ui::Size size) = 0;

    // Renders layers for a particular display via GPU composition. This method
    // should be called for every display that needs to be rendered via the GPU.
    // @param display The display-wide settings that should be applied prior to
    // drawing any layers.
    //
    // Assumptions when calling this method:
    // 1. There is exactly one caller - i.e. multi-threading is not supported.
    // 2. Additional threads may be calling the {bind,cache}ExternalTexture
    // methods above. But the main thread is responsible for holding resources
    // such that Image destruction does not occur while this method is called.
    //
    // TODO(b/136806342): This should behavior should ideally be fixed since
    // the above two assumptions are brittle, as conditional thread safetyness
    // may be insufficient when maximizing rendering performance in the future.
    //
    // @param layers The layers to draw onto the display, in Z-order.
    // @param buffer The buffer which will be drawn to. This buffer will be
    // ready once drawFence fires.
    // @param useFramebufferCache True if the framebuffer cache should be used.
    // If an implementation does not cache output framebuffers, then this
    // parameter does nothing.
    // @param bufferFence Fence signalling that the buffer is ready to be drawn
    // to.
    // @param drawFence A pointer to a fence, which will fire when the buffer
    // has been drawn to and is ready to be examined. The fence will be
    // initialized by this method. The caller will be responsible for owning the
    // fence.
    // @return An error code indicating whether drawing was successful. For
    // now, this always returns NO_ERROR.
    virtual status_t drawLayers(const DisplaySettings& display,
                                const std::vector<const LayerSettings*>& layers,
                                const std::shared_ptr<ExternalTexture>& buffer,
                                const bool useFramebufferCache, base::unique_fd&& bufferFence,
                                base::unique_fd* drawFence) = 0;

    // Clean-up method that should be called on the main thread after the
    // drawFence returned by drawLayers fires. This method will free up
    // resources used by the most recently drawn frame. If the frame is still
    // being drawn, then the implementation is free to silently ignore this call.
    virtual void cleanupPostRender() = 0;

    virtual void cleanFramebufferCache() = 0;
    // Returns the priority this context was actually created with. Note: this may not be
    // the same as specified at context creation time, due to implementation limits on the
    // number of contexts that can be created at a specific priority level in the system.
    virtual int getContextPriority() = 0;

    // Returns true if blur was requested in the RenderEngineCreationArgs and the implementation
    // also supports background blur.  If false, no blur will be applied when drawing layers. This
    // query is required to be thread safe.
    virtual bool supportsBackgroundBlur() = 0;

    // Returns the current type of RenderEngine instance that was created.
    // TODO(b/180767535): This is only implemented to allow for backend-specific behavior, which
    // we should not allow in general, so remove this.
    RenderEngineType getRenderEngineType() const { return mRenderEngineType; }

    static void validateInputBufferUsage(const sp<GraphicBuffer>&);
    static void validateOutputBufferUsage(const sp<GraphicBuffer>&);

protected:
    RenderEngine() : RenderEngine(RenderEngineType::GLES) {}

    RenderEngine(RenderEngineType type) : mRenderEngineType(type) {}

    // Maps GPU resources for this buffer.
    // Note that work may be deferred to an additional thread, i.e. this call
    // is made asynchronously, but the caller can expect that map/unmap calls
    // are performed in a manner that's conflict serializable, i.e. unmapping
    // a buffer should never occur before binding the buffer if the caller
    // called mapExternalTextureBuffer before calling unmap.
    // Note also that if the buffer contains protected content, then mapping those GPU resources may
    // be deferred until the buffer is really used for drawing. This is because typical SoCs that
    // support protected memory only support a limited amount, so optimisitically mapping protected
    // memory may be too burdensome. If a buffer contains protected content and the RenderEngine
    // implementation supports protected context, then GPU resources may be mapped into both the
    // protected and unprotected contexts.
    // If the buffer may ever be written to by RenderEngine, then isRenderable must be true.
    virtual void mapExternalTextureBuffer(const sp<GraphicBuffer>& buffer, bool isRenderable) = 0;
    // Unmaps GPU resources used by this buffer. This method should be
    // invoked when the caller will no longer hold a reference to a GraphicBuffer
    // and needs to clean up its resources.
    // Note that if there are multiple callers holding onto the same buffer, then the buffer's
    // resources may be internally ref-counted to guard against use-after-free errors. Note that
    // work may be deferred to an additional thread, i.e. this call is expected to be made
    // asynchronously, but the caller can expect that map/unmap calls are performed in a manner
    // that's conflict serializable, i.e. unmap a buffer should never occur before binding the
    // buffer if the caller called mapExternalTextureBuffer before calling unmap.
    virtual void unmapExternalTextureBuffer(const sp<GraphicBuffer>& buffer) = 0;

    // A thread safe query to determine if any post rendering cleanup is necessary.  Returning true
    // is a signal that calling the postRenderCleanup method would be a no-op and that callers can
    // avoid any thread synchronization that may be required by directly calling postRenderCleanup.
    virtual bool canSkipPostRenderCleanup() const = 0;

    friend class ExternalTexture;
    friend class threaded::RenderEngineThreaded;
    friend class RenderEngineTest_cleanupPostRender_cleansUpOnce_Test;
    const RenderEngineType mRenderEngineType;
};

struct RenderEngineCreationArgs {
    int pixelFormat;
    uint32_t imageCacheSize;
    bool useColorManagement;
    bool enableProtectedContext;
    bool precacheToneMapperShaderOnly;
    bool supportsBackgroundBlur;
    RenderEngine::ContextPriority contextPriority;
    RenderEngine::RenderEngineType renderEngineType;

    struct Builder;

private:
    // must be created by Builder via constructor with full argument list
    RenderEngineCreationArgs(int _pixelFormat, uint32_t _imageCacheSize, bool _useColorManagement,
                             bool _enableProtectedContext, bool _precacheToneMapperShaderOnly,
                             bool _supportsBackgroundBlur,
                             RenderEngine::ContextPriority _contextPriority,
                             RenderEngine::RenderEngineType _renderEngineType)
          : pixelFormat(_pixelFormat),
            imageCacheSize(_imageCacheSize),
            useColorManagement(_useColorManagement),
            enableProtectedContext(_enableProtectedContext),
            precacheToneMapperShaderOnly(_precacheToneMapperShaderOnly),
            supportsBackgroundBlur(_supportsBackgroundBlur),
            contextPriority(_contextPriority),
            renderEngineType(_renderEngineType) {}
    RenderEngineCreationArgs() = delete;
};

struct RenderEngineCreationArgs::Builder {
    Builder() {}

    Builder& setPixelFormat(int pixelFormat) {
        this->pixelFormat = pixelFormat;
        return *this;
    }
    Builder& setImageCacheSize(uint32_t imageCacheSize) {
        this->imageCacheSize = imageCacheSize;
        return *this;
    }
    Builder& setUseColorManagerment(bool useColorManagement) {
        this->useColorManagement = useColorManagement;
        return *this;
    }
    Builder& setEnableProtectedContext(bool enableProtectedContext) {
        this->enableProtectedContext = enableProtectedContext;
        return *this;
    }
    Builder& setPrecacheToneMapperShaderOnly(bool precacheToneMapperShaderOnly) {
        this->precacheToneMapperShaderOnly = precacheToneMapperShaderOnly;
        return *this;
    }
    Builder& setSupportsBackgroundBlur(bool supportsBackgroundBlur) {
        this->supportsBackgroundBlur = supportsBackgroundBlur;
        return *this;
    }
    Builder& setContextPriority(RenderEngine::ContextPriority contextPriority) {
        this->contextPriority = contextPriority;
        return *this;
    }
    Builder& setRenderEngineType(RenderEngine::RenderEngineType renderEngineType) {
        this->renderEngineType = renderEngineType;
        return *this;
    }
    RenderEngineCreationArgs build() const {
        return RenderEngineCreationArgs(pixelFormat, imageCacheSize, useColorManagement,
                                        enableProtectedContext, precacheToneMapperShaderOnly,
                                        supportsBackgroundBlur, contextPriority, renderEngineType);
    }

private:
    // 1 means RGBA_8888
    int pixelFormat = 1;
    uint32_t imageCacheSize = 0;
    bool useColorManagement = true;
    bool enableProtectedContext = false;
    bool precacheToneMapperShaderOnly = false;
    bool supportsBackgroundBlur = false;
    RenderEngine::ContextPriority contextPriority = RenderEngine::ContextPriority::MEDIUM;
    RenderEngine::RenderEngineType renderEngineType =
            RenderEngine::RenderEngineType::SKIA_GL_THREADED;
};

} // namespace renderengine
} // namespace android

#endif /* SF_RENDERENGINE_H_ */
