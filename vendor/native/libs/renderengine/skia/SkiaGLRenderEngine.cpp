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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "SkiaGLRenderEngine.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GrContextOptions.h>
#include <SkCanvas.h>
#include <SkColorFilter.h>
#include <SkColorMatrix.h>
#include <SkColorSpace.h>
#include <SkGraphics.h>
#include <SkImage.h>
#include <SkImageFilters.h>
#include <SkRegion.h>
#include <SkShadowUtils.h>
#include <SkSurface.h>
#include <android-base/stringprintf.h>
#include <gl/GrGLInterface.h>
#include <gui/TraceUtils.h>
#include <sync/sync.h>
#include <ui/BlurRegion.h>
#include <ui/DataspaceUtils.h>
#include <ui/DebugUtils.h>
#include <ui/GraphicBuffer.h>
#include <utils/Trace.h>

#include <cmath>
#include <cstdint>
#include <memory>
#include <numeric>

#include "../gl/GLExtensions.h"
#include "Cache.h"
#include "ColorSpaces.h"
#include "SkBlendMode.h"
#include "SkImageInfo.h"
#include "filters/BlurFilter.h"
#include "filters/GaussianBlurFilter.h"
#include "filters/KawaseBlurFilter.h"
#include "filters/LinearEffect.h"
#include "log/log_main.h"
#include "skia/debug/SkiaCapture.h"
#include "skia/debug/SkiaMemoryReporter.h"
#include "skia/filters/StretchShaderFactory.h"
#include "system/graphics-base-v1.0.h"

namespace {
// Debugging settings
static const bool kPrintLayerSettings = false;
static const bool kFlushAfterEveryLayer = kPrintLayerSettings;
} // namespace

bool checkGlError(const char* op, int lineNumber);

namespace android {
namespace renderengine {
namespace skia {

using base::StringAppendF;

static status_t selectConfigForAttribute(EGLDisplay dpy, EGLint const* attrs, EGLint attribute,
                                         EGLint wanted, EGLConfig* outConfig) {
    EGLint numConfigs = -1, n = 0;
    eglGetConfigs(dpy, nullptr, 0, &numConfigs);
    std::vector<EGLConfig> configs(numConfigs, EGL_NO_CONFIG_KHR);
    eglChooseConfig(dpy, attrs, configs.data(), configs.size(), &n);
    configs.resize(n);

    if (!configs.empty()) {
        if (attribute != EGL_NONE) {
            for (EGLConfig config : configs) {
                EGLint value = 0;
                eglGetConfigAttrib(dpy, config, attribute, &value);
                if (wanted == value) {
                    *outConfig = config;
                    return NO_ERROR;
                }
            }
        } else {
            // just pick the first one
            *outConfig = configs[0];
            return NO_ERROR;
        }
    }

    return NAME_NOT_FOUND;
}

static status_t selectEGLConfig(EGLDisplay display, EGLint format, EGLint renderableType,
                                EGLConfig* config) {
    // select our EGLConfig. It must support EGL_RECORDABLE_ANDROID if
    // it is to be used with WIFI displays
    status_t err;
    EGLint wantedAttribute;
    EGLint wantedAttributeValue;

    std::vector<EGLint> attribs;
    if (renderableType) {
        const ui::PixelFormat pixelFormat = static_cast<ui::PixelFormat>(format);
        const bool is1010102 = pixelFormat == ui::PixelFormat::RGBA_1010102;

        // Default to 8 bits per channel.
        const EGLint tmpAttribs[] = {
                EGL_RENDERABLE_TYPE,
                renderableType,
                EGL_RECORDABLE_ANDROID,
                EGL_TRUE,
                EGL_SURFACE_TYPE,
                EGL_WINDOW_BIT | EGL_PBUFFER_BIT,
                EGL_FRAMEBUFFER_TARGET_ANDROID,
                EGL_TRUE,
                EGL_RED_SIZE,
                is1010102 ? 10 : 8,
                EGL_GREEN_SIZE,
                is1010102 ? 10 : 8,
                EGL_BLUE_SIZE,
                is1010102 ? 10 : 8,
                EGL_ALPHA_SIZE,
                is1010102 ? 2 : 8,
                EGL_NONE,
        };
        std::copy(tmpAttribs, tmpAttribs + (sizeof(tmpAttribs) / sizeof(EGLint)),
                  std::back_inserter(attribs));
        wantedAttribute = EGL_NONE;
        wantedAttributeValue = EGL_NONE;
    } else {
        // if no renderable type specified, fallback to a simplified query
        wantedAttribute = EGL_NATIVE_VISUAL_ID;
        wantedAttributeValue = format;
    }

    err = selectConfigForAttribute(display, attribs.data(), wantedAttribute, wantedAttributeValue,
                                   config);
    if (err == NO_ERROR) {
        EGLint caveat;
        if (eglGetConfigAttrib(display, *config, EGL_CONFIG_CAVEAT, &caveat))
            ALOGW_IF(caveat == EGL_SLOW_CONFIG, "EGL_SLOW_CONFIG selected!");
    }

    return err;
}

std::unique_ptr<SkiaGLRenderEngine> SkiaGLRenderEngine::create(
        const RenderEngineCreationArgs& args) {
    // initialize EGL for the default display
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!eglInitialize(display, nullptr, nullptr)) {
        LOG_ALWAYS_FATAL("failed to initialize EGL");
    }

    const auto eglVersion = eglQueryString(display, EGL_VERSION);
    if (!eglVersion) {
        checkGlError(__FUNCTION__, __LINE__);
        LOG_ALWAYS_FATAL("eglQueryString(EGL_VERSION) failed");
    }

    const auto eglExtensions = eglQueryString(display, EGL_EXTENSIONS);
    if (!eglExtensions) {
        checkGlError(__FUNCTION__, __LINE__);
        LOG_ALWAYS_FATAL("eglQueryString(EGL_EXTENSIONS) failed");
    }

    auto& extensions = gl::GLExtensions::getInstance();
    extensions.initWithEGLStrings(eglVersion, eglExtensions);

    // The code assumes that ES2 or later is available if this extension is
    // supported.
    EGLConfig config = EGL_NO_CONFIG_KHR;
    if (!extensions.hasNoConfigContext()) {
        config = chooseEglConfig(display, args.pixelFormat, /*logConfig*/ true);
    }

    EGLContext protectedContext = EGL_NO_CONTEXT;
    const std::optional<RenderEngine::ContextPriority> priority = createContextPriority(args);
    if (args.enableProtectedContext && extensions.hasProtectedContent()) {
        protectedContext =
                createEglContext(display, config, nullptr, priority, Protection::PROTECTED);
        ALOGE_IF(protectedContext == EGL_NO_CONTEXT, "Can't create protected context");
    }

    EGLContext ctxt =
            createEglContext(display, config, protectedContext, priority, Protection::UNPROTECTED);

    // if can't create a GL context, we can only abort.
    LOG_ALWAYS_FATAL_IF(ctxt == EGL_NO_CONTEXT, "EGLContext creation failed");

    EGLSurface placeholder = EGL_NO_SURFACE;
    if (!extensions.hasSurfacelessContext()) {
        placeholder = createPlaceholderEglPbufferSurface(display, config, args.pixelFormat,
                                                         Protection::UNPROTECTED);
        LOG_ALWAYS_FATAL_IF(placeholder == EGL_NO_SURFACE, "can't create placeholder pbuffer");
    }
    EGLBoolean success = eglMakeCurrent(display, placeholder, placeholder, ctxt);
    LOG_ALWAYS_FATAL_IF(!success, "can't make placeholder pbuffer current");
    extensions.initWithGLStrings(glGetString(GL_VENDOR), glGetString(GL_RENDERER),
                                 glGetString(GL_VERSION), glGetString(GL_EXTENSIONS));

    EGLSurface protectedPlaceholder = EGL_NO_SURFACE;
    if (protectedContext != EGL_NO_CONTEXT && !extensions.hasSurfacelessContext()) {
        protectedPlaceholder = createPlaceholderEglPbufferSurface(display, config, args.pixelFormat,
                                                                  Protection::PROTECTED);
        ALOGE_IF(protectedPlaceholder == EGL_NO_SURFACE,
                 "can't create protected placeholder pbuffer");
    }

    // initialize the renderer while GL is current
    std::unique_ptr<SkiaGLRenderEngine> engine =
            std::make_unique<SkiaGLRenderEngine>(args, display, ctxt, placeholder, protectedContext,
                                                 protectedPlaceholder);

    ALOGI("OpenGL ES informations:");
    ALOGI("vendor    : %s", extensions.getVendor());
    ALOGI("renderer  : %s", extensions.getRenderer());
    ALOGI("version   : %s", extensions.getVersion());
    ALOGI("extensions: %s", extensions.getExtensions());
    ALOGI("GL_MAX_TEXTURE_SIZE = %zu", engine->getMaxTextureSize());
    ALOGI("GL_MAX_VIEWPORT_DIMS = %zu", engine->getMaxViewportDims());

    return engine;
}

std::future<void> SkiaGLRenderEngine::primeCache() {
    Cache::primeShaderCache(this);
    return {};
}

EGLConfig SkiaGLRenderEngine::chooseEglConfig(EGLDisplay display, int format, bool logConfig) {
    status_t err;
    EGLConfig config;

    // First try to get an ES3 config
    err = selectEGLConfig(display, format, EGL_OPENGL_ES3_BIT, &config);
    if (err != NO_ERROR) {
        // If ES3 fails, try to get an ES2 config
        err = selectEGLConfig(display, format, EGL_OPENGL_ES2_BIT, &config);
        if (err != NO_ERROR) {
            // If ES2 still doesn't work, probably because we're on the emulator.
            // try a simplified query
            ALOGW("no suitable EGLConfig found, trying a simpler query");
            err = selectEGLConfig(display, format, 0, &config);
            if (err != NO_ERROR) {
                // this EGL is too lame for android
                LOG_ALWAYS_FATAL("no suitable EGLConfig found, giving up");
            }
        }
    }

    if (logConfig) {
        // print some debugging info
        EGLint r, g, b, a;
        eglGetConfigAttrib(display, config, EGL_RED_SIZE, &r);
        eglGetConfigAttrib(display, config, EGL_GREEN_SIZE, &g);
        eglGetConfigAttrib(display, config, EGL_BLUE_SIZE, &b);
        eglGetConfigAttrib(display, config, EGL_ALPHA_SIZE, &a);
        ALOGI("EGL information:");
        ALOGI("vendor    : %s", eglQueryString(display, EGL_VENDOR));
        ALOGI("version   : %s", eglQueryString(display, EGL_VERSION));
        ALOGI("extensions: %s", eglQueryString(display, EGL_EXTENSIONS));
        ALOGI("Client API: %s", eglQueryString(display, EGL_CLIENT_APIS) ?: "Not Supported");
        ALOGI("EGLSurface: %d-%d-%d-%d, config=%p", r, g, b, a, config);
    }

    return config;
}

sk_sp<SkData> SkiaGLRenderEngine::SkSLCacheMonitor::load(const SkData& key) {
    // This "cache" does not actually cache anything. It just allows us to
    // monitor Skia's internal cache. So this method always returns null.
    return nullptr;
}

void SkiaGLRenderEngine::SkSLCacheMonitor::store(const SkData& key, const SkData& data,
                                                 const SkString& description) {
    mShadersCachedSinceLastCall++;
    mTotalShadersCompiled++;
    ATRACE_FORMAT("SF cache: %i shaders", mTotalShadersCompiled);
}

int SkiaGLRenderEngine::reportShadersCompiled() {
    return mSkSLCacheMonitor.totalShadersCompiled();
}

SkiaGLRenderEngine::SkiaGLRenderEngine(const RenderEngineCreationArgs& args, EGLDisplay display,
                                       EGLContext ctxt, EGLSurface placeholder,
                                       EGLContext protectedContext, EGLSurface protectedPlaceholder)
      : SkiaRenderEngine(args.renderEngineType),
        mEGLDisplay(display),
        mEGLContext(ctxt),
        mPlaceholderSurface(placeholder),
        mProtectedEGLContext(protectedContext),
        mProtectedPlaceholderSurface(protectedPlaceholder),
        mDefaultPixelFormat(static_cast<PixelFormat>(args.pixelFormat)),
        mUseColorManagement(args.useColorManagement) {
    sk_sp<const GrGLInterface> glInterface(GrGLCreateNativeInterface());
    LOG_ALWAYS_FATAL_IF(!glInterface.get());

    GrContextOptions options;
    options.fDisableDriverCorrectnessWorkarounds = true;
    options.fDisableDistanceFieldPaths = true;
    options.fReducedShaderVariations = true;
    options.fPersistentCache = &mSkSLCacheMonitor;
    mGrContext = GrDirectContext::MakeGL(glInterface, options);
    if (supportsProtectedContent()) {
        useProtectedContext(true);
        mProtectedGrContext = GrDirectContext::MakeGL(glInterface, options);
        useProtectedContext(false);
    }

    if (args.supportsBackgroundBlur) {
        ALOGD("Background Blurs Enabled");
        mBlurFilter = new KawaseBlurFilter();
    }
    mCapture = std::make_unique<SkiaCapture>();
}

SkiaGLRenderEngine::~SkiaGLRenderEngine() {
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    if (mBlurFilter) {
        delete mBlurFilter;
    }

    mCapture = nullptr;

    mGrContext->flushAndSubmit(true);
    mGrContext->abandonContext();

    if (mProtectedGrContext) {
        mProtectedGrContext->flushAndSubmit(true);
        mProtectedGrContext->abandonContext();
    }

    if (mPlaceholderSurface != EGL_NO_SURFACE) {
        eglDestroySurface(mEGLDisplay, mPlaceholderSurface);
    }
    if (mProtectedPlaceholderSurface != EGL_NO_SURFACE) {
        eglDestroySurface(mEGLDisplay, mProtectedPlaceholderSurface);
    }
    if (mEGLContext != EGL_NO_CONTEXT) {
        eglDestroyContext(mEGLDisplay, mEGLContext);
    }
    if (mProtectedEGLContext != EGL_NO_CONTEXT) {
        eglDestroyContext(mEGLDisplay, mProtectedEGLContext);
    }
    eglMakeCurrent(mEGLDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglTerminate(mEGLDisplay);
    eglReleaseThread();
}

bool SkiaGLRenderEngine::supportsProtectedContent() const {
    return mProtectedEGLContext != EGL_NO_CONTEXT;
}

GrDirectContext* SkiaGLRenderEngine::getActiveGrContext() const {
    return mInProtectedContext ? mProtectedGrContext.get() : mGrContext.get();
}

void SkiaGLRenderEngine::useProtectedContext(bool useProtectedContext) {
    if (useProtectedContext == mInProtectedContext ||
        (useProtectedContext && !supportsProtectedContent())) {
        return;
    }

    // release any scratch resources before switching into a new mode
    if (getActiveGrContext()) {
        getActiveGrContext()->purgeUnlockedResources(true);
    }

    const EGLSurface surface =
            useProtectedContext ? mProtectedPlaceholderSurface : mPlaceholderSurface;
    const EGLContext context = useProtectedContext ? mProtectedEGLContext : mEGLContext;

    if (eglMakeCurrent(mEGLDisplay, surface, surface, context) == EGL_TRUE) {
        mInProtectedContext = useProtectedContext;
        // given that we are sharing the same thread between two GrContexts we need to
        // make sure that the thread state is reset when switching between the two.
        if (getActiveGrContext()) {
            getActiveGrContext()->resetContext();
        }
    }
}

base::unique_fd SkiaGLRenderEngine::flush() {
    ATRACE_CALL();
    if (!gl::GLExtensions::getInstance().hasNativeFenceSync()) {
        return base::unique_fd();
    }

    EGLSyncKHR sync = eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_NATIVE_FENCE_ANDROID, nullptr);
    if (sync == EGL_NO_SYNC_KHR) {
        ALOGW("failed to create EGL native fence sync: %#x", eglGetError());
        return base::unique_fd();
    }

    // native fence fd will not be populated until flush() is done.
    glFlush();

    // get the fence fd
    base::unique_fd fenceFd(eglDupNativeFenceFDANDROID(mEGLDisplay, sync));
    eglDestroySyncKHR(mEGLDisplay, sync);
    if (fenceFd == EGL_NO_NATIVE_FENCE_FD_ANDROID) {
        ALOGW("failed to dup EGL native fence sync: %#x", eglGetError());
    }

    return fenceFd;
}

void SkiaGLRenderEngine::waitFence(base::borrowed_fd fenceFd) {
    if (fenceFd.get() >= 0 && !waitGpuFence(fenceFd)) {
        ATRACE_NAME("SkiaGLRenderEngine::waitFence");
        sync_wait(fenceFd.get(), -1);
    }
}

bool SkiaGLRenderEngine::waitGpuFence(base::borrowed_fd fenceFd) {
    if (!gl::GLExtensions::getInstance().hasNativeFenceSync() ||
        !gl::GLExtensions::getInstance().hasWaitSync()) {
        return false;
    }

    // Duplicate the fence for passing to eglCreateSyncKHR.
    base::unique_fd fenceDup(dup(fenceFd.get()));
    if (fenceDup.get() < 0) {
        ALOGE("failed to create duplicate fence fd: %d", fenceDup.get());
        return false;
    }

    // release the fd and transfer the ownership to EGLSync
    EGLint attribs[] = {EGL_SYNC_NATIVE_FENCE_FD_ANDROID, fenceDup.release(), EGL_NONE};
    EGLSyncKHR sync = eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_NATIVE_FENCE_ANDROID, attribs);
    if (sync == EGL_NO_SYNC_KHR) {
        ALOGE("failed to create EGL native fence sync: %#x", eglGetError());
        return false;
    }

    // XXX: The spec draft is inconsistent as to whether this should return an
    // EGLint or void.  Ignore the return value for now, as it's not strictly
    // needed.
    eglWaitSyncKHR(mEGLDisplay, sync, 0);
    EGLint error = eglGetError();
    eglDestroySyncKHR(mEGLDisplay, sync);
    if (error != EGL_SUCCESS) {
        ALOGE("failed to wait for EGL native fence sync: %#x", error);
        return false;
    }

    return true;
}

static float toDegrees(uint32_t transform) {
    switch (transform) {
        case ui::Transform::ROT_90:
            return 90.0;
        case ui::Transform::ROT_180:
            return 180.0;
        case ui::Transform::ROT_270:
            return 270.0;
        default:
            return 0.0;
    }
}

static SkColorMatrix toSkColorMatrix(const mat4& matrix) {
    return SkColorMatrix(matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0], 0, matrix[0][1],
                         matrix[1][1], matrix[2][1], matrix[3][1], 0, matrix[0][2], matrix[1][2],
                         matrix[2][2], matrix[3][2], 0, matrix[0][3], matrix[1][3], matrix[2][3],
                         matrix[3][3], 0);
}

static bool needsToneMapping(ui::Dataspace sourceDataspace, ui::Dataspace destinationDataspace) {
    int64_t sourceTransfer = sourceDataspace & HAL_DATASPACE_TRANSFER_MASK;
    int64_t destTransfer = destinationDataspace & HAL_DATASPACE_TRANSFER_MASK;

    // Treat unsupported dataspaces as srgb
    if (destTransfer != HAL_DATASPACE_TRANSFER_LINEAR &&
        destTransfer != HAL_DATASPACE_TRANSFER_HLG &&
        destTransfer != HAL_DATASPACE_TRANSFER_ST2084) {
        destTransfer = HAL_DATASPACE_TRANSFER_SRGB;
    }

    if (sourceTransfer != HAL_DATASPACE_TRANSFER_LINEAR &&
        sourceTransfer != HAL_DATASPACE_TRANSFER_HLG &&
        sourceTransfer != HAL_DATASPACE_TRANSFER_ST2084) {
        sourceTransfer = HAL_DATASPACE_TRANSFER_SRGB;
    }

    const bool isSourceLinear = sourceTransfer == HAL_DATASPACE_TRANSFER_LINEAR;
    const bool isSourceSRGB = sourceTransfer == HAL_DATASPACE_TRANSFER_SRGB;
    const bool isDestLinear = destTransfer == HAL_DATASPACE_TRANSFER_LINEAR;
    const bool isDestSRGB = destTransfer == HAL_DATASPACE_TRANSFER_SRGB;

    return !(isSourceLinear && isDestSRGB) && !(isSourceSRGB && isDestLinear) &&
            sourceTransfer != destTransfer;
}

void SkiaGLRenderEngine::mapExternalTextureBuffer(const sp<GraphicBuffer>& buffer,
                                                  bool isRenderable) {
    // Only run this if RE is running on its own thread. This way the access to GL
    // operations is guaranteed to be happening on the same thread.
    if (mRenderEngineType != RenderEngineType::SKIA_GL_THREADED) {
        return;
    }
    // We currently don't attempt to map a buffer if the buffer contains protected content
    // because GPU resources for protected buffers is much more limited.
    const bool isProtectedBuffer = buffer->getUsage() & GRALLOC_USAGE_PROTECTED;
    if (isProtectedBuffer) {
        return;
    }
    ATRACE_CALL();

    // If we were to support caching protected buffers then we will need to switch the
    // currently bound context if we are not already using the protected context (and subsequently
    // switch back after the buffer is cached).  However, for non-protected content we can bind
    // the texture in either GL context because they are initialized with the same share_context
    // which allows the texture state to be shared between them.
    auto grContext = getActiveGrContext();
    auto& cache = mTextureCache;

    std::lock_guard<std::mutex> lock(mRenderingMutex);
    mGraphicBufferExternalRefs[buffer->getId()]++;

    if (const auto& iter = cache.find(buffer->getId()); iter == cache.end()) {
        std::shared_ptr<AutoBackendTexture::LocalRef> imageTextureRef =
                std::make_shared<AutoBackendTexture::LocalRef>(grContext,
                                                               buffer->toAHardwareBuffer(),
                                                               isRenderable, mTextureCleanupMgr);
        cache.insert({buffer->getId(), imageTextureRef});
    }
}

void SkiaGLRenderEngine::unmapExternalTextureBuffer(const sp<GraphicBuffer>& buffer) {
    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    if (const auto& iter = mGraphicBufferExternalRefs.find(buffer->getId());
        iter != mGraphicBufferExternalRefs.end()) {
        if (iter->second == 0) {
            ALOGW("Attempted to unmap GraphicBuffer <id: %" PRId64
                  "> from RenderEngine texture, but the "
                  "ref count was already zero!",
                  buffer->getId());
            mGraphicBufferExternalRefs.erase(buffer->getId());
            return;
        }

        iter->second--;

        // Swap contexts if needed prior to deleting this buffer
        // See Issue 1 of
        // https://www.khronos.org/registry/EGL/extensions/EXT/EGL_EXT_protected_content.txt: even
        // when a protected context and an unprotected context are part of the same share group,
        // protected surfaces may not be accessed by an unprotected context, implying that protected
        // surfaces may only be freed when a protected context is active.
        const bool inProtected = mInProtectedContext;
        useProtectedContext(buffer->getUsage() & GRALLOC_USAGE_PROTECTED);

        if (iter->second == 0) {
            mTextureCache.erase(buffer->getId());
            mGraphicBufferExternalRefs.erase(buffer->getId());
        }

        // Swap back to the previous context so that cached values of isProtected in SurfaceFlinger
        // are up-to-date.
        if (inProtected != mInProtectedContext) {
            useProtectedContext(inProtected);
        }
    }
}

bool SkiaGLRenderEngine::canSkipPostRenderCleanup() const {
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    return mTextureCleanupMgr.isEmpty();
}

void SkiaGLRenderEngine::cleanupPostRender() {
    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    mTextureCleanupMgr.cleanup();
}

// Helper class intended to be used on the stack to ensure that texture cleanup
// is deferred until after this class goes out of scope.
class DeferTextureCleanup final {
public:
    DeferTextureCleanup(AutoBackendTexture::CleanupManager& mgr) : mMgr(mgr) {
        mMgr.setDeferredStatus(true);
    }
    ~DeferTextureCleanup() { mMgr.setDeferredStatus(false); }

private:
    DISALLOW_COPY_AND_ASSIGN(DeferTextureCleanup);
    AutoBackendTexture::CleanupManager& mMgr;
};

sk_sp<SkShader> SkiaGLRenderEngine::createRuntimeEffectShader(
        const RuntimeEffectShaderParameters& parameters) {
    // The given surface will be stretched by HWUI via matrix transformation
    // which gets similar results for most surfaces
    // Determine later on if we need to leverage the stertch shader within
    // surface flinger
    const auto& stretchEffect = parameters.layer.stretchEffect;
    auto shader = parameters.shader;
    if (stretchEffect.hasEffect()) {
        const auto targetBuffer = parameters.layer.source.buffer.buffer;
        const auto graphicBuffer = targetBuffer ? targetBuffer->getBuffer() : nullptr;
        if (graphicBuffer && parameters.shader) {
            shader = mStretchShaderFactory.createSkShader(shader, stretchEffect);
        }
    }

    if (parameters.requiresLinearEffect) {
        const ui::Dataspace inputDataspace = mUseColorManagement ? parameters.layer.sourceDataspace
                                                                 : ui::Dataspace::V0_SRGB_LINEAR;
        const ui::Dataspace outputDataspace = mUseColorManagement
                ? parameters.display.outputDataspace
                : ui::Dataspace::V0_SRGB_LINEAR;

        auto effect =
                shaders::LinearEffect{.inputDataspace = inputDataspace,
                                      .outputDataspace = outputDataspace,
                                      .undoPremultipliedAlpha = parameters.undoPremultipliedAlpha};

        auto effectIter = mRuntimeEffects.find(effect);
        sk_sp<SkRuntimeEffect> runtimeEffect = nullptr;
        if (effectIter == mRuntimeEffects.end()) {
            runtimeEffect = buildRuntimeEffect(effect);
            mRuntimeEffects.insert({effect, runtimeEffect});
        } else {
            runtimeEffect = effectIter->second;
        }
        mat4 colorTransform = parameters.layer.colorTransform;

        colorTransform *=
                mat4::scale(vec4(parameters.layerDimmingRatio, parameters.layerDimmingRatio,
                                 parameters.layerDimmingRatio, 1.f));
        const auto targetBuffer = parameters.layer.source.buffer.buffer;
        const auto graphicBuffer = targetBuffer ? targetBuffer->getBuffer() : nullptr;
        const auto hardwareBuffer = graphicBuffer ? graphicBuffer->toAHardwareBuffer() : nullptr;
        return createLinearEffectShader(parameters.shader, effect, runtimeEffect, colorTransform,
                                        parameters.display.maxLuminance,
                                        parameters.display.currentLuminanceNits,
                                        parameters.layer.source.buffer.maxLuminanceNits,
                                        hardwareBuffer, parameters.display.renderIntent);
    }
    return parameters.shader;
}

void SkiaGLRenderEngine::initCanvas(SkCanvas* canvas, const DisplaySettings& display) {
    if (CC_UNLIKELY(mCapture->isCaptureRunning())) {
        // Record display settings when capture is running.
        std::stringstream displaySettings;
        PrintTo(display, &displaySettings);
        // Store the DisplaySettings in additional information.
        canvas->drawAnnotation(SkRect::MakeEmpty(), "DisplaySettings",
                               SkData::MakeWithCString(displaySettings.str().c_str()));
    }

    // Before doing any drawing, let's make sure that we'll start at the origin of the display.
    // Some displays don't start at 0,0 for example when we're mirroring the screen. Also, virtual
    // displays might have different scaling when compared to the physical screen.

    canvas->clipRect(getSkRect(display.physicalDisplay));
    canvas->translate(display.physicalDisplay.left, display.physicalDisplay.top);

    const auto clipWidth = display.clip.width();
    const auto clipHeight = display.clip.height();
    auto rotatedClipWidth = clipWidth;
    auto rotatedClipHeight = clipHeight;
    // Scale is contingent on the rotation result.
    if (display.orientation & ui::Transform::ROT_90) {
        std::swap(rotatedClipWidth, rotatedClipHeight);
    }
    const auto scaleX = static_cast<SkScalar>(display.physicalDisplay.width()) /
            static_cast<SkScalar>(rotatedClipWidth);
    const auto scaleY = static_cast<SkScalar>(display.physicalDisplay.height()) /
            static_cast<SkScalar>(rotatedClipHeight);
    canvas->scale(scaleX, scaleY);

    // Canvas rotation is done by centering the clip window at the origin, rotating, translating
    // back so that the top left corner of the clip is at (0, 0).
    canvas->translate(rotatedClipWidth / 2, rotatedClipHeight / 2);
    canvas->rotate(toDegrees(display.orientation));
    canvas->translate(-clipWidth / 2, -clipHeight / 2);
    canvas->translate(-display.clip.left, -display.clip.top);
}

class AutoSaveRestore {
public:
    AutoSaveRestore(SkCanvas* canvas) : mCanvas(canvas) { mSaveCount = canvas->save(); }
    ~AutoSaveRestore() { restore(); }
    void replace(SkCanvas* canvas) {
        mCanvas = canvas;
        mSaveCount = canvas->save();
    }
    void restore() {
        if (mCanvas) {
            mCanvas->restoreToCount(mSaveCount);
            mCanvas = nullptr;
        }
    }

private:
    SkCanvas* mCanvas;
    int mSaveCount;
};

static SkRRect getBlurRRect(const BlurRegion& region) {
    const auto rect = SkRect::MakeLTRB(region.left, region.top, region.right, region.bottom);
    const SkVector radii[4] = {SkVector::Make(region.cornerRadiusTL, region.cornerRadiusTL),
                               SkVector::Make(region.cornerRadiusTR, region.cornerRadiusTR),
                               SkVector::Make(region.cornerRadiusBR, region.cornerRadiusBR),
                               SkVector::Make(region.cornerRadiusBL, region.cornerRadiusBL)};
    SkRRect roundedRect;
    roundedRect.setRectRadii(rect, radii);
    return roundedRect;
}

// Arbitrary default margin which should be close enough to zero.
constexpr float kDefaultMargin = 0.0001f;
static bool equalsWithinMargin(float expected, float value, float margin = kDefaultMargin) {
    LOG_ALWAYS_FATAL_IF(margin < 0.f, "Margin is negative!");
    return std::abs(expected - value) < margin;
}

namespace {
template <typename T>
void logSettings(const T& t) {
    std::stringstream stream;
    PrintTo(t, &stream);
    auto string = stream.str();
    size_t pos = 0;
    // Perfetto ignores \n, so split up manually into separate ALOGD statements.
    const size_t size = string.size();
    while (pos < size) {
        const size_t end = std::min(string.find("\n", pos), size);
        ALOGD("%s", string.substr(pos, end - pos).c_str());
        pos = end + 1;
    }
}
} // namespace

void SkiaGLRenderEngine::drawLayersInternal(
        const std::shared_ptr<std::promise<RenderEngineResult>>&& resultPromise,
        const DisplaySettings& display, const std::vector<LayerSettings>& layers,
        const std::shared_ptr<ExternalTexture>& buffer, const bool /*useFramebufferCache*/,
        base::unique_fd&& bufferFence) {
    ATRACE_NAME("SkiaGL::drawLayers");

    std::lock_guard<std::mutex> lock(mRenderingMutex);
    if (layers.empty()) {
        ALOGV("Drawing empty layer stack");
        resultPromise->set_value({NO_ERROR, base::unique_fd()});
        return;
    }

    if (buffer == nullptr) {
        ALOGE("No output buffer provided. Aborting GPU composition.");
        resultPromise->set_value({BAD_VALUE, base::unique_fd()});
        return;
    }

    validateOutputBufferUsage(buffer->getBuffer());

    auto grContext = getActiveGrContext();
    auto& cache = mTextureCache;

    // any AutoBackendTexture deletions will now be deferred until cleanupPostRender is called
    DeferTextureCleanup dtc(mTextureCleanupMgr);

    std::shared_ptr<AutoBackendTexture::LocalRef> surfaceTextureRef;
    if (const auto& it = cache.find(buffer->getBuffer()->getId()); it != cache.end()) {
        surfaceTextureRef = it->second;
    } else {
        surfaceTextureRef =
                std::make_shared<AutoBackendTexture::LocalRef>(grContext,
                                                               buffer->getBuffer()
                                                                       ->toAHardwareBuffer(),
                                                               true, mTextureCleanupMgr);
    }

    // wait on the buffer to be ready to use prior to using it
    waitFence(bufferFence);

    const ui::Dataspace dstDataspace =
            mUseColorManagement ? display.outputDataspace : ui::Dataspace::V0_SRGB_LINEAR;
    sk_sp<SkSurface> dstSurface = surfaceTextureRef->getOrCreateSurface(dstDataspace, grContext);

    SkCanvas* dstCanvas = mCapture->tryCapture(dstSurface.get());
    if (dstCanvas == nullptr) {
        ALOGE("Cannot acquire canvas from Skia.");
        resultPromise->set_value({BAD_VALUE, base::unique_fd()});
        return;
    }

    // setup color filter if necessary
    sk_sp<SkColorFilter> displayColorTransform;
    if (display.colorTransform != mat4() && !display.deviceHandlesColorTransform) {
        displayColorTransform = SkColorFilters::Matrix(toSkColorMatrix(display.colorTransform));
    }
    const bool ctModifiesAlpha =
            displayColorTransform && !displayColorTransform->isAlphaUnchanged();

    // Find the max layer white point to determine the max luminance of the scene...
    const float maxLayerWhitePoint = std::transform_reduce(
            layers.cbegin(), layers.cend(), 0.f,
            [](float left, float right) { return std::max(left, right); },
            [&](const auto& l) { return l.whitePointNits; });

    // ...and compute the dimming ratio if dimming is requested
    const float displayDimmingRatio = display.targetLuminanceNits > 0.f &&
                    maxLayerWhitePoint > 0.f && display.targetLuminanceNits > maxLayerWhitePoint
            ? maxLayerWhitePoint / display.targetLuminanceNits
            : 1.f;

    // Find if any layers have requested blur, we'll use that info to decide when to render to an
    // offscreen buffer and when to render to the native buffer.
    sk_sp<SkSurface> activeSurface(dstSurface);
    SkCanvas* canvas = dstCanvas;
    SkiaCapture::OffscreenState offscreenCaptureState;
    const LayerSettings* blurCompositionLayer = nullptr;
    if (mBlurFilter) {
        bool requiresCompositionLayer = false;
        for (const auto& layer : layers) {
            // if the layer doesn't have blur or it is not visible then continue
            if (!layerHasBlur(layer, ctModifiesAlpha)) {
                continue;
            }
            if (layer.backgroundBlurRadius > 0 &&
                layer.backgroundBlurRadius < mBlurFilter->getMaxCrossFadeRadius()) {
                requiresCompositionLayer = true;
            }
            for (auto region : layer.blurRegions) {
                if (region.blurRadius < mBlurFilter->getMaxCrossFadeRadius()) {
                    requiresCompositionLayer = true;
                }
            }
            if (requiresCompositionLayer) {
                activeSurface = dstSurface->makeSurface(dstSurface->imageInfo());
                canvas = mCapture->tryOffscreenCapture(activeSurface.get(), &offscreenCaptureState);
                blurCompositionLayer = &layer;
                break;
            }
        }
    }

    AutoSaveRestore surfaceAutoSaveRestore(canvas);
    // Clear the entire canvas with a transparent black to prevent ghost images.
    canvas->clear(SK_ColorTRANSPARENT);
    initCanvas(canvas, display);

    if (kPrintLayerSettings) {
        logSettings(display);
    }
    for (const auto& layer : layers) {
        ATRACE_FORMAT("DrawLayer: %s", layer.name.c_str());

        if (kPrintLayerSettings) {
            logSettings(layer);
        }

        sk_sp<SkImage> blurInput;
        if (blurCompositionLayer == &layer) {
            LOG_ALWAYS_FATAL_IF(activeSurface == dstSurface);
            LOG_ALWAYS_FATAL_IF(canvas == dstCanvas);

            // save a snapshot of the activeSurface to use as input to the blur shaders
            blurInput = activeSurface->makeImageSnapshot();

            // blit the offscreen framebuffer into the destination AHB, but only
            // if there are blur regions. backgroundBlurRadius blurs the entire
            // image below, so it can skip this step.
            if (layer.blurRegions.size()) {
                SkPaint paint;
                paint.setBlendMode(SkBlendMode::kSrc);
                if (CC_UNLIKELY(mCapture->isCaptureRunning())) {
                    uint64_t id = mCapture->endOffscreenCapture(&offscreenCaptureState);
                    dstCanvas->drawAnnotation(SkRect::Make(dstCanvas->imageInfo().dimensions()),
                                              String8::format("SurfaceID|%" PRId64, id).c_str(),
                                              nullptr);
                    dstCanvas->drawImage(blurInput, 0, 0, SkSamplingOptions(), &paint);
                } else {
                    activeSurface->draw(dstCanvas, 0, 0, SkSamplingOptions(), &paint);
                }
            }

            // assign dstCanvas to canvas and ensure that the canvas state is up to date
            canvas = dstCanvas;
            surfaceAutoSaveRestore.replace(canvas);
            initCanvas(canvas, display);

            LOG_ALWAYS_FATAL_IF(activeSurface->getCanvas()->getSaveCount() !=
                                dstSurface->getCanvas()->getSaveCount());
            LOG_ALWAYS_FATAL_IF(activeSurface->getCanvas()->getTotalMatrix() !=
                                dstSurface->getCanvas()->getTotalMatrix());

            // assign dstSurface to activeSurface
            activeSurface = dstSurface;
        }

        SkAutoCanvasRestore layerAutoSaveRestore(canvas, true);
        if (CC_UNLIKELY(mCapture->isCaptureRunning())) {
            // Record the name of the layer if the capture is running.
            std::stringstream layerSettings;
            PrintTo(layer, &layerSettings);
            // Store the LayerSettings in additional information.
            canvas->drawAnnotation(SkRect::MakeEmpty(), layer.name.c_str(),
                                   SkData::MakeWithCString(layerSettings.str().c_str()));
        }
        // Layers have a local transform that should be applied to them
        canvas->concat(getSkM44(layer.geometry.positionTransform).asM33());

        const auto [bounds, roundRectClip] =
                getBoundsAndClip(layer.geometry.boundaries, layer.geometry.roundedCornersCrop,
                                 layer.geometry.roundedCornersRadius);
        if (mBlurFilter && layerHasBlur(layer, ctModifiesAlpha)) {
            std::unordered_map<uint32_t, sk_sp<SkImage>> cachedBlurs;

            // if multiple layers have blur, then we need to take a snapshot now because
            // only the lowest layer will have blurImage populated earlier
            if (!blurInput) {
                blurInput = activeSurface->makeImageSnapshot();
            }
            // rect to be blurred in the coordinate space of blurInput
            const auto blurRect = canvas->getTotalMatrix().mapRect(bounds.rect());

            // if the clip needs to be applied then apply it now and make sure
            // it is restored before we attempt to draw any shadows.
            SkAutoCanvasRestore acr(canvas, true);
            if (!roundRectClip.isEmpty()) {
                canvas->clipRRect(roundRectClip, true);
            }

            // TODO(b/182216890): Filter out empty layers earlier
            if (blurRect.width() > 0 && blurRect.height() > 0) {
                if (layer.backgroundBlurRadius > 0) {
                    ATRACE_NAME("BackgroundBlur");
                    auto blurredImage = mBlurFilter->generate(grContext, layer.backgroundBlurRadius,
                                                              blurInput, blurRect);

                    cachedBlurs[layer.backgroundBlurRadius] = blurredImage;

                    mBlurFilter->drawBlurRegion(canvas, bounds, layer.backgroundBlurRadius, 1.0f,
                                                blurRect, blurredImage, blurInput);
                }

                canvas->concat(getSkM44(layer.blurRegionTransform).asM33());
                for (auto region : layer.blurRegions) {
                    if (cachedBlurs[region.blurRadius] == nullptr) {
                        ATRACE_NAME("BlurRegion");
                        cachedBlurs[region.blurRadius] =
                                mBlurFilter->generate(grContext, region.blurRadius, blurInput,
                                                      blurRect);
                    }

                    mBlurFilter->drawBlurRegion(canvas, getBlurRRect(region), region.blurRadius,
                                                region.alpha, blurRect,
                                                cachedBlurs[region.blurRadius], blurInput);
                }
            }
        }

        if (layer.shadow.length > 0) {
            // This would require a new parameter/flag to SkShadowUtils::DrawShadow
            LOG_ALWAYS_FATAL_IF(layer.disableBlending, "Cannot disableBlending with a shadow");

            SkRRect shadowBounds, shadowClip;
            if (layer.geometry.boundaries == layer.shadow.boundaries) {
                shadowBounds = bounds;
                shadowClip = roundRectClip;
            } else {
                std::tie(shadowBounds, shadowClip) =
                        getBoundsAndClip(layer.shadow.boundaries, layer.geometry.roundedCornersCrop,
                                         layer.geometry.roundedCornersRadius);
            }

            // Technically, if bounds is a rect and roundRectClip is not empty,
            // it means that the bounds and roundedCornersCrop were different
            // enough that we should intersect them to find the proper shadow.
            // In practice, this often happens when the two rectangles appear to
            // not match due to rounding errors. Draw the rounded version, which
            // looks more like the intent.
            const auto& rrect =
                    shadowBounds.isRect() && !shadowClip.isEmpty() ? shadowClip : shadowBounds;
            drawShadow(canvas, rrect, layer.shadow);
        }

        const float layerDimmingRatio = layer.whitePointNits <= 0.f
                ? displayDimmingRatio
                : (layer.whitePointNits / maxLayerWhitePoint) * displayDimmingRatio;

        const bool dimInLinearSpace = display.dimmingStage !=
                aidl::android::hardware::graphics::composer3::DimmingStage::GAMMA_OETF;

        const bool requiresLinearEffect = layer.colorTransform != mat4() ||
                (mUseColorManagement &&
                 needsToneMapping(layer.sourceDataspace, display.outputDataspace)) ||
                (dimInLinearSpace && !equalsWithinMargin(1.f, layerDimmingRatio));

        // quick abort from drawing the remaining portion of the layer
        if (layer.skipContentDraw ||
            (layer.alpha == 0 && !requiresLinearEffect && !layer.disableBlending &&
             (!displayColorTransform || displayColorTransform->isAlphaUnchanged()))) {
            continue;
        }

        // If we need to map to linear space or color management is disabled, then mark the source
        // image with the same colorspace as the destination surface so that Skia's color
        // management is a no-op.
        const ui::Dataspace layerDataspace = (!mUseColorManagement || requiresLinearEffect)
                ? dstDataspace
                : layer.sourceDataspace;

        SkPaint paint;
        if (layer.source.buffer.buffer) {
            ATRACE_NAME("DrawImage");
            validateInputBufferUsage(layer.source.buffer.buffer->getBuffer());
            const auto& item = layer.source.buffer;
            std::shared_ptr<AutoBackendTexture::LocalRef> imageTextureRef = nullptr;

            if (const auto& iter = cache.find(item.buffer->getBuffer()->getId());
                iter != cache.end()) {
                imageTextureRef = iter->second;
            } else {
                // If we didn't find the image in the cache, then create a local ref but don't cache
                // it. If we're using skia, we're guaranteed to run on a dedicated GPU thread so if
                // we didn't find anything in the cache then we intentionally did not cache this
                // buffer's resources.
                imageTextureRef = std::make_shared<
                        AutoBackendTexture::LocalRef>(grContext,
                                                      item.buffer->getBuffer()->toAHardwareBuffer(),
                                                      false, mTextureCleanupMgr);
            }

            // if the layer's buffer has a fence, then we must must respect the fence prior to using
            // the buffer.
            if (layer.source.buffer.fence != nullptr) {
                waitFence(layer.source.buffer.fence->get());
            }

            // isOpaque means we need to ignore the alpha in the image,
            // replacing it with the alpha specified by the LayerSettings. See
            // https://developer.android.com/reference/android/view/SurfaceControl.Builder#setOpaque(boolean)
            // The proper way to do this is to use an SkColorType that ignores
            // alpha, like kRGB_888x_SkColorType, and that is used if the
            // incoming image is kRGBA_8888_SkColorType. However, the incoming
            // image may be kRGBA_F16_SkColorType, for which there is no RGBX
            // SkColorType, or kRGBA_1010102_SkColorType, for which we have
            // kRGB_101010x_SkColorType, but it is not yet supported as a source
            // on the GPU. (Adding both is tracked in skbug.com/12048.) In the
            // meantime, we'll use a workaround that works unless we need to do
            // any color conversion. The workaround requires that we pretend the
            // image is already premultiplied, so that we do not premultiply it
            // before applying SkBlendMode::kPlus.
            const bool useIsOpaqueWorkaround = item.isOpaque &&
                    (imageTextureRef->colorType() == kRGBA_1010102_SkColorType ||
                     imageTextureRef->colorType() == kRGBA_F16_SkColorType);
            const auto alphaType = useIsOpaqueWorkaround ? kPremul_SkAlphaType
                    : item.isOpaque                      ? kOpaque_SkAlphaType
                    : item.usePremultipliedAlpha         ? kPremul_SkAlphaType
                                                         : kUnpremul_SkAlphaType;
            sk_sp<SkImage> image = imageTextureRef->makeImage(layerDataspace, alphaType, grContext);

            auto texMatrix = getSkM44(item.textureTransform).asM33();
            // textureTansform was intended to be passed directly into a shader, so when
            // building the total matrix with the textureTransform we need to first
            // normalize it, then apply the textureTransform, then scale back up.
            texMatrix.preScale(1.0f / bounds.width(), 1.0f / bounds.height());
            texMatrix.postScale(image->width(), image->height());

            SkMatrix matrix;
            if (!texMatrix.invert(&matrix)) {
                matrix = texMatrix;
            }
            // The shader does not respect the translation, so we add it to the texture
            // transform for the SkImage. This will make sure that the correct layer contents
            // are drawn in the correct part of the screen.
            matrix.postTranslate(bounds.rect().fLeft, bounds.rect().fTop);

            sk_sp<SkShader> shader;

            if (layer.source.buffer.useTextureFiltering) {
                shader = image->makeShader(SkTileMode::kClamp, SkTileMode::kClamp,
                                           SkSamplingOptions(
                                                   {SkFilterMode::kLinear, SkMipmapMode::kNone}),
                                           &matrix);
            } else {
                shader = image->makeShader(SkSamplingOptions(), matrix);
            }

            if (useIsOpaqueWorkaround) {
                shader = SkShaders::Blend(SkBlendMode::kPlus, shader,
                                          SkShaders::Color(SkColors::kBlack,
                                                           toSkColorSpace(layerDataspace)));
            }

            paint.setShader(createRuntimeEffectShader(
                    RuntimeEffectShaderParameters{.shader = shader,
                                                  .layer = layer,
                                                  .display = display,
                                                  .undoPremultipliedAlpha = !item.isOpaque &&
                                                          item.usePremultipliedAlpha,
                                                  .requiresLinearEffect = requiresLinearEffect,
                                                  .layerDimmingRatio = dimInLinearSpace
                                                          ? layerDimmingRatio
                                                          : 1.f}));

            // Turn on dithering when dimming beyond this (arbitrary) threshold...
            static constexpr float kDimmingThreshold = 0.2f;
            // ...or we're rendering an HDR layer down to an 8-bit target
            // Most HDR standards require at least 10-bits of color depth for source content, so we
            // can just extract the transfer function rather than dig into precise gralloc layout.
            // Furthermore, we can assume that the only 8-bit target we support is RGBA8888.
            const bool requiresDownsample = isHdrDataspace(layer.sourceDataspace) &&
                    buffer->getPixelFormat() == PIXEL_FORMAT_RGBA_8888;
            if (layerDimmingRatio <= kDimmingThreshold || requiresDownsample) {
                paint.setDither(true);
            }
            paint.setAlphaf(layer.alpha);

            if (imageTextureRef->colorType() == kAlpha_8_SkColorType) {
                LOG_ALWAYS_FATAL_IF(layer.disableBlending, "Cannot disableBlending with A8");

                // SysUI creates the alpha layer as a coverage layer, which is
                // appropriate for the DPU. Use a color matrix to convert it to
                // a mask.
                // TODO (b/219525258): Handle input as a mask.
                //
                // The color matrix will convert A8 pixels with no alpha to
                // black, as described by this vector. If the display handles
                // the color transform, we need to invert it to find the color
                // that will result in black after the DPU applies the transform.
                SkV4 black{0.0f, 0.0f, 0.0f, 1.0f}; // r, g, b, a
                if (display.colorTransform != mat4() && display.deviceHandlesColorTransform) {
                    SkM44 colorSpaceMatrix = getSkM44(display.colorTransform);
                    if (colorSpaceMatrix.invert(&colorSpaceMatrix)) {
                        black = colorSpaceMatrix * black;
                    } else {
                        // We'll just have to use 0,0,0 as black, which should
                        // be close to correct.
                        ALOGI("Could not invert colorTransform!");
                    }
                }
                SkColorMatrix colorMatrix(0, 0, 0, 0, black[0],
                                          0, 0, 0, 0, black[1],
                                          0, 0, 0, 0, black[2],
                                          0, 0, 0, -1, 1);
                if (display.colorTransform != mat4() && !display.deviceHandlesColorTransform) {
                    // On the other hand, if the device doesn't handle it, we
                    // have to apply it ourselves.
                    colorMatrix.postConcat(toSkColorMatrix(display.colorTransform));
                }
                paint.setColorFilter(SkColorFilters::Matrix(colorMatrix));
            }
        } else {
            ATRACE_NAME("DrawColor");
            const auto color = layer.source.solidColor;
            sk_sp<SkShader> shader = SkShaders::Color(SkColor4f{.fR = color.r,
                                                                .fG = color.g,
                                                                .fB = color.b,
                                                                .fA = layer.alpha},
                                                      toSkColorSpace(layerDataspace));
            paint.setShader(createRuntimeEffectShader(
                    RuntimeEffectShaderParameters{.shader = shader,
                                                  .layer = layer,
                                                  .display = display,
                                                  .undoPremultipliedAlpha = false,
                                                  .requiresLinearEffect = requiresLinearEffect,
                                                  .layerDimmingRatio = layerDimmingRatio}));
        }

        if (layer.disableBlending) {
            paint.setBlendMode(SkBlendMode::kSrc);
        }

        // An A8 buffer will already have the proper color filter attached to
        // its paint, including the displayColorTransform as needed.
        if (!paint.getColorFilter()) {
            if (!dimInLinearSpace && !equalsWithinMargin(1.0, layerDimmingRatio)) {
                // If we don't dim in linear space, then when we gamma correct the dimming ratio we
                // can assume a gamma 2.2 transfer function.
                static constexpr float kInverseGamma22 = 1.f / 2.2f;
                const auto gammaCorrectedDimmingRatio =
                        std::pow(layerDimmingRatio, kInverseGamma22);
                auto dimmingMatrix =
                        mat4::scale(vec4(gammaCorrectedDimmingRatio, gammaCorrectedDimmingRatio,
                                         gammaCorrectedDimmingRatio, 1.f));

                const auto colorFilter =
                        SkColorFilters::Matrix(toSkColorMatrix(std::move(dimmingMatrix)));
                paint.setColorFilter(displayColorTransform
                                             ? displayColorTransform->makeComposed(colorFilter)
                                             : colorFilter);
            } else {
                paint.setColorFilter(displayColorTransform);
            }
        }

        if (!roundRectClip.isEmpty()) {
            canvas->clipRRect(roundRectClip, true);
        }

        if (!bounds.isRect()) {
            paint.setAntiAlias(true);
            canvas->drawRRect(bounds, paint);
        } else {
            canvas->drawRect(bounds.rect(), paint);
        }
        if (kFlushAfterEveryLayer) {
            ATRACE_NAME("flush surface");
            activeSurface->flush();
        }
    }
    surfaceAutoSaveRestore.restore();
    mCapture->endCapture();
    {
        ATRACE_NAME("flush surface");
        LOG_ALWAYS_FATAL_IF(activeSurface != dstSurface);
        activeSurface->flush();
    }

    base::unique_fd drawFence = flush();

    // If flush failed or we don't support native fences, we need to force the
    // gl command stream to be executed.
    bool requireSync = drawFence.get() < 0;
    if (requireSync) {
        ATRACE_BEGIN("Submit(sync=true)");
    } else {
        ATRACE_BEGIN("Submit(sync=false)");
    }
    bool success = grContext->submit(requireSync);
    ATRACE_END();
    if (!success) {
        ALOGE("Failed to flush RenderEngine commands");
        // Chances are, something illegal happened (either the caller passed
        // us bad parameters, or we messed up our shader generation).
        resultPromise->set_value({INVALID_OPERATION, std::move(drawFence)});
        return;
    }

    // checkErrors();
    resultPromise->set_value({NO_ERROR, std::move(drawFence)});
    return;
}

inline SkRect SkiaGLRenderEngine::getSkRect(const FloatRect& rect) {
    return SkRect::MakeLTRB(rect.left, rect.top, rect.right, rect.bottom);
}

inline SkRect SkiaGLRenderEngine::getSkRect(const Rect& rect) {
    return SkRect::MakeLTRB(rect.left, rect.top, rect.right, rect.bottom);
}

/**
 *  Verifies that common, simple bounds + clip combinations can be converted into
 *  a single RRect draw call returning true if possible. If true the radii parameter
 *  will be filled with the correct radii values that combined with bounds param will
 *  produce the insected roundRect. If false, the returned state of the radii param is undefined.
 */
static bool intersectionIsRoundRect(const SkRect& bounds, const SkRect& crop,
                                    const SkRect& insetCrop, const vec2& cornerRadius,
                                    SkVector radii[4]) {
    const bool leftEqual = bounds.fLeft == crop.fLeft;
    const bool topEqual = bounds.fTop == crop.fTop;
    const bool rightEqual = bounds.fRight == crop.fRight;
    const bool bottomEqual = bounds.fBottom == crop.fBottom;

    // In the event that the corners of the bounds only partially align with the crop we
    // need to ensure that the resulting shape can still be represented as a round rect.
    // In particular the round rect implementation will scale the value of all corner radii
    // if the sum of the radius along any edge is greater than the length of that edge.
    // See https://www.w3.org/TR/css-backgrounds-3/#corner-overlap
    const bool requiredWidth = bounds.width() > (cornerRadius.x * 2);
    const bool requiredHeight = bounds.height() > (cornerRadius.y * 2);
    if (!requiredWidth || !requiredHeight) {
        return false;
    }

    // Check each cropped corner to ensure that it exactly matches the crop or its corner is
    // contained within the cropped shape and does not need rounded.
    // compute the UpperLeft corner radius
    if (leftEqual && topEqual) {
        radii[0].set(cornerRadius.x, cornerRadius.y);
    } else if ((leftEqual && bounds.fTop >= insetCrop.fTop) ||
               (topEqual && bounds.fLeft >= insetCrop.fLeft)) {
        radii[0].set(0, 0);
    } else {
        return false;
    }
    // compute the UpperRight corner radius
    if (rightEqual && topEqual) {
        radii[1].set(cornerRadius.x, cornerRadius.y);
    } else if ((rightEqual && bounds.fTop >= insetCrop.fTop) ||
               (topEqual && bounds.fRight <= insetCrop.fRight)) {
        radii[1].set(0, 0);
    } else {
        return false;
    }
    // compute the BottomRight corner radius
    if (rightEqual && bottomEqual) {
        radii[2].set(cornerRadius.x, cornerRadius.y);
    } else if ((rightEqual && bounds.fBottom <= insetCrop.fBottom) ||
               (bottomEqual && bounds.fRight <= insetCrop.fRight)) {
        radii[2].set(0, 0);
    } else {
        return false;
    }
    // compute the BottomLeft corner radius
    if (leftEqual && bottomEqual) {
        radii[3].set(cornerRadius.x, cornerRadius.y);
    } else if ((leftEqual && bounds.fBottom <= insetCrop.fBottom) ||
               (bottomEqual && bounds.fLeft >= insetCrop.fLeft)) {
        radii[3].set(0, 0);
    } else {
        return false;
    }

    return true;
}

inline std::pair<SkRRect, SkRRect> SkiaGLRenderEngine::getBoundsAndClip(const FloatRect& boundsRect,
                                                                        const FloatRect& cropRect,
                                                                        const vec2& cornerRadius) {
    const SkRect bounds = getSkRect(boundsRect);
    const SkRect crop = getSkRect(cropRect);

    SkRRect clip;
    if (cornerRadius.x > 0 && cornerRadius.y > 0) {
        // it the crop and the bounds are equivalent or there is no crop then we don't need a clip
        if (bounds == crop || crop.isEmpty()) {
            return {SkRRect::MakeRectXY(bounds, cornerRadius.x, cornerRadius.y), clip};
        }

        // This makes an effort to speed up common, simple bounds + clip combinations by
        // converting them to a single RRect draw. It is possible there are other cases
        // that can be converted.
        if (crop.contains(bounds)) {
            const auto insetCrop = crop.makeInset(cornerRadius.x, cornerRadius.y);
            if (insetCrop.contains(bounds)) {
                return {SkRRect::MakeRect(bounds), clip}; // clip is empty - no rounding required
            }

            SkVector radii[4];
            if (intersectionIsRoundRect(bounds, crop, insetCrop, cornerRadius, radii)) {
                SkRRect intersectionBounds;
                intersectionBounds.setRectRadii(bounds, radii);
                return {intersectionBounds, clip};
            }
        }

        // we didn't hit any of our fast paths so set the clip to the cropRect
        clip.setRectXY(crop, cornerRadius.x, cornerRadius.y);
    }

    // if we hit this point then we either don't have rounded corners or we are going to rely
    // on the clip to round the corners for us
    return {SkRRect::MakeRect(bounds), clip};
}

inline bool SkiaGLRenderEngine::layerHasBlur(const LayerSettings& layer,
                                             bool colorTransformModifiesAlpha) {
    if (layer.backgroundBlurRadius > 0 || layer.blurRegions.size()) {
        // return false if the content is opaque and would therefore occlude the blur
        const bool opaqueContent = !layer.source.buffer.buffer || layer.source.buffer.isOpaque;
        const bool opaqueAlpha = layer.alpha == 1.0f && !colorTransformModifiesAlpha;
        return layer.skipContentDraw || !(opaqueContent && opaqueAlpha);
    }
    return false;
}

inline SkColor SkiaGLRenderEngine::getSkColor(const vec4& color) {
    return SkColorSetARGB(color.a * 255, color.r * 255, color.g * 255, color.b * 255);
}

inline SkM44 SkiaGLRenderEngine::getSkM44(const mat4& matrix) {
    return SkM44(matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0],
                 matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1],
                 matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2],
                 matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3]);
}

inline SkPoint3 SkiaGLRenderEngine::getSkPoint3(const vec3& vector) {
    return SkPoint3::Make(vector.x, vector.y, vector.z);
}

size_t SkiaGLRenderEngine::getMaxTextureSize() const {
    return mGrContext->maxTextureSize();
}

size_t SkiaGLRenderEngine::getMaxViewportDims() const {
    return mGrContext->maxRenderTargetSize();
}

void SkiaGLRenderEngine::drawShadow(SkCanvas* canvas, const SkRRect& casterRRect,
                                    const ShadowSettings& settings) {
    ATRACE_CALL();
    const float casterZ = settings.length / 2.0f;
    const auto flags =
            settings.casterIsTranslucent ? kTransparentOccluder_ShadowFlag : kNone_ShadowFlag;

    SkShadowUtils::DrawShadow(canvas, SkPath::RRect(casterRRect), SkPoint3::Make(0, 0, casterZ),
                              getSkPoint3(settings.lightPos), settings.lightRadius,
                              getSkColor(settings.ambientColor), getSkColor(settings.spotColor),
                              flags);
}

EGLContext SkiaGLRenderEngine::createEglContext(EGLDisplay display, EGLConfig config,
                                                EGLContext shareContext,
                                                std::optional<ContextPriority> contextPriority,
                                                Protection protection) {
    EGLint renderableType = 0;
    if (config == EGL_NO_CONFIG_KHR) {
        renderableType = EGL_OPENGL_ES3_BIT;
    } else if (!eglGetConfigAttrib(display, config, EGL_RENDERABLE_TYPE, &renderableType)) {
        LOG_ALWAYS_FATAL("can't query EGLConfig RENDERABLE_TYPE");
    }
    EGLint contextClientVersion = 0;
    if (renderableType & EGL_OPENGL_ES3_BIT) {
        contextClientVersion = 3;
    } else if (renderableType & EGL_OPENGL_ES2_BIT) {
        contextClientVersion = 2;
    } else if (renderableType & EGL_OPENGL_ES_BIT) {
        contextClientVersion = 1;
    } else {
        LOG_ALWAYS_FATAL("no supported EGL_RENDERABLE_TYPEs");
    }

    std::vector<EGLint> contextAttributes;
    contextAttributes.reserve(7);
    contextAttributes.push_back(EGL_CONTEXT_CLIENT_VERSION);
    contextAttributes.push_back(contextClientVersion);
    if (contextPriority) {
        contextAttributes.push_back(EGL_CONTEXT_PRIORITY_LEVEL_IMG);
        switch (*contextPriority) {
            case ContextPriority::REALTIME:
                contextAttributes.push_back(EGL_CONTEXT_PRIORITY_REALTIME_NV);
                break;
            case ContextPriority::MEDIUM:
                contextAttributes.push_back(EGL_CONTEXT_PRIORITY_MEDIUM_IMG);
                break;
            case ContextPriority::LOW:
                contextAttributes.push_back(EGL_CONTEXT_PRIORITY_LOW_IMG);
                break;
            case ContextPriority::HIGH:
            default:
                contextAttributes.push_back(EGL_CONTEXT_PRIORITY_HIGH_IMG);
                break;
        }
    }
    if (protection == Protection::PROTECTED) {
        contextAttributes.push_back(EGL_PROTECTED_CONTENT_EXT);
        contextAttributes.push_back(EGL_TRUE);
    }
    contextAttributes.push_back(EGL_NONE);

    EGLContext context = eglCreateContext(display, config, shareContext, contextAttributes.data());

    if (contextClientVersion == 3 && context == EGL_NO_CONTEXT) {
        // eglGetConfigAttrib indicated we can create GLES 3 context, but we failed, thus
        // EGL_NO_CONTEXT so that we can abort.
        if (config != EGL_NO_CONFIG_KHR) {
            return context;
        }
        // If |config| is EGL_NO_CONFIG_KHR, we speculatively try to create GLES 3 context, so we
        // should try to fall back to GLES 2.
        contextAttributes[1] = 2;
        context = eglCreateContext(display, config, shareContext, contextAttributes.data());
    }

    return context;
}

std::optional<RenderEngine::ContextPriority> SkiaGLRenderEngine::createContextPriority(
        const RenderEngineCreationArgs& args) {
    if (!gl::GLExtensions::getInstance().hasContextPriority()) {
        return std::nullopt;
    }

    switch (args.contextPriority) {
        case RenderEngine::ContextPriority::REALTIME:
            if (gl::GLExtensions::getInstance().hasRealtimePriority()) {
                return RenderEngine::ContextPriority::REALTIME;
            } else {
                ALOGI("Realtime priority unsupported, degrading gracefully to high priority");
                return RenderEngine::ContextPriority::HIGH;
            }
        case RenderEngine::ContextPriority::HIGH:
        case RenderEngine::ContextPriority::MEDIUM:
        case RenderEngine::ContextPriority::LOW:
            return args.contextPriority;
        default:
            return std::nullopt;
    }
}

EGLSurface SkiaGLRenderEngine::createPlaceholderEglPbufferSurface(EGLDisplay display,
                                                                  EGLConfig config, int hwcFormat,
                                                                  Protection protection) {
    EGLConfig placeholderConfig = config;
    if (placeholderConfig == EGL_NO_CONFIG_KHR) {
        placeholderConfig = chooseEglConfig(display, hwcFormat, /*logConfig*/ true);
    }
    std::vector<EGLint> attributes;
    attributes.reserve(7);
    attributes.push_back(EGL_WIDTH);
    attributes.push_back(1);
    attributes.push_back(EGL_HEIGHT);
    attributes.push_back(1);
    if (protection == Protection::PROTECTED) {
        attributes.push_back(EGL_PROTECTED_CONTENT_EXT);
        attributes.push_back(EGL_TRUE);
    }
    attributes.push_back(EGL_NONE);

    return eglCreatePbufferSurface(display, placeholderConfig, attributes.data());
}

int SkiaGLRenderEngine::getContextPriority() {
    int value;
    eglQueryContext(mEGLDisplay, mEGLContext, EGL_CONTEXT_PRIORITY_LEVEL_IMG, &value);
    return value;
}

void SkiaGLRenderEngine::onActiveDisplaySizeChanged(ui::Size size) {
    // This cache multiplier was selected based on review of cache sizes relative
    // to the screen resolution. Looking at the worst case memory needed by blur (~1.5x),
    // shadows (~1x), and general data structures (e.g. vertex buffers) we selected this as a
    // conservative default based on that analysis.
    const float SURFACE_SIZE_MULTIPLIER = 3.5f * bytesPerPixel(mDefaultPixelFormat);
    const int maxResourceBytes = size.width * size.height * SURFACE_SIZE_MULTIPLIER;

    // start by resizing the current context
    getActiveGrContext()->setResourceCacheLimit(maxResourceBytes);

    // if it is possible to switch contexts then we will resize the other context
    const bool originalProtectedState = mInProtectedContext;
    useProtectedContext(!mInProtectedContext);
    if (mInProtectedContext != originalProtectedState) {
        getActiveGrContext()->setResourceCacheLimit(maxResourceBytes);
        // reset back to the initial context that was active when this method was called
        useProtectedContext(originalProtectedState);
    }
}

void SkiaGLRenderEngine::dump(std::string& result) {
    const gl::GLExtensions& extensions = gl::GLExtensions::getInstance();

    StringAppendF(&result, "\n ------------RE-----------------\n");
    StringAppendF(&result, "EGL implementation : %s\n", extensions.getEGLVersion());
    StringAppendF(&result, "%s\n", extensions.getEGLExtensions());
    StringAppendF(&result, "GLES: %s, %s, %s\n", extensions.getVendor(), extensions.getRenderer(),
                  extensions.getVersion());
    StringAppendF(&result, "%s\n", extensions.getExtensions());
    StringAppendF(&result, "RenderEngine supports protected context: %d\n",
                  supportsProtectedContent());
    StringAppendF(&result, "RenderEngine is in protected context: %d\n", mInProtectedContext);
    StringAppendF(&result, "RenderEngine shaders cached since last dump/primeCache: %d\n",
                  mSkSLCacheMonitor.shadersCachedSinceLastCall());

    std::vector<ResourcePair> cpuResourceMap = {
            {"skia/sk_resource_cache/bitmap_", "Bitmaps"},
            {"skia/sk_resource_cache/rrect-blur_", "Masks"},
            {"skia/sk_resource_cache/rects-blur_", "Masks"},
            {"skia/sk_resource_cache/tessellated", "Shadows"},
            {"skia", "Other"},
    };
    SkiaMemoryReporter cpuReporter(cpuResourceMap, false);
    SkGraphics::DumpMemoryStatistics(&cpuReporter);
    StringAppendF(&result, "Skia CPU Caches: ");
    cpuReporter.logTotals(result);
    cpuReporter.logOutput(result);

    {
        std::lock_guard<std::mutex> lock(mRenderingMutex);

        std::vector<ResourcePair> gpuResourceMap = {
                {"texture_renderbuffer", "Texture/RenderBuffer"},
                {"texture", "Texture"},
                {"gr_text_blob_cache", "Text"},
                {"skia", "Other"},
        };
        SkiaMemoryReporter gpuReporter(gpuResourceMap, true);
        mGrContext->dumpMemoryStatistics(&gpuReporter);
        StringAppendF(&result, "Skia's GPU Caches: ");
        gpuReporter.logTotals(result);
        gpuReporter.logOutput(result);
        StringAppendF(&result, "Skia's Wrapped Objects:\n");
        gpuReporter.logOutput(result, true);

        StringAppendF(&result, "RenderEngine tracked buffers: %zu\n",
                      mGraphicBufferExternalRefs.size());
        StringAppendF(&result, "Dumping buffer ids...\n");
        for (const auto& [id, refCounts] : mGraphicBufferExternalRefs) {
            StringAppendF(&result, "- 0x%" PRIx64 " - %d refs \n", id, refCounts);
        }
        StringAppendF(&result, "RenderEngine AHB/BackendTexture cache size: %zu\n",
                      mTextureCache.size());
        StringAppendF(&result, "Dumping buffer ids...\n");
        // TODO(178539829): It would be nice to know which layer these are coming from and what
        // the texture sizes are.
        for (const auto& [id, unused] : mTextureCache) {
            StringAppendF(&result, "- 0x%" PRIx64 "\n", id);
        }
        StringAppendF(&result, "\n");

        SkiaMemoryReporter gpuProtectedReporter(gpuResourceMap, true);
        if (mProtectedGrContext) {
            mProtectedGrContext->dumpMemoryStatistics(&gpuProtectedReporter);
        }
        StringAppendF(&result, "Skia's GPU Protected Caches: ");
        gpuProtectedReporter.logTotals(result);
        gpuProtectedReporter.logOutput(result);
        StringAppendF(&result, "Skia's Protected Wrapped Objects:\n");
        gpuProtectedReporter.logOutput(result, true);

        StringAppendF(&result, "\n");
        StringAppendF(&result, "RenderEngine runtime effects: %zu\n", mRuntimeEffects.size());
        for (const auto& [linearEffect, unused] : mRuntimeEffects) {
            StringAppendF(&result, "- inputDataspace: %s\n",
                          dataspaceDetails(
                                  static_cast<android_dataspace>(linearEffect.inputDataspace))
                                  .c_str());
            StringAppendF(&result, "- outputDataspace: %s\n",
                          dataspaceDetails(
                                  static_cast<android_dataspace>(linearEffect.outputDataspace))
                                  .c_str());
            StringAppendF(&result, "undoPremultipliedAlpha: %s\n",
                          linearEffect.undoPremultipliedAlpha ? "true" : "false");
        }
    }
    StringAppendF(&result, "\n");
}

} // namespace skia
} // namespace renderengine
} // namespace android
