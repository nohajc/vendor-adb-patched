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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <sched.h>
#include <cmath>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <android-base/stringprintf.h>
#include <cutils/compiler.h>
#include <cutils/properties.h>
#include <gui/DebugEGLImageTracker.h>
#include <renderengine/Mesh.h>
#include <renderengine/Texture.h>
#include <renderengine/private/Description.h>
#include <sync/sync.h>
#include <ui/ColorSpace.h>
#include <ui/DebugUtils.h>
#include <ui/GraphicBuffer.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <utils/KeyedVector.h>
#include <utils/Trace.h>
#include "GLESRenderEngine.h"
#include "GLExtensions.h"
#include "GLFramebuffer.h"
#include "GLImage.h"
#include "GLShadowVertexGenerator.h"
#include "Program.h"
#include "ProgramCache.h"
#include "filters/BlurFilter.h"

extern "C" EGLAPI const char* eglQueryStringImplementationANDROID(EGLDisplay dpy, EGLint name);

bool checkGlError(const char* op, int lineNumber) {
    bool errorFound = false;
    GLint error = glGetError();
    while (error != GL_NO_ERROR) {
        errorFound = true;
        error = glGetError();
        ALOGV("after %s() (line # %d) glError (0x%x)\n", op, lineNumber, error);
    }
    return errorFound;
}

static constexpr bool outputDebugPPMs = false;

void writePPM(const char* basename, GLuint width, GLuint height) {
    ALOGV("writePPM #%s: %d x %d", basename, width, height);

    std::vector<GLubyte> pixels(width * height * 4);
    std::vector<GLubyte> outBuffer(width * height * 3);

    // TODO(courtneygo): We can now have float formats, need
    // to remove this code or update to support.
    // Make returned pixels fit in uint32_t, one byte per component
    glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
    if (checkGlError(__FUNCTION__, __LINE__)) {
        return;
    }

    std::string filename(basename);
    filename.append(".ppm");
    std::ofstream file(filename.c_str(), std::ios::binary);
    if (!file.is_open()) {
        ALOGE("Unable to open file: %s", filename.c_str());
        ALOGE("You may need to do: \"adb shell setenforce 0\" to enable "
              "surfaceflinger to write debug images");
        return;
    }

    file << "P6\n";
    file << width << "\n";
    file << height << "\n";
    file << 255 << "\n";

    auto ptr = reinterpret_cast<char*>(pixels.data());
    auto outPtr = reinterpret_cast<char*>(outBuffer.data());
    for (int y = height - 1; y >= 0; y--) {
        char* data = ptr + y * width * sizeof(uint32_t);

        for (GLuint x = 0; x < width; x++) {
            // Only copy R, G and B components
            outPtr[0] = data[0];
            outPtr[1] = data[1];
            outPtr[2] = data[2];
            data += sizeof(uint32_t);
            outPtr += 3;
        }
    }
    file.write(reinterpret_cast<char*>(outBuffer.data()), outBuffer.size());
}

namespace android {
namespace renderengine {
namespace gl {

using base::StringAppendF;
using ui::Dataspace;

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

std::unique_ptr<GLESRenderEngine> GLESRenderEngine::create(const RenderEngineCreationArgs& args) {
    // initialize EGL for the default display
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!eglInitialize(display, nullptr, nullptr)) {
        LOG_ALWAYS_FATAL("failed to initialize EGL");
    }

    const auto eglVersion = eglQueryStringImplementationANDROID(display, EGL_VERSION);
    if (!eglVersion) {
        checkGlError(__FUNCTION__, __LINE__);
        LOG_ALWAYS_FATAL("eglQueryStringImplementationANDROID(EGL_VERSION) failed");
    }

    const auto eglExtensions = eglQueryStringImplementationANDROID(display, EGL_EXTENSIONS);
    if (!eglExtensions) {
        checkGlError(__FUNCTION__, __LINE__);
        LOG_ALWAYS_FATAL("eglQueryStringImplementationANDROID(EGL_EXTENSIONS) failed");
    }

    GLExtensions& extensions = GLExtensions::getInstance();
    extensions.initWithEGLStrings(eglVersion, eglExtensions);

    // The code assumes that ES2 or later is available if this extension is
    // supported.
    EGLConfig config = EGL_NO_CONFIG;
    if (!extensions.hasNoConfigContext()) {
        config = chooseEglConfig(display, args.pixelFormat, /*logConfig*/ true);
    }

    bool useContextPriority =
            extensions.hasContextPriority() && args.contextPriority == ContextPriority::HIGH;
    EGLContext protectedContext = EGL_NO_CONTEXT;
    if (args.enableProtectedContext && extensions.hasProtectedContent()) {
        protectedContext = createEglContext(display, config, nullptr, useContextPriority,
                                            Protection::PROTECTED);
        ALOGE_IF(protectedContext == EGL_NO_CONTEXT, "Can't create protected context");
    }

    EGLContext ctxt = createEglContext(display, config, protectedContext, useContextPriority,
                                       Protection::UNPROTECTED);

    // if can't create a GL context, we can only abort.
    LOG_ALWAYS_FATAL_IF(ctxt == EGL_NO_CONTEXT, "EGLContext creation failed");

    EGLSurface stub = EGL_NO_SURFACE;
    if (!extensions.hasSurfacelessContext()) {
        stub = createStubEglPbufferSurface(display, config, args.pixelFormat,
                                           Protection::UNPROTECTED);
        LOG_ALWAYS_FATAL_IF(stub == EGL_NO_SURFACE, "can't create stub pbuffer");
    }
    EGLBoolean success = eglMakeCurrent(display, stub, stub, ctxt);
    LOG_ALWAYS_FATAL_IF(!success, "can't make stub pbuffer current");
    extensions.initWithGLStrings(glGetString(GL_VENDOR), glGetString(GL_RENDERER),
                                 glGetString(GL_VERSION), glGetString(GL_EXTENSIONS));

    EGLSurface protectedStub = EGL_NO_SURFACE;
    if (protectedContext != EGL_NO_CONTEXT && !extensions.hasSurfacelessContext()) {
        protectedStub = createStubEglPbufferSurface(display, config, args.pixelFormat,
                                                    Protection::PROTECTED);
        ALOGE_IF(protectedStub == EGL_NO_SURFACE, "can't create protected stub pbuffer");
    }

    // now figure out what version of GL did we actually get
    GlesVersion version = parseGlesVersion(extensions.getVersion());

    LOG_ALWAYS_FATAL_IF(args.supportsBackgroundBlur && version < GLES_VERSION_3_0,
        "Blurs require OpenGL ES 3.0. Please unset ro.surface_flinger.supports_background_blur");

    // initialize the renderer while GL is current
    std::unique_ptr<GLESRenderEngine> engine;
    switch (version) {
        case GLES_VERSION_1_0:
        case GLES_VERSION_1_1:
            LOG_ALWAYS_FATAL("SurfaceFlinger requires OpenGL ES 2.0 minimum to run.");
            break;
        case GLES_VERSION_2_0:
        case GLES_VERSION_3_0:
            engine = std::make_unique<GLESRenderEngine>(args, display, config, ctxt, stub,
                                                        protectedContext, protectedStub);
            break;
    }

    ALOGI("OpenGL ES informations:");
    ALOGI("vendor    : %s", extensions.getVendor());
    ALOGI("renderer  : %s", extensions.getRenderer());
    ALOGI("version   : %s", extensions.getVersion());
    ALOGI("extensions: %s", extensions.getExtensions());
    ALOGI("GL_MAX_TEXTURE_SIZE = %zu", engine->getMaxTextureSize());
    ALOGI("GL_MAX_VIEWPORT_DIMS = %zu", engine->getMaxViewportDims());

    return engine;
}

EGLConfig GLESRenderEngine::chooseEglConfig(EGLDisplay display, int format, bool logConfig) {
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

GLESRenderEngine::GLESRenderEngine(const RenderEngineCreationArgs& args, EGLDisplay display,
                                   EGLConfig config, EGLContext ctxt, EGLSurface stub,
                                   EGLContext protectedContext, EGLSurface protectedStub)
      : renderengine::impl::RenderEngine(args),
        mEGLDisplay(display),
        mEGLConfig(config),
        mEGLContext(ctxt),
        mStubSurface(stub),
        mProtectedEGLContext(protectedContext),
        mProtectedStubSurface(protectedStub),
        mVpWidth(0),
        mVpHeight(0),
        mFramebufferImageCacheSize(args.imageCacheSize),
        mUseColorManagement(args.useColorManagement) {
    glGetIntegerv(GL_MAX_TEXTURE_SIZE, &mMaxTextureSize);
    glGetIntegerv(GL_MAX_VIEWPORT_DIMS, mMaxViewportDims);

    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
    glPixelStorei(GL_PACK_ALIGNMENT, 4);

    // Initialize protected EGL Context.
    if (mProtectedEGLContext != EGL_NO_CONTEXT) {
        EGLBoolean success = eglMakeCurrent(display, mProtectedStubSurface, mProtectedStubSurface,
                                            mProtectedEGLContext);
        ALOGE_IF(!success, "can't make protected context current");
        glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
        glPixelStorei(GL_PACK_ALIGNMENT, 4);
        success = eglMakeCurrent(display, mStubSurface, mStubSurface, mEGLContext);
        LOG_ALWAYS_FATAL_IF(!success, "can't make default context current");
    }

    // mColorBlindnessCorrection = M;

    if (mUseColorManagement) {
        const ColorSpace srgb(ColorSpace::sRGB());
        const ColorSpace displayP3(ColorSpace::DisplayP3());
        const ColorSpace bt2020(ColorSpace::BT2020());

        // no chromatic adaptation needed since all color spaces use D65 for their white points.
        mSrgbToXyz = mat4(srgb.getRGBtoXYZ());
        mDisplayP3ToXyz = mat4(displayP3.getRGBtoXYZ());
        mBt2020ToXyz = mat4(bt2020.getRGBtoXYZ());
        mXyzToSrgb = mat4(srgb.getXYZtoRGB());
        mXyzToDisplayP3 = mat4(displayP3.getXYZtoRGB());
        mXyzToBt2020 = mat4(bt2020.getXYZtoRGB());

        // Compute sRGB to Display P3 and BT2020 transform matrix.
        // NOTE: For now, we are limiting output wide color space support to
        // Display-P3 and BT2020 only.
        mSrgbToDisplayP3 = mXyzToDisplayP3 * mSrgbToXyz;
        mSrgbToBt2020 = mXyzToBt2020 * mSrgbToXyz;

        // Compute Display P3 to sRGB and BT2020 transform matrix.
        mDisplayP3ToSrgb = mXyzToSrgb * mDisplayP3ToXyz;
        mDisplayP3ToBt2020 = mXyzToBt2020 * mDisplayP3ToXyz;

        // Compute BT2020 to sRGB and Display P3 transform matrix
        mBt2020ToSrgb = mXyzToSrgb * mBt2020ToXyz;
        mBt2020ToDisplayP3 = mXyzToDisplayP3 * mBt2020ToXyz;
    }

    char value[PROPERTY_VALUE_MAX];
    property_get("debug.egl.traceGpuCompletion", value, "0");
    if (atoi(value)) {
        mTraceGpuCompletion = true;
        mFlushTracer = std::make_unique<FlushTracer>(this);
    }

    if (args.supportsBackgroundBlur) {
        mBlurFilter = new BlurFilter(*this);
        checkErrors("BlurFilter creation");
    }

    mImageManager = std::make_unique<ImageManager>(this);
    mImageManager->initThread();
    mDrawingBuffer = createFramebuffer();
    sp<GraphicBuffer> buf =
            new GraphicBuffer(1, 1, PIXEL_FORMAT_RGBA_8888, 1,
                              GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE, "placeholder");

    const status_t err = buf->initCheck();
    if (err != OK) {
        ALOGE("Error allocating placeholder buffer: %d", err);
        return;
    }
    mPlaceholderBuffer = buf.get();
    EGLint attributes[] = {
            EGL_NONE,
    };
    mPlaceholderImage = eglCreateImageKHR(mEGLDisplay, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
                                          mPlaceholderBuffer, attributes);
    ALOGE_IF(mPlaceholderImage == EGL_NO_IMAGE_KHR, "Failed to create placeholder image: %#x",
             eglGetError());
}

GLESRenderEngine::~GLESRenderEngine() {
    // Destroy the image manager first.
    mImageManager = nullptr;
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    unbindFrameBuffer(mDrawingBuffer.get());
    mDrawingBuffer = nullptr;
    while (!mFramebufferImageCache.empty()) {
        EGLImageKHR expired = mFramebufferImageCache.front().second;
        mFramebufferImageCache.pop_front();
        eglDestroyImageKHR(mEGLDisplay, expired);
        DEBUG_EGL_IMAGE_TRACKER_DESTROY();
    }
    eglDestroyImageKHR(mEGLDisplay, mPlaceholderImage);
    mImageCache.clear();
    eglMakeCurrent(mEGLDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglTerminate(mEGLDisplay);
}

std::unique_ptr<Framebuffer> GLESRenderEngine::createFramebuffer() {
    return std::make_unique<GLFramebuffer>(*this);
}

std::unique_ptr<Image> GLESRenderEngine::createImage() {
    return std::make_unique<GLImage>(*this);
}

Framebuffer* GLESRenderEngine::getFramebufferForDrawing() {
    return mDrawingBuffer.get();
}

void GLESRenderEngine::primeCache() const {
    ProgramCache::getInstance().primeCache(mInProtectedContext ? mProtectedEGLContext : mEGLContext,
                                           mArgs.useColorManagement,
                                           mArgs.precacheToneMapperShaderOnly);
}

base::unique_fd GLESRenderEngine::flush() {
    ATRACE_CALL();
    if (!GLExtensions::getInstance().hasNativeFenceSync()) {
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

    // Only trace if we have a valid fence, as current usage falls back to
    // calling finish() if the fence fd is invalid.
    if (CC_UNLIKELY(mTraceGpuCompletion && mFlushTracer) && fenceFd.get() >= 0) {
        mFlushTracer->queueSync(eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_FENCE_KHR, nullptr));
    }

    return fenceFd;
}

bool GLESRenderEngine::finish() {
    ATRACE_CALL();
    if (!GLExtensions::getInstance().hasFenceSync()) {
        ALOGW("no synchronization support");
        return false;
    }

    EGLSyncKHR sync = eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_FENCE_KHR, nullptr);
    if (sync == EGL_NO_SYNC_KHR) {
        ALOGW("failed to create EGL fence sync: %#x", eglGetError());
        return false;
    }

    if (CC_UNLIKELY(mTraceGpuCompletion && mFlushTracer)) {
        mFlushTracer->queueSync(eglCreateSyncKHR(mEGLDisplay, EGL_SYNC_FENCE_KHR, nullptr));
    }

    return waitSync(sync, EGL_SYNC_FLUSH_COMMANDS_BIT_KHR);
}

bool GLESRenderEngine::waitSync(EGLSyncKHR sync, EGLint flags) {
    EGLint result = eglClientWaitSyncKHR(mEGLDisplay, sync, flags, 2000000000 /*2 sec*/);
    EGLint error = eglGetError();
    eglDestroySyncKHR(mEGLDisplay, sync);
    if (result != EGL_CONDITION_SATISFIED_KHR) {
        if (result == EGL_TIMEOUT_EXPIRED_KHR) {
            ALOGW("fence wait timed out");
        } else {
            ALOGW("error waiting on EGL fence: %#x", error);
        }
        return false;
    }

    return true;
}

bool GLESRenderEngine::waitFence(base::unique_fd fenceFd) {
    if (!GLExtensions::getInstance().hasNativeFenceSync() ||
        !GLExtensions::getInstance().hasWaitSync()) {
        return false;
    }

    // release the fd and transfer the ownership to EGLSync
    EGLint attribs[] = {EGL_SYNC_NATIVE_FENCE_FD_ANDROID, fenceFd.release(), EGL_NONE};
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

void GLESRenderEngine::clearWithColor(float red, float green, float blue, float alpha) {
    ATRACE_CALL();
    glDisable(GL_BLEND);
    glClearColor(red, green, blue, alpha);
    glClear(GL_COLOR_BUFFER_BIT);
}

void GLESRenderEngine::fillRegionWithColor(const Region& region, float red, float green, float blue,
                                           float alpha) {
    size_t c;
    Rect const* r = region.getArray(&c);
    Mesh mesh = Mesh::Builder()
                        .setPrimitive(Mesh::TRIANGLES)
                        .setVertices(c * 6 /* count */, 2 /* size */)
                        .build();
    Mesh::VertexArray<vec2> position(mesh.getPositionArray<vec2>());
    for (size_t i = 0; i < c; i++, r++) {
        position[i * 6 + 0].x = r->left;
        position[i * 6 + 0].y = r->top;
        position[i * 6 + 1].x = r->left;
        position[i * 6 + 1].y = r->bottom;
        position[i * 6 + 2].x = r->right;
        position[i * 6 + 2].y = r->bottom;
        position[i * 6 + 3].x = r->left;
        position[i * 6 + 3].y = r->top;
        position[i * 6 + 4].x = r->right;
        position[i * 6 + 4].y = r->bottom;
        position[i * 6 + 5].x = r->right;
        position[i * 6 + 5].y = r->top;
    }
    setupFillWithColor(red, green, blue, alpha);
    drawMesh(mesh);
}

void GLESRenderEngine::setScissor(const Rect& region) {
    glScissor(region.left, region.top, region.getWidth(), region.getHeight());
    glEnable(GL_SCISSOR_TEST);
}

void GLESRenderEngine::disableScissor() {
    glDisable(GL_SCISSOR_TEST);
}

void GLESRenderEngine::genTextures(size_t count, uint32_t* names) {
    glGenTextures(count, names);
}

void GLESRenderEngine::deleteTextures(size_t count, uint32_t const* names) {
    for (int i = 0; i < count; ++i) {
        mTextureView.erase(names[i]);
    }
    glDeleteTextures(count, names);
}

void GLESRenderEngine::bindExternalTextureImage(uint32_t texName, const Image& image) {
    ATRACE_CALL();
    const GLImage& glImage = static_cast<const GLImage&>(image);
    const GLenum target = GL_TEXTURE_EXTERNAL_OES;

    glBindTexture(target, texName);
    if (glImage.getEGLImage() != EGL_NO_IMAGE_KHR) {
        glEGLImageTargetTexture2DOES(target, static_cast<GLeglImageOES>(glImage.getEGLImage()));
    }
}

status_t GLESRenderEngine::bindExternalTextureBuffer(uint32_t texName,
                                                     const sp<GraphicBuffer>& buffer,
                                                     const sp<Fence>& bufferFence) {
    if (buffer == nullptr) {
        return BAD_VALUE;
    }

    ATRACE_CALL();

    bool found = false;
    {
        std::lock_guard<std::mutex> lock(mRenderingMutex);
        auto cachedImage = mImageCache.find(buffer->getId());
        found = (cachedImage != mImageCache.end());
    }

    // If we couldn't find the image in the cache at this time, then either
    // SurfaceFlinger messed up registering the buffer ahead of time or we got
    // backed up creating other EGLImages.
    if (!found) {
        status_t cacheResult = mImageManager->cache(buffer);
        if (cacheResult != NO_ERROR) {
            return cacheResult;
        }
    }

    // Whether or not we needed to cache, re-check mImageCache to make sure that
    // there's an EGLImage. The current threading model guarantees that we don't
    // destroy a cached image until it's really not needed anymore (i.e. this
    // function should not be called), so the only possibility is that something
    // terrible went wrong and we should just bind something and move on.
    {
        std::lock_guard<std::mutex> lock(mRenderingMutex);
        auto cachedImage = mImageCache.find(buffer->getId());

        if (cachedImage == mImageCache.end()) {
            // We failed creating the image if we got here, so bail out.
            ALOGE("Failed to create an EGLImage when rendering");
            bindExternalTextureImage(texName, *createImage());
            return NO_INIT;
        }

        bindExternalTextureImage(texName, *cachedImage->second);
        mTextureView.insert_or_assign(texName, buffer->getId());
    }

    // Wait for the new buffer to be ready.
    if (bufferFence != nullptr && bufferFence->isValid()) {
        if (GLExtensions::getInstance().hasWaitSync()) {
            base::unique_fd fenceFd(bufferFence->dup());
            if (fenceFd == -1) {
                ALOGE("error dup'ing fence fd: %d", errno);
                return -errno;
            }
            if (!waitFence(std::move(fenceFd))) {
                ALOGE("failed to wait on fence fd");
                return UNKNOWN_ERROR;
            }
        } else {
            status_t err = bufferFence->waitForever("RenderEngine::bindExternalTextureBuffer");
            if (err != NO_ERROR) {
                ALOGE("error waiting for fence: %d", err);
                return err;
            }
        }
    }

    return NO_ERROR;
}

void GLESRenderEngine::cacheExternalTextureBuffer(const sp<GraphicBuffer>& buffer) {
    mImageManager->cacheAsync(buffer, nullptr);
}

std::shared_ptr<ImageManager::Barrier> GLESRenderEngine::cacheExternalTextureBufferForTesting(
        const sp<GraphicBuffer>& buffer) {
    auto barrier = std::make_shared<ImageManager::Barrier>();
    mImageManager->cacheAsync(buffer, barrier);
    return barrier;
}

status_t GLESRenderEngine::cacheExternalTextureBufferInternal(const sp<GraphicBuffer>& buffer) {
    if (buffer == nullptr) {
        return BAD_VALUE;
    }

    {
        std::lock_guard<std::mutex> lock(mRenderingMutex);
        if (mImageCache.count(buffer->getId()) > 0) {
            // If there's already an image then fail fast here.
            return NO_ERROR;
        }
    }
    ATRACE_CALL();

    // Create the image without holding a lock so that we don't block anything.
    std::unique_ptr<Image> newImage = createImage();

    bool created = newImage->setNativeWindowBuffer(buffer->getNativeBuffer(),
                                                   buffer->getUsage() & GRALLOC_USAGE_PROTECTED);
    if (!created) {
        ALOGE("Failed to create image. size=%ux%u st=%u usage=%#" PRIx64 " fmt=%d",
              buffer->getWidth(), buffer->getHeight(), buffer->getStride(), buffer->getUsage(),
              buffer->getPixelFormat());
        return NO_INIT;
    }

    {
        std::lock_guard<std::mutex> lock(mRenderingMutex);
        if (mImageCache.count(buffer->getId()) > 0) {
            // In theory it's possible for another thread to recache the image,
            // so bail out if another thread won.
            return NO_ERROR;
        }
        mImageCache.insert(std::make_pair(buffer->getId(), std::move(newImage)));
    }

    return NO_ERROR;
}

void GLESRenderEngine::unbindExternalTextureBuffer(uint64_t bufferId) {
    mImageManager->releaseAsync(bufferId, nullptr);
}

std::shared_ptr<ImageManager::Barrier> GLESRenderEngine::unbindExternalTextureBufferForTesting(
        uint64_t bufferId) {
    auto barrier = std::make_shared<ImageManager::Barrier>();
    mImageManager->releaseAsync(bufferId, barrier);
    return barrier;
}

void GLESRenderEngine::unbindExternalTextureBufferInternal(uint64_t bufferId) {
    std::unique_ptr<Image> image;
    {
        std::lock_guard<std::mutex> lock(mRenderingMutex);
        const auto& cachedImage = mImageCache.find(bufferId);

        if (cachedImage != mImageCache.end()) {
            ALOGV("Destroying image for buffer: %" PRIu64, bufferId);
            // Move the buffer out of cache first, so that we can destroy
            // without holding the cache's lock.
            image = std::move(cachedImage->second);
            mImageCache.erase(bufferId);
            return;
        }
    }
    ALOGV("Failed to find image for buffer: %" PRIu64, bufferId);
}

FloatRect GLESRenderEngine::setupLayerCropping(const LayerSettings& layer, Mesh& mesh) {
    // Translate win by the rounded corners rect coordinates, to have all values in
    // layer coordinate space.
    FloatRect cropWin = layer.geometry.boundaries;
    const FloatRect& roundedCornersCrop = layer.geometry.roundedCornersCrop;
    cropWin.left -= roundedCornersCrop.left;
    cropWin.right -= roundedCornersCrop.left;
    cropWin.top -= roundedCornersCrop.top;
    cropWin.bottom -= roundedCornersCrop.top;
    Mesh::VertexArray<vec2> cropCoords(mesh.getCropCoordArray<vec2>());
    cropCoords[0] = vec2(cropWin.left, cropWin.top);
    cropCoords[1] = vec2(cropWin.left, cropWin.top + cropWin.getHeight());
    cropCoords[2] = vec2(cropWin.right, cropWin.top + cropWin.getHeight());
    cropCoords[3] = vec2(cropWin.right, cropWin.top);

    setupCornerRadiusCropSize(roundedCornersCrop.getWidth(), roundedCornersCrop.getHeight());
    return cropWin;
}

void GLESRenderEngine::handleRoundedCorners(const DisplaySettings& display,
                                            const LayerSettings& layer, const Mesh& mesh) {
    // We separate the layer into 3 parts essentially, such that we only turn on blending for the
    // top rectangle and the bottom rectangle, and turn off blending for the middle rectangle.
    FloatRect bounds = layer.geometry.roundedCornersCrop;

    // Explicitly compute the transform from the clip rectangle to the physical
    // display. Normally, this is done in glViewport but we explicitly compute
    // it here so that we can get the scissor bounds correct.
    const Rect& source = display.clip;
    const Rect& destination = display.physicalDisplay;
    // Here we compute the following transform:
    // 1. Translate the top left corner of the source clip to (0, 0)
    // 2. Rotate the clip rectangle about the origin in accordance with the
    // orientation flag
    // 3. Translate the top left corner back to the origin.
    // 4. Scale the clip rectangle to the destination rectangle dimensions
    // 5. Translate the top left corner to the destination rectangle's top left
    // corner.
    const mat4 translateSource = mat4::translate(vec4(-source.left, -source.top, 0, 1));
    mat4 rotation;
    int displacementX = 0;
    int displacementY = 0;
    float destinationWidth = static_cast<float>(destination.getWidth());
    float destinationHeight = static_cast<float>(destination.getHeight());
    float sourceWidth = static_cast<float>(source.getWidth());
    float sourceHeight = static_cast<float>(source.getHeight());
    const float rot90InRadians = 2.0f * static_cast<float>(M_PI) / 4.0f;
    switch (display.orientation) {
        case ui::Transform::ROT_90:
            rotation = mat4::rotate(rot90InRadians, vec3(0, 0, 1));
            displacementX = source.getHeight();
            std::swap(sourceHeight, sourceWidth);
            break;
        case ui::Transform::ROT_180:
            rotation = mat4::rotate(rot90InRadians * 2.0f, vec3(0, 0, 1));
            displacementY = source.getHeight();
            displacementX = source.getWidth();
            break;
        case ui::Transform::ROT_270:
            rotation = mat4::rotate(rot90InRadians * 3.0f, vec3(0, 0, 1));
            displacementY = source.getWidth();
            std::swap(sourceHeight, sourceWidth);
            break;
        default:
            break;
    }

    const mat4 intermediateTranslation = mat4::translate(vec4(displacementX, displacementY, 0, 1));
    const mat4 scale = mat4::scale(
            vec4(destinationWidth / sourceWidth, destinationHeight / sourceHeight, 1, 1));
    const mat4 translateDestination =
            mat4::translate(vec4(destination.left, destination.top, 0, 1));
    const mat4 globalTransform =
            translateDestination * scale * intermediateTranslation * rotation * translateSource;

    const mat4 transformMatrix = globalTransform * layer.geometry.positionTransform;
    const vec4 leftTopCoordinate(bounds.left, bounds.top, 1.0, 1.0);
    const vec4 rightBottomCoordinate(bounds.right, bounds.bottom, 1.0, 1.0);
    const vec4 leftTopCoordinateInBuffer = transformMatrix * leftTopCoordinate;
    const vec4 rightBottomCoordinateInBuffer = transformMatrix * rightBottomCoordinate;
    bounds = FloatRect(std::min(leftTopCoordinateInBuffer[0], rightBottomCoordinateInBuffer[0]),
                       std::min(leftTopCoordinateInBuffer[1], rightBottomCoordinateInBuffer[1]),
                       std::max(leftTopCoordinateInBuffer[0], rightBottomCoordinateInBuffer[0]),
                       std::max(leftTopCoordinateInBuffer[1], rightBottomCoordinateInBuffer[1]));

    // Finally, we cut the layer into 3 parts, with top and bottom parts having rounded corners
    // and the middle part without rounded corners.
    const int32_t radius = ceil(layer.geometry.roundedCornersRadius);
    const Rect topRect(bounds.left, bounds.top, bounds.right, bounds.top + radius);
    setScissor(topRect);
    drawMesh(mesh);
    const Rect bottomRect(bounds.left, bounds.bottom - radius, bounds.right, bounds.bottom);
    setScissor(bottomRect);
    drawMesh(mesh);

    // The middle part of the layer can turn off blending.
    if (topRect.bottom < bottomRect.top) {
        const Rect middleRect(bounds.left, bounds.top + radius, bounds.right,
                              bounds.bottom - radius);
        setScissor(middleRect);
        mState.cornerRadius = 0.0;
        disableBlending();
        drawMesh(mesh);
    }
    disableScissor();
}

status_t GLESRenderEngine::bindFrameBuffer(Framebuffer* framebuffer) {
    ATRACE_CALL();
    GLFramebuffer* glFramebuffer = static_cast<GLFramebuffer*>(framebuffer);
    EGLImageKHR eglImage = glFramebuffer->getEGLImage();
    uint32_t textureName = glFramebuffer->getTextureName();
    uint32_t framebufferName = glFramebuffer->getFramebufferName();

    // Bind the texture and turn our EGLImage into a texture
    glBindTexture(GL_TEXTURE_2D, textureName);
    glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, (GLeglImageOES)eglImage);

    // Bind the Framebuffer to render into
    glBindFramebuffer(GL_FRAMEBUFFER, framebufferName);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, textureName, 0);

    uint32_t glStatus = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    ALOGE_IF(glStatus != GL_FRAMEBUFFER_COMPLETE_OES, "glCheckFramebufferStatusOES error %d",
             glStatus);

    return glStatus == GL_FRAMEBUFFER_COMPLETE_OES ? NO_ERROR : BAD_VALUE;
}

void GLESRenderEngine::unbindFrameBuffer(Framebuffer* /*framebuffer*/) {
    ATRACE_CALL();

    // back to main framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

bool GLESRenderEngine::cleanupPostRender(CleanupMode mode) {
    ATRACE_CALL();

    if (mPriorResourcesCleaned ||
        (mLastDrawFence != nullptr && mLastDrawFence->getStatus() != Fence::Status::Signaled)) {
        // If we don't have a prior frame needing cleanup, then don't do anything.
        return false;
    }

    // This is a bit of a band-aid fix for FrameCaptureProcessor, as we should
    // not need to keep memory around if we don't need to do so.
    if (mode == CleanupMode::CLEAN_ALL) {
        // TODO: SurfaceFlinger memory utilization may benefit from resetting
        // texture bindings as well. Assess if it does and there's no performance regression
        // when rebinding the same image data to the same texture, and if so then its mode
        // behavior can be tweaked.
        if (mPlaceholderImage != EGL_NO_IMAGE_KHR) {
            for (auto [textureName, bufferId] : mTextureView) {
                if (bufferId && mPlaceholderImage != EGL_NO_IMAGE_KHR) {
                    glBindTexture(GL_TEXTURE_EXTERNAL_OES, textureName);
                    glEGLImageTargetTexture2DOES(GL_TEXTURE_EXTERNAL_OES,
                                                 static_cast<GLeglImageOES>(mPlaceholderImage));
                    mTextureView[textureName] = std::nullopt;
                    checkErrors();
                }
            }
        }
        {
            std::lock_guard<std::mutex> lock(mRenderingMutex);
            mImageCache.clear();
        }
    }

    // Bind the texture to placeholder so that backing image data can be freed.
    GLFramebuffer* glFramebuffer = static_cast<GLFramebuffer*>(getFramebufferForDrawing());
    glFramebuffer->allocateBuffers(1, 1, mPlaceholderDrawBuffer);
    // Release the cached fence here, so that we don't churn reallocations when
    // we could no-op repeated calls of this method instead.
    mLastDrawFence = nullptr;
    mPriorResourcesCleaned = true;
    return true;
}

void GLESRenderEngine::checkErrors() const {
    checkErrors(nullptr);
}

void GLESRenderEngine::checkErrors(const char* tag) const {
    do {
        // there could be more than one error flag
        GLenum error = glGetError();
        if (error == GL_NO_ERROR) break;
        if (tag == nullptr) {
            ALOGE("GL error 0x%04x", int(error));
        } else {
            ALOGE("GL error: %s -> 0x%04x", tag, int(error));
        }
    } while (true);
}

bool GLESRenderEngine::supportsProtectedContent() const {
    return mProtectedEGLContext != EGL_NO_CONTEXT;
}

bool GLESRenderEngine::useProtectedContext(bool useProtectedContext) {
    if (useProtectedContext == mInProtectedContext) {
        return true;
    }
    if (useProtectedContext && mProtectedEGLContext == EGL_NO_CONTEXT) {
        return false;
    }
    const EGLSurface surface = useProtectedContext ? mProtectedStubSurface : mStubSurface;
    const EGLContext context = useProtectedContext ? mProtectedEGLContext : mEGLContext;
    const bool success = eglMakeCurrent(mEGLDisplay, surface, surface, context) == EGL_TRUE;
    if (success) {
        mInProtectedContext = useProtectedContext;
    }
    return success;
}
EGLImageKHR GLESRenderEngine::createFramebufferImageIfNeeded(ANativeWindowBuffer* nativeBuffer,
                                                             bool isProtected,
                                                             bool useFramebufferCache) {
    sp<GraphicBuffer> graphicBuffer = GraphicBuffer::from(nativeBuffer);
    if (useFramebufferCache) {
        std::lock_guard<std::mutex> lock(mFramebufferImageCacheMutex);
        for (const auto& image : mFramebufferImageCache) {
            if (image.first == graphicBuffer->getId()) {
                return image.second;
            }
        }
    }
    EGLint attributes[] = {
            isProtected ? EGL_PROTECTED_CONTENT_EXT : EGL_NONE,
            isProtected ? EGL_TRUE : EGL_NONE,
            EGL_NONE,
    };
    EGLImageKHR image = eglCreateImageKHR(mEGLDisplay, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
                                          nativeBuffer, attributes);
    if (useFramebufferCache) {
        if (image != EGL_NO_IMAGE_KHR) {
            std::lock_guard<std::mutex> lock(mFramebufferImageCacheMutex);
            if (mFramebufferImageCache.size() >= mFramebufferImageCacheSize) {
                EGLImageKHR expired = mFramebufferImageCache.front().second;
                mFramebufferImageCache.pop_front();
                eglDestroyImageKHR(mEGLDisplay, expired);
                DEBUG_EGL_IMAGE_TRACKER_DESTROY();
            }
            mFramebufferImageCache.push_back({graphicBuffer->getId(), image});
        }
    }

    if (image != EGL_NO_IMAGE_KHR) {
        DEBUG_EGL_IMAGE_TRACKER_CREATE();
    }
    return image;
}

status_t GLESRenderEngine::drawLayers(const DisplaySettings& display,
                                      const std::vector<const LayerSettings*>& layers,
                                      ANativeWindowBuffer* const buffer,
                                      const bool useFramebufferCache, base::unique_fd&& bufferFence,
                                      base::unique_fd* drawFence) {
    ATRACE_CALL();
    if (layers.empty()) {
        ALOGV("Drawing empty layer stack");
        return NO_ERROR;
    }

    if (bufferFence.get() >= 0) {
        // Duplicate the fence for passing to waitFence.
        base::unique_fd bufferFenceDup(dup(bufferFence.get()));
        if (bufferFenceDup < 0 || !waitFence(std::move(bufferFenceDup))) {
            ATRACE_NAME("Waiting before draw");
            sync_wait(bufferFence.get(), -1);
        }
    }

    if (buffer == nullptr) {
        ALOGE("No output buffer provided. Aborting GPU composition.");
        return BAD_VALUE;
    }

    std::unique_ptr<BindNativeBufferAsFramebuffer> fbo;
    // Gathering layers that requested blur, we'll need them to decide when to render to an
    // offscreen buffer, and when to render to the native buffer.
    std::deque<const LayerSettings*> blurLayers;
    if (CC_LIKELY(mBlurFilter != nullptr)) {
        for (auto layer : layers) {
            if (layer->backgroundBlurRadius > 0) {
                blurLayers.push_back(layer);
            }
        }
    }
    const auto blurLayersSize = blurLayers.size();

    if (blurLayersSize == 0) {
        fbo = std::make_unique<BindNativeBufferAsFramebuffer>(*this, buffer, useFramebufferCache);
        if (fbo->getStatus() != NO_ERROR) {
            ALOGE("Failed to bind framebuffer! Aborting GPU composition for buffer (%p).",
                  buffer->handle);
            checkErrors();
            return fbo->getStatus();
        }
        setViewportAndProjection(display.physicalDisplay, display.clip);
    } else {
        setViewportAndProjection(display.physicalDisplay, display.clip);
        auto status =
                mBlurFilter->setAsDrawTarget(display, blurLayers.front()->backgroundBlurRadius);
        if (status != NO_ERROR) {
            ALOGE("Failed to prepare blur filter! Aborting GPU composition for buffer (%p).",
                  buffer->handle);
            checkErrors();
            return status;
        }
    }

    // clear the entire buffer, sometimes when we reuse buffers we'd persist
    // ghost images otherwise.
    // we also require a full transparent framebuffer for overlays. This is
    // probably not quite efficient on all GPUs, since we could filter out
    // opaque layers.
    clearWithColor(0.0, 0.0, 0.0, 0.0);

    setOutputDataSpace(display.outputDataspace);
    setDisplayMaxLuminance(display.maxLuminance);
    setDisplayColorTransform(display.colorTransform);

    const mat4 projectionMatrix =
            ui::Transform(display.orientation).asMatrix4() * mState.projectionMatrix;
    if (!display.clearRegion.isEmpty()) {
        glDisable(GL_BLEND);
        fillRegionWithColor(display.clearRegion, 0.0, 0.0, 0.0, 1.0);
    }

    Mesh mesh = Mesh::Builder()
                        .setPrimitive(Mesh::TRIANGLE_FAN)
                        .setVertices(4 /* count */, 2 /* size */)
                        .setTexCoords(2 /* size */)
                        .setCropCoords(2 /* size */)
                        .build();
    for (auto const layer : layers) {
        if (blurLayers.size() > 0 && blurLayers.front() == layer) {
            blurLayers.pop_front();

            auto status = mBlurFilter->prepare();
            if (status != NO_ERROR) {
                ALOGE("Failed to render blur effect! Aborting GPU composition for buffer (%p).",
                      buffer->handle);
                checkErrors("Can't render first blur pass");
                return status;
            }

            if (blurLayers.size() == 0) {
                // Done blurring, time to bind the native FBO and render our blur onto it.
                fbo = std::make_unique<BindNativeBufferAsFramebuffer>(*this, buffer,
                                                                      useFramebufferCache);
                status = fbo->getStatus();
                setViewportAndProjection(display.physicalDisplay, display.clip);
            } else {
                // There's still something else to blur, so let's keep rendering to our FBO
                // instead of to the display.
                status = mBlurFilter->setAsDrawTarget(display,
                                                      blurLayers.front()->backgroundBlurRadius);
            }
            if (status != NO_ERROR) {
                ALOGE("Failed to bind framebuffer! Aborting GPU composition for buffer (%p).",
                      buffer->handle);
                checkErrors("Can't bind native framebuffer");
                return status;
            }

            status = mBlurFilter->render(blurLayersSize > 1);
            if (status != NO_ERROR) {
                ALOGE("Failed to render blur effect! Aborting GPU composition for buffer (%p).",
                      buffer->handle);
                checkErrors("Can't render blur filter");
                return status;
            }
        }

        mState.maxMasteringLuminance = layer->source.buffer.maxMasteringLuminance;
        mState.maxContentLuminance = layer->source.buffer.maxContentLuminance;
        mState.projectionMatrix = projectionMatrix * layer->geometry.positionTransform;

        const FloatRect bounds = layer->geometry.boundaries;
        Mesh::VertexArray<vec2> position(mesh.getPositionArray<vec2>());
        position[0] = vec2(bounds.left, bounds.top);
        position[1] = vec2(bounds.left, bounds.bottom);
        position[2] = vec2(bounds.right, bounds.bottom);
        position[3] = vec2(bounds.right, bounds.top);

        setupLayerCropping(*layer, mesh);
        setColorTransform(layer->colorTransform);

        bool usePremultipliedAlpha = true;
        bool disableTexture = true;
        bool isOpaque = false;
        if (layer->source.buffer.buffer != nullptr) {
            disableTexture = false;
            isOpaque = layer->source.buffer.isOpaque;

            sp<GraphicBuffer> gBuf = layer->source.buffer.buffer;
            bindExternalTextureBuffer(layer->source.buffer.textureName, gBuf,
                                      layer->source.buffer.fence);

            usePremultipliedAlpha = layer->source.buffer.usePremultipliedAlpha;
            Texture texture(Texture::TEXTURE_EXTERNAL, layer->source.buffer.textureName);
            mat4 texMatrix = layer->source.buffer.textureTransform;

            texture.setMatrix(texMatrix.asArray());
            texture.setFiltering(layer->source.buffer.useTextureFiltering);

            texture.setDimensions(gBuf->getWidth(), gBuf->getHeight());
            setSourceY410BT2020(layer->source.buffer.isY410BT2020);

            renderengine::Mesh::VertexArray<vec2> texCoords(mesh.getTexCoordArray<vec2>());
            texCoords[0] = vec2(0.0, 0.0);
            texCoords[1] = vec2(0.0, 1.0);
            texCoords[2] = vec2(1.0, 1.0);
            texCoords[3] = vec2(1.0, 0.0);
            setupLayerTexturing(texture);
        }

        const half3 solidColor = layer->source.solidColor;
        const half4 color = half4(solidColor.r, solidColor.g, solidColor.b, layer->alpha);
        // Buffer sources will have a black solid color ignored in the shader,
        // so in that scenario the solid color passed here is arbitrary.
        setupLayerBlending(usePremultipliedAlpha, isOpaque, disableTexture, color,
                           layer->geometry.roundedCornersRadius);
        if (layer->disableBlending) {
            glDisable(GL_BLEND);
        }
        setSourceDataSpace(layer->sourceDataspace);

        if (layer->shadow.length > 0.0f) {
            handleShadow(layer->geometry.boundaries, layer->geometry.roundedCornersRadius,
                         layer->shadow);
        }
        // We only want to do a special handling for rounded corners when having rounded corners
        // is the only reason it needs to turn on blending, otherwise, we handle it like the
        // usual way since it needs to turn on blending anyway.
        else if (layer->geometry.roundedCornersRadius > 0.0 && color.a >= 1.0f && isOpaque) {
            handleRoundedCorners(display, *layer, mesh);
        } else {
            drawMesh(mesh);
        }

        // Cleanup if there's a buffer source
        if (layer->source.buffer.buffer != nullptr) {
            disableBlending();
            setSourceY410BT2020(false);
            disableTexturing();
        }
    }

    if (drawFence != nullptr) {
        *drawFence = flush();
    }
    // If flush failed or we don't support native fences, we need to force the
    // gl command stream to be executed.
    if (drawFence == nullptr || drawFence->get() < 0) {
        bool success = finish();
        if (!success) {
            ALOGE("Failed to flush RenderEngine commands");
            checkErrors();
            // Chances are, something illegal happened (either the caller passed
            // us bad parameters, or we messed up our shader generation).
            return INVALID_OPERATION;
        }
        mLastDrawFence = nullptr;
    } else {
        // The caller takes ownership of drawFence, so we need to duplicate the
        // fd here.
        mLastDrawFence = new Fence(dup(drawFence->get()));
    }
    mPriorResourcesCleaned = false;

    checkErrors();
    return NO_ERROR;
}

void GLESRenderEngine::setViewportAndProjection(Rect viewport, Rect clip) {
    ATRACE_CALL();
    mVpWidth = viewport.getWidth();
    mVpHeight = viewport.getHeight();

    // We pass the the top left corner instead of the bottom left corner,
    // because since we're rendering off-screen first.
    glViewport(viewport.left, viewport.top, mVpWidth, mVpHeight);

    mState.projectionMatrix = mat4::ortho(clip.left, clip.right, clip.top, clip.bottom, 0, 1);
}

void GLESRenderEngine::setupLayerBlending(bool premultipliedAlpha, bool opaque, bool disableTexture,
                                          const half4& color, float cornerRadius) {
    mState.isPremultipliedAlpha = premultipliedAlpha;
    mState.isOpaque = opaque;
    mState.color = color;
    mState.cornerRadius = cornerRadius;

    if (disableTexture) {
        mState.textureEnabled = false;
    }

    if (color.a < 1.0f || !opaque || cornerRadius > 0.0f) {
        glEnable(GL_BLEND);
        glBlendFuncSeparate(premultipliedAlpha ? GL_ONE : GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA,
                            GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
    } else {
        glDisable(GL_BLEND);
    }
}

void GLESRenderEngine::setSourceY410BT2020(bool enable) {
    mState.isY410BT2020 = enable;
}

void GLESRenderEngine::setSourceDataSpace(Dataspace source) {
    mDataSpace = source;
}

void GLESRenderEngine::setOutputDataSpace(Dataspace dataspace) {
    mOutputDataSpace = dataspace;
}

void GLESRenderEngine::setDisplayMaxLuminance(const float maxLuminance) {
    mState.displayMaxLuminance = maxLuminance;
}

void GLESRenderEngine::setupLayerTexturing(const Texture& texture) {
    GLuint target = texture.getTextureTarget();
    glBindTexture(target, texture.getTextureName());
    GLenum filter = GL_NEAREST;
    if (texture.getFiltering()) {
        filter = GL_LINEAR;
    }
    glTexParameteri(target, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(target, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(target, GL_TEXTURE_MAG_FILTER, filter);
    glTexParameteri(target, GL_TEXTURE_MIN_FILTER, filter);

    mState.texture = texture;
    mState.textureEnabled = true;
}

void GLESRenderEngine::setColorTransform(const mat4& colorTransform) {
    mState.colorMatrix = colorTransform;
}

void GLESRenderEngine::setDisplayColorTransform(const mat4& colorTransform) {
    mState.displayColorMatrix = colorTransform;
}

void GLESRenderEngine::disableTexturing() {
    mState.textureEnabled = false;
}

void GLESRenderEngine::disableBlending() {
    glDisable(GL_BLEND);
}

void GLESRenderEngine::setupFillWithColor(float r, float g, float b, float a) {
    mState.isPremultipliedAlpha = true;
    mState.isOpaque = false;
    mState.color = half4(r, g, b, a);
    mState.textureEnabled = false;
    glDisable(GL_BLEND);
}

void GLESRenderEngine::setupCornerRadiusCropSize(float width, float height) {
    mState.cropSize = half2(width, height);
}

void GLESRenderEngine::drawMesh(const Mesh& mesh) {
    ATRACE_CALL();
    if (mesh.getTexCoordsSize()) {
        glEnableVertexAttribArray(Program::texCoords);
        glVertexAttribPointer(Program::texCoords, mesh.getTexCoordsSize(), GL_FLOAT, GL_FALSE,
                              mesh.getByteStride(), mesh.getTexCoords());
    }

    glVertexAttribPointer(Program::position, mesh.getVertexSize(), GL_FLOAT, GL_FALSE,
                          mesh.getByteStride(), mesh.getPositions());

    if (mState.cornerRadius > 0.0f) {
        glEnableVertexAttribArray(Program::cropCoords);
        glVertexAttribPointer(Program::cropCoords, mesh.getVertexSize(), GL_FLOAT, GL_FALSE,
                              mesh.getByteStride(), mesh.getCropCoords());
    }

    if (mState.drawShadows) {
        glEnableVertexAttribArray(Program::shadowColor);
        glVertexAttribPointer(Program::shadowColor, mesh.getShadowColorSize(), GL_FLOAT, GL_FALSE,
                              mesh.getByteStride(), mesh.getShadowColor());

        glEnableVertexAttribArray(Program::shadowParams);
        glVertexAttribPointer(Program::shadowParams, mesh.getShadowParamsSize(), GL_FLOAT, GL_FALSE,
                              mesh.getByteStride(), mesh.getShadowParams());
    }

    Description managedState = mState;
    // By default, DISPLAY_P3 is the only supported wide color output. However,
    // when HDR content is present, hardware composer may be able to handle
    // BT2020 data space, in that case, the output data space is set to be
    // BT2020_HLG or BT2020_PQ respectively. In GPU fall back we need
    // to respect this and convert non-HDR content to HDR format.
    if (mUseColorManagement) {
        Dataspace inputStandard = static_cast<Dataspace>(mDataSpace & Dataspace::STANDARD_MASK);
        Dataspace inputTransfer = static_cast<Dataspace>(mDataSpace & Dataspace::TRANSFER_MASK);
        Dataspace outputStandard =
                static_cast<Dataspace>(mOutputDataSpace & Dataspace::STANDARD_MASK);
        Dataspace outputTransfer =
                static_cast<Dataspace>(mOutputDataSpace & Dataspace::TRANSFER_MASK);
        bool needsXYZConversion = needsXYZTransformMatrix();

        // NOTE: if the input standard of the input dataspace is not STANDARD_DCI_P3 or
        // STANDARD_BT2020, it will be  treated as STANDARD_BT709
        if (inputStandard != Dataspace::STANDARD_DCI_P3 &&
            inputStandard != Dataspace::STANDARD_BT2020) {
            inputStandard = Dataspace::STANDARD_BT709;
        }

        if (needsXYZConversion) {
            // The supported input color spaces are standard RGB, Display P3 and BT2020.
            switch (inputStandard) {
                case Dataspace::STANDARD_DCI_P3:
                    managedState.inputTransformMatrix = mDisplayP3ToXyz;
                    break;
                case Dataspace::STANDARD_BT2020:
                    managedState.inputTransformMatrix = mBt2020ToXyz;
                    break;
                default:
                    managedState.inputTransformMatrix = mSrgbToXyz;
                    break;
            }

            // The supported output color spaces are BT2020, Display P3 and standard RGB.
            switch (outputStandard) {
                case Dataspace::STANDARD_BT2020:
                    managedState.outputTransformMatrix = mXyzToBt2020;
                    break;
                case Dataspace::STANDARD_DCI_P3:
                    managedState.outputTransformMatrix = mXyzToDisplayP3;
                    break;
                default:
                    managedState.outputTransformMatrix = mXyzToSrgb;
                    break;
            }
        } else if (inputStandard != outputStandard) {
            // At this point, the input data space and output data space could be both
            // HDR data spaces, but they match each other, we do nothing in this case.
            // In addition to the case above, the input data space could be
            // - scRGB linear
            // - scRGB non-linear
            // - sRGB
            // - Display P3
            // - BT2020
            // The output data spaces could be
            // - sRGB
            // - Display P3
            // - BT2020
            switch (outputStandard) {
                case Dataspace::STANDARD_BT2020:
                    if (inputStandard == Dataspace::STANDARD_BT709) {
                        managedState.outputTransformMatrix = mSrgbToBt2020;
                    } else if (inputStandard == Dataspace::STANDARD_DCI_P3) {
                        managedState.outputTransformMatrix = mDisplayP3ToBt2020;
                    }
                    break;
                case Dataspace::STANDARD_DCI_P3:
                    if (inputStandard == Dataspace::STANDARD_BT709) {
                        managedState.outputTransformMatrix = mSrgbToDisplayP3;
                    } else if (inputStandard == Dataspace::STANDARD_BT2020) {
                        managedState.outputTransformMatrix = mBt2020ToDisplayP3;
                    }
                    break;
                default:
                    if (inputStandard == Dataspace::STANDARD_DCI_P3) {
                        managedState.outputTransformMatrix = mDisplayP3ToSrgb;
                    } else if (inputStandard == Dataspace::STANDARD_BT2020) {
                        managedState.outputTransformMatrix = mBt2020ToSrgb;
                    }
                    break;
            }
        }

        // we need to convert the RGB value to linear space and convert it back when:
        // - there is a color matrix that is not an identity matrix, or
        // - there is an output transform matrix that is not an identity matrix, or
        // - the input transfer function doesn't match the output transfer function.
        if (managedState.hasColorMatrix() || managedState.hasOutputTransformMatrix() ||
            inputTransfer != outputTransfer) {
            managedState.inputTransferFunction =
                    Description::dataSpaceToTransferFunction(inputTransfer);
            managedState.outputTransferFunction =
                    Description::dataSpaceToTransferFunction(outputTransfer);
        }
    }

    ProgramCache::getInstance().useProgram(mInProtectedContext ? mProtectedEGLContext : mEGLContext,
                                           managedState);

    if (mState.drawShadows) {
        glDrawElements(mesh.getPrimitive(), mesh.getIndexCount(), GL_UNSIGNED_SHORT,
                       mesh.getIndices());
    } else {
        glDrawArrays(mesh.getPrimitive(), 0, mesh.getVertexCount());
    }

    if (mUseColorManagement && outputDebugPPMs) {
        static uint64_t managedColorFrameCount = 0;
        std::ostringstream out;
        out << "/data/texture_out" << managedColorFrameCount++;
        writePPM(out.str().c_str(), mVpWidth, mVpHeight);
    }

    if (mesh.getTexCoordsSize()) {
        glDisableVertexAttribArray(Program::texCoords);
    }

    if (mState.cornerRadius > 0.0f) {
        glDisableVertexAttribArray(Program::cropCoords);
    }

    if (mState.drawShadows) {
        glDisableVertexAttribArray(Program::shadowColor);
        glDisableVertexAttribArray(Program::shadowParams);
    }
}

size_t GLESRenderEngine::getMaxTextureSize() const {
    return mMaxTextureSize;
}

size_t GLESRenderEngine::getMaxViewportDims() const {
    return mMaxViewportDims[0] < mMaxViewportDims[1] ? mMaxViewportDims[0] : mMaxViewportDims[1];
}

void GLESRenderEngine::dump(std::string& result) {
    const GLExtensions& extensions = GLExtensions::getInstance();
    ProgramCache& cache = ProgramCache::getInstance();

    StringAppendF(&result, "EGL implementation : %s\n", extensions.getEGLVersion());
    StringAppendF(&result, "%s\n", extensions.getEGLExtensions());
    StringAppendF(&result, "GLES: %s, %s, %s\n", extensions.getVendor(), extensions.getRenderer(),
                  extensions.getVersion());
    StringAppendF(&result, "%s\n", extensions.getExtensions());
    StringAppendF(&result, "RenderEngine supports protected context: %d\n",
                  supportsProtectedContent());
    StringAppendF(&result, "RenderEngine is in protected context: %d\n", mInProtectedContext);
    StringAppendF(&result, "RenderEngine program cache size for unprotected context: %zu\n",
                  cache.getSize(mEGLContext));
    StringAppendF(&result, "RenderEngine program cache size for protected context: %zu\n",
                  cache.getSize(mProtectedEGLContext));
    StringAppendF(&result, "RenderEngine last dataspace conversion: (%s) to (%s)\n",
                  dataspaceDetails(static_cast<android_dataspace>(mDataSpace)).c_str(),
                  dataspaceDetails(static_cast<android_dataspace>(mOutputDataSpace)).c_str());
    {
        std::lock_guard<std::mutex> lock(mRenderingMutex);
        StringAppendF(&result, "RenderEngine image cache size: %zu\n", mImageCache.size());
        StringAppendF(&result, "Dumping buffer ids...\n");
        for (const auto& [id, unused] : mImageCache) {
            StringAppendF(&result, "0x%" PRIx64 "\n", id);
        }
    }
    {
        std::lock_guard<std::mutex> lock(mFramebufferImageCacheMutex);
        StringAppendF(&result, "RenderEngine framebuffer image cache size: %zu\n",
                      mFramebufferImageCache.size());
        StringAppendF(&result, "Dumping buffer ids...\n");
        for (const auto& [id, unused] : mFramebufferImageCache) {
            StringAppendF(&result, "0x%" PRIx64 "\n", id);
        }
    }
}

GLESRenderEngine::GlesVersion GLESRenderEngine::parseGlesVersion(const char* str) {
    int major, minor;
    if (sscanf(str, "OpenGL ES-CM %d.%d", &major, &minor) != 2) {
        if (sscanf(str, "OpenGL ES %d.%d", &major, &minor) != 2) {
            ALOGW("Unable to parse GL_VERSION string: \"%s\"", str);
            return GLES_VERSION_1_0;
        }
    }

    if (major == 1 && minor == 0) return GLES_VERSION_1_0;
    if (major == 1 && minor >= 1) return GLES_VERSION_1_1;
    if (major == 2 && minor >= 0) return GLES_VERSION_2_0;
    if (major == 3 && minor >= 0) return GLES_VERSION_3_0;

    ALOGW("Unrecognized OpenGL ES version: %d.%d", major, minor);
    return GLES_VERSION_1_0;
}

EGLContext GLESRenderEngine::createEglContext(EGLDisplay display, EGLConfig config,
                                              EGLContext shareContext, bool useContextPriority,
                                              Protection protection) {
    EGLint renderableType = 0;
    if (config == EGL_NO_CONFIG) {
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
    if (useContextPriority) {
        contextAttributes.push_back(EGL_CONTEXT_PRIORITY_LEVEL_IMG);
        contextAttributes.push_back(EGL_CONTEXT_PRIORITY_HIGH_IMG);
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
        if (config != EGL_NO_CONFIG) {
            return context;
        }
        // If |config| is EGL_NO_CONFIG, we speculatively try to create GLES 3 context, so we should
        // try to fall back to GLES 2.
        contextAttributes[1] = 2;
        context = eglCreateContext(display, config, shareContext, contextAttributes.data());
    }

    return context;
}

EGLSurface GLESRenderEngine::createStubEglPbufferSurface(EGLDisplay display, EGLConfig config,
                                                         int hwcFormat, Protection protection) {
    EGLConfig stubConfig = config;
    if (stubConfig == EGL_NO_CONFIG) {
        stubConfig = chooseEglConfig(display, hwcFormat, /*logConfig*/ true);
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

    return eglCreatePbufferSurface(display, stubConfig, attributes.data());
}

bool GLESRenderEngine::isHdrDataSpace(const Dataspace dataSpace) const {
    const Dataspace standard = static_cast<Dataspace>(dataSpace & Dataspace::STANDARD_MASK);
    const Dataspace transfer = static_cast<Dataspace>(dataSpace & Dataspace::TRANSFER_MASK);
    return standard == Dataspace::STANDARD_BT2020 &&
            (transfer == Dataspace::TRANSFER_ST2084 || transfer == Dataspace::TRANSFER_HLG);
}

// For convenience, we want to convert the input color space to XYZ color space first,
// and then convert from XYZ color space to output color space when
// - SDR and HDR contents are mixed, either SDR content will be converted to HDR or
//   HDR content will be tone-mapped to SDR; Or,
// - there are HDR PQ and HLG contents presented at the same time, where we want to convert
//   HLG content to PQ content.
// In either case above, we need to operate the Y value in XYZ color space. Thus, when either
// input data space or output data space is HDR data space, and the input transfer function
// doesn't match the output transfer function, we would enable an intermediate transfrom to
// XYZ color space.
bool GLESRenderEngine::needsXYZTransformMatrix() const {
    const bool isInputHdrDataSpace = isHdrDataSpace(mDataSpace);
    const bool isOutputHdrDataSpace = isHdrDataSpace(mOutputDataSpace);
    const Dataspace inputTransfer = static_cast<Dataspace>(mDataSpace & Dataspace::TRANSFER_MASK);
    const Dataspace outputTransfer =
            static_cast<Dataspace>(mOutputDataSpace & Dataspace::TRANSFER_MASK);

    return (isInputHdrDataSpace || isOutputHdrDataSpace) && inputTransfer != outputTransfer;
}

bool GLESRenderEngine::isImageCachedForTesting(uint64_t bufferId) {
    std::lock_guard<std::mutex> lock(mRenderingMutex);
    const auto& cachedImage = mImageCache.find(bufferId);
    return cachedImage != mImageCache.end();
}

bool GLESRenderEngine::isTextureNameKnownForTesting(uint32_t texName) {
    const auto& entry = mTextureView.find(texName);
    return entry != mTextureView.end();
}

std::optional<uint64_t> GLESRenderEngine::getBufferIdForTextureNameForTesting(uint32_t texName) {
    const auto& entry = mTextureView.find(texName);
    return entry != mTextureView.end() ? entry->second : std::nullopt;
}

bool GLESRenderEngine::isFramebufferImageCachedForTesting(uint64_t bufferId) {
    std::lock_guard<std::mutex> lock(mFramebufferImageCacheMutex);
    return std::any_of(mFramebufferImageCache.cbegin(), mFramebufferImageCache.cend(),
                       [=](std::pair<uint64_t, EGLImageKHR> image) {
                           return image.first == bufferId;
                       });
}

// FlushTracer implementation
GLESRenderEngine::FlushTracer::FlushTracer(GLESRenderEngine* engine) : mEngine(engine) {
    mThread = std::thread(&GLESRenderEngine::FlushTracer::loop, this);
}

GLESRenderEngine::FlushTracer::~FlushTracer() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mRunning = false;
    }
    mCondition.notify_all();
    if (mThread.joinable()) {
        mThread.join();
    }
}

void GLESRenderEngine::FlushTracer::queueSync(EGLSyncKHR sync) {
    std::lock_guard<std::mutex> lock(mMutex);
    char name[64];
    const uint64_t frameNum = mFramesQueued++;
    snprintf(name, sizeof(name), "Queueing sync for frame: %lu",
             static_cast<unsigned long>(frameNum));
    ATRACE_NAME(name);
    mQueue.push({sync, frameNum});
    ATRACE_INT("GPU Frames Outstanding", mQueue.size());
    mCondition.notify_one();
}

void GLESRenderEngine::FlushTracer::loop() {
    while (mRunning) {
        QueueEntry entry;
        {
            std::lock_guard<std::mutex> lock(mMutex);

            mCondition.wait(mMutex,
                            [&]() REQUIRES(mMutex) { return !mQueue.empty() || !mRunning; });

            if (!mRunning) {
                // if mRunning is false, then FlushTracer is being destroyed, so
                // bail out now.
                break;
            }
            entry = mQueue.front();
            mQueue.pop();
        }
        {
            char name[64];
            snprintf(name, sizeof(name), "waiting for frame %lu",
                     static_cast<unsigned long>(entry.mFrameNum));
            ATRACE_NAME(name);
            mEngine->waitSync(entry.mSync, 0);
        }
    }
}

void GLESRenderEngine::handleShadow(const FloatRect& casterRect, float casterCornerRadius,
                                    const ShadowSettings& settings) {
    ATRACE_CALL();
    const float casterZ = settings.length / 2.0f;
    const GLShadowVertexGenerator shadows(casterRect, casterCornerRadius, casterZ,
                                          settings.casterIsTranslucent, settings.ambientColor,
                                          settings.spotColor, settings.lightPos,
                                          settings.lightRadius);

    // setup mesh for both shadows
    Mesh mesh = Mesh::Builder()
                        .setPrimitive(Mesh::TRIANGLES)
                        .setVertices(shadows.getVertexCount(), 2 /* size */)
                        .setShadowAttrs()
                        .setIndices(shadows.getIndexCount())
                        .build();

    Mesh::VertexArray<vec2> position = mesh.getPositionArray<vec2>();
    Mesh::VertexArray<vec4> shadowColor = mesh.getShadowColorArray<vec4>();
    Mesh::VertexArray<vec3> shadowParams = mesh.getShadowParamsArray<vec3>();
    shadows.fillVertices(position, shadowColor, shadowParams);
    shadows.fillIndices(mesh.getIndicesArray());

    mState.cornerRadius = 0.0f;
    mState.drawShadows = true;
    setupLayerTexturing(mShadowTexture.getTexture());
    drawMesh(mesh);
    mState.drawShadows = false;
}

} // namespace gl
} // namespace renderengine
} // namespace android
