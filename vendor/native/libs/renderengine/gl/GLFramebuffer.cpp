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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "GLFramebuffer.h"

#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES2/gl2ext.h>
#include <GLES3/gl3.h>
#include <gui/DebugEGLImageTracker.h>
#include <nativebase/nativebase.h>
#include <utils/Trace.h>
#include "GLESRenderEngine.h"

namespace android {
namespace renderengine {
namespace gl {

GLFramebuffer::GLFramebuffer(GLESRenderEngine& engine)
      : mEngine(engine), mEGLDisplay(engine.getEGLDisplay()), mEGLImage(EGL_NO_IMAGE_KHR) {
    glGenTextures(1, &mTextureName);
    glGenFramebuffers(1, &mFramebufferName);
}

GLFramebuffer::~GLFramebuffer() {
    glDeleteFramebuffers(1, &mFramebufferName);
    glDeleteTextures(1, &mTextureName);
}

bool GLFramebuffer::setNativeWindowBuffer(ANativeWindowBuffer* nativeBuffer, bool isProtected,
                                          const bool useFramebufferCache) {
    ATRACE_CALL();
    if (mEGLImage != EGL_NO_IMAGE_KHR) {
        if (!usingFramebufferCache) {
            eglDestroyImageKHR(mEGLDisplay, mEGLImage);
            DEBUG_EGL_IMAGE_TRACKER_DESTROY();
        }
        mEGLImage = EGL_NO_IMAGE_KHR;
        mBufferWidth = 0;
        mBufferHeight = 0;
    }

    if (nativeBuffer) {
        mEGLImage = mEngine.createFramebufferImageIfNeeded(nativeBuffer, isProtected,
                                                           useFramebufferCache);
        if (mEGLImage == EGL_NO_IMAGE_KHR) {
            return false;
        }
        usingFramebufferCache = useFramebufferCache;
        mBufferWidth = nativeBuffer->width;
        mBufferHeight = nativeBuffer->height;
    }
    return true;
}

void GLFramebuffer::allocateBuffers(uint32_t width, uint32_t height, void* data) {
    ATRACE_CALL();

    glBindTexture(GL_TEXTURE_2D, mTextureName);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, width, height, 0, GL_RGB, GL_UNSIGNED_BYTE, data);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_MIRRORED_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_MIRRORED_REPEAT);

    mBufferHeight = height;
    mBufferWidth = width;
    mEngine.checkErrors("Allocating Fbo texture");

    bind();
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, mTextureName, 0);
    mStatus = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    unbind();
    glBindTexture(GL_TEXTURE_2D, 0);

    if (mStatus != GL_FRAMEBUFFER_COMPLETE) {
        ALOGE("Frame buffer is not complete. Error %d", mStatus);
    }
}

void GLFramebuffer::bind() const {
    glBindFramebuffer(GL_FRAMEBUFFER, mFramebufferName);
}

void GLFramebuffer::bindAsReadBuffer() const {
    glBindFramebuffer(GL_READ_FRAMEBUFFER, mFramebufferName);
}

void GLFramebuffer::bindAsDrawBuffer() const {
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, mFramebufferName);
}

void GLFramebuffer::unbind() const {
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

} // namespace gl
} // namespace renderengine
} // namespace android
