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

#include <cstdint>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <renderengine/Framebuffer.h>

struct ANativeWindowBuffer;

namespace android {
namespace renderengine {
namespace gl {

class GLESRenderEngine;

class GLFramebuffer : public renderengine::Framebuffer {
public:
    explicit GLFramebuffer(GLESRenderEngine& engine);
    explicit GLFramebuffer(GLESRenderEngine& engine, bool multiTarget);
    ~GLFramebuffer() override;

    bool setNativeWindowBuffer(ANativeWindowBuffer* nativeBuffer, bool isProtected,
                               const bool useFramebufferCache) override;
    void allocateBuffers(uint32_t width, uint32_t height, void* data = nullptr);
    EGLImageKHR getEGLImage() const { return mEGLImage; }
    uint32_t getTextureName() const { return mTextureName; }
    uint32_t getFramebufferName() const { return mFramebufferName; }
    int32_t getBufferHeight() const { return mBufferHeight; }
    int32_t getBufferWidth() const { return mBufferWidth; }
    GLenum getStatus() const { return mStatus; }
    void bind() const;
    void bindAsReadBuffer() const;
    void bindAsDrawBuffer() const;
    void unbind() const;

private:
    GLESRenderEngine& mEngine;
    EGLDisplay mEGLDisplay;
    EGLImageKHR mEGLImage;
    bool usingFramebufferCache = false;
    GLenum mStatus = GL_FRAMEBUFFER_UNSUPPORTED;
    uint32_t mTextureName, mFramebufferName;

    int32_t mBufferHeight = 0;
    int32_t mBufferWidth = 0;
};

} // namespace gl
} // namespace renderengine
} // namespace android
