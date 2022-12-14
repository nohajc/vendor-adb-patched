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

#pragma once

#include <cstdint>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>

struct ANativeWindowBuffer;

namespace android {
namespace renderengine {
namespace gl {

class GLESRenderEngine;

class GLVertexBuffer {
public:
    explicit GLVertexBuffer();
    ~GLVertexBuffer();

    void allocateBuffers(const GLfloat data[], const GLuint size);
    uint32_t getBufferName() const { return mBufferName; }
    void bind() const;
    void unbind() const;

private:
    uint32_t mBufferName;
};

} // namespace gl
} // namespace renderengine
} // namespace android
