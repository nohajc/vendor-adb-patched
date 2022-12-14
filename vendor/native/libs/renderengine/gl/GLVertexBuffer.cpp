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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "GLVertexBuffer.h"

#include <GLES/gl.h>
#include <GLES2/gl2.h>
#include <nativebase/nativebase.h>
#include <utils/Trace.h>

namespace android {
namespace renderengine {
namespace gl {

GLVertexBuffer::GLVertexBuffer() {
    glGenBuffers(1, &mBufferName);
}

GLVertexBuffer::~GLVertexBuffer() {
    glDeleteBuffers(1, &mBufferName);
}

void GLVertexBuffer::allocateBuffers(const GLfloat data[], const GLuint size) {
    ATRACE_CALL();
    bind();
    glBufferData(GL_ARRAY_BUFFER, size * sizeof(GLfloat), data, GL_STATIC_DRAW);
    unbind();
}

void GLVertexBuffer::bind() const {
    glBindBuffer(GL_ARRAY_BUFFER, mBufferName);
}

void GLVertexBuffer::unbind() const {
    glBindBuffer(GL_ARRAY_BUFFER, 0);
}

} // namespace gl
} // namespace renderengine
} // namespace android
