/*
 * Copyright 2019 The Android Open Source Project
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

#include "GenericProgram.h"

#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>

namespace android {
namespace renderengine {
namespace gl {

GenericProgram::GenericProgram(GLESRenderEngine& engine) : mEngine(engine) {}

GenericProgram::~GenericProgram() {
    if (mVertexShaderHandle != 0) {
        if (mProgramHandle != 0) {
            glDetachShader(mProgramHandle, mVertexShaderHandle);
        }
        glDeleteShader(mVertexShaderHandle);
    }

    if (mFragmentShaderHandle != 0) {
        if (mProgramHandle != 0) {
            glDetachShader(mProgramHandle, mFragmentShaderHandle);
        }
        glDeleteShader(mFragmentShaderHandle);
    }

    if (mProgramHandle != 0) {
        glDeleteProgram(mProgramHandle);
    }
}

void GenericProgram::compile(string vertexShader, string fragmentShader) {
    mVertexShaderHandle = compileShader(GL_VERTEX_SHADER, vertexShader);
    mFragmentShaderHandle = compileShader(GL_FRAGMENT_SHADER, fragmentShader);
    if (mVertexShaderHandle == 0 || mFragmentShaderHandle == 0) {
        ALOGE("Aborting program creation.");
        return;
    }
    mProgramHandle = createAndLink(mVertexShaderHandle, mFragmentShaderHandle);
    mEngine.checkErrors("Linking program");
}

void GenericProgram::useProgram() const {
    glUseProgram(mProgramHandle);
}

GLuint GenericProgram::compileShader(GLuint type, string src) const {
    const GLuint shader = glCreateShader(type);
    if (shader == 0) {
        mEngine.checkErrors("Creating shader");
        return 0;
    }
    const GLchar* charSrc = (const GLchar*)src.c_str();
    glShaderSource(shader, 1, &charSrc, nullptr);
    glCompileShader(shader);

    GLint isCompiled = 0;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &isCompiled);
    if (isCompiled == GL_FALSE) {
        GLint maxLength = 0;
        glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &maxLength);
        string errorLog;
        errorLog.reserve(maxLength);
        glGetShaderInfoLog(shader, maxLength, &maxLength, errorLog.data());
        glDeleteShader(shader);
        ALOGE("Error compiling shader: %s", errorLog.c_str());
        return 0;
    }
    return shader;
}
GLuint GenericProgram::createAndLink(GLuint vertexShader, GLuint fragmentShader) const {
    const GLuint program = glCreateProgram();
    mEngine.checkErrors("Creating program");

    glAttachShader(program, vertexShader);
    glAttachShader(program, fragmentShader);
    glLinkProgram(program);
    mEngine.checkErrors("Linking program");
    return program;
}

GLuint GenericProgram::getUniformLocation(const string name) const {
    if (mProgramHandle == 0) {
        ALOGE("Can't get location of %s on an invalid program.", name.c_str());
        return -1;
    }
    return glGetUniformLocation(mProgramHandle, (const GLchar*)name.c_str());
}

GLuint GenericProgram::getAttributeLocation(const string name) const {
    if (mProgramHandle == 0) {
        ALOGE("Can't get location of %s on an invalid program.", name.c_str());
        return -1;
    }
    return glGetAttribLocation(mProgramHandle, (const GLchar*)name.c_str());
}

bool GenericProgram::isValid() const {
    return mProgramHandle != 0;
}

} // namespace gl
} // namespace renderengine
} // namespace android
