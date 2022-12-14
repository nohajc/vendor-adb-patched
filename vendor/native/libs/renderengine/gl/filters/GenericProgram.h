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

#pragma once

#include <ui/GraphicTypes.h>
#include "../GLESRenderEngine.h"
#include "../GLFramebuffer.h"

using namespace std;

namespace android {
namespace renderengine {
namespace gl {

class GenericProgram {
public:
    explicit GenericProgram(GLESRenderEngine& renderEngine);
    ~GenericProgram();
    void compile(string vertexShader, string fragmentShader);
    bool isValid() const;
    void useProgram() const;
    GLuint getAttributeLocation(const string name) const;
    GLuint getUniformLocation(const string name) const;

private:
    GLuint compileShader(GLuint type, const string src) const;
    GLuint createAndLink(GLuint vertexShader, GLuint fragmentShader) const;

    GLESRenderEngine& mEngine;
    GLuint mVertexShaderHandle = 0;
    GLuint mFragmentShaderHandle = 0;
    GLuint mProgramHandle = 0;
};

} // namespace gl
} // namespace renderengine
} // namespace android
