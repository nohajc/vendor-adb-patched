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

#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <GLES3/gl3.h>

#include "GLShadowTexture.h"
#include "GLSkiaShadowPort.h"

namespace android {
namespace renderengine {
namespace gl {

GLShadowTexture::GLShadowTexture() {
    fillShadowTextureData(mTextureData, SHADOW_TEXTURE_WIDTH);

    glGenTextures(1, &mName);
    glBindTexture(GL_TEXTURE_2D, mName);
    glTexImage2D(GL_TEXTURE_2D, 0 /* base image level */, GL_ALPHA, SHADOW_TEXTURE_WIDTH,
                 SHADOW_TEXTURE_HEIGHT, 0 /* border */, GL_ALPHA, GL_UNSIGNED_BYTE, mTextureData);
    mTexture.init(Texture::TEXTURE_2D, mName);
    mTexture.setFiltering(true);
    mTexture.setDimensions(SHADOW_TEXTURE_WIDTH, 1);
}

GLShadowTexture::~GLShadowTexture() {
    glDeleteTextures(1, &mName);
}

const Texture& GLShadowTexture::getTexture() {
    return mTexture;
}

} // namespace gl
} // namespace renderengine
} // namespace android
