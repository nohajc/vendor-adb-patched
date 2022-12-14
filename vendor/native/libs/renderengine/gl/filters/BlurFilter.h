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
#include "../GLVertexBuffer.h"
#include "GenericProgram.h"

using namespace std;

namespace android {
namespace renderengine {
namespace gl {

/**
 * This is an implementation of a Kawase blur, as described in here:
 * https://community.arm.com/cfs-file/__key/communityserver-blogs-components-weblogfiles/
 * 00-00-00-20-66/siggraph2015_2D00_mmg_2D00_marius_2D00_notes.pdf
 */
class BlurFilter {
public:
    // Downsample FBO to improve performance
    static constexpr float kFboScale = 0.25f;
    // Maximum number of render passes
    static constexpr uint32_t kMaxPasses = 4;
    // To avoid downscaling artifacts, we interpolate the blurred fbo with the full composited
    // image, up to this radius.
    static constexpr float kMaxCrossFadeRadius = 30.0f;

    explicit BlurFilter(GLESRenderEngine& engine);
    virtual ~BlurFilter(){};

    // Set up render targets, redirecting output to offscreen texture.
    status_t setAsDrawTarget(const DisplaySettings&, uint32_t radius);
    // Execute blur passes, rendering to offscreen texture.
    status_t prepare();
    // Render blur to the bound framebuffer (screen).
    status_t render(bool multiPass);

private:
    uint32_t mRadius;
    void drawMesh(GLuint uv, GLuint position);
    string getVertexShader() const;
    string getFragmentShader() const;
    string getMixFragShader() const;

    GLESRenderEngine& mEngine;
    // Frame buffer holding the composited background.
    GLFramebuffer mCompositionFbo;
    // Frame buffers holding the blur passes.
    GLFramebuffer mPingFbo;
    GLFramebuffer mPongFbo;
    uint32_t mDisplayWidth = 0;
    uint32_t mDisplayHeight = 0;
    uint32_t mDisplayX = 0;
    uint32_t mDisplayY = 0;
    // Buffer holding the final blur pass.
    GLFramebuffer* mLastDrawTarget;

    // VBO containing vertex and uv data of a fullscreen triangle.
    GLVertexBuffer mMeshBuffer;

    GenericProgram mMixProgram;
    GLuint mMPosLoc;
    GLuint mMUvLoc;
    GLuint mMMixLoc;
    GLuint mMTextureLoc;
    GLuint mMCompositionTextureLoc;

    GenericProgram mBlurProgram;
    GLuint mBPosLoc;
    GLuint mBUvLoc;
    GLuint mBTextureLoc;
    GLuint mBOffsetLoc;
};

} // namespace gl
} // namespace renderengine
} // namespace android
