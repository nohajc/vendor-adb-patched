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

#include <math/vec4.h>
#include <renderengine/Mesh.h>
#include <ui/Rect.h>

namespace android {
namespace renderengine {
namespace gl {

/**
 * The shadow geometry logic and vertex generation code has been ported from skia shadow
 * fast path OpenGL implementation to draw shadows around rects and rounded rects including
 * circles.
 *
 * path: skia/src/gpu/GrRenderTargetContext.cpp GrRenderTargetContext::drawFastShadow
 *
 * Modifications made:
 * - Switched to using std lib math functions
 * - Fall off function is implemented in vertex shader rather than a shadow texture
 * - Removed transformations applied on the caster rect since the caster will be in local
 *   coordinate space and will be transformed by the vertex shader.
 */

enum RRectType {
    kFill_RRectType,
    kStroke_RRectType,
    kOverstroke_RRectType,
};

struct Geometry {
    vec4 fColor;
    float fOuterRadius;
    float fUmbraInset;
    float fInnerRadius;
    float fBlurRadius;
    FloatRect fDevBounds;
    RRectType fType;
    bool fIsCircle;
    bool fIsStroked;
};

std::unique_ptr<Geometry> getSpotShadowGeometry(const FloatRect& casterRect,
                                                float casterCornerRadius, float casterZ,
                                                bool casterIsTranslucent, const vec4& spotColor,
                                                const vec3& lightPosition, float lightRadius);

std::unique_ptr<Geometry> getAmbientShadowGeometry(const FloatRect& casterRect,
                                                   float casterCornerRadius, float casterZ,
                                                   bool casterIsTranslucent,
                                                   const vec4& ambientColor);

int getVertexCountForGeometry(const Geometry& shadowGeometry);

int getIndexCountForGeometry(const Geometry& shadowGeometry);

void fillVerticesForGeometry(const Geometry& shadowGeometry, int vertexCount,
                             Mesh::VertexArray<vec2> position, Mesh::VertexArray<vec4> shadowColor,
                             Mesh::VertexArray<vec3> shadowParams);

void fillIndicesForGeometry(const Geometry& shadowGeometry, int indexCount,
                            int startingVertexOffset, uint16_t* indices);

/**
 * Maps shadow geometry 'alpha' varying (1 for darkest, 0 for transparent) to
 * darkness at that spot. Values are determined by an exponential falloff
 * function provided by UX.
 *
 * The texture is used for quick lookup in theshadow shader.
 *
 * textureData - filled with shadow texture data that needs to be at least of
 *               size textureWidth
 *
 * textureWidth - width of the texture, height is always 1
 */
void fillShadowTextureData(uint8_t* textureData, size_t textureWidth);

} // namespace gl
} // namespace renderengine
} // namespace android
