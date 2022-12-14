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

#include <renderengine/Mesh.h>

#include <math/vec4.h>

#include <ui/Rect.h>
#include <ui/Transform.h>

#include "GLShadowVertexGenerator.h"

namespace android {
namespace renderengine {
namespace gl {

GLShadowVertexGenerator::GLShadowVertexGenerator(const FloatRect& casterRect,
                                                 float casterCornerRadius, float casterZ,
                                                 bool casterIsTranslucent, const vec4& ambientColor,
                                                 const vec4& spotColor, const vec3& lightPosition,
                                                 float lightRadius) {
    mDrawAmbientShadow = ambientColor.a > 0.f;
    mDrawSpotShadow = spotColor.a > 0.f;

    // Generate geometries and find number of vertices to generate
    if (mDrawAmbientShadow) {
        mAmbientShadowGeometry = getAmbientShadowGeometry(casterRect, casterCornerRadius, casterZ,
                                                          casterIsTranslucent, ambientColor);
        mAmbientShadowVertexCount = getVertexCountForGeometry(*mAmbientShadowGeometry.get());
        mAmbientShadowIndexCount = getIndexCountForGeometry(*mAmbientShadowGeometry.get());
    } else {
        mAmbientShadowVertexCount = 0;
        mAmbientShadowIndexCount = 0;
    }

    if (mDrawSpotShadow) {
        mSpotShadowGeometry =
                getSpotShadowGeometry(casterRect, casterCornerRadius, casterZ, casterIsTranslucent,
                                      spotColor, lightPosition, lightRadius);
        mSpotShadowVertexCount = getVertexCountForGeometry(*mSpotShadowGeometry.get());
        mSpotShadowIndexCount = getIndexCountForGeometry(*mSpotShadowGeometry.get());
    } else {
        mSpotShadowVertexCount = 0;
        mSpotShadowIndexCount = 0;
    }
}

size_t GLShadowVertexGenerator::getVertexCount() const {
    return mAmbientShadowVertexCount + mSpotShadowVertexCount;
}

size_t GLShadowVertexGenerator::getIndexCount() const {
    return mAmbientShadowIndexCount + mSpotShadowIndexCount;
}

void GLShadowVertexGenerator::fillVertices(Mesh::VertexArray<vec2>& position,
                                           Mesh::VertexArray<vec4>& color,
                                           Mesh::VertexArray<vec3>& params) const {
    if (mDrawAmbientShadow) {
        fillVerticesForGeometry(*mAmbientShadowGeometry.get(), mAmbientShadowVertexCount, position,
                                color, params);
    }
    if (mDrawSpotShadow) {
        fillVerticesForGeometry(*mSpotShadowGeometry.get(), mSpotShadowVertexCount,
                                Mesh::VertexArray<vec2>(position, mAmbientShadowVertexCount),
                                Mesh::VertexArray<vec4>(color, mAmbientShadowVertexCount),
                                Mesh::VertexArray<vec3>(params, mAmbientShadowVertexCount));
    }
}

void GLShadowVertexGenerator::fillIndices(uint16_t* indices) const {
    if (mDrawAmbientShadow) {
        fillIndicesForGeometry(*mAmbientShadowGeometry.get(), mAmbientShadowIndexCount,
                               0 /* starting vertex offset */, indices);
    }
    if (mDrawSpotShadow) {
        fillIndicesForGeometry(*mSpotShadowGeometry.get(), mSpotShadowIndexCount,
                               mAmbientShadowVertexCount /* starting vertex offset */,
                               &(indices[mAmbientShadowIndexCount]));
    }
}

} // namespace gl
} // namespace renderengine
} // namespace android
