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
#include <ui/Rect.h>

#include "GLSkiaShadowPort.h"

namespace android {
namespace renderengine {

class Mesh;

namespace gl {

/**
 * Generates gl attributes required to draw shadow spot and/or ambient shadows.
 *
 * Each shadow can support different colors. This class generates three vertex attributes for
 * each shadow, its position, color and shadow params(offset and distance). These can be sent
 * using a single glDrawElements call.
 */
class GLShadowVertexGenerator {
public:
    GLShadowVertexGenerator(const FloatRect& casterRect, float casterCornerRadius, float casterZ,
                            bool casterIsTranslucent, const vec4& ambientColor,
                            const vec4& spotColor, const vec3& lightPosition, float lightRadius);
    ~GLShadowVertexGenerator() = default;

    size_t getVertexCount() const;
    size_t getIndexCount() const;
    void fillVertices(Mesh::VertexArray<vec2>& position, Mesh::VertexArray<vec4>& color,
                      Mesh::VertexArray<vec3>& params) const;
    void fillIndices(uint16_t* indices) const;

private:
    bool mDrawAmbientShadow;
    std::unique_ptr<Geometry> mAmbientShadowGeometry;
    int mAmbientShadowVertexCount = 0;
    int mAmbientShadowIndexCount = 0;

    bool mDrawSpotShadow;
    std::unique_ptr<Geometry> mSpotShadowGeometry;
    int mSpotShadowVertexCount = 0;
    int mSpotShadowIndexCount = 0;
};

} // namespace gl
} // namespace renderengine
} // namespace android
