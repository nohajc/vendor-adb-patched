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

#include <math/vec4.h>

#include <renderengine/Mesh.h>

#include <ui/Rect.h>
#include <ui/Transform.h>

#include <utils/Log.h>

#include "GLSkiaShadowPort.h"

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

static inline float divide_and_pin(float numer, float denom, float min, float max) {
    if (denom == 0.0f) return min;
    return std::clamp(numer / denom, min, max);
}

static constexpr auto SK_ScalarSqrt2 = 1.41421356f;
static constexpr auto kAmbientHeightFactor = 1.0f / 128.0f;
static constexpr auto kAmbientGeomFactor = 64.0f;
// Assuming that we have a light height of 600 for the spot shadow,
// the spot values will reach their maximum at a height of approximately 292.3077.
// We'll round up to 300 to keep it simple.
static constexpr auto kMaxAmbientRadius = 300 * kAmbientHeightFactor * kAmbientGeomFactor;

inline float AmbientBlurRadius(float height) {
    return std::min(height * kAmbientHeightFactor * kAmbientGeomFactor, kMaxAmbientRadius);
}
inline float AmbientRecipAlpha(float height) {
    return 1.0f + std::max(height * kAmbientHeightFactor, 0.0f);
}

//////////////////////////////////////////////////////////////////////////////
// Circle Data
//
// We have two possible cases for geometry for a circle:

// In the case of a normal fill, we draw geometry for the circle as an octagon.
static const uint16_t gFillCircleIndices[] = {
        // enter the octagon
        // clang-format off
         0, 1, 8, 1, 2, 8,
         2, 3, 8, 3, 4, 8,
         4, 5, 8, 5, 6, 8,
         6, 7, 8, 7, 0, 8,
        // clang-format on
};

// For stroked circles, we use two nested octagons.
static const uint16_t gStrokeCircleIndices[] = {
        // enter the octagon
        // clang-format off
         0, 1,  9, 0,  9,  8,
         1, 2, 10, 1, 10,  9,
         2, 3, 11, 2, 11, 10,
         3, 4, 12, 3, 12, 11,
         4, 5, 13, 4, 13, 12,
         5, 6, 14, 5, 14, 13,
         6, 7, 15, 6, 15, 14,
         7, 0,  8, 7,  8, 15,
        // clang-format on
};

#define SK_ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
static const int kIndicesPerFillCircle = SK_ARRAY_COUNT(gFillCircleIndices);
static const int kIndicesPerStrokeCircle = SK_ARRAY_COUNT(gStrokeCircleIndices);
static const int kVertsPerStrokeCircle = 16;
static const int kVertsPerFillCircle = 9;

static int circle_type_to_vert_count(bool stroked) {
    return stroked ? kVertsPerStrokeCircle : kVertsPerFillCircle;
}

static int circle_type_to_index_count(bool stroked) {
    return stroked ? kIndicesPerStrokeCircle : kIndicesPerFillCircle;
}

static const uint16_t* circle_type_to_indices(bool stroked) {
    return stroked ? gStrokeCircleIndices : gFillCircleIndices;
}

///////////////////////////////////////////////////////////////////////////////
// RoundRect Data
//
// The geometry for a shadow roundrect is similar to a 9-patch:
//    ____________
//   |_|________|_|
//   | |        | |
//   | |        | |
//   | |        | |
//   |_|________|_|
//   |_|________|_|
//
// However, each corner is rendered as a fan rather than a simple quad, as below. (The diagram
// shows the upper part of the upper left corner. The bottom triangle would similarly be split
// into two triangles.)
//    ________
//   |\  \   |
//   |  \ \  |
//   |    \\ |
//   |      \|
//   --------
//
// The center of the fan handles the curve of the corner. For roundrects where the stroke width
// is greater than the corner radius, the outer triangles blend from the curve to the straight
// sides. Otherwise these triangles will be degenerate.
//
// In the case where the stroke width is greater than the corner radius and the
// blur radius (overstroke), we add additional geometry to mark out the rectangle in the center.
// This rectangle extends the coverage values of the center edges of the 9-patch.
//    ____________
//   |_|________|_|
//   | |\ ____ /| |
//   | | |    | | |
//   | | |____| | |
//   |_|/______\|_|
//   |_|________|_|
//
// For filled rrects we reuse the stroke geometry but add an additional quad to the center.

static const uint16_t gRRectIndices[] = {
        // clang-format off
     // overstroke quads
     // we place this at the beginning so that we can skip these indices when rendering as filled
     0, 6, 25, 0, 25, 24,
     6, 18, 27, 6, 27, 25,
     18, 12, 26, 18, 26, 27,
     12, 0, 24, 12, 24, 26,

     // corners
     0, 1, 2, 0, 2, 3, 0, 3, 4, 0, 4, 5,
     6, 11, 10, 6, 10, 9, 6, 9, 8, 6, 8, 7,
     12, 17, 16, 12, 16, 15, 12, 15, 14, 12, 14, 13,
     18, 19, 20, 18, 20, 21, 18, 21, 22, 18, 22, 23,

     // edges
     0, 5, 11, 0, 11, 6,
     6, 7, 19, 6, 19, 18,
     18, 23, 17, 18, 17, 12,
     12, 13, 1, 12, 1, 0,

     // fill quad
     // we place this at the end so that we can skip these indices when rendering as stroked
     0, 6, 18, 0, 18, 12,
        // clang-format on
};

// overstroke count
static const int kIndicesPerOverstrokeRRect = SK_ARRAY_COUNT(gRRectIndices) - 6;
// simple stroke count skips overstroke indices
static const int kIndicesPerStrokeRRect = kIndicesPerOverstrokeRRect - 6 * 4;
// fill count adds final quad to stroke count
static const int kIndicesPerFillRRect = kIndicesPerStrokeRRect + 6;
static const int kVertsPerStrokeRRect = 24;
static const int kVertsPerOverstrokeRRect = 28;
static const int kVertsPerFillRRect = 24;

static int rrect_type_to_vert_count(RRectType type) {
    switch (type) {
        case kFill_RRectType:
            return kVertsPerFillRRect;
        case kStroke_RRectType:
            return kVertsPerStrokeRRect;
        case kOverstroke_RRectType:
            return kVertsPerOverstrokeRRect;
    }
    ALOGE("Invalid rect type: %d", type);
    return -1;
}

static int rrect_type_to_index_count(RRectType type) {
    switch (type) {
        case kFill_RRectType:
            return kIndicesPerFillRRect;
        case kStroke_RRectType:
            return kIndicesPerStrokeRRect;
        case kOverstroke_RRectType:
            return kIndicesPerOverstrokeRRect;
    }
    ALOGE("Invalid rect type: %d", type);
    return -1;
}

static const uint16_t* rrect_type_to_indices(RRectType type) {
    switch (type) {
        case kFill_RRectType:
        case kStroke_RRectType:
            return gRRectIndices + 6 * 4;
        case kOverstroke_RRectType:
            return gRRectIndices;
    }
    ALOGE("Invalid rect type: %d", type);
    return nullptr;
}

static void fillInCircleVerts(const Geometry& args, bool isStroked,
                              Mesh::VertexArray<vec2>& position,
                              Mesh::VertexArray<vec4>& shadowColor,
                              Mesh::VertexArray<vec3>& shadowParams) {
    vec4 color = args.fColor;
    float outerRadius = args.fOuterRadius;
    float innerRadius = args.fInnerRadius;
    float blurRadius = args.fBlurRadius;
    float distanceCorrection = outerRadius / blurRadius;

    const FloatRect& bounds = args.fDevBounds;

    // The inner radius in the vertex data must be specified in normalized space.
    innerRadius = innerRadius / outerRadius;

    vec2 center = vec2(bounds.getWidth() / 2.0f, bounds.getHeight() / 2.0f);
    float halfWidth = 0.5f * bounds.getWidth();
    float octOffset = 0.41421356237f; // sqrt(2) - 1
    int vertexCount = 0;

    position[vertexCount] = center + vec2(-octOffset * halfWidth, -halfWidth);
    shadowColor[vertexCount] = color;
    shadowParams[vertexCount] = vec3(-octOffset, -1, distanceCorrection);
    vertexCount++;

    position[vertexCount] = center + vec2(octOffset * halfWidth, -halfWidth);
    shadowColor[vertexCount] = color;
    shadowParams[vertexCount] = vec3(octOffset, -1, distanceCorrection);
    vertexCount++;

    position[vertexCount] = center + vec2(halfWidth, -octOffset * halfWidth);
    shadowColor[vertexCount] = color;
    shadowParams[vertexCount] = vec3(1, -octOffset, distanceCorrection);
    vertexCount++;

    position[vertexCount] = center + vec2(halfWidth, octOffset * halfWidth);
    shadowColor[vertexCount] = color;
    shadowParams[vertexCount] = vec3(1, octOffset, distanceCorrection);
    vertexCount++;

    position[vertexCount] = center + vec2(octOffset * halfWidth, halfWidth);
    shadowColor[vertexCount] = color;
    shadowParams[vertexCount] = vec3(octOffset, 1, distanceCorrection);
    vertexCount++;

    position[vertexCount] = center + vec2(-octOffset * halfWidth, halfWidth);
    shadowColor[vertexCount] = color;
    shadowParams[vertexCount] = vec3(-octOffset, 1, distanceCorrection);
    vertexCount++;

    position[vertexCount] = center + vec2(-halfWidth, octOffset * halfWidth);
    shadowColor[vertexCount] = color;
    shadowParams[vertexCount] = vec3(-1, octOffset, distanceCorrection);
    vertexCount++;

    position[vertexCount] = center + vec2(-halfWidth, -octOffset * halfWidth);
    shadowColor[vertexCount] = color;
    shadowParams[vertexCount] = vec3(-1, -octOffset, distanceCorrection);
    vertexCount++;

    if (isStroked) {
        // compute the inner ring

        // cosine and sine of pi/8
        float c = 0.923579533f;
        float s = 0.382683432f;
        float r = args.fInnerRadius;

        position[vertexCount] = center + vec2(-s * r, -c * r);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(-s * innerRadius, -c * innerRadius, distanceCorrection);
        vertexCount++;

        position[vertexCount] = center + vec2(s * r, -c * r);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(s * innerRadius, -c * innerRadius, distanceCorrection);
        vertexCount++;

        position[vertexCount] = center + vec2(c * r, -s * r);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(c * innerRadius, -s * innerRadius, distanceCorrection);
        vertexCount++;

        position[vertexCount] = center + vec2(c * r, s * r);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(c * innerRadius, s * innerRadius, distanceCorrection);
        vertexCount++;

        position[vertexCount] = center + vec2(s * r, c * r);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(s * innerRadius, c * innerRadius, distanceCorrection);
        vertexCount++;

        position[vertexCount] = center + vec2(-s * r, c * r);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(-s * innerRadius, c * innerRadius, distanceCorrection);
        vertexCount++;

        position[vertexCount] = center + vec2(-c * r, s * r);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(-c * innerRadius, s * innerRadius, distanceCorrection);
        vertexCount++;

        position[vertexCount] = center + vec2(-c * r, -s * r);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(-c * innerRadius, -s * innerRadius, distanceCorrection);
        vertexCount++;
    } else {
        // filled
        position[vertexCount] = center;
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(0, 0, distanceCorrection);
        vertexCount++;
    }
}

static void fillInRRectVerts(const Geometry& args, Mesh::VertexArray<vec2>& position,
                             Mesh::VertexArray<vec4>& shadowColor,
                             Mesh::VertexArray<vec3>& shadowParams) {
    vec4 color = args.fColor;
    float outerRadius = args.fOuterRadius;

    const FloatRect& bounds = args.fDevBounds;

    float umbraInset = args.fUmbraInset;
    float minDim = 0.5f * std::min(bounds.getWidth(), bounds.getHeight());
    if (umbraInset > minDim) {
        umbraInset = minDim;
    }

    float xInner[4] = {bounds.left + umbraInset, bounds.right - umbraInset,
                       bounds.left + umbraInset, bounds.right - umbraInset};
    float xMid[4] = {bounds.left + outerRadius, bounds.right - outerRadius,
                     bounds.left + outerRadius, bounds.right - outerRadius};
    float xOuter[4] = {bounds.left, bounds.right, bounds.left, bounds.right};
    float yInner[4] = {bounds.top + umbraInset, bounds.top + umbraInset, bounds.bottom - umbraInset,
                       bounds.bottom - umbraInset};
    float yMid[4] = {bounds.top + outerRadius, bounds.top + outerRadius,
                     bounds.bottom - outerRadius, bounds.bottom - outerRadius};
    float yOuter[4] = {bounds.top, bounds.top, bounds.bottom, bounds.bottom};

    float blurRadius = args.fBlurRadius;

    // In the case where we have to inset more for the umbra, our two triangles in the
    // corner get skewed to a diamond rather than a square. To correct for that,
    // we also skew the vectors we send to the shader that help define the circle.
    // By doing so, we end up with a quarter circle in the corner rather than the
    // elliptical curve.

    // This is a bit magical, but it gives us the correct results at extrema:
    //   a) umbraInset == outerRadius produces an orthogonal vector
    //   b) outerRadius == 0 produces a diagonal vector
    // And visually the corner looks correct.
    vec2 outerVec = vec2(outerRadius - umbraInset, -outerRadius - umbraInset);
    outerVec = normalize(outerVec);
    // We want the circle edge to fall fractionally along the diagonal at
    //      (sqrt(2)*(umbraInset - outerRadius) + outerRadius)/sqrt(2)*umbraInset
    //
    // Setting the components of the diagonal offset to the following value will give us that.
    float diagVal = umbraInset / (SK_ScalarSqrt2 * (outerRadius - umbraInset) - outerRadius);
    vec2 diagVec = vec2(diagVal, diagVal);
    float distanceCorrection = umbraInset / blurRadius;

    int vertexCount = 0;
    // build corner by corner
    for (int i = 0; i < 4; ++i) {
        // inner point
        position[vertexCount] = vec2(xInner[i], yInner[i]);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(0, 0, distanceCorrection);
        vertexCount++;

        // outer points
        position[vertexCount] = vec2(xOuter[i], yInner[i]);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(0, -1, distanceCorrection);
        vertexCount++;

        position[vertexCount] = vec2(xOuter[i], yMid[i]);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(outerVec.x, outerVec.y, distanceCorrection);
        vertexCount++;

        position[vertexCount] = vec2(xOuter[i], yOuter[i]);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(diagVec.x, diagVec.y, distanceCorrection);
        vertexCount++;

        position[vertexCount] = vec2(xMid[i], yOuter[i]);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(outerVec.x, outerVec.y, distanceCorrection);
        vertexCount++;

        position[vertexCount] = vec2(xInner[i], yOuter[i]);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(0, -1, distanceCorrection);
        vertexCount++;
    }

    // Add the additional vertices for overstroked rrects.
    // Effectively this is an additional stroked rrect, with its
    // parameters equal to those in the center of the 9-patch. This will
    // give constant values across this inner ring.
    if (kOverstroke_RRectType == args.fType) {
        float inset = umbraInset + args.fInnerRadius;

        // TL
        position[vertexCount] = vec2(bounds.left + inset, bounds.top + inset);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(0, 0, distanceCorrection);
        vertexCount++;

        // TR
        position[vertexCount] = vec2(bounds.right - inset, bounds.top + inset);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(0, 0, distanceCorrection);
        vertexCount++;

        // BL
        position[vertexCount] = vec2(bounds.left + inset, bounds.bottom - inset);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(0, 0, distanceCorrection);
        vertexCount++;

        // BR
        position[vertexCount] = vec2(bounds.right - inset, bounds.bottom - inset);
        shadowColor[vertexCount] = color;
        shadowParams[vertexCount] = vec3(0, 0, distanceCorrection);
        vertexCount++;
    }
}

int getVertexCountForGeometry(const Geometry& shadowGeometry) {
    if (shadowGeometry.fIsCircle) {
        return circle_type_to_vert_count(shadowGeometry.fType);
    }

    return rrect_type_to_vert_count(shadowGeometry.fType);
}

int getIndexCountForGeometry(const Geometry& shadowGeometry) {
    if (shadowGeometry.fIsCircle) {
        return circle_type_to_index_count(kStroke_RRectType == shadowGeometry.fType);
    }

    return rrect_type_to_index_count(shadowGeometry.fType);
}

void fillVerticesForGeometry(const Geometry& shadowGeometry, int /* vertexCount */,
                             Mesh::VertexArray<vec2> position, Mesh::VertexArray<vec4> shadowColor,
                             Mesh::VertexArray<vec3> shadowParams) {
    if (shadowGeometry.fIsCircle) {
        fillInCircleVerts(shadowGeometry, shadowGeometry.fIsStroked, position, shadowColor,
                          shadowParams);
    } else {
        fillInRRectVerts(shadowGeometry, position, shadowColor, shadowParams);
    }
}

void fillIndicesForGeometry(const Geometry& shadowGeometry, int indexCount,
                            int startingVertexOffset, uint16_t* indices) {
    if (shadowGeometry.fIsCircle) {
        const uint16_t* primIndices = circle_type_to_indices(shadowGeometry.fIsStroked);
        for (int i = 0; i < indexCount; ++i) {
            indices[i] = primIndices[i] + startingVertexOffset;
        }
    } else {
        const uint16_t* primIndices = rrect_type_to_indices(shadowGeometry.fType);
        for (int i = 0; i < indexCount; ++i) {
            indices[i] = primIndices[i] + startingVertexOffset;
        }
    }
}

inline void GetSpotParams(float occluderZ, float lightX, float lightY, float lightZ,
                          float lightRadius, float& blurRadius, float& scale, vec2& translate) {
    float zRatio = divide_and_pin(occluderZ, lightZ - occluderZ, 0.0f, 0.95f);
    blurRadius = lightRadius * zRatio;
    scale = divide_and_pin(lightZ, lightZ - occluderZ, 1.0f, 1.95f);
    translate.x = -zRatio * lightX;
    translate.y = -zRatio * lightY;
}

static std::unique_ptr<Geometry> getShadowGeometry(const vec4& color, const FloatRect& devRect,
                                                   float devRadius, float blurRadius,
                                                   float insetWidth) {
    // An insetWidth > 1/2 rect width or height indicates a simple fill.
    const bool isCircle = ((devRadius >= devRect.getWidth()) && (devRadius >= devRect.getHeight()));

    FloatRect bounds = devRect;
    float innerRadius = 0.0f;
    float outerRadius = devRadius;
    float umbraInset;

    RRectType type = kFill_RRectType;
    if (isCircle) {
        umbraInset = 0;
    } else {
        umbraInset = std::max(outerRadius, blurRadius);
    }

    // If stroke is greater than width or height, this is still a fill,
    // otherwise we compute stroke params.
    if (isCircle) {
        innerRadius = devRadius - insetWidth;
        type = innerRadius > 0 ? kStroke_RRectType : kFill_RRectType;
    } else {
        if (insetWidth <= 0.5f * std::min(devRect.getWidth(), devRect.getHeight())) {
            // We don't worry about a real inner radius, we just need to know if we
            // need to create overstroke vertices.
            innerRadius = std::max(insetWidth - umbraInset, 0.0f);
            type = innerRadius > 0 ? kOverstroke_RRectType : kStroke_RRectType;
        }
    }
    const bool isStroked = (kStroke_RRectType == type);
    return std::make_unique<Geometry>(Geometry{color, outerRadius, umbraInset, innerRadius,
                                               blurRadius, bounds, type, isCircle, isStroked});
}

std::unique_ptr<Geometry> getAmbientShadowGeometry(const FloatRect& casterRect,
                                                   float casterCornerRadius, float casterZ,
                                                   bool casterIsTranslucent,
                                                   const vec4& ambientColor) {
    float devSpaceInsetWidth = AmbientBlurRadius(casterZ);
    const float umbraRecipAlpha = AmbientRecipAlpha(casterZ);
    const float devSpaceAmbientBlur = devSpaceInsetWidth * umbraRecipAlpha;

    // Outset the shadow rrect to the border of the penumbra
    float ambientPathOutset = devSpaceInsetWidth;
    FloatRect outsetRect(casterRect);
    outsetRect.left -= ambientPathOutset;
    outsetRect.top -= ambientPathOutset;
    outsetRect.right += ambientPathOutset;
    outsetRect.bottom += ambientPathOutset;

    float outsetRad = casterCornerRadius + ambientPathOutset;
    if (casterIsTranslucent) {
        // set a large inset to force a fill
        devSpaceInsetWidth = outsetRect.getWidth();
    }

    return getShadowGeometry(ambientColor, outsetRect, std::abs(outsetRad), devSpaceAmbientBlur,
                             std::abs(devSpaceInsetWidth));
}

std::unique_ptr<Geometry> getSpotShadowGeometry(const FloatRect& casterRect,
                                                float casterCornerRadius, float casterZ,
                                                bool casterIsTranslucent, const vec4& spotColor,
                                                const vec3& lightPosition, float lightRadius) {
    float devSpaceSpotBlur;
    float spotScale;
    vec2 spotOffset;
    GetSpotParams(casterZ, lightPosition.x, lightPosition.y, lightPosition.z, lightRadius,
                  devSpaceSpotBlur, spotScale, spotOffset);
    // handle scale of radius due to CTM
    const float srcSpaceSpotBlur = devSpaceSpotBlur;

    // Adjust translate for the effect of the scale.
    spotOffset.x += spotScale;
    spotOffset.y += spotScale;

    // Compute the transformed shadow rect
    ui::Transform shadowTransform;
    shadowTransform.set(spotOffset.x, spotOffset.y);
    shadowTransform.set(spotScale, 0, 0, spotScale);
    FloatRect spotShadowRect = shadowTransform.transform(casterRect);
    float spotShadowRadius = casterCornerRadius * spotScale;

    // Compute the insetWidth
    float blurOutset = srcSpaceSpotBlur;
    float insetWidth = blurOutset;
    if (casterIsTranslucent) {
        // If transparent, just do a fill
        insetWidth += spotShadowRect.getWidth();
    } else {
        // For shadows, instead of using a stroke we specify an inset from the penumbra
        // border. We want to extend this inset area so that it meets up with the caster
        // geometry. The inset geometry will by default already be inset by the blur width.
        //
        // We compare the min and max corners inset by the radius between the original
        // rrect and the shadow rrect. The distance between the two plus the difference
        // between the scaled radius and the original radius gives the distance from the
        // transformed shadow shape to the original shape in that corner. The max
        // of these gives the maximum distance we need to cover.
        //
        // Since we are outsetting by 1/2 the blur distance, we just add the maxOffset to
        // that to get the full insetWidth.
        float maxOffset;
        if (casterCornerRadius <= 0.f) {
            // Manhattan distance works better for rects
            maxOffset = std::max(std::max(std::abs(spotShadowRect.left - casterRect.left),
                                          std::abs(spotShadowRect.top - casterRect.top)),
                                 std::max(std::abs(spotShadowRect.right - casterRect.right),
                                          std::abs(spotShadowRect.bottom - casterRect.bottom)));
        } else {
            float dr = spotShadowRadius - casterCornerRadius;
            vec2 upperLeftOffset = vec2(spotShadowRect.left - casterRect.left + dr,
                                        spotShadowRect.top - casterRect.top + dr);
            vec2 lowerRightOffset = vec2(spotShadowRect.right - casterRect.right - dr,
                                         spotShadowRect.bottom - casterRect.bottom - dr);
            maxOffset = sqrt(std::max(dot(upperLeftOffset, lowerRightOffset),
                                      dot(lowerRightOffset, lowerRightOffset))) +
                    dr;
        }
        insetWidth += std::max(blurOutset, maxOffset);
    }

    // Outset the shadow rrect to the border of the penumbra
    spotShadowRadius += blurOutset;
    spotShadowRect.left -= blurOutset;
    spotShadowRect.top -= blurOutset;
    spotShadowRect.right += blurOutset;
    spotShadowRect.bottom += blurOutset;

    return getShadowGeometry(spotColor, spotShadowRect, std::abs(spotShadowRadius),
                             2.0f * devSpaceSpotBlur, std::abs(insetWidth));
}

void fillShadowTextureData(uint8_t* data, size_t shadowTextureWidth) {
    for (int i = 0; i < shadowTextureWidth; i++) {
        const float d = 1 - i / ((shadowTextureWidth * 1.0f) - 1.0f);
        data[i] = static_cast<uint8_t>((exp(-4.0f * d * d) - 0.018f) * 255);
    }
}

} // namespace gl
} // namespace renderengine
} // namespace android
