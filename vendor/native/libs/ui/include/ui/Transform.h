/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <stdint.h>
#include <sys/types.h>
#include <array>
#include <ostream>
#include <string>

#include <math/mat4.h>
#include <math/vec2.h>
#include <math/vec3.h>
#include <ui/Point.h>
#include <ui/Rect.h>
#include <ui/Rotation.h>

namespace android {

class Region;

namespace ui {

class Transform {
public:
    Transform();
    Transform(const Transform&  other);
    explicit Transform(uint32_t orientation, int w = 0, int h = 0);
    ~Transform();

    enum RotationFlags : uint32_t {
        ROT_0 = 0,
        FLIP_H = 1, // HAL_TRANSFORM_FLIP_H
        FLIP_V = 2, // HAL_TRANSFORM_FLIP_V
        ROT_90 = 4, // HAL_TRANSFORM_ROT_90
        ROT_180 = FLIP_H | FLIP_V,
        ROT_270 = ROT_180 | ROT_90,
        ROT_INVALID = 0x80
    };

    enum type_mask : uint32_t {
        IDENTITY            = 0,
        TRANSLATE           = 0x1,
        ROTATE              = 0x2,
        SCALE               = 0x4,
        UNKNOWN             = 0x8
    };

    // query the transform
    bool preserveRects() const;

    // Returns if bilinear filtering is needed after applying this transform to avoid aliasing.
    bool needsBilinearFiltering() const;

    uint32_t getType() const;
    uint32_t getOrientation() const;
    bool operator==(const Transform& other) const;

    const vec3& operator [] (size_t i) const;  // returns column i
    float   tx() const;
    float   ty() const;
    float dsdx() const;
    float dtdx() const;
    float dtdy() const;
    float dsdy() const;
    float det() const;

    float getScaleX() const;
    float getScaleY() const;

    // modify the transform
    void        reset();
    void        set(float tx, float ty);
    void        set(float a, float b, float c, float d);
    status_t    set(uint32_t flags, float w, float h);
    void        set(const std::array<float, 9>& matrix);

    // transform data
    Rect    makeBounds(int w, int h) const;
    vec2    transform(float x, float y) const;
    Region  transform(const Region& reg) const;
    Rect    transform(const Rect& bounds,
                      bool roundOutwards = false) const;
    FloatRect transform(const FloatRect& bounds) const;
    Transform& operator = (const Transform& other);
    Transform operator * (const Transform& rhs) const;
    Transform operator * (float value) const;
    // assumes the last row is < 0 , 0 , 1 >
    vec2 transform(const vec2& v) const;
    vec3 transform(const vec3& v) const;

    // Expands from the internal 3x3 matrix to an equivalent 4x4 matrix
    mat4 asMatrix4() const;

    Transform inverse() const;

    // for debugging
    void dump(std::string& result, const char* name, const char* prefix = "") const;
    void dump(const char* name, const char* prefix = "") const;

    static constexpr RotationFlags toRotationFlags(Rotation);
    static constexpr Rotation toRotation(RotationFlags);

private:
    struct mat33 {
        vec3 v[3];
        inline const vec3& operator [] (size_t i) const { return v[i]; }
        inline vec3& operator [] (size_t i) { return v[i]; }
    };

    enum { UNKNOWN_TYPE = 0x80000000 };

    uint32_t type() const;
    static bool absIsOne(float f);
    static bool isZero(float f);

    mat33               mMatrix;
    mutable uint32_t    mType;
};

inline void PrintTo(const Transform& t, ::std::ostream* os) {
    std::string out;
    t.dump(out, "ui::Transform");
    *os << out;
}

inline constexpr Transform::RotationFlags Transform::toRotationFlags(Rotation rotation) {
    switch (rotation) {
        case ROTATION_0:
            return ROT_0;
        case ROTATION_90:
            return ROT_90;
        case ROTATION_180:
            return ROT_180;
        case ROTATION_270:
            return ROT_270;
        default:
            return ROT_INVALID;
    }
}

inline constexpr Rotation Transform::toRotation(Transform::RotationFlags rotationFlags) {
    switch (rotationFlags) {
        case ROT_0:
            return ROTATION_0;
        case ROT_90:
            return ROTATION_90;
        case ROT_180:
            return ROTATION_180;
        case ROT_270:
            return ROTATION_270;
        default:
            return ROTATION_0;
    }
}

}  // namespace ui
}  // namespace android
