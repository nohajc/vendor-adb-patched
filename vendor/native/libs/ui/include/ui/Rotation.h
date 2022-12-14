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

#include <type_traits>

namespace android::ui {

enum class Rotation { Rotation0 = 0, Rotation90 = 1, Rotation180 = 2, Rotation270 = 3 };

// Equivalent to Surface.java constants.
constexpr auto ROTATION_0 = Rotation::Rotation0;
constexpr auto ROTATION_90 = Rotation::Rotation90;
constexpr auto ROTATION_180 = Rotation::Rotation180;
constexpr auto ROTATION_270 = Rotation::Rotation270;

constexpr auto toRotation(std::underlying_type_t<Rotation> rotation) {
    return static_cast<Rotation>(rotation);
}

constexpr auto toRotationInt(Rotation rotation) {
    return static_cast<std::underlying_type_t<Rotation>>(rotation);
}

constexpr Rotation operator+(Rotation lhs, Rotation rhs) {
    constexpr auto N = toRotationInt(ROTATION_270) + 1;
    return toRotation((toRotationInt(lhs) + toRotationInt(rhs)) % N);
}

constexpr const char* toCString(Rotation rotation) {
    switch (rotation) {
        case ROTATION_0:
            return "ROTATION_0";
        case ROTATION_90:
            return "ROTATION_90";
        case ROTATION_180:
            return "ROTATION_180";
        case ROTATION_270:
            return "ROTATION_270";
    }
}

} // namespace android::ui
