/*
 * Copyright 2021 The Android Open Source Project
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

#include <utils/Flattenable.h>
#include "FloatRect.h"

#include <math.h>
#include <type_traits>

namespace android {

struct StretchEffect : public LightFlattenablePod<StretchEffect> {
  constexpr static const float CONTENT_DISTANCE_STRETCHED = 1.f;

  float width = 0;
  float height = 0;
  float vectorX = 0;
  float vectorY = 0;
  float maxAmountX = 0;
  float maxAmountY = 0;
  FloatRect mappedChildBounds = {0, 0, 0, 0};

  bool operator==(const StretchEffect& other) const {
    return width == other.width && height == other.height &&
        vectorX == other.vectorX &&
        vectorY == other.vectorY &&
        maxAmountX == other.maxAmountX &&
        maxAmountY == other.maxAmountY &&
        mappedChildBounds == other.mappedChildBounds;
  }

  bool operator!=(const StretchEffect& other) const { return !(*this == other); }

  static bool isZero(float value) {
    constexpr float NON_ZERO_EPSILON = 0.001f;
    return fabsf(value) <= NON_ZERO_EPSILON;
  }

  bool isNoOp() const { return isZero(vectorX) && isZero(vectorY); }

  bool hasEffect() const { return !isNoOp(); }

  void sanitize() {
    // If the area is empty, or the max amount is zero, then reset back to defaults
    if (width == 0.f || height == 0.f || isZero(maxAmountX) ||
        isZero(maxAmountY)) {
      *this = StretchEffect{};
    }
  }

  float getStretchWidthMultiplier() const {
      return CONTENT_DISTANCE_STRETCHED / (1.f + abs(vectorX));
  }

  float getStretchHeightMultiplier() const {
      return CONTENT_DISTANCE_STRETCHED / (1.f + abs(vectorY));
  }
};

static_assert(std::is_trivially_copyable<StretchEffect>::value,
              "StretchEffect must be trivially copyable to be flattenable");

} // namespace android