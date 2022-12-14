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

#include <ftl/cast.h>
#include <gtest/gtest.h>

#include <cfloat>
#include <cmath>
#include <limits>

namespace android::test {

using ftl::cast_safety;
using ftl::CastSafety;

template <typename T>
constexpr T min = std::numeric_limits<T>::lowest();

template <typename T>
constexpr T max = std::numeric_limits<T>::max();

template <typename T>
constexpr T inf = std::numeric_limits<T>::infinity();

template <typename T>
constexpr T NaN = std::numeric_limits<T>::quiet_NaN();

// Keep in sync with example usage in header file.

static_assert(cast_safety<uint8_t>(-1) == CastSafety::kUnderflow);
static_assert(cast_safety<int8_t>(128u) == CastSafety::kOverflow);

static_assert(cast_safety<uint32_t>(-.1f) == CastSafety::kUnderflow);
static_assert(cast_safety<int32_t>(static_cast<float>(INT32_MAX)) == CastSafety::kOverflow);

static_assert(cast_safety<float>(-DBL_MAX) == CastSafety::kUnderflow);

// Unsigned to unsigned.

static_assert(cast_safety<uint8_t>(0u) == CastSafety::kSafe);
static_assert(cast_safety<uint16_t>(max<uint8_t>) == CastSafety::kSafe);
static_assert(cast_safety<uint8_t>(static_cast<uint32_t>(max<uint8_t>)) == CastSafety::kSafe);

static_assert(cast_safety<uint32_t>(max<uint64_t>) == CastSafety::kOverflow);
static_assert(cast_safety<uint8_t>(static_cast<uint32_t>(max<uint8_t>) + 1) ==
              CastSafety::kOverflow);

// Unsigned to signed.

static_assert(cast_safety<int16_t>(0u) == CastSafety::kSafe);
static_assert(cast_safety<int16_t>(max<uint8_t>) == CastSafety::kSafe);
static_assert(cast_safety<int16_t>(max<uint16_t>) == CastSafety::kOverflow);

static_assert(cast_safety<int64_t>(static_cast<uint64_t>(max<int64_t>) - 1) == CastSafety::kSafe);
static_assert(cast_safety<int64_t>(static_cast<uint64_t>(max<int64_t>)) == CastSafety::kSafe);
static_assert(cast_safety<int64_t>(static_cast<uint64_t>(max<int64_t>) + 1) ==
              CastSafety::kOverflow);

// Signed to unsigned.

static_assert(cast_safety<uint16_t>(0) == CastSafety::kSafe);
static_assert(cast_safety<uint16_t>(max<int8_t>) == CastSafety::kSafe);
static_assert(cast_safety<uint16_t>(max<int16_t>) == CastSafety::kSafe);

static_assert(cast_safety<uint32_t>(-1) == CastSafety::kUnderflow);
static_assert(cast_safety<uint32_t>(max<int64_t>) == CastSafety::kOverflow);

static_assert(cast_safety<uint32_t>(static_cast<int64_t>(max<uint32_t>) - 1) == CastSafety::kSafe);
static_assert(cast_safety<uint32_t>(static_cast<int64_t>(max<uint32_t>)) == CastSafety::kSafe);
static_assert(cast_safety<uint32_t>(static_cast<int64_t>(max<uint32_t>) + 1) ==
              CastSafety::kOverflow);

// Signed to signed.

static_assert(cast_safety<int8_t>(-129) == CastSafety::kUnderflow);
static_assert(cast_safety<int8_t>(-128) == CastSafety::kSafe);
static_assert(cast_safety<int8_t>(127) == CastSafety::kSafe);
static_assert(cast_safety<int8_t>(128) == CastSafety::kOverflow);

static_assert(cast_safety<int32_t>(static_cast<int64_t>(min<int32_t>)) == CastSafety::kSafe);
static_assert(cast_safety<int32_t>(static_cast<int64_t>(max<int32_t>)) == CastSafety::kSafe);

static_assert(cast_safety<int16_t>(min<int32_t>) == CastSafety::kUnderflow);
static_assert(cast_safety<int32_t>(max<int64_t>) == CastSafety::kOverflow);

// Float to float.

static_assert(cast_safety<double>(max<float>) == CastSafety::kSafe);
static_assert(cast_safety<double>(min<float>) == CastSafety::kSafe);

static_assert(cast_safety<float>(min<double>) == CastSafety::kUnderflow);
static_assert(cast_safety<float>(max<double>) == CastSafety::kOverflow);

TEST(CastSafety, FloatToFloat) {
  EXPECT_EQ(cast_safety<float>(std::nexttoward(static_cast<double>(min<float>), min<double>)),
            CastSafety::kUnderflow);
  EXPECT_EQ(cast_safety<float>(std::nexttoward(static_cast<double>(max<float>), max<double>)),
            CastSafety::kOverflow);
}

// Unsigned to float.

static_assert(cast_safety<float>(0u) == CastSafety::kSafe);
static_assert(cast_safety<float>(max<uint64_t>) == CastSafety::kSafe);

static_assert(cast_safety<double>(0u) == CastSafety::kSafe);
static_assert(cast_safety<double>(max<uint64_t>) == CastSafety::kSafe);

// Signed to float.

static_assert(cast_safety<float>(min<int64_t>) == CastSafety::kSafe);
static_assert(cast_safety<float>(max<int64_t>) == CastSafety::kSafe);

static_assert(cast_safety<double>(min<int64_t>) == CastSafety::kSafe);
static_assert(cast_safety<double>(max<int64_t>) == CastSafety::kSafe);

// Float to unsigned.

static_assert(cast_safety<uint32_t>(0.f) == CastSafety::kSafe);
static_assert(cast_safety<uint32_t>(min<float>) == CastSafety::kUnderflow);
static_assert(cast_safety<uint32_t>(max<float>) == CastSafety::kOverflow);
static_assert(cast_safety<uint32_t>(-.1f) == CastSafety::kUnderflow);

static_assert(cast_safety<uint16_t>(-inf<float>) == CastSafety::kUnderflow);
static_assert(cast_safety<uint32_t>(inf<float>) == CastSafety::kOverflow);
static_assert(cast_safety<uint64_t>(NaN<float>) == CastSafety::kOverflow);

static_assert(cast_safety<uint32_t>(static_cast<float>(max<int32_t>)) == CastSafety::kSafe);
static_assert(cast_safety<uint32_t>(static_cast<float>(max<uint32_t>)) == CastSafety::kOverflow);
static_assert(cast_safety<uint32_t>(static_cast<double>(max<int32_t>)) == CastSafety::kSafe);
static_assert(cast_safety<uint32_t>(static_cast<double>(max<uint32_t>)) == CastSafety::kSafe);

static_assert(cast_safety<uint64_t>(0.0) == CastSafety::kSafe);
static_assert(cast_safety<uint64_t>(min<double>) == CastSafety::kUnderflow);
static_assert(cast_safety<uint64_t>(max<double>) == CastSafety::kOverflow);
static_assert(cast_safety<uint64_t>(-.1) == CastSafety::kUnderflow);

static_assert(cast_safety<uint64_t>(static_cast<float>(max<int64_t>)) == CastSafety::kSafe);
static_assert(cast_safety<uint64_t>(static_cast<float>(max<uint64_t>)) == CastSafety::kOverflow);
static_assert(cast_safety<uint64_t>(static_cast<double>(max<int64_t>)) == CastSafety::kSafe);
static_assert(cast_safety<uint64_t>(static_cast<double>(max<uint64_t>)) == CastSafety::kOverflow);

// Float to signed.

static_assert(cast_safety<int32_t>(0.f) == CastSafety::kSafe);
static_assert(cast_safety<int32_t>(min<float>) == CastSafety::kUnderflow);
static_assert(cast_safety<int32_t>(max<float>) == CastSafety::kOverflow);

static_assert(cast_safety<int16_t>(-inf<double>) == CastSafety::kUnderflow);
static_assert(cast_safety<int32_t>(inf<double>) == CastSafety::kOverflow);
static_assert(cast_safety<int64_t>(NaN<double>) == CastSafety::kOverflow);

static_assert(cast_safety<int32_t>(static_cast<float>(min<int32_t>)) == CastSafety::kSafe);
static_assert(cast_safety<int32_t>(static_cast<float>(max<int32_t>)) == CastSafety::kOverflow);
static_assert(cast_safety<int32_t>(static_cast<double>(min<int32_t>)) == CastSafety::kSafe);
static_assert(cast_safety<int32_t>(static_cast<double>(max<int32_t>)) == CastSafety::kSafe);

static_assert(cast_safety<int64_t>(0.0) == CastSafety::kSafe);
static_assert(cast_safety<int64_t>(min<double>) == CastSafety::kUnderflow);
static_assert(cast_safety<int64_t>(max<double>) == CastSafety::kOverflow);

static_assert(cast_safety<int64_t>(static_cast<float>(min<int64_t>)) == CastSafety::kSafe);
static_assert(cast_safety<int64_t>(static_cast<float>(max<int64_t>)) == CastSafety::kOverflow);
static_assert(cast_safety<int64_t>(static_cast<double>(min<int64_t>)) == CastSafety::kSafe);
static_assert(cast_safety<int64_t>(static_cast<double>(max<int64_t>)) == CastSafety::kOverflow);

TEST(CastSafety, FloatToSigned) {
  constexpr int32_t kMax = ftl::details::safe_limits<int32_t, float>::max();
  static_assert(kMax == 2'147'483'520);
  EXPECT_EQ(kMax, static_cast<int32_t>(std::nexttowardf(max<int32_t>, 0)));

  EXPECT_EQ(cast_safety<int32_t>(std::nexttowardf(min<int32_t>, 0)), CastSafety::kSafe);
  EXPECT_EQ(cast_safety<int32_t>(std::nexttowardf(max<int32_t>, 0)), CastSafety::kSafe);
  EXPECT_EQ(cast_safety<int64_t>(std::nexttoward(min<int64_t>, 0)), CastSafety::kSafe);
  EXPECT_EQ(cast_safety<int64_t>(std::nexttoward(max<int64_t>, 0)), CastSafety::kSafe);

  EXPECT_EQ(cast_safety<int32_t>(std::nexttowardf(min<int32_t>, min<float>)),
            CastSafety::kUnderflow);
  EXPECT_EQ(cast_safety<int32_t>(std::nexttowardf(max<int32_t>, max<float>)),
            CastSafety::kOverflow);
  EXPECT_EQ(cast_safety<int64_t>(std::nexttoward(min<int64_t>, min<double>)),
            CastSafety::kUnderflow);
  EXPECT_EQ(cast_safety<int64_t>(std::nexttoward(max<int64_t>, max<double>)),
            CastSafety::kOverflow);
}

}  // namespace android::test
