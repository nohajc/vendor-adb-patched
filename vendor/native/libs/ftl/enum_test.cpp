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

#include <ftl/enum.h>
#include <gtest/gtest.h>

namespace android::test {

// Keep in sync with example usage in header file.
namespace {

enum class E { A, B, C, F = 5, ftl_last = F };

static_assert(ftl::enum_begin_v<E> == E::A);
static_assert(ftl::enum_last_v<E> == E::F);
static_assert(ftl::enum_size_v<E> == 6);

static_assert(ftl::enum_name<E::B>() == "B");
static_assert(ftl::enum_name<E::ftl_last>() == "F");
static_assert(ftl::enum_name(E::C).value_or("?") == "C");
static_assert(ftl::enum_name(E{3}).value_or("?") == "?");

enum class F : std::uint16_t { X = 0b1, Y = 0b10, Z = 0b100 };

static_assert(ftl::enum_begin_v<F> == F{0});
static_assert(ftl::enum_last_v<F> == F{15});
static_assert(ftl::enum_size_v<F> == 16);

static_assert(ftl::flag_name(F::Z).value_or("?") == "Z");
static_assert(ftl::flag_name(F{0b111}).value_or("?") == "?");

// If a scoped enum is unsigned, its implicit range corresponds to its bit indices.
enum class Flags : std::uint8_t {
  kNone = 0,
  kFlag1 = 0b0000'0010,
  kFlag4 = 0b0001'0000,
  kFlag7 = 0b1000'0000,
  kMask = kFlag1 | kFlag4 | kFlag7,
  kAll = 0b1111'1111
};

static_assert(ftl::enum_begin_v<Flags> == Flags{0});
static_assert(ftl::enum_last_v<Flags> == Flags{7});
static_assert(ftl::enum_size_v<Flags> == 8);

static_assert(ftl::enum_name<Flags::kNone>() == "kNone");
static_assert(ftl::enum_name<Flags::kFlag4>() == "kFlag4");
static_assert(ftl::enum_name<Flags::kFlag7>() == "kFlag7");

// Though not flags, the enumerators are within the implicit range of bit indices.
enum class Planet : std::uint8_t {
  kMercury,
  kVenus,
  kEarth,
  kMars,
  kJupiter,
  kSaturn,
  kUranus,
  kNeptune
};

constexpr Planet kPluto{ftl::to_underlying(Planet::kNeptune) + 1};  // Honorable mention.

static_assert(ftl::enum_begin_v<Planet> == Planet::kMercury);
static_assert(ftl::enum_last_v<Planet> == Planet::kNeptune);
static_assert(ftl::enum_size_v<Planet> == 8);

static_assert(ftl::enum_name<Planet::kMercury>() == "kMercury");
static_assert(ftl::enum_name<Planet::kSaturn>() == "kSaturn");

// Unscoped enum must define explicit range, even if the underlying type is fixed.
enum Temperature : int {
  kRoom = 20,
  kFridge = 4,
  kFreezer = -18,

  ftl_first = kFreezer,
  ftl_last = kRoom
};

static_assert(ftl::enum_begin_v<Temperature> == kFreezer);
static_assert(ftl::enum_last_v<Temperature> == kRoom);
static_assert(ftl::enum_size_v<Temperature> == 39);

static_assert(ftl::enum_name<kFreezer>() == "kFreezer");
static_assert(ftl::enum_name<kFridge>() == "kFridge");
static_assert(ftl::enum_name<kRoom>() == "kRoom");

}  // namespace

TEST(Enum, Range) {
  std::string string;
  for (E v : ftl::enum_range<E>()) {
    string += ftl::enum_name(v).value_or("?");
  }
  EXPECT_EQ(string, "ABC??F");
}

TEST(Enum, Name) {
  {
    EXPECT_EQ(ftl::flag_name(Flags::kFlag1), "kFlag1");
    EXPECT_EQ(ftl::flag_name(Flags::kFlag7), "kFlag7");

    EXPECT_EQ(ftl::flag_name(Flags::kNone), std::nullopt);
    EXPECT_EQ(ftl::flag_name(Flags::kMask), std::nullopt);
    EXPECT_EQ(ftl::flag_name(Flags::kAll), std::nullopt);
  }
  {
    EXPECT_EQ(ftl::enum_name(Planet::kEarth), "kEarth");
    EXPECT_EQ(ftl::enum_name(Planet::kNeptune), "kNeptune");

    EXPECT_EQ(ftl::enum_name(kPluto), std::nullopt);
  }
  {
    EXPECT_EQ(ftl::enum_name(kRoom), "kRoom");
    EXPECT_EQ(ftl::enum_name(kFridge), "kFridge");
    EXPECT_EQ(ftl::enum_name(kFreezer), "kFreezer");

    EXPECT_EQ(ftl::enum_name(static_cast<Temperature>(-30)), std::nullopt);
    EXPECT_EQ(ftl::enum_name(static_cast<Temperature>(0)), std::nullopt);
    EXPECT_EQ(ftl::enum_name(static_cast<Temperature>(100)), std::nullopt);
  }
}

TEST(Enum, String) {
  {
    EXPECT_EQ(ftl::flag_string(Flags::kFlag1), "kFlag1");
    EXPECT_EQ(ftl::flag_string(Flags::kFlag7), "kFlag7");

    EXPECT_EQ(ftl::flag_string(Flags::kNone), "0b0");
    EXPECT_EQ(ftl::flag_string(Flags::kMask), "0b10010010");
    EXPECT_EQ(ftl::flag_string(Flags::kAll), "0b11111111");

    enum class Flags64 : std::uint64_t {
      kFlag0 = 0b1ull,
      kFlag63 = 0x8000'0000'0000'0000ull,
      kMask = kFlag0 | kFlag63
    };

    EXPECT_EQ(ftl::flag_string(Flags64::kFlag0), "kFlag0");
    EXPECT_EQ(ftl::flag_string(Flags64::kFlag63), "kFlag63");
    EXPECT_EQ(ftl::flag_string(Flags64::kMask), "0x8000000000000001");
  }
  {
    EXPECT_EQ(ftl::enum_string(Planet::kEarth), "kEarth");
    EXPECT_EQ(ftl::enum_string(Planet::kNeptune), "kNeptune");

    EXPECT_EQ(ftl::enum_string(kPluto), "8");
  }
  {
    EXPECT_EQ(ftl::enum_string(kRoom), "kRoom");
    EXPECT_EQ(ftl::enum_string(kFridge), "kFridge");
    EXPECT_EQ(ftl::enum_string(kFreezer), "kFreezer");

    EXPECT_EQ(ftl::enum_string(static_cast<Temperature>(-30)), "-30");
    EXPECT_EQ(ftl::enum_string(static_cast<Temperature>(0)), "0");
    EXPECT_EQ(ftl::enum_string(static_cast<Temperature>(100)), "100");
  }
}

}  // namespace android::test
