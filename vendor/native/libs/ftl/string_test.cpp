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

#include <ftl/string.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <sstream>
#include <type_traits>

namespace android::test {

// Keep in sync with example usage in header file.
TEST(String, ToChars) {
  ftl::to_chars_buffer_t<> buffer;

  EXPECT_EQ(ftl::to_chars(buffer, 123u), "123");
  EXPECT_EQ(ftl::to_chars(buffer, -42, ftl::Radix::kBin), "-0b101010");
  EXPECT_EQ(ftl::to_chars(buffer, 0xcafe, ftl::Radix::kHex), "0xcafe");
  EXPECT_EQ(ftl::to_chars(buffer, '*', ftl::Radix::kHex), "0x2a");
}

namespace {

template <typename F, typename T>
void ToCharsTest() {
  constexpr auto kRadix = F::kRadix;

  using Limits = std::numeric_limits<T>;
  constexpr auto kMin = Limits::min();
  constexpr auto kMax = Limits::max();
  constexpr auto kNeg = static_cast<T>(-42);
  constexpr auto kPos = static_cast<T>(123);

  ftl::to_chars_buffer_t<T> buffer;

  EXPECT_EQ(ftl::to_chars(buffer, kMin, kRadix), F{}(kMin));
  EXPECT_EQ(ftl::to_chars(buffer, kMax, kRadix), F{}(kMax));
  EXPECT_EQ(ftl::to_chars(buffer, kNeg, kRadix), F{}(kNeg));
  EXPECT_EQ(ftl::to_chars(buffer, kPos, kRadix), F{}(kPos));
}

template <typename...>
struct Types {};

template <typename F, typename Types>
struct ToCharsTests;

template <typename F, typename T, typename... Ts>
struct ToCharsTests<F, Types<T, Ts...>> {
  static void test() {
    ToCharsTest<F, T>();
    ToCharsTests<F, Types<Ts...>>::test();
  }
};

template <typename F>
struct ToCharsTests<F, Types<>> {
  static void test() {}
};

template <typename T, typename U = std::make_unsigned_t<T>>
U to_unsigned(std::ostream& stream, T v) {
  if (std::is_same_v<T, U>) return v;

  if (v < 0) {
    stream << '-';
    return std::numeric_limits<U>::max() - static_cast<U>(v) + 1;
  } else {
    return static_cast<U>(v);
  }
}

struct Bin {
  static constexpr auto kRadix = ftl::Radix::kBin;

  template <typename T>
  std::string operator()(T v) const {
    std::ostringstream stream;
    auto u = to_unsigned(stream, v);
    stream << "0b";

    if (u == 0) {
      stream << 0;
    } else {
      std::ostringstream digits;
      do {
        digits << (u & 1);
      } while (u >>= 1);

      const auto str = digits.str();
      std::copy(str.rbegin(), str.rend(), std::ostream_iterator<char>(stream));
    }

    return stream.str();
  }
};

struct Dec {
  static constexpr auto kRadix = ftl::Radix::kDec;

  template <typename T>
  std::string operator()(T v) const {
    return std::to_string(v);
  }
};

struct Hex {
  static constexpr auto kRadix = ftl::Radix::kHex;

  template <typename T>
  std::string operator()(T v) const {
    std::ostringstream stream;
    const auto u = to_unsigned(stream, v);
    stream << "0x" << std::hex << std::nouppercase;
    stream << (sizeof(T) == 1 ? static_cast<unsigned>(u) : u);
    return stream.str();
  }
};

using IntegerTypes =
    Types<char, unsigned char, signed char, std::uint8_t, std::uint16_t, std::uint32_t,
          std::uint64_t, std::int8_t, std::int16_t, std::int32_t, std::int64_t>;

}  // namespace

TEST(String, ToCharsBin) {
  ToCharsTests<Bin, IntegerTypes>::test();

  {
    const std::uint8_t x = 0b1111'1111;
    ftl::to_chars_buffer_t<decltype(x)> buffer;
    EXPECT_EQ(ftl::to_chars(buffer, x, ftl::Radix::kBin), "0b11111111");
  }
  {
    const std::int16_t x = -0b1000'0000'0000'0000;
    ftl::to_chars_buffer_t<decltype(x)> buffer;
    EXPECT_EQ(ftl::to_chars(buffer, x, ftl::Radix::kBin), "-0b1000000000000000");
  }
}

TEST(String, ToCharsDec) {
  ToCharsTests<Dec, IntegerTypes>::test();

  {
    const std::uint32_t x = UINT32_MAX;
    ftl::to_chars_buffer_t<decltype(x)> buffer;
    EXPECT_EQ(ftl::to_chars(buffer, x), "4294967295");
  }
  {
    const std::int32_t x = INT32_MIN;
    ftl::to_chars_buffer_t<decltype(x)> buffer;
    EXPECT_EQ(ftl::to_chars(buffer, x), "-2147483648");
  }
}

TEST(String, ToCharsHex) {
  ToCharsTests<Hex, IntegerTypes>::test();

  {
    const std::uint16_t x = 0xfade;
    ftl::to_chars_buffer_t<decltype(x)> buffer;
    EXPECT_EQ(ftl::to_chars(buffer, x, ftl::Radix::kHex), "0xfade");
  }
  {
    ftl::to_chars_buffer_t<> buffer;
    EXPECT_EQ(ftl::to_chars(buffer, INT64_MIN, ftl::Radix::kHex), "-0x8000000000000000");
  }
}

}  // namespace android::test
