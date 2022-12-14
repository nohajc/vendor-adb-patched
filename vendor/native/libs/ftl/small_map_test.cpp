/*
 * Copyright 2020 The Android Open Source Project
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

#include <ftl/small_map.h>
#include <gtest/gtest.h>

#include <cctype>

namespace android::test {

using ftl::SmallMap;

// Keep in sync with example usage in header file.
TEST(SmallMap, Example) {
  ftl::SmallMap<int, std::string, 3> map;
  EXPECT_TRUE(map.empty());
  EXPECT_FALSE(map.dynamic());

  map = ftl::init::map<int, std::string>(123, "abc")(-1)(42, 3u, '?');
  EXPECT_EQ(map.size(), 3u);
  EXPECT_FALSE(map.dynamic());

  EXPECT_TRUE(map.contains(123));

  EXPECT_EQ(map.find(42, [](const std::string& s) { return s.size(); }), 3u);

  const auto opt = map.find(-1);
  ASSERT_TRUE(opt);

  std::string& ref = *opt;
  EXPECT_TRUE(ref.empty());
  ref = "xyz";

  EXPECT_EQ(map, SmallMap(ftl::init::map(-1, "xyz")(42, "???")(123, "abc")));
}

TEST(SmallMap, Construct) {
  {
    // Default constructor.
    SmallMap<int, std::string, 2> map;

    EXPECT_TRUE(map.empty());
    EXPECT_FALSE(map.dynamic());
  }
  {
    // In-place constructor with same types.
    SmallMap<int, std::string, 5> map =
        ftl::init::map<int, std::string>(123, "abc")(456, "def")(789, "ghi");

    EXPECT_EQ(map.size(), 3u);
    EXPECT_EQ(map.max_size(), 5u);
    EXPECT_FALSE(map.dynamic());

    EXPECT_EQ(map, SmallMap(ftl::init::map(123, "abc")(456, "def")(789, "ghi")));
  }
  {
    // In-place constructor with different types.
    SmallMap<int, std::string, 5> map =
        ftl::init::map<int, std::string>(123, "abc")(-1)(42, 3u, '?');

    EXPECT_EQ(map.size(), 3u);
    EXPECT_EQ(map.max_size(), 5u);
    EXPECT_FALSE(map.dynamic());

    EXPECT_EQ(map, SmallMap(ftl::init::map(42, "???")(123, "abc")(-1, "\0\0\0")));
  }
  {
    // In-place constructor with implicit size.
    SmallMap map = ftl::init::map<int, std::string>(123, "abc")(-1)(42, 3u, '?');

    static_assert(std::is_same_v<decltype(map), SmallMap<int, std::string, 3>>);
    EXPECT_EQ(map.size(), 3u);
    EXPECT_EQ(map.max_size(), 3u);
    EXPECT_FALSE(map.dynamic());

    EXPECT_EQ(map, SmallMap(ftl::init::map(-1, "\0\0\0")(42, "???")(123, "abc")));
  }
}

TEST(SmallMap, Find) {
  {
    // Constant reference.
    const ftl::SmallMap map = ftl::init::map('a', 'A')('b', 'B')('c', 'C');

    const auto opt = map.find('b');
    EXPECT_EQ(opt, 'B');

    const char d = 'D';
    const auto ref = map.find('d').value_or(std::cref(d));
    EXPECT_EQ(ref.get(), 'D');
  }
  {
    // Mutable reference.
    ftl::SmallMap map = ftl::init::map('a', 'A')('b', 'B')('c', 'C');

    const auto opt = map.find('c');
    EXPECT_EQ(opt, 'C');

    char d = 'd';
    const auto ref = map.find('d').value_or(std::ref(d));
    ref.get() = 'D';
    EXPECT_EQ(d, 'D');
  }
  {
    // Constant unary operation.
    const ftl::SmallMap map = ftl::init::map('a', 'x')('b', 'y')('c', 'z');
    EXPECT_EQ(map.find('c', [](char c) { return std::toupper(c); }), 'Z');
  }
  {
    // Mutable unary operation.
    ftl::SmallMap map = ftl::init::map('a', 'x')('b', 'y')('c', 'z');
    EXPECT_TRUE(map.find('c', [](char& c) { c = std::toupper(c); }));

    EXPECT_EQ(map, SmallMap(ftl::init::map('c', 'Z')('b', 'y')('a', 'x')));
  }
}

}  // namespace android::test
