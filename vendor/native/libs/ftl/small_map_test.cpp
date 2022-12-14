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
#include <string>

using namespace std::string_literals;

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

  EXPECT_EQ(map.get(42, [](const std::string& s) { return s.size(); }), 3u);

  const auto opt = map.get(-1);
  ASSERT_TRUE(opt);

  std::string& ref = *opt;
  EXPECT_TRUE(ref.empty());
  ref = "xyz";

  map.emplace_or_replace(0, "vanilla", 2u, 3u);
  EXPECT_TRUE(map.dynamic());

  EXPECT_EQ(map, SmallMap(ftl::init::map(-1, "xyz")(0, "nil")(42, "???")(123, "abc")));
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

TEST(SmallMap, Assign) {
  {
    // Same types; smaller capacity.
    SmallMap map1 = ftl::init::map<char, std::string>('k', "kilo")('M', "mega")('G', "giga");
    const SmallMap map2 = ftl::init::map('T', "tera"s)('P', "peta"s);

    map1 = map2;
    EXPECT_EQ(map1, map2);
  }
  {
    // Convertible types; same capacity.
    SmallMap map1 = ftl::init::map<char, std::string>('M', "mega")('G', "giga");
    const SmallMap map2 = ftl::init::map('T', "tera")('P', "peta");

    map1 = map2;
    EXPECT_EQ(map1, map2);
  }
  {
    // Convertible types; zero capacity.
    SmallMap<char, std::string, 0> map1 = ftl::init::map('M', "mega")('G', "giga");
    const SmallMap<char, std::string, 0> map2 = ftl::init::map('T', "tera")('P', "peta");

    map1 = map2;
    EXPECT_EQ(map1, map2);
  }
}

TEST(SmallMap, UniqueKeys) {
  {
    // Duplicate mappings are discarded.
    const SmallMap map = ftl::init::map<int, float>(1)(2)(3)(2)(3)(1)(3)(2)(1);

    EXPECT_EQ(map.size(), 3u);
    EXPECT_EQ(map.max_size(), 9u);

    using Map = decltype(map);
    EXPECT_EQ(map, Map(ftl::init::map(1, 0.f)(2, 0.f)(3, 0.f)));
  }
  {
    // Duplicate mappings may be reordered.
    const SmallMap map = ftl::init::map('a', 'A')(
        'b', 'B')('b')('b')('c', 'C')('a')('d')('c')('e', 'E')('d', 'D')('a')('f', 'F');

    EXPECT_EQ(map.size(), 6u);
    EXPECT_EQ(map.max_size(), 12u);

    using Map = decltype(map);
    EXPECT_EQ(map, Map(ftl::init::map('a', 'A')('b', 'B')('c', 'C')('d', 'D')('e', 'E')('f', 'F')));
  }
}

TEST(SmallMap, Find) {
  {
    // Constant reference.
    const SmallMap map = ftl::init::map('a', 'A')('b', 'B')('c', 'C');

    const auto opt = map.get('b');
    EXPECT_EQ(opt, 'B');

    const char d = 'D';
    const auto ref = map.get('d').value_or(std::cref(d));
    EXPECT_EQ(ref.get(), 'D');
  }
  {
    // Mutable reference.
    SmallMap map = ftl::init::map('a', 'A')('b', 'B')('c', 'C');

    const auto opt = map.get('c');
    EXPECT_EQ(opt, 'C');

    char d = 'd';
    const auto ref = map.get('d').value_or(std::ref(d));
    ref.get() = 'D';
    EXPECT_EQ(d, 'D');
  }
  {
    // Constant unary operation.
    const SmallMap map = ftl::init::map('a', 'x')('b', 'y')('c', 'z');
    EXPECT_EQ(map.get('c', [](char c) { return std::toupper(c); }), 'Z');
  }
  {
    // Mutable unary operation.
    SmallMap map = ftl::init::map('a', 'x')('b', 'y')('c', 'z');
    EXPECT_TRUE(map.get('c', [](char& c) { c = std::toupper(c); }));

    EXPECT_EQ(map, SmallMap(ftl::init::map('c', 'Z')('b', 'y')('a', 'x')));
  }
}

TEST(SmallMap, TryEmplace) {
  SmallMap<int, std::string, 3> map;
  using Pair = decltype(map)::value_type;

  {
    const auto [it, ok] = map.try_emplace(123, "abc");
    ASSERT_TRUE(ok);
    EXPECT_EQ(*it, Pair(123, "abc"s));
  }
  {
    const auto [it, ok] = map.try_emplace(42, 3u, '?');
    ASSERT_TRUE(ok);
    EXPECT_EQ(*it, Pair(42, "???"s));
  }
  {
    const auto [it, ok] = map.try_emplace(-1);
    ASSERT_TRUE(ok);
    EXPECT_EQ(*it, Pair(-1, std::string()));
    EXPECT_FALSE(map.dynamic());
  }
  {
    // Insertion fails if mapping exists.
    const auto [it, ok] = map.try_emplace(42, "!!!");
    EXPECT_FALSE(ok);
    EXPECT_EQ(*it, Pair(42, "???"));
    EXPECT_FALSE(map.dynamic());
  }
  {
    // Insertion at capacity promotes the map.
    const auto [it, ok] = map.try_emplace(999, "xyz");
    ASSERT_TRUE(ok);
    EXPECT_EQ(*it, Pair(999, "xyz"));
    EXPECT_TRUE(map.dynamic());
  }

  EXPECT_EQ(map, SmallMap(ftl::init::map(-1, ""s)(42, "???"s)(123, "abc"s)(999, "xyz"s)));
}

namespace {

// The mapped type does not require a copy/move assignment operator.
struct String {
  template <typename... Args>
  String(Args... args) : str(args...) {}
  const std::string str;

  bool operator==(const String& other) const { return other.str == str; }
};

}  // namespace

TEST(SmallMap, TryReplace) {
  SmallMap<int, String, 3> map = ftl::init::map(1, "a")(2, "B");
  using Pair = decltype(map)::value_type;

  {
    // Replacing fails unless mapping exists.
    const auto it = map.try_replace(3, "c");
    EXPECT_EQ(it, map.end());
  }
  {
    // Replacement arguments can refer to the replaced mapping.
    const auto ref = map.get(2, [](const auto& s) { return s.str[0]; });
    ASSERT_TRUE(ref);

    // Construct std::string from one character.
    const auto it = map.try_replace(2, 1u, static_cast<char>(std::tolower(*ref)));
    ASSERT_NE(it, map.end());
    EXPECT_EQ(*it, Pair(2, "b"));
  }

  EXPECT_FALSE(map.dynamic());
  EXPECT_TRUE(map.try_emplace(3, "abc").second);
  EXPECT_TRUE(map.try_emplace(4, "d").second);
  EXPECT_TRUE(map.dynamic());

  {
    // Replacing fails unless mapping exists.
    const auto it = map.try_replace(5, "e");
    EXPECT_EQ(it, map.end());
  }
  {
    // Replacement arguments can refer to the replaced mapping.
    const auto ref = map.get(3);
    ASSERT_TRUE(ref);

    // Construct std::string from substring.
    const auto it = map.try_replace(3, ref->get().str, 2u, 1u);
    ASSERT_NE(it, map.end());
    EXPECT_EQ(*it, Pair(3, "c"));
  }

  EXPECT_EQ(map, SmallMap(ftl::init::map(4, "d"s)(3, "c"s)(2, "b"s)(1, "a"s)));
}

TEST(SmallMap, EmplaceOrReplace) {
  SmallMap<int, String, 3> map = ftl::init::map(1, "a")(2, "B");
  using Pair = decltype(map)::value_type;

  {
    // New mapping is emplaced.
    const auto [it, emplace] = map.emplace_or_replace(3, "c");
    EXPECT_TRUE(emplace);
    EXPECT_EQ(*it, Pair(3, "c"));
  }
  {
    // Replacement arguments can refer to the replaced mapping.
    const auto ref = map.get(2, [](const auto& s) { return s.str[0]; });
    ASSERT_TRUE(ref);

    // Construct std::string from one character.
    const auto [it, emplace] = map.emplace_or_replace(2, 1u, static_cast<char>(std::tolower(*ref)));
    EXPECT_FALSE(emplace);
    EXPECT_EQ(*it, Pair(2, "b"));
  }

  EXPECT_FALSE(map.dynamic());
  EXPECT_FALSE(map.emplace_or_replace(3, "abc").second);  // Replace.
  EXPECT_TRUE(map.emplace_or_replace(4, "d").second);     // Emplace.
  EXPECT_TRUE(map.dynamic());

  {
    // New mapping is emplaced.
    const auto [it, emplace] = map.emplace_or_replace(5, "e");
    EXPECT_TRUE(emplace);
    EXPECT_EQ(*it, Pair(5, "e"));
  }
  {
    // Replacement arguments can refer to the replaced mapping.
    const auto ref = map.get(3);
    ASSERT_TRUE(ref);

    // Construct std::string from substring.
    const auto [it, emplace] = map.emplace_or_replace(3, ref->get().str, 2u, 1u);
    EXPECT_FALSE(emplace);
    EXPECT_EQ(*it, Pair(3, "c"));
  }

  EXPECT_EQ(map, SmallMap(ftl::init::map(5, "e"s)(4, "d"s)(3, "c"s)(2, "b"s)(1, "a"s)));
}

TEST(SmallMap, Erase) {
  {
    SmallMap map = ftl::init::map(1, '1')(2, '2')(3, '3')(4, '4');
    EXPECT_FALSE(map.dynamic());

    EXPECT_FALSE(map.erase(0));  // Key not found.

    EXPECT_TRUE(map.erase(2));
    EXPECT_EQ(map, SmallMap(ftl::init::map(1, '1')(3, '3')(4, '4')));

    EXPECT_TRUE(map.erase(1));
    EXPECT_EQ(map, SmallMap(ftl::init::map(3, '3')(4, '4')));

    EXPECT_TRUE(map.erase(4));
    EXPECT_EQ(map, SmallMap(ftl::init::map(3, '3')));

    EXPECT_TRUE(map.erase(3));
    EXPECT_FALSE(map.erase(3));  // Key not found.

    EXPECT_TRUE(map.empty());
    EXPECT_FALSE(map.dynamic());
  }
  {
    SmallMap map = ftl::init::map(1, '1')(2, '2')(3, '3');
    map.try_emplace(4, '4');
    EXPECT_TRUE(map.dynamic());

    EXPECT_FALSE(map.erase(0));  // Key not found.

    EXPECT_TRUE(map.erase(2));
    EXPECT_EQ(map, SmallMap(ftl::init::map(1, '1')(3, '3')(4, '4')));

    EXPECT_TRUE(map.erase(1));
    EXPECT_EQ(map, SmallMap(ftl::init::map(3, '3')(4, '4')));

    EXPECT_TRUE(map.erase(4));
    EXPECT_EQ(map, SmallMap(ftl::init::map(3, '3')));

    EXPECT_TRUE(map.erase(3));
    EXPECT_FALSE(map.erase(3));  // Key not found.

    EXPECT_TRUE(map.empty());
    EXPECT_TRUE(map.dynamic());
  }
}

TEST(SmallMap, Clear) {
  SmallMap map = ftl::init::map(1, '1')(2, '2')(3, '3');

  map.clear();

  EXPECT_TRUE(map.empty());
  EXPECT_FALSE(map.dynamic());

  map = ftl::init::map(1, '1')(2, '2')(3, '3');
  map.try_emplace(4, '4');

  map.clear();

  EXPECT_TRUE(map.empty());
  EXPECT_TRUE(map.dynamic());
}

TEST(SmallMap, KeyEqual) {
  struct KeyEqual {
    bool operator()(int lhs, int rhs) const { return lhs % 10 == rhs % 10; }
  };

  SmallMap<int, char, 1, KeyEqual> map;

  EXPECT_TRUE(map.try_emplace(3, '3').second);
  EXPECT_FALSE(map.try_emplace(13, '3').second);

  EXPECT_TRUE(map.try_emplace(22, '2').second);
  EXPECT_TRUE(map.contains(42));

  EXPECT_TRUE(map.try_emplace(111, '1').second);
  EXPECT_EQ(map.get(321), '1');

  map.erase(123);
  EXPECT_EQ(map, SmallMap(ftl::init::map<int, char, KeyEqual>(1, '1')(2, '2')));
}

}  // namespace android::test
