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

#include <ftl/small_vector.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <iterator>
#include <string>
#include <utility>

using namespace std::string_literals;

namespace android::test {

using ftl::SmallVector;

// Keep in sync with example usage in header file.
TEST(SmallVector, Example) {
  ftl::SmallVector<char, 3> vector;
  EXPECT_TRUE(vector.empty());
  EXPECT_FALSE(vector.dynamic());

  vector = {'a', 'b', 'c'};
  EXPECT_EQ(vector.size(), 3u);
  EXPECT_FALSE(vector.dynamic());

  vector.push_back('d');
  EXPECT_TRUE(vector.dynamic());

  vector.unstable_erase(vector.begin());
  EXPECT_EQ(vector, (ftl::SmallVector{'d', 'b', 'c'}));

  vector.pop_back();
  EXPECT_EQ(vector.back(), 'b');
  EXPECT_TRUE(vector.dynamic());

  const char array[] = "hi";
  vector = ftl::SmallVector(array);
  EXPECT_EQ(vector, (ftl::SmallVector{'h', 'i', '\0'}));
  EXPECT_FALSE(vector.dynamic());

  ftl::SmallVector strings = ftl::init::list<std::string>("abc")("123456", 3u)(3u, '?');
  ASSERT_EQ(strings.size(), 3u);
  EXPECT_FALSE(strings.dynamic());

  EXPECT_EQ(strings[0], "abc");
  EXPECT_EQ(strings[1], "123");
  EXPECT_EQ(strings[2], "???");
}

TEST(SmallVector, Construct) {
  {
    // Default constructor.
    SmallVector<std::string, 2> vector;

    EXPECT_TRUE(vector.empty());
    EXPECT_FALSE(vector.dynamic());
  }
  {
    // Array constructor.
    const float floats[] = {.1f, .2f, .3f};
    SmallVector vector(floats);

    EXPECT_EQ(vector, (SmallVector{.1f, .2f, .3f}));
    EXPECT_FALSE(vector.dynamic());
  }
  {
    // Iterator constructor.
    const char chars[] = "abcdef";
    std::string string(chars);
    SmallVector<char, sizeof(chars)> vector(string.begin(), string.end());

    EXPECT_STREQ(vector.begin(), chars);
    EXPECT_FALSE(vector.dynamic());
  }
  {
    // Variadic constructor with same types.
    SmallVector vector = {1, 2, 3};

    static_assert(std::is_same_v<decltype(vector), SmallVector<int, 3>>);
    EXPECT_EQ(vector, (SmallVector{1, 2, 3}));
    EXPECT_FALSE(vector.dynamic());
  }
  {
    // Variadic constructor with different types.
    const auto copy = "quince"s;
    auto move = "tart"s;
    SmallVector vector = {copy, std::move(move)};

    static_assert(std::is_same_v<decltype(vector), SmallVector<std::string, 2>>);
    EXPECT_EQ(vector, (SmallVector{"quince"s, "tart"s}));
    EXPECT_FALSE(vector.dynamic());
  }
  {
    // In-place constructor with same types.
    SmallVector vector =
        ftl::init::list<std::string>("redolent", 3u)("velveteen", 6u)("cakewalk", 4u);

    static_assert(std::is_same_v<decltype(vector), SmallVector<std::string, 3>>);
    EXPECT_EQ(vector, (SmallVector{"red"s, "velvet"s, "cake"s}));
    EXPECT_FALSE(vector.dynamic());
  }
  {
    // In-place constructor with different types.
    const auto copy = "red"s;
    auto move = "velvet"s;
    std::initializer_list<char> list = {'c', 'a', 'k', 'e'};
    SmallVector vector = ftl::init::list<std::string>(copy.c_str())(std::move(move))(list);

    static_assert(std::is_same_v<decltype(vector), SmallVector<std::string, 3>>);
    EXPECT_TRUE(move.empty());
    EXPECT_EQ(vector, (SmallVector{"red"s, "velvet"s, "cake"s}));
    EXPECT_FALSE(vector.dynamic());
  }
  {
    // Conversion from StaticVector.
    ftl::StaticVector doubles = {.1, .2, .3};
    SmallVector vector = std::move(doubles);
    EXPECT_TRUE(doubles.empty());

    static_assert(std::is_same_v<decltype(vector), SmallVector<double, 3>>);
    EXPECT_EQ(vector, (SmallVector{.1, .2, .3}));
    EXPECT_FALSE(vector.dynamic());
  }
}

TEST(SmallVector, String) {
  SmallVector<char, 10> chars;
  char c = 'a';
  std::generate_n(std::back_inserter(chars), chars.max_size(), [&c] { return c++; });
  chars.push_back('\0');

  EXPECT_TRUE(chars.dynamic());
  EXPECT_EQ(chars.size(), 11u);
  EXPECT_STREQ(chars.begin(), "abcdefghij");

  // Constructor takes iterator range.
  const char numbers[] = "123456";
  SmallVector<char, 10> string(std::begin(numbers), std::end(numbers));

  EXPECT_FALSE(string.dynamic());
  EXPECT_STREQ(string.begin(), "123456");
  EXPECT_EQ(string.size(), 7u);

  // Similar to emplace, but replaces rather than inserts.
  string.replace(string.begin() + 5, '\0');
  EXPECT_STREQ(string.begin(), "12345");

  swap(chars, string);

  EXPECT_STREQ(chars.begin(), "12345");
  EXPECT_STREQ(string.begin(), "abcdefghij");

  EXPECT_FALSE(chars.dynamic());
  EXPECT_TRUE(string.dynamic());
}

TEST(SmallVector, CopyableElement) {
  struct Pair {
    // Needed because std::vector does not use list initialization to emplace.
    Pair(int a, int b) : a(a), b(b) {}

    const int a, b;
    bool operator==(Pair p) const { return p.a == a && p.b == b; }
  };

  SmallVector<Pair, 5> pairs;

  EXPECT_TRUE(pairs.empty());
  EXPECT_EQ(pairs.max_size(), 5u);

  for (size_t i = 0; i < pairs.max_size(); ++i) {
    EXPECT_EQ(pairs.size(), i);

    const int a = static_cast<int>(i) * 2;
    EXPECT_EQ(pairs.emplace_back(a, a + 1), Pair(a, a + 1));
  }

  EXPECT_EQ(pairs.size(), 5u);
  EXPECT_FALSE(pairs.dynamic());

  // The vector is promoted when full.
  EXPECT_EQ(pairs.emplace_back(10, 11), Pair(10, 11));
  EXPECT_TRUE(pairs.dynamic());

  EXPECT_EQ(pairs, (SmallVector{Pair{0, 1}, Pair{2, 3}, Pair{4, 5}, Pair{6, 7}, Pair{8, 9},
                                Pair{10, 11}}));

  // Constructor takes at most N elements.
  SmallVector<int, 6> sums = {0, 0, 0, 0, 0, 0};
  EXPECT_FALSE(sums.dynamic());

  // Random-access iterators comply with standard.
  std::transform(pairs.begin(), pairs.end(), sums.begin(), [](Pair p) { return p.a + p.b; });
  EXPECT_EQ(sums, (SmallVector{1, 5, 9, 13, 17, 21}));

  sums.pop_back();
  std::reverse(sums.begin(), sums.end());

  EXPECT_EQ(sums, (SmallVector{17, 13, 9, 5, 1}));
}

TEST(SmallVector, MovableElement) {
  // Construct std::string elements in place from per-element arguments.
  SmallVector strings = ftl::init::list<std::string>()()()("cake")("velvet")("red")();
  strings.pop_back();

  EXPECT_EQ(strings.max_size(), 7u);
  EXPECT_EQ(strings.size(), 6u);

  // Erase "cake" and append a substring copy.
  {
    const auto it =
        std::find_if(strings.begin(), strings.end(), [](const auto& s) { return !s.empty(); });
    ASSERT_FALSE(it == strings.end());
    EXPECT_EQ(*it, "cake");

    // Construct std::string from first 4 characters of string literal.
    strings.unstable_erase(it);
    EXPECT_EQ(strings.emplace_back("cakewalk", 4u), "cake"s);
  }

  strings[1] = "quince"s;

  // Replace last empty string with "tart".
  {
    const auto rit = std::find(strings.rbegin(), strings.rend(), std::string());
    ASSERT_FALSE(rit == strings.rend());

    std::initializer_list<char> list = {'t', 'a', 'r', 't'};
    strings.replace(rit.base() - 1, list);
  }

  strings.front().assign("pie");

  EXPECT_EQ(strings, (SmallVector{"pie"s, "quince"s, "tart"s, "red"s, "velvet"s, "cake"s}));

  strings.push_back("nougat");
  strings.push_back("oreo");
  EXPECT_TRUE(strings.dynamic());

  std::rotate(strings.begin(), strings.end() - 2, strings.end());

  EXPECT_EQ(strings, (SmallVector{"nougat"s, "oreo"s, "pie"s, "quince"s, "tart"s, "red"s, "velvet"s,
                                  "cake"s}));
}

TEST(SmallVector, Replace) {
  // Replacing does not require a copy/move assignment operator.
  struct Word {
    explicit Word(std::string str) : str(std::move(str)) {}
    const std::string str;

    bool operator==(const Word& other) const { return other.str == str; }
  };

  SmallVector words = ftl::init::list<Word>("colored")("velour");

  // The replaced element can be referenced by the replacement.
  {
    const Word& word = words.replace(words.last(), words.back().str.substr(0, 3) + "vet");
    EXPECT_EQ(word, Word("velvet"));
  }

  // The vector is not promoted if replacing while full.
  EXPECT_FALSE(words.dynamic());

  words.emplace_back("cake");
  EXPECT_TRUE(words.dynamic());

  {
    const Word& word = words.replace(words.begin(), words.front().str.substr(4));
    EXPECT_EQ(word, Word("red"));
  }

  EXPECT_EQ(words, (SmallVector{Word("red"), Word("velvet"), Word("cake")}));
}

TEST(SmallVector, ReverseAppend) {
  SmallVector strings = {"red"s, "velvet"s, "cake"s};
  EXPECT_FALSE(strings.dynamic());

  auto rit = strings.rbegin();
  while (rit != strings.rend()) {
    // Iterator and reference are invalidated on insertion.
    const auto i = std::distance(strings.begin(), rit.base());
    std::string s = *rit;

    strings.push_back(std::move(s));
    rit = std::make_reverse_iterator(strings.begin() + i) + 1;
  }

  EXPECT_EQ(strings, (SmallVector{"red"s, "velvet"s, "cake"s, "cake"s, "velvet"s, "red"s}));
  EXPECT_TRUE(strings.dynamic());
}

TEST(SmallVector, Sort) {
  SmallVector strings = ftl::init::list<std::string>("pie")("quince")("tart")("red")("velvet");
  strings.push_back("cake"s);

  auto sorted = std::move(strings);
  EXPECT_TRUE(strings.empty());

  EXPECT_TRUE(sorted.dynamic());
  EXPECT_TRUE(strings.dynamic());

  std::sort(sorted.begin(), sorted.end());
  EXPECT_EQ(sorted, (SmallVector{"cake"s, "pie"s, "quince"s, "red"s, "tart"s, "velvet"s}));

  // Constructor takes array reference.
  {
    const char* array[] = {"cake", "lie"};
    strings = SmallVector(array);
    EXPECT_FALSE(strings.dynamic());
  }

  EXPECT_GT(sorted, strings);
  swap(sorted, strings);
  EXPECT_LT(sorted, strings);

  EXPECT_FALSE(sorted.dynamic());
  EXPECT_TRUE(strings.dynamic());

  // Append remaining elements, such that "pie" is the only difference.
  for (const char* str : {"quince", "red", "tart", "velvet"}) {
    sorted.emplace_back(str);
  }
  EXPECT_TRUE(sorted.dynamic());

  EXPECT_NE(sorted, strings);

  // Replace second element with "pie".
  const auto it = sorted.begin() + 1;
  EXPECT_EQ(sorted.replace(it, 'p' + it->substr(1)), "pie");

  EXPECT_EQ(sorted, strings);
}

namespace {

struct DestroyCounts {
  DestroyCounts(int& live, int& dead) : counts{live, dead} {}
  DestroyCounts(const DestroyCounts& other) : counts(other.counts) {}
  DestroyCounts(DestroyCounts&& other) : counts(other.counts) { other.alive = false; }
  ~DestroyCounts() { ++(alive ? counts.live : counts.dead); }

  struct {
    int& live;
    int& dead;
  } counts;

  bool alive = true;
};

void swap(DestroyCounts& lhs, DestroyCounts& rhs) {
  std::swap(lhs.alive, rhs.alive);
}

}  // namespace

TEST(SmallVector, Destroy) {
  int live = 0;
  int dead = 0;

  { SmallVector<DestroyCounts, 3> counts; }
  EXPECT_EQ(0, live);
  EXPECT_EQ(0, dead);

  {
    SmallVector<DestroyCounts, 3> counts;
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);

    EXPECT_FALSE(counts.dynamic());
  }
  EXPECT_EQ(3, live);
  EXPECT_EQ(0, dead);

  live = 0;
  {
    SmallVector<DestroyCounts, 3> counts;
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);

    EXPECT_TRUE(counts.dynamic());
  }
  EXPECT_EQ(4, live);
  EXPECT_EQ(3, dead);

  live = dead = 0;
  {
    SmallVector<DestroyCounts, 2> counts;
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);

    auto copy = counts;
    EXPECT_TRUE(copy.dynamic());
  }
  EXPECT_EQ(6, live);
  EXPECT_EQ(2, dead);

  live = dead = 0;
  {
    SmallVector<DestroyCounts, 2> counts;
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);

    auto move = std::move(counts);
    EXPECT_TRUE(move.dynamic());
  }
  EXPECT_EQ(3, live);
  EXPECT_EQ(2, dead);

  live = dead = 0;
  {
    SmallVector<DestroyCounts, 2> counts1;
    counts1.emplace_back(live, dead);
    counts1.emplace_back(live, dead);
    counts1.emplace_back(live, dead);

    EXPECT_TRUE(counts1.dynamic());
    EXPECT_EQ(2, dead);
    dead = 0;

    SmallVector<DestroyCounts, 2> counts2;
    counts2.emplace_back(live, dead);

    EXPECT_FALSE(counts2.dynamic());

    swap(counts1, counts2);

    EXPECT_FALSE(counts1.dynamic());
    EXPECT_TRUE(counts2.dynamic());

    EXPECT_EQ(0, live);
    EXPECT_EQ(1, dead);

    dead = 0;
  }
  EXPECT_EQ(4, live);
  EXPECT_EQ(0, dead);
}

}  // namespace android::test
