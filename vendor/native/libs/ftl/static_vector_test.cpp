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

#include <ftl/static_vector.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <iterator>
#include <string>
#include <utility>

using namespace std::string_literals;

namespace android::test {

using ftl::StaticVector;

// Keep in sync with example usage in header file.
TEST(StaticVector, Example) {
  ftl::StaticVector<char, 3> vector;
  EXPECT_TRUE(vector.empty());

  vector = {'a', 'b'};
  EXPECT_EQ(vector.size(), 2u);

  vector.push_back('c');
  EXPECT_TRUE(vector.full());

  EXPECT_FALSE(vector.push_back('d'));
  EXPECT_EQ(vector.size(), 3u);

  vector.unstable_erase(vector.begin());
  EXPECT_EQ(vector, (ftl::StaticVector{'c', 'b'}));

  vector.pop_back();
  EXPECT_EQ(vector.back(), 'c');

  const char array[] = "hi";
  vector = ftl::StaticVector(array);
  EXPECT_EQ(vector, (ftl::StaticVector{'h', 'i', '\0'}));

  ftl::StaticVector strings = ftl::init::list<std::string>("abc")("123456", 3u)(3u, '?');
  ASSERT_EQ(strings.size(), 3u);

  EXPECT_EQ(strings[0], "abc");
  EXPECT_EQ(strings[1], "123");
  EXPECT_EQ(strings[2], "???");
}

TEST(StaticVector, Construct) {
  {
    // Default constructor.
    StaticVector<std::string, 2> vector;
    EXPECT_TRUE(vector.empty());
  }
  {
    // Array constructor.
    const float floats[] = {.1f, .2f, .3f};
    StaticVector vector(floats);
    EXPECT_EQ(vector, (StaticVector{.1f, .2f, .3f}));
  }
  {
    // Iterator constructor.
    const char chars[] = "abcdef";
    std::string string(chars);
    StaticVector<char, sizeof(chars)> vector(string.begin(), string.end());

    EXPECT_STREQ(vector.begin(), chars);
  }
  {
    // Variadic constructor with same types.
    StaticVector vector = {1, 2, 3};

    static_assert(std::is_same_v<decltype(vector), StaticVector<int, 3>>);
    EXPECT_EQ(vector, (StaticVector{1, 2, 3}));
  }
  {
    // Variadic constructor with different types.
    const auto copy = "quince"s;
    auto move = "tart"s;
    StaticVector vector = {copy, std::move(move)};

    static_assert(std::is_same_v<decltype(vector), StaticVector<std::string, 2>>);
    EXPECT_EQ(vector, (StaticVector{"quince"s, "tart"s}));
  }
  {
    // In-place constructor with same types.
    StaticVector vector =
        ftl::init::list<std::string>("redolent", 3u)("velveteen", 6u)("cakewalk", 4u);

    static_assert(std::is_same_v<decltype(vector), StaticVector<std::string, 3>>);
    EXPECT_EQ(vector, (StaticVector{"red"s, "velvet"s, "cake"s}));
  }
  {
    // In-place constructor with different types.
    const auto copy = "red"s;
    auto move = "velvet"s;
    std::initializer_list<char> list = {'c', 'a', 'k', 'e'};
    StaticVector vector = ftl::init::list<std::string>(copy.c_str())(std::move(move))(list);

    static_assert(std::is_same_v<decltype(vector), StaticVector<std::string, 3>>);
    EXPECT_TRUE(move.empty());
    EXPECT_EQ(vector, (StaticVector{"red"s, "velvet"s, "cake"s}));
  }
  {
    struct String {
      explicit String(const char* str) : str(str) {}
      explicit String(const char** ptr) : str(*ptr) {}
      const char* str;
    };

    const char* strings[] = {"a", "b", "c", "d"};

    {
      // Two iterator-like elements.
      StaticVector<String, 3> vector(strings, strings + 3);
      ASSERT_EQ(vector.size(), 2u);

      EXPECT_STREQ(vector[0].str, "a");
      EXPECT_STREQ(vector[1].str, "d");
    }
    {
      // Disambiguating iterator constructor.
      StaticVector<String, 3> vector(ftl::kIteratorRange, strings, strings + 3);
      ASSERT_EQ(vector.size(), 3u);

      EXPECT_STREQ(vector[0].str, "a");
      EXPECT_STREQ(vector[1].str, "b");
      EXPECT_STREQ(vector[2].str, "c");
    }
  }
}

TEST(StaticVector, String) {
  StaticVector<char, 10> chars;
  char c = 'a';
  std::generate_n(std::back_inserter(chars), chars.max_size(), [&c] { return c++; });
  chars.back() = '\0';

  EXPECT_STREQ(chars.begin(), "abcdefghi");

  // Constructor takes iterator range.
  const char numbers[] = "123456";
  StaticVector<char, 10> string(std::begin(numbers), std::end(numbers));

  EXPECT_STREQ(string.begin(), "123456");
  EXPECT_EQ(string.size(), 7u);

  // Similar to emplace, but replaces rather than inserts.
  string.replace(string.begin() + 5, '\0');
  EXPECT_STREQ(string.begin(), "12345");

  swap(chars, string);

  EXPECT_STREQ(chars.begin(), "12345");
  EXPECT_STREQ(string.begin(), "abcdefghi");
}

TEST(StaticVector, CopyableElement) {
  struct Pair {
    const int a, b;
    bool operator==(Pair p) const { return p.a == a && p.b == b; }
  };

  StaticVector<Pair, 5> pairs;

  EXPECT_TRUE(pairs.empty());
  EXPECT_EQ(pairs.max_size(), 5u);

  for (size_t i = 0; i < pairs.max_size(); ++i) {
    EXPECT_EQ(pairs.size(), i);

    const int a = static_cast<int>(i) * 2;
    const auto it = pairs.emplace_back(a, a + 1);
    ASSERT_NE(it, pairs.end());
    EXPECT_EQ(*it, (Pair{a, a + 1}));
  }

  EXPECT_TRUE(pairs.full());
  EXPECT_EQ(pairs.size(), 5u);

  // Insertion fails if the vector is full.
  const auto it = pairs.emplace_back(10, 11);
  EXPECT_EQ(it, pairs.end());

  EXPECT_EQ(pairs, (StaticVector{Pair{0, 1}, Pair{2, 3}, Pair{4, 5}, Pair{6, 7}, Pair{8, 9}}));

  // Constructor takes at most N elements.
  StaticVector<int, 6> sums = {0, 0, 0, 0, 0, -1};
  EXPECT_TRUE(sums.full());

  // Random-access iterators comply with standard.
  std::transform(pairs.begin(), pairs.end(), sums.begin(), [](Pair p) { return p.a + p.b; });
  EXPECT_EQ(sums, (StaticVector{1, 5, 9, 13, 17, -1}));

  sums.pop_back();
  std::reverse(sums.begin(), sums.end());

  EXPECT_EQ(sums, (StaticVector{17, 13, 9, 5, 1}));
}

TEST(StaticVector, MovableElement) {
  // Construct std::string elements in place from per-element arguments.
  StaticVector strings = ftl::init::list<std::string>()()()("cake")("velvet")("red")();
  strings.pop_back();

  EXPECT_EQ(strings.max_size(), 7u);
  EXPECT_EQ(strings.size(), 6u);

  // Erase "cake" and append a substring copy.
  {
    auto it =
        std::find_if(strings.begin(), strings.end(), [](const auto& s) { return !s.empty(); });
    ASSERT_FALSE(it == strings.end());
    EXPECT_EQ(*it, "cake");

    strings.unstable_erase(it);

    // Construct std::string from first 4 characters of string literal.
    it = strings.emplace_back("cakewalk", 4u);
    ASSERT_NE(it, strings.end());
    EXPECT_EQ(*it, "cake"s);
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

  EXPECT_EQ(strings, (StaticVector{"pie"s, "quince"s, "tart"s, "red"s, "velvet"s, "cake"s}));
}

TEST(StaticVector, Replace) {
  // Replacing does not require a copy/move assignment operator.
  struct Word {
    explicit Word(std::string str) : str(std::move(str)) {}
    const std::string str;
  };

  StaticVector words = ftl::init::list<Word>("red")("velour")("cake");

  // The replaced element can be referenced by the replacement.
  const auto it = words.begin() + 1;
  const Word& word = words.replace(it, it->str.substr(0, 3) + "vet");
  EXPECT_EQ(word.str, "velvet");
}

TEST(StaticVector, ReverseTruncate) {
  StaticVector<std::string, 10> strings("pie", "quince", "tart", "red", "velvet", "cake");
  EXPECT_FALSE(strings.full());

  for (auto it = strings.begin(); it != strings.end(); ++it) {
    strings.replace(it, strings.back());
    strings.pop_back();
  }

  EXPECT_EQ(strings, (StaticVector{"cake"s, "velvet"s, "red"s}));
}

TEST(StaticVector, Sort) {
  StaticVector<std::string, 7> strings("pie", "quince", "tart", "red", "velvet", "cake");
  EXPECT_FALSE(strings.full());

  auto sorted = std::move(strings);
  EXPECT_TRUE(strings.empty());

  std::sort(sorted.begin(), sorted.end());
  EXPECT_EQ(sorted, (StaticVector{"cake"s, "pie"s, "quince"s, "red"s, "tart"s, "velvet"s}));

  // Constructor takes array reference.
  {
    const char* array[] = {"cake", "lie"};
    strings = StaticVector(array);
  }

  EXPECT_GT(sorted, strings);
  swap(sorted, strings);
  EXPECT_LT(sorted, strings);

  // Append remaining elements, such that "pie" is the only difference.
  for (const char* str : {"quince", "red", "tart", "velvet"}) {
    sorted.emplace_back(str);
  }

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

TEST(StaticVector, Destroy) {
  int live = 0;
  int dead = 0;

  { StaticVector<DestroyCounts, 5> counts; }
  EXPECT_EQ(0, live);
  EXPECT_EQ(0, dead);

  {
    StaticVector<DestroyCounts, 5> counts;
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
  }
  EXPECT_EQ(3, live);
  EXPECT_EQ(0, dead);

  live = 0;
  {
    StaticVector<DestroyCounts, 5> counts;
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);

    auto copy = counts;
  }
  EXPECT_EQ(6, live);
  EXPECT_EQ(0, dead);

  live = 0;
  {
    StaticVector<DestroyCounts, 5> counts;
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);
    counts.emplace_back(live, dead);

    auto move = std::move(counts);
  }
  EXPECT_EQ(3, live);
  EXPECT_EQ(3, dead);

  live = dead = 0;
  {
    StaticVector<DestroyCounts, 5> counts1;
    counts1.emplace_back(live, dead);
    counts1.emplace_back(live, dead);
    counts1.emplace_back(live, dead);

    StaticVector<DestroyCounts, 5> counts2;
    counts2.emplace_back(live, dead);

    swap(counts1, counts2);

    EXPECT_EQ(0, live);
    EXPECT_EQ(2, dead);

    dead = 0;
  }
  EXPECT_EQ(4, live);
  EXPECT_EQ(0, dead);
}

}  // namespace android::test
