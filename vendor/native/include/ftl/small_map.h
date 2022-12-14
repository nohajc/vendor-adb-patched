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

#pragma once

#include <ftl/initializer_list.h>
#include <ftl/small_vector.h>

#include <functional>
#include <optional>
#include <type_traits>
#include <utility>

namespace android::ftl {

// Associative container with unique, unordered keys. Unlike std::unordered_map, key-value pairs are
// stored in contiguous storage for cache efficiency. The map is allocated statically until its size
// exceeds N, at which point mappings are relocated to dynamic memory.
//
// SmallMap<K, V, 0> unconditionally allocates on the heap.
//
// Example usage:
//
//   ftl::SmallMap<int, std::string, 3> map;
//   assert(map.empty());
//   assert(!map.dynamic());
//
//   map = ftl::init::map<int, std::string>(123, "abc")(-1)(42, 3u, '?');
//   assert(map.size() == 3u);
//   assert(!map.dynamic());
//
//   assert(map.contains(123));
//   assert(map.find(42, [](const std::string& s) { return s.size(); }) == 3u);
//
//   const auto opt = map.find(-1);
//   assert(opt);
//
//   std::string& ref = *opt;
//   assert(ref.empty());
//   ref = "xyz";
//
//   assert(map == SmallMap(ftl::init::map(-1, "xyz")(42, "???")(123, "abc")));
//
template <typename K, typename V, std::size_t N>
class SmallMap final {
  using Map = SmallVector<std::pair<const K, V>, N>;

 public:
  using key_type = K;
  using mapped_type = V;

  using value_type = typename Map::value_type;
  using size_type = typename Map::size_type;
  using difference_type = typename Map::difference_type;

  using reference = typename Map::reference;
  using iterator = typename Map::iterator;

  using const_reference = typename Map::const_reference;
  using const_iterator = typename Map::const_iterator;

  // Creates an empty map.
  SmallMap() = default;

  // Constructs at most N key-value pairs in place by forwarding per-pair constructor arguments.
  // The template arguments K, V, and N are inferred using the deduction guide defined below.
  // The syntax for listing pairs is as follows:
  //
  //   ftl::SmallMap map = ftl::init::map<int, std::string>(123, "abc")(-1)(42, 3u, '?');
  //
  //   static_assert(std::is_same_v<decltype(map), ftl::SmallMap<int, std::string, 3>>);
  //   assert(map.size() == 3u);
  //   assert(map.contains(-1) && map.find(-1)->get().empty());
  //   assert(map.contains(42) && map.find(42)->get() == "???");
  //   assert(map.contains(123) && map.find(123)->get() == "abc");
  //
  // The types of the key and value are deduced if the first pair contains exactly two arguments:
  //
  //   ftl::SmallMap map = ftl::init::map(0, 'a')(1, 'b')(2, 'c');
  //   static_assert(std::is_same_v<decltype(map), ftl::SmallMap<int, char, 3>>);
  //
  template <typename U, std::size_t... Sizes, typename... Types>
  SmallMap(InitializerList<U, std::index_sequence<Sizes...>, Types...>&& list)
      : map_(std::move(list)) {
    // TODO: Enforce unique keys.
  }

  size_type max_size() const { return map_.max_size(); }
  size_type size() const { return map_.size(); }
  bool empty() const { return map_.empty(); }

  // Returns whether the map is backed by static or dynamic storage.
  bool dynamic() const { return map_.dynamic(); }

  iterator begin() { return map_.begin(); }
  const_iterator begin() const { return cbegin(); }
  const_iterator cbegin() const { return map_.cbegin(); }

  iterator end() { return map_.end(); }
  const_iterator end() const { return cend(); }
  const_iterator cend() const { return map_.cend(); }

  // Returns whether a mapping exists for the given key.
  bool contains(const key_type& key) const {
    return find(key, [](const mapped_type&) {});
  }

  // Returns a reference to the value for the given key, or std::nullopt if the key was not found.
  //
  //   ftl::SmallMap map = ftl::init::map('a', 'A')('b', 'B')('c', 'C');
  //
  //   const auto opt = map.find('c');
  //   assert(opt == 'C');
  //
  //   char d = 'd';
  //   const auto ref = map.find('d').value_or(std::ref(d));
  //   ref.get() = 'D';
  //   assert(d == 'D');
  //
  auto find(const key_type& key) const -> std::optional<std::reference_wrapper<const mapped_type>> {
    return find(key, [](const mapped_type& v) { return std::cref(v); });
  }

  auto find(const key_type& key) -> std::optional<std::reference_wrapper<mapped_type>> {
    return find(key, [](mapped_type& v) { return std::ref(v); });
  }

  // Returns the result R of a unary operation F on (a constant or mutable reference to) the value
  // for the given key, or std::nullopt if the key was not found. If F has a return type of void,
  // then the Boolean result indicates whether the key was found.
  //
  //   ftl::SmallMap map = ftl::init::map('a', 'x')('b', 'y')('c', 'z');
  //
  //   assert(map.find('c', [](char c) { return std::toupper(c); }) == 'Z');
  //   assert(map.find('c', [](char& c) { c = std::toupper(c); }));
  //
  template <typename F, typename R = std::invoke_result_t<F, const mapped_type&>>
  auto find(const key_type& key, F f) const
      -> std::conditional_t<std::is_void_v<R>, bool, std::optional<R>> {
    for (auto& [k, v] : *this) {
      if (k == key) {
        if constexpr (std::is_void_v<R>) {
          f(v);
          return true;
        } else {
          return f(v);
        }
      }
    }

    return {};
  }

  template <typename F>
  auto find(const key_type& key, F f) {
    return std::as_const(*this).find(
        key, [&f](const mapped_type& v) { return f(const_cast<mapped_type&>(v)); });
  }

 private:
  Map map_;
};

// Deduction guide for in-place constructor.
template <typename K, typename V, std::size_t... Sizes, typename... Types>
SmallMap(InitializerList<KeyValue<K, V>, std::index_sequence<Sizes...>, Types...>&&)
    -> SmallMap<K, V, sizeof...(Sizes)>;

// Returns whether the key-value pairs of two maps are equal.
template <typename K, typename V, std::size_t N, typename Q, typename W, std::size_t M>
bool operator==(const SmallMap<K, V, N>& lhs, const SmallMap<Q, W, M>& rhs) {
  if (lhs.size() != rhs.size()) return false;

  for (const auto& [k, v] : lhs) {
    const auto& lv = v;
    if (!rhs.find(k, [&lv](const auto& rv) { return lv == rv; }).value_or(false)) {
      return false;
    }
  }

  return true;
}

// TODO: Remove in C++20.
template <typename K, typename V, std::size_t N, typename Q, typename W, std::size_t M>
inline bool operator!=(const SmallMap<K, V, N>& lhs, const SmallMap<Q, W, M>& rhs) {
  return !(lhs == rhs);
}

}  // namespace android::ftl
