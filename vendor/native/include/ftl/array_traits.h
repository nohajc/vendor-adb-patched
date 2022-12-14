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

#include <algorithm>
#include <iterator>
#include <new>
#include <type_traits>

#define FTL_ARRAY_TRAIT(T, U) using U = typename ArrayTraits<T>::U

namespace android::ftl {

template <typename T>
struct ArrayTraits {
  using value_type = T;
  using size_type = std::size_t;
  using difference_type = std::ptrdiff_t;

  using pointer = value_type*;
  using reference = value_type&;
  using iterator = pointer;
  using reverse_iterator = std::reverse_iterator<iterator>;

  using const_pointer = const value_type*;
  using const_reference = const value_type&;
  using const_iterator = const_pointer;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  template <typename... Args>
  static pointer construct_at(const_iterator it, Args&&... args) {
    void* const ptr = const_cast<void*>(static_cast<const void*>(it));
    if constexpr (std::is_constructible_v<value_type, Args...>) {
      // TODO: Replace with std::construct_at in C++20.
      return new (ptr) value_type(std::forward<Args>(args)...);
    } else {
      // Fall back to list initialization.
      return new (ptr) value_type{std::forward<Args>(args)...};
    }
  }
};

// CRTP mixin to define iterator functions in terms of non-const Self::begin and Self::end.
template <typename Self, typename T>
class ArrayIterators {
  FTL_ARRAY_TRAIT(T, size_type);

  FTL_ARRAY_TRAIT(T, reference);
  FTL_ARRAY_TRAIT(T, iterator);
  FTL_ARRAY_TRAIT(T, reverse_iterator);

  FTL_ARRAY_TRAIT(T, const_reference);
  FTL_ARRAY_TRAIT(T, const_iterator);
  FTL_ARRAY_TRAIT(T, const_reverse_iterator);

  Self& self() const { return *const_cast<Self*>(static_cast<const Self*>(this)); }

 public:
  const_iterator begin() const { return cbegin(); }
  const_iterator cbegin() const { return self().begin(); }

  const_iterator end() const { return cend(); }
  const_iterator cend() const { return self().end(); }

  reverse_iterator rbegin() { return std::make_reverse_iterator(self().end()); }
  const_reverse_iterator rbegin() const { return crbegin(); }
  const_reverse_iterator crbegin() const { return self().rbegin(); }

  reverse_iterator rend() { return std::make_reverse_iterator(self().begin()); }
  const_reverse_iterator rend() const { return crend(); }
  const_reverse_iterator crend() const { return self().rend(); }

  iterator last() { return self().end() - 1; }
  const_iterator last() const { return self().last(); }

  reference front() { return *self().begin(); }
  const_reference front() const { return self().front(); }

  reference back() { return *last(); }
  const_reference back() const { return self().back(); }

  reference operator[](size_type i) { return *(self().begin() + i); }
  const_reference operator[](size_type i) const { return self()[i]; }
};

// Mixin to define comparison operators for an array-like template.
// TODO: Replace with operator<=> in C++20.
template <template <typename, std::size_t> class Array>
struct ArrayComparators {
  template <typename T, std::size_t N, std::size_t M>
  friend bool operator==(const Array<T, N>& lhs, const Array<T, M>& rhs) {
    return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
  }

  template <typename T, std::size_t N, std::size_t M>
  friend bool operator<(const Array<T, N>& lhs, const Array<T, M>& rhs) {
    return std::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
  }

  template <typename T, std::size_t N, std::size_t M>
  friend bool operator>(const Array<T, N>& lhs, const Array<T, M>& rhs) {
    return rhs < lhs;
  }

  template <typename T, std::size_t N, std::size_t M>
  friend bool operator!=(const Array<T, N>& lhs, const Array<T, M>& rhs) {
    return !(lhs == rhs);
  }

  template <typename T, std::size_t N, std::size_t M>
  friend bool operator>=(const Array<T, N>& lhs, const Array<T, M>& rhs) {
    return !(lhs < rhs);
  }

  template <typename T, std::size_t N, std::size_t M>
  friend bool operator<=(const Array<T, N>& lhs, const Array<T, M>& rhs) {
    return !(lhs > rhs);
  }
};

}  // namespace android::ftl
