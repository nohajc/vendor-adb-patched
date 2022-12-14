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

#include <future>
#include <type_traits>
#include <utility>

namespace android::ftl {

// Creates a future that defers a function call until its result is queried.
//
//   auto future = ftl::defer([](int x) { return x + 1; }, 99);
//   assert(future.get() == 100);
//
template <typename F, typename... Args>
inline auto defer(F&& f, Args&&... args) {
  return std::async(std::launch::deferred, std::forward<F>(f), std::forward<Args>(args)...);
}

// Creates a future that wraps a value.
//
//   auto future = ftl::yield(42);
//   assert(future.get() == 42);
//
//   auto ptr = std::make_unique<char>('!');
//   auto future = ftl::yield(std::move(ptr));
//   assert(*future.get() == '!');
//
template <typename T>
inline std::future<T> yield(T&& v) {
  return defer([](T&& v) { return std::forward<T>(v); }, std::forward<T>(v));
}

namespace details {

template <typename T>
struct future_result {
  using type = T;
};

template <typename T>
struct future_result<std::future<T>> {
  using type = T;
};

template <typename T>
using future_result_t = typename future_result<T>::type;

// Attaches a continuation to a future. The continuation is a function that maps T to either R or
// std::future<R>. In the former case, the chain wraps the result in a future as if by ftl::yield.
//
//   auto future = ftl::yield(123);
//   std::future<char> futures[] = {ftl::yield('a'), ftl::yield('b')};
//
//   std::future<char> chain =
//       ftl::chain(std::move(future))
//           .then([](int x) { return static_cast<std::size_t>(x % 2); })
//           .then([&futures](std::size_t i) { return std::move(futures[i]); });
//
//   assert(chain.get() == 'b');
//
template <typename T>
struct Chain {
  // Implicit conversion.
  Chain(std::future<T>&& f) : future(std::move(f)) {}
  operator std::future<T>&&() && { return std::move(future); }

  T get() && { return future.get(); }

  template <typename F, typename R = std::invoke_result_t<F, T>>
  auto then(F&& op) && -> Chain<future_result_t<R>> {
    return defer(
        [](auto&& f, F&& op) {
          R r = op(f.get());
          if constexpr (std::is_same_v<R, future_result_t<R>>) {
            return r;
          } else {
            return r.get();
          }
        },
        std::move(future), std::forward<F>(op));
  }

  std::future<T> future;
};

}  // namespace details

template <typename T>
inline auto chain(std::future<T>&& f) -> details::Chain<T> {
  return std::move(f);
}

}  // namespace android::ftl
