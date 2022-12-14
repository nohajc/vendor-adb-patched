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

namespace android::promise {
namespace impl {

template <typename T>
struct FutureResult {
    using Type = T;
};

template <typename T>
struct FutureResult<std::future<T>> {
    using Type = T;
};

} // namespace impl

template <typename T>
using FutureResult = typename impl::FutureResult<T>::Type;

template <typename... Args>
inline auto defer(Args... args) {
    return std::async(std::launch::deferred, std::forward<Args>(args)...);
}

template <typename T>
inline std::future<T> yield(T&& v) {
    return defer([](T&& v) { return std::forward<T>(v); }, std::forward<T>(v));
}

template <typename T>
struct Chain {
    Chain(std::future<T>&& f) : future(std::move(f)) {}
    operator std::future<T>&&() && { return std::move(future); }

    T get() && { return future.get(); }

    template <typename F, typename R = std::invoke_result_t<F, T>>
    auto then(F&& op) && -> Chain<FutureResult<R>> {
        return defer(
                [](auto&& f, F&& op) {
                    R r = op(f.get());
                    if constexpr (std::is_same_v<R, FutureResult<R>>) {
                        return r;
                    } else {
                        return r.get();
                    }
                },
                std::move(future), std::forward<F>(op));
    }

    std::future<T> future;
};

template <typename T>
inline Chain<T> chain(std::future<T>&& f) {
    return std::move(f);
}

} // namespace android::promise
