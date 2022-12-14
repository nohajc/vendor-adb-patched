/*
 * Copyright 2019 The Android Open Source Project
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
namespace android {

template <typename T, template <typename> class AbilityType>
struct Ability {
    T& base() { return static_cast<T&>(*this); }
    T const& base() const { return static_cast<T const&>(*this); }
};

template <typename T>
struct Add : Ability<T, Add> {
    inline T operator+(T const& other) const { return T(this->base().value() + other.value()); }
    inline T& operator++() {
        ++this->base().value();
        return this->base();
    };
    inline T operator++(int) {
        T tmp(this->base());
        operator++();
        return tmp;
    };
    inline T& operator+=(T const& other) {
        this->base().value() += other.value();
        return this->base();
    };
};

template <typename T>
struct Compare : Ability<T, Compare> {
    inline bool operator==(T const& other) const { return this->base().value() == other.value(); };
    inline bool operator<(T const& other) const { return this->base().value() < other.value(); }
    inline bool operator<=(T const& other) const { return (*this < other) || (*this == other); }
    inline bool operator!=(T const& other) const { return !(*this == other); }
    inline bool operator>=(T const& other) const { return !(*this < other); }
    inline bool operator>(T const& other) const { return !(*this < other || *this == other); }
};

template <typename T>
struct Hash : Ability<T, Hash> {
    [[nodiscard]] std::size_t hash() const {
        return std::hash<typename std::remove_const<
                typename std::remove_reference<decltype(this->base().value())>::type>::type>{}(
                this->base().value());
    }
};

template <typename T, typename W, template <typename> class... Ability>
struct StrongTyping : Ability<StrongTyping<T, W, Ability...>>... {
    constexpr StrongTyping() = default;
    constexpr explicit StrongTyping(T const& value) : mValue(value) {}
    StrongTyping(StrongTyping const&) = default;
    StrongTyping& operator=(StrongTyping const&) = default;
    explicit inline operator T() const { return mValue; }
    T const& value() const { return mValue; }
    T& value() { return mValue; }

    friend std::ostream& operator<<(std::ostream& os, const StrongTyping<T, W, Ability...>& value) {
        return os << value.value();
    }

private:
    T mValue{0};
};
} // namespace android

namespace std {
template <typename T, typename W, template <typename> class... Ability>
struct hash<android::StrongTyping<T, W, Ability...>> {
    std::size_t operator()(android::StrongTyping<T, W, Ability...> const& k) const {
        return k.hash();
    }
};
} // namespace std
