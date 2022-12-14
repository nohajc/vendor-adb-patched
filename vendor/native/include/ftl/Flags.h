/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android-base/stringprintf.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>

#include <ftl/NamedEnum.h>
#include "utils/BitSet.h"

#pragma once

namespace android {

namespace details {

template <typename F>
inline constexpr auto flag_count = sizeof(F) * __CHAR_BIT__;

template <typename F, typename T, T... I>
constexpr auto generate_flag_values(std::integer_sequence<T, I...> seq) {
    constexpr size_t count = seq.size();

    std::array<F, count> values{};
    for (size_t i = 0, v = 0; v < count; ++i) {
        values[v++] = static_cast<F>(T{1} << i);
    }

    return values;
}

template <typename F>
inline constexpr auto flag_values = generate_flag_values<F>(
        std::make_integer_sequence<std::underlying_type_t<F>, flag_count<F>>{});

template <typename F, std::size_t... I>
constexpr auto generate_flag_names(std::index_sequence<I...>) noexcept {
    return std::array<std::optional<std::string_view>, sizeof...(I)>{
            {enum_value_name<F, flag_values<F>[I]>()...}};
}

template <typename F>
inline constexpr auto flag_names =
        generate_flag_names<F>(std::make_index_sequence<flag_count<F>>{});

// A trait for determining whether a type is specifically an enum class or not.
template <typename T, bool = std::is_enum_v<T>>
struct is_enum_class : std::false_type {};

// By definition, an enum class is an enum that is not implicitly convertible to its underlying
// type.
template <typename T>
struct is_enum_class<T, true>
      : std::bool_constant<!std::is_convertible_v<T, std::underlying_type_t<T>>> {};

template <typename T>
inline constexpr bool is_enum_class_v = is_enum_class<T>::value;
} // namespace details

template <auto V>
constexpr auto flag_name() {
    using F = decltype(V);
    return details::enum_value_name<F, V>();
}

template <typename F>
constexpr std::optional<std::string_view> flag_name(F flag) {
    using U = std::underlying_type_t<F>;
    auto idx = static_cast<size_t>(__builtin_ctzl(static_cast<U>(flag)));
    return details::flag_names<F>[idx];
}

/* A class for handling flags defined by an enum or enum class in a type-safe way. */
template <typename F>
class Flags {
    // F must be an enum or its underlying type is undefined. Theoretically we could specialize this
    // further to avoid this restriction but in general we want to encourage the use of enums
    // anyways.
    static_assert(std::is_enum_v<F>, "Flags type must be an enum");
    using U = typename std::underlying_type_t<F>;

public:
    constexpr Flags(F f) : mFlags(static_cast<U>(f)) {}
    constexpr Flags() : mFlags(0) {}
    constexpr Flags(const Flags<F>& f) : mFlags(f.mFlags) {}

    // Provide a non-explicit construct for non-enum classes since they easily convert to their
    // underlying types (e.g. when used with bitwise operators). For enum classes, however, we
    // should force them to be explicitly constructed from their underlying types to make full use
    // of the type checker.
    template <typename T = U>
    constexpr Flags(T t, typename std::enable_if_t<!details::is_enum_class_v<F>, T>* = nullptr)
          : mFlags(t) {}
    template <typename T = U>
    explicit constexpr Flags(T t,
                             typename std::enable_if_t<details::is_enum_class_v<F>, T>* = nullptr)
          : mFlags(t) {}

    class Iterator {
        // The type can't be larger than 64-bits otherwise it won't fit in BitSet64.
        static_assert(sizeof(U) <= sizeof(uint64_t));

    public:
        Iterator(Flags<F> flags) : mRemainingFlags(flags.mFlags) { (*this)++; }
        Iterator() : mRemainingFlags(0), mCurrFlag(static_cast<F>(0)) {}

        // Pre-fix ++
        Iterator& operator++() {
            if (mRemainingFlags.isEmpty()) {
                mCurrFlag = static_cast<F>(0);
            } else {
                uint64_t bit = mRemainingFlags.clearLastMarkedBit(); // counts from left
                const U flag = 1 << (64 - bit - 1);
                mCurrFlag = static_cast<F>(flag);
            }
            return *this;
        }

        // Post-fix ++
        Iterator operator++(int) {
            Iterator iter = *this;
            ++*this;
            return iter;
        }

        bool operator==(Iterator other) const {
            return mCurrFlag == other.mCurrFlag && mRemainingFlags == other.mRemainingFlags;
        }

        bool operator!=(Iterator other) const { return !(*this == other); }

        F operator*() { return mCurrFlag; }

        // iterator traits

        // In the future we could make this a bidirectional const iterator instead of a forward
        // iterator but it doesn't seem worth the added complexity at this point. This could not,
        // however, be made a non-const iterator as assigning one flag to another is a non-sensical
        // operation.
        using iterator_category = std::input_iterator_tag;
        using value_type = F;
        // Per the C++ spec, because input iterators are not assignable the iterator's reference
        // type does not actually need to be a reference. In fact, making it a reference would imply
        // that modifying it would change the underlying Flags object, which is obviously wrong for
        // the same reason this can't be a non-const iterator.
        using reference = F;
        using difference_type = void;
        using pointer = void;

    private:
        BitSet64 mRemainingFlags;
        F mCurrFlag;
    };

    /*
     * Tests whether the given flag is set.
     */
    bool test(F flag) const {
        U f = static_cast<U>(flag);
        return (f & mFlags) == f;
    }

    /* Tests whether any of the given flags are set */
    bool any(Flags<F> f) { return (mFlags & f.mFlags) != 0; }

    /* Tests whether all of the given flags are set */
    bool all(Flags<F> f) { return (mFlags & f.mFlags) == f.mFlags; }

    Flags<F> operator|(Flags<F> rhs) const { return static_cast<F>(mFlags | rhs.mFlags); }
    Flags<F>& operator|=(Flags<F> rhs) {
        mFlags = mFlags | rhs.mFlags;
        return *this;
    }

    Flags<F> operator&(Flags<F> rhs) const { return static_cast<F>(mFlags & rhs.mFlags); }
    Flags<F>& operator&=(Flags<F> rhs) {
        mFlags = mFlags & rhs.mFlags;
        return *this;
    }

    Flags<F> operator^(Flags<F> rhs) const { return static_cast<F>(mFlags ^ rhs.mFlags); }
    Flags<F>& operator^=(Flags<F> rhs) {
        mFlags = mFlags ^ rhs.mFlags;
        return *this;
    }

    Flags<F> operator~() { return static_cast<F>(~mFlags); }

    bool operator==(Flags<F> rhs) const { return mFlags == rhs.mFlags; }
    bool operator!=(Flags<F> rhs) const { return !operator==(rhs); }

    Flags<F>& operator=(const Flags<F>& rhs) {
        mFlags = rhs.mFlags;
        return *this;
    }

    Iterator begin() const { return Iterator(*this); }

    Iterator end() const { return Iterator(); }

    /*
     * Returns the stored set of flags.
     *
     * Note that this returns the underlying type rather than the base enum class. This is because
     * the value is no longer necessarily a strict member of the enum since the returned value could
     * be multiple enum variants OR'd together.
     */
    U get() const { return mFlags; }

    std::string string() const {
        std::string result;
        bool first = true;
        U unstringified = 0;
        for (const F f : *this) {
            std::optional<std::string_view> flagString = flag_name(f);
            if (flagString) {
                appendFlag(result, flagString.value(), first);
            } else {
                unstringified |= static_cast<U>(f);
            }
        }

        if (unstringified != 0) {
            appendFlag(result, base::StringPrintf("0x%08x", unstringified), first);
        }

        if (first) {
            result += "0x0";
        }

        return result;
    }

private:
    U mFlags;

    static void appendFlag(std::string& str, const std::string_view& flag, bool& first) {
        if (first) {
            first = false;
        } else {
            str += " | ";
        }
        str += flag;
    }
};

// This namespace provides operator overloads for enum classes to make it easier to work with them
// as flags. In order to use these, add them via a `using namespace` declaration.
namespace flag_operators {

template <typename F, typename = std::enable_if_t<details::is_enum_class_v<F>>>
inline Flags<F> operator~(F f) {
    using U = typename std::underlying_type_t<F>;
    return static_cast<F>(~static_cast<U>(f));
}
template <typename F, typename = std::enable_if_t<details::is_enum_class_v<F>>>
Flags<F> operator|(F lhs, F rhs) {
    using U = typename std::underlying_type_t<F>;
    return static_cast<F>(static_cast<U>(lhs) | static_cast<U>(rhs));
}

} // namespace flag_operators
} // namespace android
