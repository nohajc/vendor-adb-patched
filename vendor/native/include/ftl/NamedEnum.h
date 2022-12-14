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

#pragma once

namespace android {

namespace details {
template <typename E, E V>
constexpr std::optional<std::string_view> enum_value_name() {
    // Should look something like (but all on one line):
    //   std::optional<std::string_view>
    //   android::details::enum_value_name()
    //   [E = android::test::TestEnums, V = android::test::TestEnums::ONE]
    std::string_view view = __PRETTY_FUNCTION__;
    size_t templateStart = view.rfind("[");
    size_t templateEnd = view.rfind("]");
    if (templateStart == std::string::npos || templateEnd == std::string::npos) {
        return std::nullopt;
    }

    // Extract the template parameters without the enclosing braces.
    // Example (cont'd): E = android::test::TestEnums, V = android::test::TestEnums::ONE
    view = view.substr(templateStart + 1, templateEnd - templateStart - 1);
    size_t valStart = view.rfind("V = ");
    if (valStart == std::string::npos) {
        return std::nullopt;
    }

    // Example (cont'd): V = android::test::TestEnums::ONE
    view = view.substr(valStart);
    // Check invalid enum values with cast, like V = (android::test::TestEnums)8.
    if (view.find('(') != std::string::npos) {
        return std::nullopt;
    }
    size_t nameStart = view.rfind("::");
    if (nameStart == std::string::npos) {
        return std::nullopt;
    }

    // Chop off the initial "::"
    nameStart += 2;
    return view.substr(nameStart);
}

template <typename E, typename T, T... I>
constexpr auto generate_enum_values(std::integer_sequence<T, I...> seq) {
    constexpr size_t count = seq.size();

    std::array<E, count> values{};
    for (size_t i = 0, v = 0; v < count; ++i) {
        values[v++] = static_cast<E>(T{0} + i);
    }

    return values;
}

template <typename E, std::size_t N>
inline constexpr auto enum_values =
        generate_enum_values<E>(std::make_integer_sequence<std::underlying_type_t<E>, N>{});

template <typename E, std::size_t N, std::size_t... I>
constexpr auto generate_enum_names(std::index_sequence<I...>) noexcept {
    return std::array<std::optional<std::string_view>, sizeof...(I)>{
            {enum_value_name<E, enum_values<E, N>[I]>()...}};
}

template <typename E, std::size_t N>
inline constexpr auto enum_names = generate_enum_names<E, N>(std::make_index_sequence<N>{});

} // namespace details

class NamedEnum {
public:
    // By default allowed enum value range is 0 ~ 7.
    template <typename E>
    static constexpr size_t max = 8;

    template <auto V>
    static constexpr auto enum_name() {
        using E = decltype(V);
        return details::enum_value_name<E, V>();
    }

    template <typename E>
    static constexpr std::optional<std::string_view> enum_name(E val) {
        auto idx = static_cast<size_t>(val);
        return idx < max<E> ? details::enum_names<E, max<E>>[idx] : std::nullopt;
    }

    // Helper function for parsing enum value to string.
    // Example : enum class TestEnums { ZERO = 0x0 };
    // NamedEnum::string(TestEnums::ZERO) returns string of "ZERO".
    // Note the default maximum enum is 8, if the enum ID to be parsed if greater than 8 like 16,
    // it should be declared to specialized the maximum enum by below:
    // template <> constexpr size_t NamedEnum::max<TestEnums> = 16;
    // If the enum class definition is sparse and contains enum values starting from a large value,
    // Do not specialize it to a large number to avoid performance issues.
    // The recommended maximum enum number to specialize is 64.
    template <typename E>
    static const std::string string(E val, const char* fallbackFormat = "%02d") {
        std::string result;
        std::optional<std::string_view> enumString = enum_name(val);
        result += enumString ? enumString.value() : base::StringPrintf(fallbackFormat, val);
        return result;
    }
};

} // namespace android
