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

#include <gtest/gtest.h>
#include <ftl/NamedEnum.h>

namespace android {

// Test enum class maximum enum value smaller than default maximum of 8.
enum class TestEnums { ZERO = 0x0, ONE = 0x1, TWO = 0x2, THREE = 0x3, SEVEN = 0x7 };
// Big enum contains enum values greater than default maximum of 8.
enum class TestBigEnums { ZERO = 0x0, FIFTEEN = 0xF };

// Declared to specialize the maximum enum since the enum size exceeds 8 by default.
template <>
constexpr size_t NamedEnum::max<TestBigEnums> = 16;

namespace test {
using android::TestBigEnums;
using android::TestEnums;

TEST(NamedEnum, RuntimeNamedEnum) {
    TestEnums e = TestEnums::ZERO;
    ASSERT_EQ(NamedEnum::enum_name(e), "ZERO");

    e = TestEnums::ONE;
    ASSERT_EQ(NamedEnum::enum_name(e), "ONE");

    e = TestEnums::THREE;
    ASSERT_EQ(NamedEnum::enum_name(e), "THREE");

    e = TestEnums::SEVEN;
    ASSERT_EQ(NamedEnum::enum_name(e), "SEVEN");
}

// Test big enum
TEST(NamedEnum, RuntimeBigNamedEnum) {
    TestBigEnums e = TestBigEnums::ZERO;
    ASSERT_EQ(NamedEnum::enum_name(e), "ZERO");

    e = TestBigEnums::FIFTEEN;
    ASSERT_EQ(NamedEnum::enum_name(e), "FIFTEEN");
}

TEST(NamedEnum, RuntimeNamedEnumAsString) {
    TestEnums e = TestEnums::ZERO;
    ASSERT_EQ(NamedEnum::string(e), "ZERO");

    e = TestEnums::ONE;
    ASSERT_EQ(NamedEnum::string(e), "ONE");

    e = TestEnums::THREE;
    ASSERT_EQ(NamedEnum::string(e), "THREE");

    e = TestEnums::SEVEN;
    ASSERT_EQ(NamedEnum::string(e), "SEVEN");
}

TEST(NamedEnum, RuntimeBigNamedEnumAsString) {
    TestBigEnums e = TestBigEnums::ZERO;
    ASSERT_EQ(NamedEnum::string(e), "ZERO");

    e = TestBigEnums::FIFTEEN;
    ASSERT_EQ(NamedEnum::string(e), "FIFTEEN");
}

TEST(NamedEnum, RuntimeUnknownNamedEnum) {
    TestEnums e = static_cast<TestEnums>(0x5);
    ASSERT_EQ(NamedEnum::enum_name(e), std::nullopt);
    e = static_cast<TestEnums>(0x9);
    ASSERT_EQ(NamedEnum::enum_name(e), std::nullopt);
}

TEST(NamedEnum, RuntimeUnknownNamedEnumAsString) {
    TestEnums e = static_cast<TestEnums>(0x5);
    ASSERT_EQ(NamedEnum::string(e), "05");
    e = static_cast<TestEnums>(0x9);
    ASSERT_EQ(NamedEnum::string(e, "0x%08x"), "0x00000009");
}

TEST(NamedEnum, CompileTimeFlagName) {
    static_assert(NamedEnum::enum_name<TestEnums::TWO>() == "TWO");
    static_assert(NamedEnum::enum_name<TestEnums::THREE>() == "THREE");
}

} // namespace test

} // namespace android
