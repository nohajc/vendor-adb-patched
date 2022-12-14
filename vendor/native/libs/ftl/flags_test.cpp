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

#include <ftl/flags.h>
#include <gtest/gtest.h>

#include <type_traits>

namespace android::test {

using ftl::Flags;
using namespace ftl::flag_operators;

enum class TestFlags : uint8_t { ONE = 0x1, TWO = 0x2, THREE = 0x4 };

TEST(Flags, Test) {
    Flags<TestFlags> flags = TestFlags::ONE;
    ASSERT_TRUE(flags.test(TestFlags::ONE));
    ASSERT_FALSE(flags.test(TestFlags::TWO));
    ASSERT_FALSE(flags.test(TestFlags::THREE));
}

TEST(Flags, Any) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::TWO;
    ASSERT_TRUE(flags.any(TestFlags::ONE));
    ASSERT_TRUE(flags.any(TestFlags::TWO));
    ASSERT_FALSE(flags.any(TestFlags::THREE));
    ASSERT_TRUE(flags.any(TestFlags::ONE | TestFlags::TWO));
    ASSERT_TRUE(flags.any(TestFlags::TWO | TestFlags::THREE));
    ASSERT_TRUE(flags.any(TestFlags::ONE | TestFlags::THREE));
    ASSERT_TRUE(flags.any(TestFlags::ONE | TestFlags::TWO | TestFlags::THREE));
}

TEST(Flags, All) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::TWO;
    ASSERT_TRUE(flags.all(TestFlags::ONE));
    ASSERT_TRUE(flags.all(TestFlags::TWO));
    ASSERT_FALSE(flags.all(TestFlags::THREE));
    ASSERT_TRUE(flags.all(TestFlags::ONE | TestFlags::TWO));
    ASSERT_FALSE(flags.all(TestFlags::TWO | TestFlags::THREE));
    ASSERT_FALSE(flags.all(TestFlags::ONE | TestFlags::THREE));
    ASSERT_FALSE(flags.all(TestFlags::ONE | TestFlags::TWO | TestFlags::THREE));
}

TEST(Flags, DefaultConstructor_hasNoFlagsSet) {
    Flags<TestFlags> flags;
    ASSERT_FALSE(flags.any(TestFlags::ONE | TestFlags::TWO | TestFlags::THREE));
}

TEST(Flags, NotOperator_onEmptyFlagsSetsAllFlags) {
    Flags<TestFlags> flags;
    flags = ~flags;
    ASSERT_TRUE(flags.all(TestFlags::ONE | TestFlags::TWO | TestFlags::THREE));
}

TEST(Flags, NotOperator_onNonEmptyFlagsInvertsFlags) {
    Flags<TestFlags> flags = TestFlags::TWO;
    flags = ~flags;
    ASSERT_TRUE(flags.all(TestFlags::ONE | TestFlags::THREE));
    ASSERT_FALSE(flags.test(TestFlags::TWO));
}

TEST(Flags, OrOperator_withNewFlag) {
    Flags<TestFlags> flags = TestFlags::ONE;
    Flags<TestFlags> flags2 = flags | TestFlags::TWO;
    ASSERT_FALSE(flags2.test(TestFlags::THREE));
    ASSERT_TRUE(flags2.all(TestFlags::ONE | TestFlags::TWO));
}

TEST(Flags, OrOperator_withExistingFlag) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::THREE;
    Flags<TestFlags> flags2 = flags | TestFlags::THREE;
    ASSERT_FALSE(flags2.test(TestFlags::TWO));
    ASSERT_TRUE(flags2.all(TestFlags::ONE | TestFlags::THREE));
}

TEST(Flags, OrEqualsOperator_withNewFlag) {
    Flags<TestFlags> flags;
    flags |= TestFlags::THREE;
    ASSERT_TRUE(flags.test(TestFlags::THREE));
    ASSERT_FALSE(flags.any(TestFlags::ONE | TestFlags::TWO));
}

TEST(Flags, OrEqualsOperator_withExistingFlag) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::THREE;
    flags |= TestFlags::THREE;
    ASSERT_TRUE(flags.all(TestFlags::ONE | TestFlags::THREE));
    ASSERT_FALSE(flags.test(TestFlags::TWO));
}

TEST(Flags, AndOperator_withOneSetFlag) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::THREE;
    Flags<TestFlags> andFlags = flags & TestFlags::THREE;
    ASSERT_TRUE(andFlags.test(TestFlags::THREE));
    ASSERT_FALSE(andFlags.any(TestFlags::ONE | TestFlags::TWO));
}

TEST(Flags, AndOperator_withMultipleSetFlags) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::THREE;
    Flags<TestFlags> andFlags = flags & (TestFlags::ONE | TestFlags::THREE);
    ASSERT_TRUE(andFlags.all(TestFlags::ONE | TestFlags::THREE));
    ASSERT_FALSE(andFlags.test(TestFlags::TWO));
}

TEST(Flags, AndOperator_withNoSetFlags) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::THREE;
    Flags<TestFlags> andFlags = flags & TestFlags::TWO;
    ASSERT_FALSE(andFlags.any(TestFlags::ONE | TestFlags::TWO | TestFlags::THREE));
}

TEST(Flags, Equality) {
    Flags<TestFlags> flags1 = TestFlags::ONE | TestFlags::TWO;
    Flags<TestFlags> flags2 = TestFlags::ONE | TestFlags::TWO;
    ASSERT_EQ(flags1, flags2);
}

TEST(Flags, Inequality) {
    Flags<TestFlags> flags1 = TestFlags::ONE | TestFlags::TWO;
    Flags<TestFlags> flags2 = TestFlags::ONE | TestFlags::THREE;
    ASSERT_NE(flags1, flags2);
}

TEST(Flags, EqualsOperator) {
    Flags<TestFlags> flags;
    flags = TestFlags::ONE;
    ASSERT_TRUE(flags.test(TestFlags::ONE));
    ASSERT_FALSE(flags.any(TestFlags::TWO | TestFlags::THREE));
}

TEST(Flags, EqualsOperator_DontShareState) {
    Flags<TestFlags> flags1 = TestFlags::ONE | TestFlags::TWO;
    Flags<TestFlags> flags2 = flags1;
    ASSERT_EQ(flags1, flags2);

    flags1 &= TestFlags::TWO;
    ASSERT_NE(flags1, flags2);
}

TEST(Flags, GetValue) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::TWO;
    ASSERT_EQ(flags.get(), 0x3);
}

TEST(Flags, String_NoFlags) {
    Flags<TestFlags> flags;
    ASSERT_EQ(flags.string(), "0x0");
}

TEST(Flags, String_KnownValues) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::TWO;
    ASSERT_EQ(flags.string(), "ONE | TWO");
}

TEST(Flags, String_UnknownValues) {
    auto flags = Flags<TestFlags>(0b1011);
    ASSERT_EQ(flags.string(), "ONE | TWO | 0b1000");
}

TEST(FlagsIterator, IteratesOverAllFlags) {
    Flags<TestFlags> flags1 = TestFlags::ONE | TestFlags::TWO;
    Flags<TestFlags> flags2;
    for (TestFlags f : flags1) {
        flags2 |= f;
    }
    ASSERT_EQ(flags2, flags1);
}

TEST(FlagsIterator, IteratesInExpectedOrder) {
    const std::vector<TestFlags> flagOrder = {TestFlags::ONE, TestFlags::TWO};
    Flags<TestFlags> flags;
    for (TestFlags f : flagOrder) {
        flags |= f;
    }

    size_t idx = 0;
    auto iter = flags.begin();
    while (iter != flags.end() && idx < flagOrder.size()) {
        // Make sure the order is what we expect
        ASSERT_EQ(*iter, flagOrder[idx]);
        iter++;
        idx++;
    }
    ASSERT_EQ(iter, flags.end());
}
TEST(FlagsIterator, PostFixIncrement) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::TWO;
    auto iter = flags.begin();
    ASSERT_EQ(*(iter++), TestFlags::ONE);
    ASSERT_EQ(*iter, TestFlags::TWO);
    ASSERT_EQ(*(iter++), TestFlags::TWO);
    ASSERT_EQ(iter, flags.end());
}

TEST(FlagsIterator, PreFixIncrement) {
    Flags<TestFlags> flags = TestFlags::ONE | TestFlags::TWO;
    auto iter = flags.begin();
    ASSERT_EQ(*++iter, TestFlags::TWO);
    ASSERT_EQ(++iter, flags.end());
}

} // namespace android::test
