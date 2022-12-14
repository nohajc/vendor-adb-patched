/*
 * Copyright (C) 2021 The Android Open Source Project
 * Android BPF library - public API
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
#include "LongArrayMultiStateCounter.h"

namespace android {
namespace battery {

class LongArrayMultiStateCounterTest : public testing::Test {};

TEST_F(LongArrayMultiStateCounterTest, stateChange) {
    LongArrayMultiStateCounter testCounter(2, std::vector<uint64_t>(4));
    testCounter.updateValue(std::vector<uint64_t>({0, 0, 0, 0}), 1000);
    testCounter.setState(0, 1000);
    testCounter.setState(1, 2000);
    testCounter.updateValue(std::vector<uint64_t>({100, 200, 300, 400}), 3000);

    // Time was split in half between the two states, so the counts will be split 50:50 too
    EXPECT_EQ(std::vector<uint64_t>({50, 100, 150, 200}), testCounter.getCount(0));
    EXPECT_EQ(std::vector<uint64_t>({50, 100, 150, 200}), testCounter.getCount(1));
}

TEST_F(LongArrayMultiStateCounterTest, accumulation) {
    LongArrayMultiStateCounter testCounter(2, std::vector<uint64_t>(4));
    testCounter.updateValue(std::vector<uint64_t>({0, 0, 0, 0}), 1000);
    testCounter.setState(0, 1000);
    testCounter.setState(1, 2000);
    testCounter.updateValue(std::vector<uint64_t>({100, 200, 300, 400}), 3000);
    testCounter.setState(0, 4000);
    testCounter.updateValue(std::vector<uint64_t>({200, 300, 400, 500}), 8000);

    // The first delta is split 50:50:
    //   0: {50, 100, 150, 200}
    //   1: {50, 100, 150, 200}
    // The second delta is split 4:1
    //   0: {80, 80, 80, 80}
    //   1: {20, 20, 20, 20}
    EXPECT_EQ(std::vector<uint64_t>({130, 180, 230, 280}), testCounter.getCount(0));
    EXPECT_EQ(std::vector<uint64_t>({70, 120, 170, 220}), testCounter.getCount(1));
}

TEST_F(LongArrayMultiStateCounterTest, toString) {
    LongArrayMultiStateCounter testCounter(2, std::vector<uint64_t>(4));
    testCounter.updateValue(std::vector<uint64_t>({0, 0, 0, 0}), 1000);
    testCounter.setState(0, 1000);
    testCounter.setState(1, 2000);
    testCounter.updateValue(std::vector<uint64_t>({100, 200, 300, 400}), 3000);

    EXPECT_STREQ("[0: {50, 100, 150, 200}, 1: {50, 100, 150, 200}] updated: 3000 currentState: 1",
                 testCounter.toString().c_str());
}

} // namespace battery
} // namespace android
