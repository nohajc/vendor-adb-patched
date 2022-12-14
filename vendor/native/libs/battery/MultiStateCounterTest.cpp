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
#include "MultiStateCounter.h"

namespace android {
namespace battery {

typedef MultiStateCounter<double> DoubleMultiStateCounter;

template <>
bool DoubleMultiStateCounter::delta(const double& previousValue, const double& newValue,
                                    double* outValue) const {
    *outValue = newValue - previousValue;
    return *outValue >= 0;
}

template <>
void DoubleMultiStateCounter::add(double* value1, const double& value2, const uint64_t numerator,
                                  const uint64_t denominator) const {
    if (numerator != denominator) {
        // The caller ensures that denominator != 0
        *value1 += value2 * numerator / denominator;
    } else {
        *value1 += value2;
    }
}

template <>
std::string DoubleMultiStateCounter::valueToString(const double& v) const {
    return std::to_string(v);
}

class MultiStateCounterTest : public testing::Test {};

TEST_F(MultiStateCounterTest, constructor) {
    DoubleMultiStateCounter testCounter(3, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(1, 0);
    double delta = testCounter.updateValue(3.14, 3000);

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(3.14, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));
    EXPECT_DOUBLE_EQ(3.14, delta);
}

TEST_F(MultiStateCounterTest, stateChange) {
    DoubleMultiStateCounter testCounter(3, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(1, 0);
    testCounter.setState(2, 1000);
    testCounter.updateValue(6.0, 3000);

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(2.0, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(4.0, testCounter.getCount(2));
}

TEST_F(MultiStateCounterTest, setEnabled) {
    DoubleMultiStateCounter testCounter(3, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(1, 0);
    testCounter.setEnabled(false, 1000);
    testCounter.setState(2, 2000);
    testCounter.updateValue(6.0, 3000);

    // In state 1: accumulated 1000 before disabled, that's 6.0 * 1000/3000 = 2.0
    // In state 2: 0, since it is still disabled
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(2.0, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));

    // Should have no effect since the counter is disabled
    testCounter.setState(0, 3500);

    // Should have no effect since the counter is disabled
    testCounter.updateValue(10.0, 4000);

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(2.0, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));

    testCounter.setState(2, 4500);

    // Enable the counter to partially accumulate deltas for the current state, 2
    testCounter.setEnabled(true, 5000);
    testCounter.setEnabled(false, 6000);
    testCounter.setEnabled(true, 7000);
    testCounter.updateValue(20.0, 8000);

    // The delta is 10.0 over 5000-3000=2000.
    // Counter has been enabled in state 2 for (6000-5000)+(8000-7000) = 2000,
    // so its share is (20.0-10.0) * 2000/(8000-4000) = 5.0
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(2.0, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(5.0, testCounter.getCount(2));

    testCounter.reset();
    testCounter.setState(0, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(1, 2000);
    testCounter.setEnabled(false, 3000);
    testCounter.updateValue(200, 5000);

    // 200 over 5000 = 40 per second
    // Counter was in state 0 from 0 to 2000, so 2 sec, so the count should be 40 * 2 = 80
    // It stayed in state 1 from 2000 to 3000, at which point the counter was disabled,
    // so the count for state 1 should be 40 * 1 = 40.
    // The remaining 2 seconds from 3000 to 5000 don't count because the counter was disabled.
    EXPECT_DOUBLE_EQ(80.0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(40.0, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));
}

TEST_F(MultiStateCounterTest, reset) {
    DoubleMultiStateCounter testCounter(3, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(1, 0);
    testCounter.updateValue(2.72, 3000);

    testCounter.reset();

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));

    // Assert that we can still continue accumulating after a reset
    testCounter.updateValue(0, 4000);
    testCounter.updateValue(3.14, 5000);

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));
    EXPECT_DOUBLE_EQ(3.14, testCounter.getCount(1));
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));
}

TEST_F(MultiStateCounterTest, timeAdjustment_setState) {
    DoubleMultiStateCounter testCounter(3, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(1, 0);
    testCounter.setState(2, 2000);

    // Time moves back
    testCounter.setState(1, 1000);
    testCounter.updateValue(6.0, 3000);

    EXPECT_DOUBLE_EQ(0, testCounter.getCount(0));

    // We were in state 1 from 0 to 2000, which was erased because the time moved back.
    // Then from 1000 to 3000, so we expect the count to be 6 * (2000/3000)
    EXPECT_DOUBLE_EQ(4.0, testCounter.getCount(1));

    // No time was effectively accumulated for state 2, because the timestamp moved back
    // while we were in state 2.
    EXPECT_DOUBLE_EQ(0, testCounter.getCount(2));
}

TEST_F(MultiStateCounterTest, timeAdjustment_updateValue) {
    DoubleMultiStateCounter testCounter(1, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(0, 0);
    testCounter.updateValue(6.0, 2000);

    // Time moves back. The delta over the negative interval from 2000 to 1000 is ignored
    testCounter.updateValue(8.0, 1000);
    double delta = testCounter.updateValue(11.0, 3000);

    // The total accumulated count is:
    //  6.0          // For the period 0-2000
    //  +(11.0-8.0)  // For the period 1000-3000
    EXPECT_DOUBLE_EQ(9.0, testCounter.getCount(0));

    //  11.0-8.0
    EXPECT_DOUBLE_EQ(3.0, delta);
}

TEST_F(MultiStateCounterTest, updateValue_nonmonotonic) {
    DoubleMultiStateCounter testCounter(2, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(0, 0);
    testCounter.updateValue(6.0, 2000);

    // Value goes down. The negative delta from 6.0 to 4.0 is ignored
    testCounter.updateValue(4.0, 3000);

    // Value goes up again. The positive delta from 4.0 to 7.0 is accumulated.
    double delta = testCounter.updateValue(7.0, 4000);

    // The total accumulated count is:
    //  6.0          // For the period 0-2000
    //  +(7.0-4.0)   // For the period 3000-4000
    EXPECT_DOUBLE_EQ(9.0, testCounter.getCount(0));

    //  7.0-4.0
    EXPECT_DOUBLE_EQ(3.0, delta);
}

TEST_F(MultiStateCounterTest, incrementValue) {
    DoubleMultiStateCounter testCounter(2, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(0, 0);
    testCounter.updateValue(6.0, 2000);

    testCounter.setState(1, 3000);

    testCounter.incrementValue(8.0, 6000);

    // The total accumulated count is:
    //  6.0             // For the period 0-2000
    //  +(8.0 * 0.25)   // For the period 3000-4000
    EXPECT_DOUBLE_EQ(8.0, testCounter.getCount(0));

    // 0                // For the period 0-3000
    // +(8.0 * 0.75)    // For the period 3000-4000
    EXPECT_DOUBLE_EQ(6.0, testCounter.getCount(1));
}

TEST_F(MultiStateCounterTest, addValue) {
    DoubleMultiStateCounter testCounter(1, 0);
    testCounter.updateValue(0, 0);
    testCounter.setState(0, 0);
    testCounter.updateValue(6.0, 2000);

    testCounter.addValue(8.0);

    EXPECT_DOUBLE_EQ(14.0, testCounter.getCount(0));

    testCounter.setEnabled(false, 3000);
    testCounter.addValue(888.0);

    EXPECT_DOUBLE_EQ(14.0, testCounter.getCount(0));
}

TEST_F(MultiStateCounterTest, toString) {
    DoubleMultiStateCounter testCounter(2, 0);

    EXPECT_STREQ("[0: 0.000000, 1: 0.000000] currentState: none", testCounter.toString().c_str());

    testCounter.updateValue(0, 0);
    testCounter.setState(1, 0);
    testCounter.setState(1, 2000);
    EXPECT_STREQ("[0: 0.000000, 1: 0.000000 timeInStateSinceUpdate: 2000]"
                 " updated: 0 currentState: 1 stateChanged: 2000",
                 testCounter.toString().c_str());

    testCounter.updateValue(3.14, 3000);

    EXPECT_STREQ("[0: 0.000000, 1: 3.140000] updated: 3000 currentState: 1",
                 testCounter.toString().c_str());
}

} // namespace battery
} // namespace android
