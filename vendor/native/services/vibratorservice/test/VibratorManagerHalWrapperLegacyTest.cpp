/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *            http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "VibratorManagerHalWrapperLegacyTest"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>

#include <vibratorservice/VibratorManagerHalWrapper.h>

using android::hardware::vibrator::CompositeEffect;
using android::hardware::vibrator::CompositePrimitive;
using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;

using std::chrono::milliseconds;

using namespace android;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class MockHalController : public vibrator::HalController {
public:
    MockHalController() = default;
    virtual ~MockHalController() = default;

    MOCK_METHOD(bool, init, (), (override));
    MOCK_METHOD(void, tryReconnect, (), (override));
};

// -------------------------------------------------------------------------------------------------

class VibratorManagerHalWrapperLegacyTest : public Test {
public:
    void SetUp() override {
        mMockController = std::make_shared<StrictMock<MockHalController>>();
        mWrapper = std::make_unique<vibrator::LegacyManagerHalWrapper>(mMockController);
        ASSERT_NE(mWrapper, nullptr);
    }

protected:
    std::shared_ptr<StrictMock<MockHalController>> mMockController = nullptr;
    std::unique_ptr<vibrator::ManagerHalWrapper> mWrapper = nullptr;
};

// -------------------------------------------------------------------------------------------------

TEST_F(VibratorManagerHalWrapperLegacyTest, TestPing) {
    EXPECT_CALL(*mMockController.get(), init()).Times(Exactly(1)).WillOnce(Return(false));

    ASSERT_TRUE(mWrapper->ping().isUnsupported());
}

TEST_F(VibratorManagerHalWrapperLegacyTest, TestTryReconnect) {
    EXPECT_CALL(*mMockController.get(), tryReconnect()).Times(Exactly(1));

    mWrapper->tryReconnect();
}

TEST_F(VibratorManagerHalWrapperLegacyTest, TestGetCapabilities) {
    auto result = mWrapper->getCapabilities();
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(vibrator::ManagerCapabilities::NONE, result.value());
}

TEST_F(VibratorManagerHalWrapperLegacyTest, TestGetVibratorIds) {
    std::vector<int> expectedIds = {0};

    EXPECT_CALL(*mMockController.get(), init())
            .Times(Exactly(2))
            .WillOnce(Return(false))
            .WillRepeatedly(Return(true));

    auto result = mWrapper->getVibratorIds();
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(std::vector<int32_t>(), result.value());

    result = mWrapper->getVibratorIds();
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(expectedIds, result.value());
}

TEST_F(VibratorManagerHalWrapperLegacyTest, TestGetVibratorWithValidIdReturnsController) {
    EXPECT_CALL(*mMockController.get(), init())
            .Times(Exactly(2))
            .WillOnce(Return(false))
            .WillRepeatedly(Return(true));

    ASSERT_TRUE(mWrapper->getVibrator(0).isFailed());

    auto result = mWrapper->getVibrator(0);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(mMockController.get(), result.value().get());
}

TEST_F(VibratorManagerHalWrapperLegacyTest, TestGetVibratorWithInvalidIdFails) {
    ASSERT_TRUE(mWrapper->getVibrator(-1).isFailed());
}

TEST_F(VibratorManagerHalWrapperLegacyTest, TestSyncedOperationsUnsupported) {
    std::vector<int32_t> vibratorIds;
    vibratorIds.push_back(0);

    ASSERT_TRUE(mWrapper->prepareSynced(vibratorIds).isUnsupported());
    ASSERT_TRUE(mWrapper->triggerSynced([]() {}).isUnsupported());
    ASSERT_TRUE(mWrapper->cancelSynced().isUnsupported());
}
