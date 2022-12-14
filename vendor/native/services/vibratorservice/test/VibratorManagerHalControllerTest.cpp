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

#define LOG_TAG "VibratorManagerHalControllerTest"

#include <cutils/atomic.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>

#include <vibratorservice/VibratorManagerHalController.h>

#include "test_utils.h"

using android::vibrator::HalController;

using namespace android;
using namespace testing;

static constexpr int MAX_ATTEMPTS = 2;
static const std::vector<int32_t> VIBRATOR_IDS = {1, 2};
static constexpr int VIBRATOR_ID = 1;

class MockManagerHalWrapper : public vibrator::ManagerHalWrapper {
public:
    MOCK_METHOD(void, tryReconnect, (), (override));
    MOCK_METHOD(vibrator::HalResult<void>, ping, (), (override));
    MOCK_METHOD(vibrator::HalResult<vibrator::ManagerCapabilities>, getCapabilities, (),
                (override));
    MOCK_METHOD(vibrator::HalResult<std::vector<int32_t>>, getVibratorIds, (), (override));
    MOCK_METHOD(vibrator::HalResult<std::shared_ptr<HalController>>, getVibrator, (int32_t id),
                (override));
    MOCK_METHOD(vibrator::HalResult<void>, prepareSynced, (const std::vector<int32_t>& ids),
                (override));
    MOCK_METHOD(vibrator::HalResult<void>, triggerSynced,
                (const std::function<void()>& completionCallback), (override));
    MOCK_METHOD(vibrator::HalResult<void>, cancelSynced, (), (override));
};

class VibratorManagerHalControllerTest : public Test {
public:
    void SetUp() override {
        mConnectCounter = 0;
        auto callbackScheduler = std::make_shared<vibrator::CallbackScheduler>();
        mMockHal = std::make_shared<StrictMock<MockManagerHalWrapper>>();
        auto connector = [this](std::shared_ptr<vibrator::CallbackScheduler>) {
            android_atomic_inc(&mConnectCounter);
            return mMockHal;
        };
        mController = std::make_unique<vibrator::ManagerHalController>(std::move(callbackScheduler),
                                                                       connector);
        ASSERT_NE(mController, nullptr);
    }

protected:
    int32_t mConnectCounter;
    std::shared_ptr<MockManagerHalWrapper> mMockHal;
    std::unique_ptr<vibrator::ManagerHalController> mController;

    void setHalExpectations(int32_t cardinality, vibrator::HalResult<void> voidResult,
                            vibrator::HalResult<vibrator::ManagerCapabilities> capabilitiesResult,
                            vibrator::HalResult<std::vector<int32_t>> idsResult,
                            vibrator::HalResult<std::shared_ptr<HalController>> vibratorResult) {
        EXPECT_CALL(*mMockHal.get(), ping())
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), getCapabilities())
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(capabilitiesResult));
        EXPECT_CALL(*mMockHal.get(), getVibratorIds())
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(idsResult));
        EXPECT_CALL(*mMockHal.get(), getVibrator(_))
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(vibratorResult));
        EXPECT_CALL(*mMockHal.get(), prepareSynced(_))
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), triggerSynced(_))
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(voidResult));
        EXPECT_CALL(*mMockHal.get(), cancelSynced())
                .Times(Exactly(cardinality))
                .WillRepeatedly(Return(voidResult));

        if (cardinality > 1) {
            // One reconnection call after each failure.
            EXPECT_CALL(*mMockHal.get(), tryReconnect()).Times(Exactly(7 * cardinality));
        }
    }
};

TEST_F(VibratorManagerHalControllerTest, TestInit) {
    mController->init();
    ASSERT_EQ(1, mConnectCounter);

    // Noop when wrapper was already initialized.
    mController->init();
    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestApiCallsAreForwardedToHal) {
    setHalExpectations(/* cardinality= */ 1, vibrator::HalResult<void>::ok(),
                       vibrator::HalResult<vibrator::ManagerCapabilities>::ok(
                               vibrator::ManagerCapabilities::SYNC),
                       vibrator::HalResult<std::vector<int32_t>>::ok(VIBRATOR_IDS),
                       vibrator::HalResult<std::shared_ptr<HalController>>::ok(nullptr));

    ASSERT_TRUE(mController->ping().isOk());

    auto getCapabilitiesResult = mController->getCapabilities();
    ASSERT_TRUE(getCapabilitiesResult.isOk());
    ASSERT_EQ(vibrator::ManagerCapabilities::SYNC, getCapabilitiesResult.value());

    auto getVibratorIdsResult = mController->getVibratorIds();
    ASSERT_TRUE(getVibratorIdsResult.isOk());
    ASSERT_EQ(VIBRATOR_IDS, getVibratorIdsResult.value());

    auto getVibratorResult = mController->getVibrator(VIBRATOR_ID);
    ASSERT_TRUE(getVibratorResult.isOk());
    ASSERT_EQ(nullptr, getVibratorResult.value());

    ASSERT_TRUE(mController->prepareSynced(VIBRATOR_IDS).isOk());
    ASSERT_TRUE(mController->triggerSynced([]() {}).isOk());
    ASSERT_TRUE(mController->cancelSynced().isOk());

    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestUnsupportedApiResultDoNotResetHalConnection) {
    setHalExpectations(/* cardinality= */ 1, vibrator::HalResult<void>::unsupported(),
                       vibrator::HalResult<vibrator::ManagerCapabilities>::unsupported(),
                       vibrator::HalResult<std::vector<int32_t>>::unsupported(),
                       vibrator::HalResult<std::shared_ptr<HalController>>::unsupported());

    ASSERT_EQ(0, mConnectCounter);

    ASSERT_TRUE(mController->ping().isUnsupported());
    ASSERT_TRUE(mController->getCapabilities().isUnsupported());
    ASSERT_TRUE(mController->getVibratorIds().isUnsupported());
    ASSERT_TRUE(mController->getVibrator(VIBRATOR_ID).isUnsupported());
    ASSERT_TRUE(mController->prepareSynced(VIBRATOR_IDS).isUnsupported());
    ASSERT_TRUE(mController->triggerSynced([]() {}).isUnsupported());
    ASSERT_TRUE(mController->cancelSynced().isUnsupported());

    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestFailedApiResultResetsHalConnection) {
    setHalExpectations(MAX_ATTEMPTS, vibrator::HalResult<void>::failed("message"),
                       vibrator::HalResult<vibrator::ManagerCapabilities>::failed("message"),
                       vibrator::HalResult<std::vector<int32_t>>::failed("message"),
                       vibrator::HalResult<std::shared_ptr<HalController>>::failed("message"));

    ASSERT_EQ(0, mConnectCounter);

    ASSERT_TRUE(mController->ping().isFailed());
    ASSERT_TRUE(mController->getCapabilities().isFailed());
    ASSERT_TRUE(mController->getVibratorIds().isFailed());
    ASSERT_TRUE(mController->getVibrator(VIBRATOR_ID).isFailed());
    ASSERT_TRUE(mController->prepareSynced(VIBRATOR_IDS).isFailed());
    ASSERT_TRUE(mController->triggerSynced([]() {}).isFailed());
    ASSERT_TRUE(mController->cancelSynced().isFailed());

    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestFailedApiResultReturnsSuccessAfterRetries) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), ping())
                .Times(Exactly(1))
                .WillRepeatedly(Return(vibrator::HalResult<void>::failed("message")));
        EXPECT_CALL(*mMockHal.get(), tryReconnect()).Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), ping())
                .Times(Exactly(1))
                .WillRepeatedly(Return(vibrator::HalResult<void>::ok()));
    }

    ASSERT_EQ(0, mConnectCounter);
    ASSERT_TRUE(mController->ping().isOk());
    ASSERT_EQ(1, mConnectCounter);
}

TEST_F(VibratorManagerHalControllerTest, TestMultiThreadConnectsOnlyOnce) {
    ASSERT_EQ(0, mConnectCounter);

    EXPECT_CALL(*mMockHal.get(), ping())
            .Times(Exactly(10))
            .WillRepeatedly(Return(vibrator::HalResult<void>::ok()));

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&]() { ASSERT_TRUE(mController->ping().isOk()); }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    // Connector was called only by the first thread to use the api.
    ASSERT_EQ(1, mConnectCounter);
}
