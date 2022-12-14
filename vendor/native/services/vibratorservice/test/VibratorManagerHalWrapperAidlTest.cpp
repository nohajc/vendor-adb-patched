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

#define LOG_TAG "VibratorManagerHalWrapperAidlTest"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>

#include <vibratorservice/VibratorManagerHalWrapper.h>

#include "test_utils.h"

using android::binder::Status;

using android::hardware::vibrator::Braking;
using android::hardware::vibrator::CompositeEffect;
using android::hardware::vibrator::CompositePrimitive;
using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;
using android::hardware::vibrator::IVibrator;
using android::hardware::vibrator::IVibratorCallback;
using android::hardware::vibrator::IVibratorManager;
using android::hardware::vibrator::PrimitivePwle;

using namespace android;
using namespace testing;

static const auto OFF_FN = [](vibrator::HalWrapper* hal) { return hal->off(); };

class MockBinder : public BBinder {
public:
    MOCK_METHOD(status_t, linkToDeath,
                (const sp<DeathRecipient>& recipient, void* cookie, uint32_t flags), (override));
    MOCK_METHOD(status_t, unlinkToDeath,
                (const wp<DeathRecipient>& recipient, void* cookie, uint32_t flags,
                 wp<DeathRecipient>* outRecipient),
                (override));
    MOCK_METHOD(status_t, pingBinder, (), (override));
};

class MockIVibrator : public IVibrator {
public:
    MOCK_METHOD(Status, getCapabilities, (int32_t * ret), (override));
    MOCK_METHOD(Status, off, (), (override));
    MOCK_METHOD(Status, on, (int32_t timeout, const sp<IVibratorCallback>& cb), (override));
    MOCK_METHOD(Status, perform,
                (Effect e, EffectStrength s, const sp<IVibratorCallback>& cb, int32_t* ret),
                (override));
    MOCK_METHOD(Status, getSupportedEffects, (std::vector<Effect> * ret), (override));
    MOCK_METHOD(Status, setAmplitude, (float amplitude), (override));
    MOCK_METHOD(Status, setExternalControl, (bool enabled), (override));
    MOCK_METHOD(Status, getCompositionDelayMax, (int32_t * ret), (override));
    MOCK_METHOD(Status, getCompositionSizeMax, (int32_t * ret), (override));
    MOCK_METHOD(Status, getSupportedPrimitives, (std::vector<CompositePrimitive> * ret),
                (override));
    MOCK_METHOD(Status, getPrimitiveDuration, (CompositePrimitive p, int32_t* ret), (override));
    MOCK_METHOD(Status, compose,
                (const std::vector<CompositeEffect>& e, const sp<IVibratorCallback>& cb),
                (override));
    MOCK_METHOD(Status, composePwle,
                (const std::vector<PrimitivePwle>& e, const sp<IVibratorCallback>& cb), (override));
    MOCK_METHOD(Status, getSupportedAlwaysOnEffects, (std::vector<Effect> * ret), (override));
    MOCK_METHOD(Status, alwaysOnEnable, (int32_t id, Effect e, EffectStrength s), (override));
    MOCK_METHOD(Status, alwaysOnDisable, (int32_t id), (override));
    MOCK_METHOD(Status, getQFactor, (float * ret), (override));
    MOCK_METHOD(Status, getResonantFrequency, (float * ret), (override));
    MOCK_METHOD(Status, getFrequencyResolution, (float* ret), (override));
    MOCK_METHOD(Status, getFrequencyMinimum, (float* ret), (override));
    MOCK_METHOD(Status, getBandwidthAmplitudeMap, (std::vector<float> * ret), (override));
    MOCK_METHOD(Status, getPwlePrimitiveDurationMax, (int32_t * ret), (override));
    MOCK_METHOD(Status, getPwleCompositionSizeMax, (int32_t * ret), (override));
    MOCK_METHOD(Status, getSupportedBraking, (std::vector<Braking> * ret), (override));
    MOCK_METHOD(int32_t, getInterfaceVersion, (), (override));
    MOCK_METHOD(std::string, getInterfaceHash, (), (override));
    MOCK_METHOD(IBinder*, onAsBinder, (), (override));
};

class MockIVibratorManager : public IVibratorManager {
public:
    MOCK_METHOD(Status, getCapabilities, (int32_t * ret), (override));
    MOCK_METHOD(Status, getVibratorIds, (std::vector<int32_t> * ret), (override));
    MOCK_METHOD(Status, getVibrator, (int32_t id, sp<IVibrator>* ret), (override));
    MOCK_METHOD(Status, prepareSynced, (const std::vector<int32_t>& ids), (override));
    MOCK_METHOD(Status, triggerSynced, (const sp<IVibratorCallback>& cb), (override));
    MOCK_METHOD(Status, cancelSynced, (), (override));
    MOCK_METHOD(int32_t, getInterfaceVersion, (), (override));
    MOCK_METHOD(std::string, getInterfaceHash, (), (override));
    MOCK_METHOD(IBinder*, onAsBinder, (), (override));
};

// -------------------------------------------------------------------------------------------------

class VibratorManagerHalWrapperAidlTest : public Test {
public:
    void SetUp() override {
        mMockBinder = new StrictMock<MockBinder>();
        mMockVibrator = new StrictMock<MockIVibrator>();
        mMockHal = new StrictMock<MockIVibratorManager>();
        mMockScheduler = std::make_shared<StrictMock<vibrator::MockCallbackScheduler>>();
        mWrapper = std::make_unique<vibrator::AidlManagerHalWrapper>(mMockScheduler, mMockHal);
        ASSERT_NE(mWrapper, nullptr);
    }

protected:
    std::shared_ptr<StrictMock<vibrator::MockCallbackScheduler>> mMockScheduler = nullptr;
    std::unique_ptr<vibrator::ManagerHalWrapper> mWrapper = nullptr;
    sp<StrictMock<MockIVibratorManager>> mMockHal = nullptr;
    sp<StrictMock<MockIVibrator>> mMockVibrator = nullptr;
    sp<StrictMock<MockBinder>> mMockBinder = nullptr;
};

// -------------------------------------------------------------------------------------------------

static const std::vector<int32_t> kVibratorIds = {1, 2};
static constexpr int kVibratorId = 1;

ACTION(TriggerCallback) {
    if (arg0 != nullptr) {
        arg0->onComplete();
    }
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestPing) {
    EXPECT_CALL(*mMockHal.get(), onAsBinder())
            .Times(Exactly(2))
            .WillRepeatedly(Return(mMockBinder.get()));
    EXPECT_CALL(*mMockBinder.get(), pingBinder())
            .Times(Exactly(2))
            .WillOnce(Return(android::OK))
            .WillRepeatedly(Return(android::DEAD_OBJECT));

    ASSERT_TRUE(mWrapper->ping().isOk());
    ASSERT_TRUE(mWrapper->ping().isFailed());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestGetCapabilitiesDoesNotCacheFailedResult) {
    EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
            .Times(Exactly(3))
            .WillOnce(
                    Return(Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(IVibratorManager::CAP_SYNC), Return(Status())));

    ASSERT_TRUE(mWrapper->getCapabilities().isUnsupported());
    ASSERT_TRUE(mWrapper->getCapabilities().isFailed());

    auto result = mWrapper->getCapabilities();
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(vibrator::ManagerCapabilities::SYNC, result.value());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestGetCapabilitiesCachesResult) {
    EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(IVibratorManager::CAP_SYNC), Return(Status())));

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&]() {
            auto result = mWrapper->getCapabilities();
            ASSERT_TRUE(result.isOk());
            ASSERT_EQ(vibrator::ManagerCapabilities::SYNC, result.value());
        }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    auto result = mWrapper->getCapabilities();
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(vibrator::ManagerCapabilities::SYNC, result.value());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestGetVibratorIdsDoesNotCacheFailedResult) {
    EXPECT_CALL(*mMockHal.get(), getVibratorIds(_))
            .Times(Exactly(3))
            .WillOnce(
                    Return(Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(kVibratorIds), Return(Status())));

    ASSERT_TRUE(mWrapper->getVibratorIds().isUnsupported());
    ASSERT_TRUE(mWrapper->getVibratorIds().isFailed());

    auto result = mWrapper->getVibratorIds();
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(kVibratorIds, result.value());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestGetVibratorIdsCachesResult) {
    EXPECT_CALL(*mMockHal.get(), getVibratorIds(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(kVibratorIds), Return(Status())));

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(std::thread([&]() {
            auto result = mWrapper->getVibratorIds();
            ASSERT_TRUE(result.isOk());
            ASSERT_EQ(kVibratorIds, result.value());
        }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    auto result = mWrapper->getVibratorIds();
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(kVibratorIds, result.value());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestGetVibratorWithValidIdReturnsController) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getVibratorIds(_))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<0>(kVibratorIds), Return(Status())));

        EXPECT_CALL(*mMockHal.get(), getVibrator(Eq(kVibratorId), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(mMockVibrator), Return(Status())));
    }

    auto result = mWrapper->getVibrator(kVibratorId);
    ASSERT_TRUE(result.isOk());
    ASSERT_NE(nullptr, result.value().get());
    ASSERT_TRUE(result.value().get()->init());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestGetVibratorWithInvalidIdFails) {
    EXPECT_CALL(*mMockHal.get(), getVibratorIds(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(kVibratorIds), Return(Status())));

    ASSERT_TRUE(mWrapper->getVibrator(0).isFailed());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestGetVibratorRecoversVibratorPointer) {
    EXPECT_CALL(*mMockHal.get(), getVibratorIds(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(kVibratorIds), Return(Status())));

    EXPECT_CALL(*mMockHal.get(), getVibrator(Eq(kVibratorId), _))
            .Times(Exactly(3))
            .WillOnce(DoAll(SetArgPointee<1>(nullptr),
                            Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY))))
            .WillRepeatedly(DoAll(SetArgPointee<1>(mMockVibrator), Return(Status())));

    EXPECT_CALL(*mMockVibrator.get(), off())
            .Times(Exactly(3))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(Return(Status()));

    // Get vibrator controller is successful even if first getVibrator.
    auto result = mWrapper->getVibrator(kVibratorId);
    ASSERT_TRUE(result.isOk());
    ASSERT_NE(nullptr, result.value().get());

    auto vibrator = result.value();
    // First getVibrator call fails.
    ASSERT_FALSE(vibrator->init());
    // First and second off() calls fail, reload IVibrator with getVibrator.
    ASSERT_TRUE(vibrator->doWithRetry<void>(OFF_FN, "off").isFailed());
    // Third call to off() worked after IVibrator reloaded.
    ASSERT_TRUE(vibrator->doWithRetry<void>(OFF_FN, "off").isOk());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestPrepareSynced) {
    EXPECT_CALL(*mMockHal.get(), getVibratorIds(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(kVibratorIds), Return(Status())));

    EXPECT_CALL(*mMockHal.get(), getVibrator(_, _))
            .Times(Exactly(2))
            .WillRepeatedly(DoAll(SetArgPointee<1>(mMockVibrator), Return(Status())));

    EXPECT_CALL(*mMockHal.get(), prepareSynced(Eq(kVibratorIds)))
            .Times(Exactly(3))
            .WillOnce(
                    Return(Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(Return(Status()));

    ASSERT_TRUE(mWrapper->getVibratorIds().isOk());
    ASSERT_TRUE(mWrapper->prepareSynced(kVibratorIds).isUnsupported());
    ASSERT_TRUE(mWrapper->prepareSynced(kVibratorIds).isFailed());
    ASSERT_TRUE(mWrapper->prepareSynced(kVibratorIds).isOk());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestTriggerSyncedWithCallbackSupport) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<0>(IVibratorManager::CAP_TRIGGER_CALLBACK),
                                      Return(Status())));
        EXPECT_CALL(*mMockHal.get(), triggerSynced(_))
                .Times(Exactly(3))
                .WillOnce(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)))
                .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
                .WillRepeatedly(DoAll(TriggerCallback(), Return(Status())));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    ASSERT_TRUE(mWrapper->triggerSynced(callback).isUnsupported());
    ASSERT_TRUE(mWrapper->triggerSynced(callback).isFailed());
    ASSERT_TRUE(mWrapper->triggerSynced(callback).isOk());
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestTriggerSyncedWithoutCallbackSupport) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
                .Times(Exactly(1))
                .WillRepeatedly(
                        DoAll(SetArgPointee<0>(IVibratorManager::CAP_SYNC), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), triggerSynced(Eq(nullptr)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status()));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    ASSERT_TRUE(mWrapper->triggerSynced(callback).isOk());
    ASSERT_EQ(0, *callbackCounter.get());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestCancelSynced) {
    EXPECT_CALL(*mMockHal.get(), cancelSynced())
            .Times(Exactly(3))
            .WillOnce(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(Return(Status()));

    ASSERT_TRUE(mWrapper->cancelSynced().isUnsupported());
    ASSERT_TRUE(mWrapper->cancelSynced().isFailed());
    ASSERT_TRUE(mWrapper->cancelSynced().isOk());
}

TEST_F(VibratorManagerHalWrapperAidlTest, TestCancelSyncedReloadsAllControllers) {
    EXPECT_CALL(*mMockHal.get(), getVibratorIds(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(kVibratorIds), Return(Status())));

    EXPECT_CALL(*mMockHal.get(), getVibrator(_, _))
            .Times(Exactly(2))
            .WillRepeatedly(DoAll(SetArgPointee<1>(mMockVibrator), Return(Status())));

    EXPECT_CALL(*mMockHal.get(), cancelSynced()).Times(Exactly(1)).WillRepeatedly(Return(Status()));

    ASSERT_TRUE(mWrapper->getVibratorIds().isOk());
    ASSERT_TRUE(mWrapper->cancelSynced().isOk());
}
