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

#define LOG_TAG "VibratorHalWrapperHidlV1_3Test"

#include <android/hardware/vibrator/IVibrator.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>
#include <thread>

#include <vibratorservice/VibratorCallbackScheduler.h>
#include <vibratorservice/VibratorHalWrapper.h>

#include "test_utils.h"

namespace V1_0 = android::hardware::vibrator::V1_0;
namespace V1_1 = android::hardware::vibrator::V1_1;
namespace V1_2 = android::hardware::vibrator::V1_2;
namespace V1_3 = android::hardware::vibrator::V1_3;

using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;
using android::hardware::vibrator::IVibrator;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class MockIVibratorV1_3 : public V1_3::IVibrator {
public:
    MOCK_METHOD(hardware::Return<V1_0::Status>, on, (uint32_t timeoutMs), (override));
    MOCK_METHOD(hardware::Return<V1_0::Status>, off, (), (override));
    MOCK_METHOD(hardware::Return<bool>, supportsAmplitudeControl, (), (override));
    MOCK_METHOD(hardware::Return<bool>, supportsExternalControl, (), (override));
    MOCK_METHOD(hardware::Return<V1_0::Status>, setAmplitude, (uint8_t amplitude), (override));
    MOCK_METHOD(hardware::Return<V1_0::Status>, setExternalControl, (bool enabled), (override));
    MOCK_METHOD(hardware::Return<void>, perform,
                (V1_0::Effect effect, V1_0::EffectStrength strength, perform_cb cb), (override));
    MOCK_METHOD(hardware::Return<void>, perform_1_1,
                (V1_1::Effect_1_1 effect, V1_0::EffectStrength strength, perform_cb cb),
                (override));
    MOCK_METHOD(hardware::Return<void>, perform_1_2,
                (V1_2::Effect effect, V1_0::EffectStrength strength, perform_cb cb), (override));
    MOCK_METHOD(hardware::Return<void>, perform_1_3,
                (V1_3::Effect effect, V1_0::EffectStrength strength, perform_cb cb), (override));
};

// -------------------------------------------------------------------------------------------------

class VibratorHalWrapperHidlV1_3Test : public Test {
public:
    void SetUp() override {
        mMockHal = new StrictMock<MockIVibratorV1_3>();
        mMockScheduler = std::make_shared<StrictMock<vibrator::MockCallbackScheduler>>();
        mWrapper = std::make_unique<vibrator::HidlHalWrapperV1_3>(mMockScheduler, mMockHal);
        ASSERT_NE(mWrapper, nullptr);
    }

protected:
    std::shared_ptr<StrictMock<vibrator::MockCallbackScheduler>> mMockScheduler = nullptr;
    std::unique_ptr<vibrator::HalWrapper> mWrapper = nullptr;
    sp<StrictMock<MockIVibratorV1_3>> mMockHal = nullptr;
};

// -------------------------------------------------------------------------------------------------

TEST_F(VibratorHalWrapperHidlV1_3Test, TestSetExternalControl) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), setExternalControl(Eq(true)))
                .Times(Exactly(2))
                .WillOnce([]() { return hardware::Return<V1_0::Status>(V1_0::Status::OK); })
                .WillRepeatedly([]() {
                    return hardware::Return<V1_0::Status>(V1_0::Status::UNSUPPORTED_OPERATION);
                });
        EXPECT_CALL(*mMockHal.get(), setExternalControl(Eq(false)))
                .Times(Exactly(2))
                .WillOnce([]() { return hardware::Return<V1_0::Status>(V1_0::Status::BAD_VALUE); })
                .WillRepeatedly([]() {
                    return hardware::Return<V1_0::Status>(hardware::Status::fromExceptionCode(-1));
                });
    }

    ASSERT_TRUE(mWrapper->setExternalControl(true).isOk());
    ASSERT_TRUE(mWrapper->setExternalControl(true).isUnsupported());
    ASSERT_TRUE(mWrapper->setExternalControl(false).isFailed());
    ASSERT_TRUE(mWrapper->setExternalControl(false).isFailed());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestGetInfoSuccessful) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() { return hardware::Return<bool>(true); });
        EXPECT_CALL(*mMockHal.get(), supportsExternalControl()).Times(Exactly(1)).WillOnce([]() {
            return hardware::Return<bool>(true);
        });
    }

    ASSERT_EQ(vibrator::Capabilities::AMPLITUDE_CONTROL | vibrator::Capabilities::EXTERNAL_CONTROL |
                      vibrator::Capabilities::EXTERNAL_AMPLITUDE_CONTROL,
              mWrapper->getInfo().capabilities.value());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestGetInfoOnlyAmplitudeControl) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl()).Times(Exactly(1)).WillOnce([]() {
            return hardware::Return<bool>(true);
        });
        EXPECT_CALL(*mMockHal.get(), supportsExternalControl()).Times(Exactly(1)).WillOnce([]() {
            return hardware::Return<bool>(false);
        });
    }

    ASSERT_EQ(vibrator::Capabilities::AMPLITUDE_CONTROL, mWrapper->getInfo().capabilities.value());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestGetInfoOnlyExternalControl) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl()).Times(Exactly(1)).WillOnce([]() {
            return hardware::Return<bool>(false);
        });
        EXPECT_CALL(*mMockHal.get(), supportsExternalControl()).Times(Exactly(1)).WillOnce([]() {
            return hardware::Return<bool>(true);
        });
    }

    ASSERT_EQ(vibrator::Capabilities::EXTERNAL_CONTROL, mWrapper->getInfo().capabilities.value());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestGetInfoNoCapabilities) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() { return hardware::Return<bool>(false); });
        EXPECT_CALL(*mMockHal.get(), supportsExternalControl()).Times(Exactly(1)).WillOnce([]() {
            return hardware::Return<bool>(false);
        });
    }

    ASSERT_EQ(vibrator::Capabilities::NONE, mWrapper->getInfo().capabilities.value());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestGetInfoFailed) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() {
                    return hardware::Return<bool>(hardware::Status::fromExceptionCode(-1));
                });

        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() { return hardware::Return<bool>(true); });
        EXPECT_CALL(*mMockHal.get(), supportsExternalControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() {
                    return hardware::Return<bool>(hardware::Status::fromExceptionCode(-1));
                });
    }

    ASSERT_TRUE(mWrapper->getInfo().capabilities.isFailed());
    ASSERT_TRUE(mWrapper->getInfo().capabilities.isFailed());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestGetInfoCachesResult) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() { return hardware::Return<bool>(true); });
        EXPECT_CALL(*mMockHal.get(), supportsExternalControl()).Times(Exactly(1)).WillOnce([]() {
            return hardware::Return<bool>(false);
        });
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(
                std::thread([&]() { ASSERT_TRUE(mWrapper->getInfo().capabilities.isOk()); }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    ASSERT_EQ(vibrator::Capabilities::AMPLITUDE_CONTROL, mWrapper->getInfo().capabilities.value());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestGetInfoDoesNotCacheFailedResult) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() {
                    return hardware::Return<bool>(hardware::Status::fromExceptionCode(-1));
                });

        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() { return hardware::Return<bool>(true); });
        EXPECT_CALL(*mMockHal.get(), supportsExternalControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() {
                    return hardware::Return<bool>(hardware::Status::fromExceptionCode(-1));
                });

        EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() { return hardware::Return<bool>(true); });
        EXPECT_CALL(*mMockHal.get(), supportsExternalControl())
                .Times(Exactly(1))
                .WillRepeatedly([]() { return hardware::Return<bool>(false); });
    }

    // Call to supportsAmplitudeControl failed.
    ASSERT_TRUE(mWrapper->getInfo().capabilities.isFailed());

    // Call to supportsExternalControl failed.
    ASSERT_TRUE(mWrapper->getInfo().capabilities.isFailed());

    // Returns successful result from third call.
    ASSERT_EQ(vibrator::Capabilities::AMPLITUDE_CONTROL, mWrapper->getInfo().capabilities.value());

    // Returns cached successful result.
    ASSERT_EQ(vibrator::Capabilities::AMPLITUDE_CONTROL, mWrapper->getInfo().capabilities.value());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestPerformEffectV1_0) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(),
                    perform(Eq(V1_0::Effect::CLICK), Eq(V1_0::EffectStrength::LIGHT), _))
                .Times(Exactly(1))
                .WillRepeatedly(
                        [](V1_0::Effect, V1_0::EffectStrength, MockIVibratorV1_3::perform_cb cb) {
                            cb(V1_0::Status::OK, 10);
                            return hardware::Return<void>();
                        });
        EXPECT_CALL(*mMockScheduler.get(), schedule(_, Eq(10ms)))
                .Times(Exactly(1))
                .WillRepeatedly(vibrator::TriggerSchedulerCallback());
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());
    auto result = mWrapper->performEffect(Effect::CLICK, EffectStrength::LIGHT, callback);

    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(10ms, result.value());
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestPerformEffectV1_1) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(),
                    perform_1_1(Eq(V1_1::Effect_1_1::TICK), Eq(V1_0::EffectStrength::LIGHT), _))
                .Times(Exactly(1))
                .WillRepeatedly([](V1_1::Effect_1_1, V1_0::EffectStrength,
                                   MockIVibratorV1_3::perform_cb cb) {
                    cb(V1_0::Status::OK, 10);
                    return hardware::Return<void>();
                });
        EXPECT_CALL(*mMockScheduler.get(), schedule(_, Eq(10ms)))
                .Times(Exactly(1))
                .WillRepeatedly(vibrator::TriggerSchedulerCallback());
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());
    auto result = mWrapper->performEffect(Effect::TICK, EffectStrength::LIGHT, callback);

    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(10ms, result.value());
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestPerformEffectV1_2) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(),
                    perform_1_2(Eq(V1_2::Effect::THUD), Eq(V1_0::EffectStrength::LIGHT), _))
                .Times(Exactly(1))
                .WillRepeatedly(
                        [](V1_2::Effect, V1_0::EffectStrength, MockIVibratorV1_3::perform_cb cb) {
                            cb(V1_0::Status::OK, 10);
                            return hardware::Return<void>();
                        });
        EXPECT_CALL(*mMockScheduler.get(), schedule(_, Eq(10ms)))
                .Times(Exactly(1))
                .WillRepeatedly(vibrator::TriggerSchedulerCallback());
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());
    auto result = mWrapper->performEffect(Effect::THUD, EffectStrength::LIGHT, callback);

    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(10ms, result.value());
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_3Test, TestPerformEffectV1_3) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(),
                    perform_1_3(Eq(V1_3::Effect::TEXTURE_TICK), Eq(V1_0::EffectStrength::LIGHT), _))
                .Times(Exactly(1))
                .WillRepeatedly(
                        [](V1_3::Effect, V1_0::EffectStrength, MockIVibratorV1_3::perform_cb cb) {
                            cb(V1_0::Status::OK, 10);
                            return hardware::Return<void>();
                        });
        EXPECT_CALL(*mMockScheduler.get(), schedule(_, Eq(10ms)))
                .Times(Exactly(1))
                .WillRepeatedly(vibrator::TriggerSchedulerCallback());
        EXPECT_CALL(*mMockHal.get(),
                    perform_1_3(Eq(V1_3::Effect::TEXTURE_TICK), Eq(V1_0::EffectStrength::MEDIUM),
                                _))
                .Times(Exactly(1))
                .WillRepeatedly(
                        [](V1_3::Effect, V1_0::EffectStrength, MockIVibratorV1_3::perform_cb cb) {
                            cb(V1_0::Status::UNSUPPORTED_OPERATION, 0);
                            return hardware::Return<void>();
                        });
        EXPECT_CALL(*mMockHal.get(),
                    perform_1_3(Eq(V1_3::Effect::TEXTURE_TICK), Eq(V1_0::EffectStrength::STRONG),
                                _))
                .Times(Exactly(2))
                .WillOnce([](V1_3::Effect, V1_0::EffectStrength, MockIVibratorV1_3::perform_cb cb) {
                    cb(V1_0::Status::BAD_VALUE, 0);
                    return hardware::Return<void>();
                })
                .WillRepeatedly(
                        [](V1_3::Effect, V1_0::EffectStrength, MockIVibratorV1_3::perform_cb) {
                            return hardware::Return<void>(hardware::Status::fromExceptionCode(-1));
                        });
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    auto result = mWrapper->performEffect(Effect::TEXTURE_TICK, EffectStrength::LIGHT, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(10ms, result.value());
    ASSERT_EQ(1, *callbackCounter.get());

    result = mWrapper->performEffect(Effect::TEXTURE_TICK, EffectStrength::MEDIUM, callback);
    ASSERT_TRUE(result.isUnsupported());

    result = mWrapper->performEffect(Effect::TEXTURE_TICK, EffectStrength::STRONG, callback);
    ASSERT_TRUE(result.isFailed());

    result = mWrapper->performEffect(Effect::TEXTURE_TICK, EffectStrength::STRONG, callback);
    ASSERT_TRUE(result.isFailed());

    // Callback not triggered for unsupported and on failure
    ASSERT_EQ(1, *callbackCounter.get());
}
