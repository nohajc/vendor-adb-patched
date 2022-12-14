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

#define LOG_TAG "VibratorHalWrapperHidlV1_0Test"

#include <android/hardware/vibrator/IVibrator.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>
#include <thread>

#include <vibratorservice/VibratorCallbackScheduler.h>
#include <vibratorservice/VibratorHalWrapper.h>

#include "test_utils.h"

namespace V1_0 = android::hardware::vibrator::V1_0;

using android::hardware::vibrator::Braking;
using android::hardware::vibrator::CompositeEffect;
using android::hardware::vibrator::CompositePrimitive;
using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;
using android::hardware::vibrator::IVibrator;
using android::hardware::vibrator::PrimitivePwle;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class MockIVibratorV1_0 : public V1_0::IVibrator {
public:
    MOCK_METHOD(hardware::Return<void>, ping, (), (override));
    MOCK_METHOD(hardware::Return<V1_0::Status>, on, (uint32_t timeoutMs), (override));
    MOCK_METHOD(hardware::Return<V1_0::Status>, off, (), (override));
    MOCK_METHOD(hardware::Return<bool>, supportsAmplitudeControl, (), (override));
    MOCK_METHOD(hardware::Return<V1_0::Status>, setAmplitude, (uint8_t amplitude), (override));
    MOCK_METHOD(hardware::Return<void>, perform,
                (V1_0::Effect effect, V1_0::EffectStrength strength, perform_cb cb), (override));
};

// -------------------------------------------------------------------------------------------------

class VibratorHalWrapperHidlV1_0Test : public Test {
public:
    void SetUp() override {
        mMockHal = new StrictMock<MockIVibratorV1_0>();
        mMockScheduler = std::make_shared<StrictMock<vibrator::MockCallbackScheduler>>();
        mWrapper = std::make_unique<vibrator::HidlHalWrapperV1_0>(mMockScheduler, mMockHal);
        ASSERT_NE(mWrapper, nullptr);
    }

protected:
    std::shared_ptr<StrictMock<vibrator::MockCallbackScheduler>> mMockScheduler = nullptr;
    std::unique_ptr<vibrator::HalWrapper> mWrapper = nullptr;
    sp<StrictMock<MockIVibratorV1_0>> mMockHal = nullptr;
};

// -------------------------------------------------------------------------------------------------

TEST_F(VibratorHalWrapperHidlV1_0Test, TestPing) {
    EXPECT_CALL(*mMockHal.get(), ping())
            .Times(Exactly(2))
            .WillOnce([]() { return hardware::Return<void>(); })
            .WillRepeatedly([]() {
                return hardware::Return<void>(hardware::Status::fromExceptionCode(-1));
            });

    ASSERT_TRUE(mWrapper->ping().isOk());
    ASSERT_TRUE(mWrapper->ping().isFailed());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestOn) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), on(Eq(static_cast<uint32_t>(1))))
                .Times(Exactly(1))
                .WillRepeatedly(
                        [](uint32_t) { return hardware::Return<V1_0::Status>(V1_0::Status::OK); });
        EXPECT_CALL(*mMockScheduler.get(), schedule(_, Eq(1ms)))
                .Times(Exactly(1))
                .WillRepeatedly(vibrator::TriggerSchedulerCallback());
        EXPECT_CALL(*mMockHal.get(), on(Eq(static_cast<uint32_t>(10))))
                .Times(Exactly(1))
                .WillRepeatedly([](uint32_t) {
                    return hardware::Return<V1_0::Status>(V1_0::Status::UNSUPPORTED_OPERATION);
                });
        EXPECT_CALL(*mMockHal.get(), on(Eq(static_cast<uint32_t>(11))))
                .Times(Exactly(1))
                .WillRepeatedly([](uint32_t) {
                    return hardware::Return<V1_0::Status>(V1_0::Status::BAD_VALUE);
                });
        EXPECT_CALL(*mMockHal.get(), on(Eq(static_cast<uint32_t>(12))))
                .Times(Exactly(1))
                .WillRepeatedly([](uint32_t) {
                    return hardware::Return<V1_0::Status>(hardware::Status::fromExceptionCode(-1));
                });
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    ASSERT_TRUE(mWrapper->on(1ms, callback).isOk());
    ASSERT_EQ(1, *callbackCounter.get());

    ASSERT_TRUE(mWrapper->on(10ms, callback).isUnsupported());
    ASSERT_TRUE(mWrapper->on(11ms, callback).isFailed());
    ASSERT_TRUE(mWrapper->on(12ms, callback).isFailed());

    // Callback not triggered for unsupported and on failure
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestOff) {
    EXPECT_CALL(*mMockHal.get(), off())
            .Times(Exactly(4))
            .WillOnce([]() { return hardware::Return<V1_0::Status>(V1_0::Status::OK); })
            .WillOnce([]() {
                return hardware::Return<V1_0::Status>(V1_0::Status::UNSUPPORTED_OPERATION);
            })
            .WillOnce([]() { return hardware::Return<V1_0::Status>(V1_0::Status::BAD_VALUE); })
            .WillRepeatedly([]() {
                return hardware::Return<V1_0::Status>(hardware::Status::fromExceptionCode(-1));
            });

    ASSERT_TRUE(mWrapper->off().isOk());
    ASSERT_TRUE(mWrapper->off().isUnsupported());
    ASSERT_TRUE(mWrapper->off().isFailed());
    ASSERT_TRUE(mWrapper->off().isFailed());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestSetAmplitude) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), setAmplitude(Eq(static_cast<uint8_t>(1))))
                .Times(Exactly(1))
                .WillRepeatedly(
                        [](uint8_t) { return hardware::Return<V1_0::Status>(V1_0::Status::OK); });
        EXPECT_CALL(*mMockHal.get(), setAmplitude(Eq(static_cast<uint8_t>(2))))
                .Times(Exactly(1))
                .WillRepeatedly([](uint8_t) {
                    return hardware::Return<V1_0::Status>(V1_0::Status::UNSUPPORTED_OPERATION);
                });
        EXPECT_CALL(*mMockHal.get(), setAmplitude(Eq(static_cast<uint8_t>(3))))
                .Times(Exactly(1))
                .WillRepeatedly([](uint8_t) {
                    return hardware::Return<V1_0::Status>(V1_0::Status::BAD_VALUE);
                });
        EXPECT_CALL(*mMockHal.get(), setAmplitude(Eq(static_cast<uint8_t>(4))))
                .Times(Exactly(1))
                .WillRepeatedly([](uint8_t) {
                    return hardware::Return<V1_0::Status>(hardware::Status::fromExceptionCode(-1));
                });
    }

    auto maxAmplitude = std::numeric_limits<uint8_t>::max();
    ASSERT_TRUE(mWrapper->setAmplitude(1.0f / maxAmplitude).isOk());
    ASSERT_TRUE(mWrapper->setAmplitude(2.0f / maxAmplitude).isUnsupported());
    ASSERT_TRUE(mWrapper->setAmplitude(3.0f / maxAmplitude).isFailed());
    ASSERT_TRUE(mWrapper->setAmplitude(4.0f / maxAmplitude).isFailed());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestSetExternalControlUnsupported) {
    ASSERT_TRUE(mWrapper->setExternalControl(true).isUnsupported());
    ASSERT_TRUE(mWrapper->setExternalControl(false).isUnsupported());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestAlwaysOnEnableUnsupported) {
    ASSERT_TRUE(mWrapper->alwaysOnEnable(1, Effect::CLICK, EffectStrength::LIGHT).isUnsupported());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestAlwaysOnDisableUnsupported) {
    ASSERT_TRUE(mWrapper->alwaysOnDisable(1).isUnsupported());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestGetInfoDoesNotCacheFailedResult) {
    EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl())
            .Times(Exactly(2))
            .WillOnce([]() {
                return hardware::Return<bool>(hardware::Status::fromExceptionCode(-1));
            })
            .WillRepeatedly([]() { return hardware::Return<bool>(true); });

    ASSERT_TRUE(mWrapper->getInfo().capabilities.isFailed());

    vibrator::Info info = mWrapper->getInfo();
    ASSERT_EQ(vibrator::Capabilities::AMPLITUDE_CONTROL, info.capabilities.value());
    ASSERT_TRUE(info.supportedEffects.isUnsupported());
    ASSERT_TRUE(info.supportedBraking.isUnsupported());
    ASSERT_TRUE(info.supportedPrimitives.isUnsupported());
    ASSERT_TRUE(info.primitiveDurations.isUnsupported());
    ASSERT_TRUE(info.primitiveDelayMax.isUnsupported());
    ASSERT_TRUE(info.pwlePrimitiveDurationMax.isUnsupported());
    ASSERT_TRUE(info.compositionSizeMax.isUnsupported());
    ASSERT_TRUE(info.pwleSizeMax.isUnsupported());
    ASSERT_TRUE(info.minFrequency.isUnsupported());
    ASSERT_TRUE(info.resonantFrequency.isUnsupported());
    ASSERT_TRUE(info.frequencyResolution.isUnsupported());
    ASSERT_TRUE(info.qFactor.isUnsupported());
    ASSERT_TRUE(info.maxAmplitudes.isUnsupported());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestGetInfoWithoutAmplitudeControl) {
    EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl()).Times(Exactly(1)).WillRepeatedly([]() {
        return hardware::Return<bool>(false);
    });

    ASSERT_EQ(vibrator::Capabilities::NONE, mWrapper->getInfo().capabilities.value());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestGetInfoCachesResult) {
    EXPECT_CALL(*mMockHal.get(), supportsAmplitudeControl()).Times(Exactly(1)).WillRepeatedly([]() {
        return hardware::Return<bool>(true);
    });

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(
                std::thread([&]() { ASSERT_TRUE(mWrapper->getInfo().capabilities.isOk()); }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    vibrator::Info info = mWrapper->getInfo();
    ASSERT_EQ(vibrator::Capabilities::AMPLITUDE_CONTROL, info.capabilities.value());
    ASSERT_TRUE(info.supportedEffects.isUnsupported());
    ASSERT_TRUE(info.supportedBraking.isUnsupported());
    ASSERT_TRUE(info.supportedPrimitives.isUnsupported());
    ASSERT_TRUE(info.primitiveDurations.isUnsupported());
    ASSERT_TRUE(info.minFrequency.isUnsupported());
    ASSERT_TRUE(info.resonantFrequency.isUnsupported());
    ASSERT_TRUE(info.frequencyResolution.isUnsupported());
    ASSERT_TRUE(info.qFactor.isUnsupported());
    ASSERT_TRUE(info.maxAmplitudes.isUnsupported());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestPerformEffect) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(),
                    perform(Eq(V1_0::Effect::CLICK), Eq(V1_0::EffectStrength::LIGHT), _))
                .Times(Exactly(1))
                .WillRepeatedly(
                        [](V1_0::Effect, V1_0::EffectStrength, MockIVibratorV1_0::perform_cb cb) {
                            cb(V1_0::Status::OK, 10);
                            return hardware::Return<void>();
                        });
        EXPECT_CALL(*mMockScheduler.get(), schedule(_, Eq(10ms)))
                .Times(Exactly(1))
                .WillRepeatedly(vibrator::TriggerSchedulerCallback());
        EXPECT_CALL(*mMockHal.get(),
                    perform(Eq(V1_0::Effect::CLICK), Eq(V1_0::EffectStrength::MEDIUM), _))
                .Times(Exactly(1))
                .WillRepeatedly(
                        [](V1_0::Effect, V1_0::EffectStrength, MockIVibratorV1_0::perform_cb cb) {
                            cb(V1_0::Status::UNSUPPORTED_OPERATION, 10);
                            return hardware::Return<void>();
                        });
        EXPECT_CALL(*mMockHal.get(),
                    perform(Eq(V1_0::Effect::CLICK), Eq(V1_0::EffectStrength::STRONG), _))
                .Times(Exactly(2))
                .WillOnce([](V1_0::Effect, V1_0::EffectStrength, MockIVibratorV1_0::perform_cb cb) {
                    cb(V1_0::Status::BAD_VALUE, 10);
                    return hardware::Return<void>();
                })
                .WillRepeatedly(
                        [](V1_0::Effect, V1_0::EffectStrength, MockIVibratorV1_0::perform_cb) {
                            return hardware::Return<void>(hardware::Status::fromExceptionCode(-1));
                        });
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    auto result = mWrapper->performEffect(Effect::CLICK, EffectStrength::LIGHT, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(10ms, result.value());
    ASSERT_EQ(1, *callbackCounter.get());

    result = mWrapper->performEffect(Effect::CLICK, EffectStrength::MEDIUM, callback);
    ASSERT_TRUE(result.isUnsupported());

    result = mWrapper->performEffect(Effect::CLICK, EffectStrength::STRONG, callback);
    ASSERT_TRUE(result.isFailed());

    result = mWrapper->performEffect(Effect::CLICK, EffectStrength::STRONG, callback);
    ASSERT_TRUE(result.isFailed());

    // Callback not triggered for unsupported and on failure
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestPerformEffectUnsupported) {
    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());
    // Using TICK that is only available in v1.1
    auto result = mWrapper->performEffect(Effect::TICK, EffectStrength::LIGHT, callback);
    ASSERT_TRUE(result.isUnsupported());
    // No callback is triggered.
    ASSERT_EQ(0, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestPerformComposedEffectUnsupported) {
    std::vector<CompositeEffect> emptyEffects, singleEffect, multipleEffects;
    singleEffect.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::CLICK, 10ms, 0.0f));
    multipleEffects.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::SPIN, 100ms, 0.5f));
    multipleEffects.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::THUD, 1000ms, 1.0f));

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    ASSERT_TRUE(mWrapper->performComposedEffect(singleEffect, callback).isUnsupported());
    ASSERT_TRUE(mWrapper->performComposedEffect(multipleEffects, callback).isUnsupported());

    // No callback is triggered.
    ASSERT_EQ(0, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperHidlV1_0Test, TestPerformPwleEffectUnsupported) {
    std::vector<PrimitivePwle> emptyPrimitives, multiplePrimitives;
    multiplePrimitives.push_back(vibrator::TestFactory::createActivePwle(0, 1, 0, 1, 10ms));
    multiplePrimitives.push_back(vibrator::TestFactory::createBrakingPwle(Braking::NONE, 100ms));

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    ASSERT_TRUE(mWrapper->performPwleEffect(emptyPrimitives, callback).isUnsupported());
    ASSERT_TRUE(mWrapper->performPwleEffect(multiplePrimitives, callback).isUnsupported());

    // No callback is triggered.
    ASSERT_EQ(0, *callbackCounter.get());
}
