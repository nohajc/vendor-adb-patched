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

#define LOG_TAG "VibratorHalWrapperAidlTest"

#include <android/hardware/vibrator/IVibrator.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>
#include <thread>

#include <vibratorservice/VibratorCallbackScheduler.h>
#include <vibratorservice/VibratorHalWrapper.h>

#include "test_utils.h"

using android::binder::Status;

using android::hardware::vibrator::Braking;
using android::hardware::vibrator::CompositeEffect;
using android::hardware::vibrator::CompositePrimitive;
using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;
using android::hardware::vibrator::IVibrator;
using android::hardware::vibrator::IVibratorCallback;
using android::hardware::vibrator::PrimitivePwle;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

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

// -------------------------------------------------------------------------------------------------

class VibratorHalWrapperAidlTest : public Test {
public:
    void SetUp() override {
        mMockBinder = new StrictMock<MockBinder>();
        mMockHal = new StrictMock<MockIVibrator>();
        mMockScheduler = std::make_shared<StrictMock<vibrator::MockCallbackScheduler>>();
        mWrapper = std::make_unique<vibrator::AidlHalWrapper>(mMockScheduler, mMockHal);
        ASSERT_NE(mWrapper, nullptr);
    }

protected:
    std::shared_ptr<StrictMock<vibrator::MockCallbackScheduler>> mMockScheduler = nullptr;
    std::unique_ptr<vibrator::HalWrapper> mWrapper = nullptr;
    sp<StrictMock<MockIVibrator>> mMockHal = nullptr;
    sp<StrictMock<MockBinder>> mMockBinder = nullptr;
};

// -------------------------------------------------------------------------------------------------

ACTION(TriggerCallbackInArg1) {
    if (arg1 != nullptr) {
        arg1->onComplete();
    }
}

ACTION(TriggerCallbackInArg2) {
    if (arg2 != nullptr) {
        arg2->onComplete();
    }
}

TEST_F(VibratorHalWrapperAidlTest, TestPing) {
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

TEST_F(VibratorHalWrapperAidlTest, TestOnWithCallbackSupport) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
                .Times(Exactly(1))
                .WillRepeatedly(
                        DoAll(SetArgPointee<0>(IVibrator::CAP_ON_CALLBACK), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), on(Eq(10), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(TriggerCallbackInArg1(), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), on(Eq(100), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(
                        Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)));
        EXPECT_CALL(*mMockHal.get(), on(Eq(1000), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    ASSERT_TRUE(mWrapper->on(10ms, callback).isOk());
    ASSERT_EQ(1, *callbackCounter.get());

    ASSERT_TRUE(mWrapper->on(100ms, callback).isUnsupported());
    // Callback not triggered for unsupported
    ASSERT_EQ(1, *callbackCounter.get());

    ASSERT_TRUE(mWrapper->on(1000ms, callback).isFailed());
    // Callback not triggered on failure
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperAidlTest, TestOnWithoutCallbackSupport) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
                .Times(Exactly(1))
                .WillRepeatedly(
                        DoAll(SetArgPointee<0>(IVibrator::CAP_COMPOSE_EFFECTS), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), on(Eq(10), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status()));
        EXPECT_CALL(*mMockScheduler.get(), schedule(_, Eq(10ms)))
                .Times(Exactly(1))
                .WillRepeatedly(vibrator::TriggerSchedulerCallback());
        EXPECT_CALL(*mMockHal.get(), on(Eq(11), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)));
        EXPECT_CALL(*mMockHal.get(), on(Eq(12), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    ASSERT_TRUE(mWrapper->on(10ms, callback).isOk());
    ASSERT_EQ(1, *callbackCounter.get());

    ASSERT_TRUE(mWrapper->on(11ms, callback).isUnsupported());
    ASSERT_TRUE(mWrapper->on(12ms, callback).isFailed());

    // Callback not triggered for unsupported and on failure
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperAidlTest, TestOff) {
    EXPECT_CALL(*mMockHal.get(), off())
            .Times(Exactly(3))
            .WillOnce(Return(Status()))
            .WillOnce(
                    Return(Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)))
            .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));

    ASSERT_TRUE(mWrapper->off().isOk());
    ASSERT_TRUE(mWrapper->off().isUnsupported());
    ASSERT_TRUE(mWrapper->off().isFailed());
}

TEST_F(VibratorHalWrapperAidlTest, TestSetAmplitude) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), setAmplitude(Eq(0.1f))).Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), setAmplitude(Eq(0.2f)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)));
        EXPECT_CALL(*mMockHal.get(), setAmplitude(Eq(0.5f)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    ASSERT_TRUE(mWrapper->setAmplitude(0.1f).isOk());
    ASSERT_TRUE(mWrapper->setAmplitude(0.2f).isUnsupported());
    ASSERT_TRUE(mWrapper->setAmplitude(0.5f).isFailed());
}

TEST_F(VibratorHalWrapperAidlTest, TestSetExternalControl) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), setExternalControl(Eq(true))).Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), setExternalControl(Eq(false)))
                .Times(Exactly(2))
                .WillOnce(Return(
                        Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    ASSERT_TRUE(mWrapper->setExternalControl(true).isOk());
    ASSERT_TRUE(mWrapper->setExternalControl(false).isUnsupported());
    ASSERT_TRUE(mWrapper->setExternalControl(false).isFailed());
}

TEST_F(VibratorHalWrapperAidlTest, TestAlwaysOnEnable) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(),
                    alwaysOnEnable(Eq(1), Eq(Effect::CLICK), Eq(EffectStrength::LIGHT)))
                .Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(),
                    alwaysOnEnable(Eq(2), Eq(Effect::TICK), Eq(EffectStrength::MEDIUM)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)));
        EXPECT_CALL(*mMockHal.get(),
                    alwaysOnEnable(Eq(3), Eq(Effect::POP), Eq(EffectStrength::STRONG)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    auto result = mWrapper->alwaysOnEnable(1, Effect::CLICK, EffectStrength::LIGHT);
    ASSERT_TRUE(result.isOk());
    result = mWrapper->alwaysOnEnable(2, Effect::TICK, EffectStrength::MEDIUM);
    ASSERT_TRUE(result.isUnsupported());
    result = mWrapper->alwaysOnEnable(3, Effect::POP, EffectStrength::STRONG);
    ASSERT_TRUE(result.isFailed());
}

TEST_F(VibratorHalWrapperAidlTest, TestAlwaysOnDisable) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), alwaysOnDisable(Eq(1))).Times(Exactly(1));
        EXPECT_CALL(*mMockHal.get(), alwaysOnDisable(Eq(2)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(
                        Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)));
        EXPECT_CALL(*mMockHal.get(), alwaysOnDisable(Eq(3)))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    ASSERT_TRUE(mWrapper->alwaysOnDisable(1).isOk());
    ASSERT_TRUE(mWrapper->alwaysOnDisable(2).isUnsupported());
    ASSERT_TRUE(mWrapper->alwaysOnDisable(3).isFailed());
}

TEST_F(VibratorHalWrapperAidlTest, TestGetInfoDoesNotCacheFailedResult) {
    constexpr float F_MIN = 100.f;
    constexpr float F0 = 123.f;
    constexpr float F_RESOLUTION = 0.5f;
    constexpr float Q_FACTOR = 123.f;
    constexpr int32_t COMPOSITION_SIZE_MAX = 10;
    constexpr int32_t PWLE_SIZE_MAX = 20;
    constexpr int32_t PRIMITIVE_DELAY_MAX = 100;
    constexpr int32_t PWLE_DURATION_MAX = 200;
    std::vector<Effect> supportedEffects = {Effect::CLICK, Effect::TICK};
    std::vector<CompositePrimitive> supportedPrimitives = {CompositePrimitive::CLICK};
    std::vector<Braking> supportedBraking = {Braking::CLAB};
    std::vector<float> amplitudes = {0.f, 1.f, 0.f};

    std::vector<std::chrono::milliseconds> primitiveDurations;
    constexpr auto primitiveRange = enum_range<CompositePrimitive>();
    constexpr auto primitiveCount = std::distance(primitiveRange.begin(), primitiveRange.end());
    primitiveDurations.resize(primitiveCount);
    primitiveDurations[static_cast<size_t>(CompositePrimitive::CLICK)] = 10ms;

    EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(IVibrator::CAP_ON_CALLBACK), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getSupportedEffects(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(supportedEffects), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getSupportedBraking(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(supportedBraking), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getSupportedPrimitives(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(supportedPrimitives), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getPrimitiveDuration(Eq(CompositePrimitive::CLICK), _))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<1>(10), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getCompositionSizeMax(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(COMPOSITION_SIZE_MAX), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getCompositionDelayMax(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(PRIMITIVE_DELAY_MAX), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getPwlePrimitiveDurationMax(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(PWLE_DURATION_MAX), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getPwleCompositionSizeMax(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(PWLE_SIZE_MAX), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getFrequencyMinimum(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(F_MIN), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getResonantFrequency(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(F0), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getFrequencyResolution(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(F_RESOLUTION), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getQFactor(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(Q_FACTOR), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getBandwidthAmplitudeMap(_))
            .Times(Exactly(2))
            .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
            .WillRepeatedly(DoAll(SetArgPointee<0>(amplitudes), Return(Status())));

    vibrator::Info failed = mWrapper->getInfo();
    ASSERT_TRUE(failed.capabilities.isFailed());
    ASSERT_TRUE(failed.supportedEffects.isFailed());
    ASSERT_TRUE(failed.supportedBraking.isFailed());
    ASSERT_TRUE(failed.supportedPrimitives.isFailed());
    ASSERT_TRUE(failed.primitiveDurations.isFailed());
    ASSERT_TRUE(failed.primitiveDelayMax.isFailed());
    ASSERT_TRUE(failed.pwlePrimitiveDurationMax.isFailed());
    ASSERT_TRUE(failed.compositionSizeMax.isFailed());
    ASSERT_TRUE(failed.pwleSizeMax.isFailed());
    ASSERT_TRUE(failed.minFrequency.isFailed());
    ASSERT_TRUE(failed.resonantFrequency.isFailed());
    ASSERT_TRUE(failed.frequencyResolution.isFailed());
    ASSERT_TRUE(failed.qFactor.isFailed());
    ASSERT_TRUE(failed.maxAmplitudes.isFailed());

    vibrator::Info successful = mWrapper->getInfo();
    ASSERT_EQ(vibrator::Capabilities::ON_CALLBACK, successful.capabilities.value());
    ASSERT_EQ(supportedEffects, successful.supportedEffects.value());
    ASSERT_EQ(supportedBraking, successful.supportedBraking.value());
    ASSERT_EQ(supportedPrimitives, successful.supportedPrimitives.value());
    ASSERT_EQ(primitiveDurations, successful.primitiveDurations.value());
    ASSERT_EQ(std::chrono::milliseconds(PRIMITIVE_DELAY_MAX), successful.primitiveDelayMax.value());
    ASSERT_EQ(std::chrono::milliseconds(PWLE_DURATION_MAX),
              successful.pwlePrimitiveDurationMax.value());
    ASSERT_EQ(COMPOSITION_SIZE_MAX, successful.compositionSizeMax.value());
    ASSERT_EQ(PWLE_SIZE_MAX, successful.pwleSizeMax.value());
    ASSERT_EQ(F_MIN, successful.minFrequency.value());
    ASSERT_EQ(F0, successful.resonantFrequency.value());
    ASSERT_EQ(F_RESOLUTION, successful.frequencyResolution.value());
    ASSERT_EQ(Q_FACTOR, successful.qFactor.value());
    ASSERT_EQ(amplitudes, successful.maxAmplitudes.value());
}

TEST_F(VibratorHalWrapperAidlTest, TestGetInfoCachesResult) {
    constexpr float F_MIN = 100.f;
    constexpr float F0 = 123.f;
    constexpr int32_t COMPOSITION_SIZE_MAX = 10;
    constexpr int32_t PWLE_SIZE_MAX = 20;
    constexpr int32_t PRIMITIVE_DELAY_MAX = 100;
    constexpr int32_t PWLE_DURATION_MAX = 200;
    std::vector<Effect> supportedEffects = {Effect::CLICK, Effect::TICK};

    EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(IVibrator::CAP_ON_CALLBACK), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getSupportedEffects(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(supportedEffects), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getQFactor(_))
            .Times(Exactly(1))
            .WillRepeatedly(
                    Return(Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)));
    EXPECT_CALL(*mMockHal.get(), getSupportedPrimitives(_))
            .Times(Exactly(1))
            .WillRepeatedly(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)));
    EXPECT_CALL(*mMockHal.get(), getCompositionSizeMax(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(COMPOSITION_SIZE_MAX), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getCompositionDelayMax(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(PRIMITIVE_DELAY_MAX), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getPwlePrimitiveDurationMax(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(PWLE_DURATION_MAX), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getPwleCompositionSizeMax(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(PWLE_SIZE_MAX), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getFrequencyMinimum(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(F_MIN), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getResonantFrequency(_))
            .Times(Exactly(1))
            .WillRepeatedly(DoAll(SetArgPointee<0>(F0), Return(Status())));
    EXPECT_CALL(*mMockHal.get(), getFrequencyResolution(_))
            .Times(Exactly(1))
            .WillRepeatedly(
                    Return(Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)));
    EXPECT_CALL(*mMockHal.get(), getBandwidthAmplitudeMap(_))
            .Times(Exactly(1))
            .WillRepeatedly(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)));
    EXPECT_CALL(*mMockHal.get(), getSupportedBraking(_))
            .Times(Exactly(1))
            .WillRepeatedly(
                    Return(Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)));

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.push_back(
                std::thread([&]() { ASSERT_TRUE(mWrapper->getInfo().capabilities.isOk()); }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    vibrator::Info info = mWrapper->getInfo();
    ASSERT_EQ(vibrator::Capabilities::ON_CALLBACK, info.capabilities.value());
    ASSERT_EQ(supportedEffects, info.supportedEffects.value());
    ASSERT_TRUE(info.supportedBraking.isUnsupported());
    ASSERT_TRUE(info.supportedPrimitives.isUnsupported());
    ASSERT_TRUE(info.primitiveDurations.isUnsupported());
    ASSERT_EQ(std::chrono::milliseconds(PRIMITIVE_DELAY_MAX), info.primitiveDelayMax.value());
    ASSERT_EQ(std::chrono::milliseconds(PWLE_DURATION_MAX), info.pwlePrimitiveDurationMax.value());
    ASSERT_EQ(COMPOSITION_SIZE_MAX, info.compositionSizeMax.value());
    ASSERT_EQ(PWLE_SIZE_MAX, info.pwleSizeMax.value());
    ASSERT_EQ(F_MIN, info.minFrequency.value());
    ASSERT_EQ(F0, info.resonantFrequency.value());
    ASSERT_TRUE(info.frequencyResolution.isUnsupported());
    ASSERT_TRUE(info.qFactor.isUnsupported());
    ASSERT_TRUE(info.maxAmplitudes.isUnsupported());
}

TEST_F(VibratorHalWrapperAidlTest, TestPerformEffectWithCallbackSupport) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
                .Times(Exactly(1))
                .WillRepeatedly(
                        DoAll(SetArgPointee<0>(IVibrator::CAP_PERFORM_CALLBACK), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), perform(Eq(Effect::CLICK), Eq(EffectStrength::LIGHT), _, _))
                .Times(Exactly(1))
                .WillRepeatedly(
                        DoAll(SetArgPointee<3>(1000), TriggerCallbackInArg2(), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), perform(Eq(Effect::POP), Eq(EffectStrength::MEDIUM), _, _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)));
        EXPECT_CALL(*mMockHal.get(), perform(Eq(Effect::THUD), Eq(EffectStrength::STRONG), _, _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    auto result = mWrapper->performEffect(Effect::CLICK, EffectStrength::LIGHT, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(1000ms, result.value());
    ASSERT_EQ(1, *callbackCounter.get());

    result = mWrapper->performEffect(Effect::POP, EffectStrength::MEDIUM, callback);
    ASSERT_TRUE(result.isUnsupported());
    // Callback not triggered for unsupported
    ASSERT_EQ(1, *callbackCounter.get());

    result = mWrapper->performEffect(Effect::THUD, EffectStrength::STRONG, callback);
    ASSERT_TRUE(result.isFailed());
    // Callback not triggered on failure
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperAidlTest, TestPerformEffectWithoutCallbackSupport) {
    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getCapabilities(_))
                .Times(Exactly(1))
                .WillRepeatedly(
                        DoAll(SetArgPointee<0>(IVibrator::CAP_ON_CALLBACK), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), perform(Eq(Effect::CLICK), Eq(EffectStrength::LIGHT), _, _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<3>(10), Return(Status())));
        EXPECT_CALL(*mMockScheduler.get(), schedule(_, Eq(10ms)))
                .Times(Exactly(1))
                .WillRepeatedly(vibrator::TriggerSchedulerCallback());
        EXPECT_CALL(*mMockHal.get(), perform(Eq(Effect::POP), Eq(EffectStrength::MEDIUM), _, _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(
                        Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)));
        EXPECT_CALL(*mMockHal.get(), perform(Eq(Effect::THUD), Eq(EffectStrength::STRONG), _, _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    auto result = mWrapper->performEffect(Effect::CLICK, EffectStrength::LIGHT, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(10ms, result.value());
    ASSERT_EQ(1, *callbackCounter.get());

    result = mWrapper->performEffect(Effect::POP, EffectStrength::MEDIUM, callback);
    ASSERT_TRUE(result.isUnsupported());

    result = mWrapper->performEffect(Effect::THUD, EffectStrength::STRONG, callback);
    ASSERT_TRUE(result.isFailed());

    // Callback not triggered for unsupported and on failure
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperAidlTest, TestPerformComposedEffect) {
    std::vector<CompositePrimitive> supportedPrimitives = {CompositePrimitive::CLICK,
                                                           CompositePrimitive::SPIN,
                                                           CompositePrimitive::THUD};
    std::vector<CompositeEffect> emptyEffects, singleEffect, multipleEffects;
    singleEffect.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::CLICK, 10ms, 0.0f));
    multipleEffects.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::SPIN, 100ms, 0.5f));
    multipleEffects.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::THUD, 1000ms, 1.0f));

    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getSupportedPrimitives(_))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<0>(supportedPrimitives), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), getPrimitiveDuration(Eq(CompositePrimitive::CLICK), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), getPrimitiveDuration(Eq(CompositePrimitive::SPIN), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(2), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), getPrimitiveDuration(Eq(CompositePrimitive::THUD), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(3), Return(Status())));

        EXPECT_CALL(*mMockHal.get(), compose(Eq(emptyEffects), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(TriggerCallbackInArg1(), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), compose(Eq(singleEffect), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromStatusT(UNKNOWN_TRANSACTION)));
        EXPECT_CALL(*mMockHal.get(), compose(Eq(multipleEffects), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    auto result = mWrapper->performComposedEffect(emptyEffects, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(0ms, result.value());
    ASSERT_EQ(1, *callbackCounter.get());

    result = mWrapper->performComposedEffect(singleEffect, callback);
    ASSERT_TRUE(result.isUnsupported());
    // Callback not triggered for unsupported
    ASSERT_EQ(1, *callbackCounter.get());

    result = mWrapper->performComposedEffect(multipleEffects, callback);
    ASSERT_TRUE(result.isFailed());
    // Callback not triggered on failure
    ASSERT_EQ(1, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperAidlTest, TestPerformComposedCachesPrimitiveDurationsAndIgnoresFailures) {
    std::vector<CompositePrimitive> supportedPrimitives = {CompositePrimitive::SPIN,
                                                           CompositePrimitive::THUD};
    std::vector<CompositeEffect> multipleEffects;
    multipleEffects.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::SPIN, 10ms, 0.5f));
    multipleEffects.push_back(
            vibrator::TestFactory::createCompositeEffect(CompositePrimitive::THUD, 100ms, 1.0f));

    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), getSupportedPrimitives(_))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<0>(supportedPrimitives), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), getPrimitiveDuration(Eq(CompositePrimitive::SPIN), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(2), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), getPrimitiveDuration(Eq(CompositePrimitive::THUD), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)));
        EXPECT_CALL(*mMockHal.get(), compose(Eq(multipleEffects), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(TriggerCallbackInArg1(), Return(Status())));

        EXPECT_CALL(*mMockHal.get(), getPrimitiveDuration(Eq(CompositePrimitive::SPIN), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(2), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), getPrimitiveDuration(Eq(CompositePrimitive::THUD), _))
                .Times(Exactly(1))
                .WillRepeatedly(DoAll(SetArgPointee<1>(2), Return(Status())));
        EXPECT_CALL(*mMockHal.get(), compose(Eq(multipleEffects), _))
                .Times(Exactly(2))
                .WillRepeatedly(DoAll(TriggerCallbackInArg1(), Return(Status())));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    auto result = mWrapper->performComposedEffect(multipleEffects, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(112ms, result.value()); // Failed primitive durations counted as 1.
    ASSERT_EQ(1, *callbackCounter.get());

    result = mWrapper->performComposedEffect(multipleEffects, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(114ms, result.value()); // Second fetch succeeds and returns primitive duration.
    ASSERT_EQ(2, *callbackCounter.get());

    result = mWrapper->performComposedEffect(multipleEffects, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(114ms, result.value()); // Cached durations not fetched again, same duration returned.
    ASSERT_EQ(3, *callbackCounter.get());
}

TEST_F(VibratorHalWrapperAidlTest, TestPerformPwleEffect) {
    std::vector<PrimitivePwle> emptyPrimitives, multiplePrimitives;
    multiplePrimitives.push_back(vibrator::TestFactory::createActivePwle(0, 1, 0, 1, 10ms));
    multiplePrimitives.push_back(vibrator::TestFactory::createBrakingPwle(Braking::NONE, 100ms));

    {
        InSequence seq;
        EXPECT_CALL(*mMockHal.get(), composePwle(Eq(emptyPrimitives), _))
                .Times(Exactly(1))
                .WillRepeatedly(Return(
                        Status::fromExceptionCode(Status::Exception::EX_UNSUPPORTED_OPERATION)));
        EXPECT_CALL(*mMockHal.get(), composePwle(Eq(multiplePrimitives), _))
                .Times(Exactly(2))
                .WillOnce(Return(Status::fromExceptionCode(Status::Exception::EX_SECURITY)))
                .WillRepeatedly(DoAll(TriggerCallbackInArg1(), Return(Status())));
    }

    std::unique_ptr<int32_t> callbackCounter = std::make_unique<int32_t>();
    auto callback = vibrator::TestFactory::createCountingCallback(callbackCounter.get());

    auto result = mWrapper->performPwleEffect(emptyPrimitives, callback);
    ASSERT_TRUE(result.isUnsupported());
    // Callback not triggered on failure
    ASSERT_EQ(0, *callbackCounter.get());

    result = mWrapper->performPwleEffect(multiplePrimitives, callback);
    ASSERT_TRUE(result.isFailed());
    // Callback not triggered for unsupported
    ASSERT_EQ(0, *callbackCounter.get());

    result = mWrapper->performPwleEffect(multiplePrimitives, callback);
    ASSERT_TRUE(result.isOk());
    ASSERT_EQ(1, *callbackCounter.get());
}
