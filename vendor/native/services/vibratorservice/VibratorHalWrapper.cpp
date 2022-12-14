/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "VibratorHalWrapper"

#include <android/hardware/vibrator/1.3/IVibrator.h>
#include <android/hardware/vibrator/IVibrator.h>
#include <hardware/vibrator.h>
#include <cmath>

#include <utils/Log.h>

#include <vibratorservice/VibratorCallbackScheduler.h>
#include <vibratorservice/VibratorHalWrapper.h>

using android::hardware::vibrator::Braking;
using android::hardware::vibrator::CompositeEffect;
using android::hardware::vibrator::CompositePrimitive;
using android::hardware::vibrator::Effect;
using android::hardware::vibrator::EffectStrength;
using android::hardware::vibrator::PrimitivePwle;

using std::chrono::milliseconds;

namespace V1_0 = android::hardware::vibrator::V1_0;
namespace V1_1 = android::hardware::vibrator::V1_1;
namespace V1_2 = android::hardware::vibrator::V1_2;
namespace V1_3 = android::hardware::vibrator::V1_3;
namespace Aidl = android::hardware::vibrator;

namespace android {

namespace vibrator {

// -------------------------------------------------------------------------------------------------

template <class T>
bool isStaticCastValid(Effect effect) {
    T castEffect = static_cast<T>(effect);
    auto iter = hardware::hidl_enum_range<T>();
    return castEffect >= *iter.begin() && castEffect <= *std::prev(iter.end());
}

// -------------------------------------------------------------------------------------------------

const constexpr char* STATUS_T_ERROR_MESSAGE_PREFIX = "status_t = ";
const constexpr char* STATUS_V_1_0_ERROR_MESSAGE_PREFIX =
        "android::hardware::vibrator::V1_0::Status = ";

template <typename T>
HalResult<T> HalResult<T>::fromStatus(V1_0::Status status, T data) {
    switch (status) {
        case V1_0::Status::OK:
            return HalResult<T>::ok(data);
        case V1_0::Status::UNSUPPORTED_OPERATION:
            return HalResult<T>::unsupported();
        default:
            return HalResult<T>::failed(STATUS_V_1_0_ERROR_MESSAGE_PREFIX + toString(status));
    }
}

template <typename T>
template <typename R>
HalResult<T> HalResult<T>::fromReturn(hardware::Return<R>& ret, T data) {
    return ret.isOk() ? HalResult<T>::ok(data) : HalResult<T>::failed(ret.description());
}

template <typename T>
template <typename R>
HalResult<T> HalResult<T>::fromReturn(hardware::Return<R>& ret, V1_0::Status status, T data) {
    return ret.isOk() ? HalResult<T>::fromStatus(status, data)
                      : HalResult<T>::failed(ret.description());
}

// -------------------------------------------------------------------------------------------------

HalResult<void> HalResult<void>::fromStatus(status_t status) {
    if (status == android::OK) {
        return HalResult<void>::ok();
    }
    return HalResult<void>::failed(STATUS_T_ERROR_MESSAGE_PREFIX + statusToString(status));
}

HalResult<void> HalResult<void>::fromStatus(binder::Status status) {
    if (status.exceptionCode() == binder::Status::EX_UNSUPPORTED_OPERATION ||
        status.transactionError() == android::UNKNOWN_TRANSACTION) {
        // UNKNOWN_TRANSACTION means the HAL implementation is an older version, so this is
        // the same as the operation being unsupported by this HAL. Should not retry.
        return HalResult<void>::unsupported();
    }
    if (status.isOk()) {
        return HalResult<void>::ok();
    }
    return HalResult<void>::failed(std::string(status.toString8().c_str()));
}

HalResult<void> HalResult<void>::fromStatus(V1_0::Status status) {
    switch (status) {
        case V1_0::Status::OK:
            return HalResult<void>::ok();
        case V1_0::Status::UNSUPPORTED_OPERATION:
            return HalResult<void>::unsupported();
        default:
            return HalResult<void>::failed(STATUS_V_1_0_ERROR_MESSAGE_PREFIX + toString(status));
    }
}

template <typename R>
HalResult<void> HalResult<void>::fromReturn(hardware::Return<R>& ret) {
    return ret.isOk() ? HalResult<void>::ok() : HalResult<void>::failed(ret.description());
}

// -------------------------------------------------------------------------------------------------

Info HalWrapper::getInfo() {
    getCapabilities();
    getPrimitiveDurations();
    std::lock_guard<std::mutex> lock(mInfoMutex);
    if (mInfoCache.mSupportedEffects.isFailed()) {
        mInfoCache.mSupportedEffects = getSupportedEffectsInternal();
    }
    if (mInfoCache.mSupportedBraking.isFailed()) {
        mInfoCache.mSupportedBraking = getSupportedBrakingInternal();
    }
    if (mInfoCache.mPrimitiveDelayMax.isFailed()) {
        mInfoCache.mPrimitiveDelayMax = getPrimitiveDelayMaxInternal();
    }
    if (mInfoCache.mPwlePrimitiveDurationMax.isFailed()) {
        mInfoCache.mPwlePrimitiveDurationMax = getPrimitiveDurationMaxInternal();
    }
    if (mInfoCache.mCompositionSizeMax.isFailed()) {
        mInfoCache.mCompositionSizeMax = getCompositionSizeMaxInternal();
    }
    if (mInfoCache.mPwleSizeMax.isFailed()) {
        mInfoCache.mPwleSizeMax = getPwleSizeMaxInternal();
    }
    if (mInfoCache.mMinFrequency.isFailed()) {
        mInfoCache.mMinFrequency = getMinFrequencyInternal();
    }
    if (mInfoCache.mResonantFrequency.isFailed()) {
        mInfoCache.mResonantFrequency = getResonantFrequencyInternal();
    }
    if (mInfoCache.mFrequencyResolution.isFailed()) {
        mInfoCache.mFrequencyResolution = getFrequencyResolutionInternal();
    }
    if (mInfoCache.mQFactor.isFailed()) {
        mInfoCache.mQFactor = getQFactorInternal();
    }
    if (mInfoCache.mMaxAmplitudes.isFailed()) {
        mInfoCache.mMaxAmplitudes = getMaxAmplitudesInternal();
    }
    return mInfoCache.get();
}

HalResult<milliseconds> HalWrapper::performComposedEffect(const std::vector<CompositeEffect>&,
                                                          const std::function<void()>&) {
    ALOGV("Skipped performComposedEffect because it's not available in Vibrator HAL");
    return HalResult<milliseconds>::unsupported();
}

HalResult<void> HalWrapper::performPwleEffect(const std::vector<PrimitivePwle>&,
                                              const std::function<void()>&) {
    ALOGV("Skipped performPwleEffect because it's not available in Vibrator HAL");
    return HalResult<void>::unsupported();
}

HalResult<Capabilities> HalWrapper::getCapabilities() {
    std::lock_guard<std::mutex> lock(mInfoMutex);
    if (mInfoCache.mCapabilities.isFailed()) {
        mInfoCache.mCapabilities = getCapabilitiesInternal();
    }
    return mInfoCache.mCapabilities;
}

HalResult<std::vector<milliseconds>> HalWrapper::getPrimitiveDurations() {
    std::lock_guard<std::mutex> lock(mInfoMutex);
    if (mInfoCache.mSupportedPrimitives.isFailed()) {
        mInfoCache.mSupportedPrimitives = getSupportedPrimitivesInternal();
        if (mInfoCache.mSupportedPrimitives.isUnsupported()) {
            mInfoCache.mPrimitiveDurations = HalResult<std::vector<milliseconds>>::unsupported();
        }
    }
    if (mInfoCache.mPrimitiveDurations.isFailed() && mInfoCache.mSupportedPrimitives.isOk()) {
        mInfoCache.mPrimitiveDurations =
                getPrimitiveDurationsInternal(mInfoCache.mSupportedPrimitives.value());
    }
    return mInfoCache.mPrimitiveDurations;
}

HalResult<std::vector<Effect>> HalWrapper::getSupportedEffectsInternal() {
    ALOGV("Skipped getSupportedEffects because it's not available in Vibrator HAL");
    return HalResult<std::vector<Effect>>::unsupported();
}

HalResult<std::vector<Braking>> HalWrapper::getSupportedBrakingInternal() {
    ALOGV("Skipped getSupportedBraking because it's not available in Vibrator HAL");
    return HalResult<std::vector<Braking>>::unsupported();
}

HalResult<std::vector<CompositePrimitive>> HalWrapper::getSupportedPrimitivesInternal() {
    ALOGV("Skipped getSupportedPrimitives because it's not available in Vibrator HAL");
    return HalResult<std::vector<CompositePrimitive>>::unsupported();
}

HalResult<std::vector<milliseconds>> HalWrapper::getPrimitiveDurationsInternal(
        const std::vector<CompositePrimitive>&) {
    ALOGV("Skipped getPrimitiveDurations because it's not available in Vibrator HAL");
    return HalResult<std::vector<milliseconds>>::unsupported();
}

HalResult<milliseconds> HalWrapper::getPrimitiveDelayMaxInternal() {
    ALOGV("Skipped getPrimitiveDelayMaxInternal because it's not available in Vibrator HAL");
    return HalResult<milliseconds>::unsupported();
}

HalResult<milliseconds> HalWrapper::getPrimitiveDurationMaxInternal() {
    ALOGV("Skipped getPrimitiveDurationMaxInternal because it's not available in Vibrator HAL");
    return HalResult<milliseconds>::unsupported();
}

HalResult<int32_t> HalWrapper::getCompositionSizeMaxInternal() {
    ALOGV("Skipped getCompositionSizeMaxInternal because it's not available in Vibrator HAL");
    return HalResult<int32_t>::unsupported();
}

HalResult<int32_t> HalWrapper::getPwleSizeMaxInternal() {
    ALOGV("Skipped getPwleSizeMaxInternal because it's not available in Vibrator HAL");
    return HalResult<int32_t>::unsupported();
}

HalResult<float> HalWrapper::getMinFrequencyInternal() {
    ALOGV("Skipped getMinFrequency because it's not available in Vibrator HAL");
    return HalResult<float>::unsupported();
}

HalResult<float> HalWrapper::getResonantFrequencyInternal() {
    ALOGV("Skipped getResonantFrequency because it's not available in Vibrator HAL");
    return HalResult<float>::unsupported();
}

HalResult<float> HalWrapper::getFrequencyResolutionInternal() {
    ALOGV("Skipped getFrequencyResolution because it's not available in Vibrator HAL");
    return HalResult<float>::unsupported();
}

HalResult<float> HalWrapper::getQFactorInternal() {
    ALOGV("Skipped getQFactor because it's not available in Vibrator HAL");
    return HalResult<float>::unsupported();
}

HalResult<std::vector<float>> HalWrapper::getMaxAmplitudesInternal() {
    ALOGV("Skipped getMaxAmplitudes because it's not available in Vibrator HAL");
    return HalResult<std::vector<float>>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<void> AidlHalWrapper::ping() {
    return HalResult<void>::fromStatus(IInterface::asBinder(getHal())->pingBinder());
}

void AidlHalWrapper::tryReconnect() {
    auto result = mReconnectFn();
    if (!result.isOk()) {
        return;
    }
    sp<Aidl::IVibrator> newHandle = result.value();
    if (newHandle) {
        std::lock_guard<std::mutex> lock(mHandleMutex);
        mHandle = std::move(newHandle);
    }
}

HalResult<void> AidlHalWrapper::on(milliseconds timeout,
                                   const std::function<void()>& completionCallback) {
    HalResult<Capabilities> capabilities = getCapabilities();
    bool supportsCallback = capabilities.isOk() &&
            static_cast<int32_t>(capabilities.value() & Capabilities::ON_CALLBACK);
    auto cb = supportsCallback ? new HalCallbackWrapper(completionCallback) : nullptr;

    auto ret = HalResult<void>::fromStatus(getHal()->on(timeout.count(), cb));
    if (!supportsCallback && ret.isOk()) {
        mCallbackScheduler->schedule(completionCallback, timeout);
    }

    return ret;
}

HalResult<void> AidlHalWrapper::off() {
    return HalResult<void>::fromStatus(getHal()->off());
}

HalResult<void> AidlHalWrapper::setAmplitude(float amplitude) {
    return HalResult<void>::fromStatus(getHal()->setAmplitude(amplitude));
}

HalResult<void> AidlHalWrapper::setExternalControl(bool enabled) {
    return HalResult<void>::fromStatus(getHal()->setExternalControl(enabled));
}

HalResult<void> AidlHalWrapper::alwaysOnEnable(int32_t id, Effect effect, EffectStrength strength) {
    return HalResult<void>::fromStatus(getHal()->alwaysOnEnable(id, effect, strength));
}

HalResult<void> AidlHalWrapper::alwaysOnDisable(int32_t id) {
    return HalResult<void>::fromStatus(getHal()->alwaysOnDisable(id));
}

HalResult<milliseconds> AidlHalWrapper::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    HalResult<Capabilities> capabilities = getCapabilities();
    bool supportsCallback = capabilities.isOk() &&
            static_cast<int32_t>(capabilities.value() & Capabilities::PERFORM_CALLBACK);
    auto cb = supportsCallback ? new HalCallbackWrapper(completionCallback) : nullptr;

    int32_t lengthMs;
    auto result = getHal()->perform(effect, strength, cb, &lengthMs);
    milliseconds length = milliseconds(lengthMs);

    auto ret = HalResult<milliseconds>::fromStatus(result, length);
    if (!supportsCallback && ret.isOk()) {
        mCallbackScheduler->schedule(completionCallback, length);
    }

    return ret;
}

HalResult<milliseconds> AidlHalWrapper::performComposedEffect(
        const std::vector<CompositeEffect>& primitives,
        const std::function<void()>& completionCallback) {
    // This method should always support callbacks, so no need to double check.
    auto cb = new HalCallbackWrapper(completionCallback);

    auto durations = getPrimitiveDurations().valueOr({});
    milliseconds duration(0);
    for (const auto& effect : primitives) {
        auto primitiveIdx = static_cast<size_t>(effect.primitive);
        if (primitiveIdx < durations.size()) {
            duration += durations[primitiveIdx];
        } else {
            // Make sure the returned duration is positive to indicate successful vibration.
            duration += milliseconds(1);
        }
        duration += milliseconds(effect.delayMs);
    }

    return HalResult<milliseconds>::fromStatus(getHal()->compose(primitives, cb), duration);
}

HalResult<void> AidlHalWrapper::performPwleEffect(const std::vector<PrimitivePwle>& primitives,
                                                  const std::function<void()>& completionCallback) {
    // This method should always support callbacks, so no need to double check.
    auto cb = new HalCallbackWrapper(completionCallback);
    return HalResult<void>::fromStatus(getHal()->composePwle(primitives, cb));
}

HalResult<Capabilities> AidlHalWrapper::getCapabilitiesInternal() {
    int32_t capabilities = 0;
    auto result = getHal()->getCapabilities(&capabilities);
    return HalResult<Capabilities>::fromStatus(result, static_cast<Capabilities>(capabilities));
}

HalResult<std::vector<Effect>> AidlHalWrapper::getSupportedEffectsInternal() {
    std::vector<Effect> supportedEffects;
    auto result = getHal()->getSupportedEffects(&supportedEffects);
    return HalResult<std::vector<Effect>>::fromStatus(result, supportedEffects);
}

HalResult<std::vector<Braking>> AidlHalWrapper::getSupportedBrakingInternal() {
    std::vector<Braking> supportedBraking;
    auto result = getHal()->getSupportedBraking(&supportedBraking);
    return HalResult<std::vector<Braking>>::fromStatus(result, supportedBraking);
}

HalResult<std::vector<CompositePrimitive>> AidlHalWrapper::getSupportedPrimitivesInternal() {
    std::vector<CompositePrimitive> supportedPrimitives;
    auto result = getHal()->getSupportedPrimitives(&supportedPrimitives);
    return HalResult<std::vector<CompositePrimitive>>::fromStatus(result, supportedPrimitives);
}

HalResult<std::vector<milliseconds>> AidlHalWrapper::getPrimitiveDurationsInternal(
        const std::vector<CompositePrimitive>& supportedPrimitives) {
    std::vector<milliseconds> durations;
    constexpr auto primitiveRange = enum_range<CompositePrimitive>();
    constexpr auto primitiveCount = std::distance(primitiveRange.begin(), primitiveRange.end());
    durations.resize(primitiveCount);

    for (auto primitive : supportedPrimitives) {
        auto primitiveIdx = static_cast<size_t>(primitive);
        if (primitiveIdx >= durations.size()) {
            // Safety check, should not happen if enum_range is correct.
            ALOGE("Supported primitive %zu is outside range [0,%zu), skipping load duration",
                  primitiveIdx, durations.size());
            continue;
        }
        int32_t duration = 0;
        auto result = getHal()->getPrimitiveDuration(primitive, &duration);
        auto halResult = HalResult<int32_t>::fromStatus(result, duration);
        if (halResult.isUnsupported()) {
            // Should not happen, supported primitives should always support requesting duration.
            ALOGE("Supported primitive %zu returned unsupported for getPrimitiveDuration",
                  primitiveIdx);
        }
        if (halResult.isFailed()) {
            // Fail entire request if one request has failed.
            return HalResult<std::vector<milliseconds>>::failed(result.toString8().c_str());
        }
        durations[primitiveIdx] = milliseconds(duration);
    }

    return HalResult<std::vector<milliseconds>>::ok(durations);
}

HalResult<milliseconds> AidlHalWrapper::getPrimitiveDelayMaxInternal() {
    int32_t delay = 0;
    auto result = getHal()->getCompositionDelayMax(&delay);
    return HalResult<milliseconds>::fromStatus(result, milliseconds(delay));
}

HalResult<milliseconds> AidlHalWrapper::getPrimitiveDurationMaxInternal() {
    int32_t delay = 0;
    auto result = getHal()->getPwlePrimitiveDurationMax(&delay);
    return HalResult<milliseconds>::fromStatus(result, milliseconds(delay));
}

HalResult<int32_t> AidlHalWrapper::getCompositionSizeMaxInternal() {
    int32_t size = 0;
    auto result = getHal()->getCompositionSizeMax(&size);
    return HalResult<int32_t>::fromStatus(result, size);
}

HalResult<int32_t> AidlHalWrapper::getPwleSizeMaxInternal() {
    int32_t size = 0;
    auto result = getHal()->getPwleCompositionSizeMax(&size);
    return HalResult<int32_t>::fromStatus(result, size);
}

HalResult<float> AidlHalWrapper::getMinFrequencyInternal() {
    float minFrequency = 0;
    auto result = getHal()->getFrequencyMinimum(&minFrequency);
    return HalResult<float>::fromStatus(result, minFrequency);
}

HalResult<float> AidlHalWrapper::getResonantFrequencyInternal() {
    float f0 = 0;
    auto result = getHal()->getResonantFrequency(&f0);
    return HalResult<float>::fromStatus(result, f0);
}

HalResult<float> AidlHalWrapper::getFrequencyResolutionInternal() {
    float frequencyResolution = 0;
    auto result = getHal()->getFrequencyResolution(&frequencyResolution);
    return HalResult<float>::fromStatus(result, frequencyResolution);
}

HalResult<float> AidlHalWrapper::getQFactorInternal() {
    float qFactor = 0;
    auto result = getHal()->getQFactor(&qFactor);
    return HalResult<float>::fromStatus(result, qFactor);
}

HalResult<std::vector<float>> AidlHalWrapper::getMaxAmplitudesInternal() {
    std::vector<float> amplitudes;
    auto result = getHal()->getBandwidthAmplitudeMap(&amplitudes);
    return HalResult<std::vector<float>>::fromStatus(result, amplitudes);
}

sp<Aidl::IVibrator> AidlHalWrapper::getHal() {
    std::lock_guard<std::mutex> lock(mHandleMutex);
    return mHandle;
}

// -------------------------------------------------------------------------------------------------

template <typename I>
HalResult<void> HidlHalWrapper<I>::ping() {
    auto result = getHal()->ping();
    return HalResult<void>::fromReturn(result);
}

template <typename I>
void HidlHalWrapper<I>::tryReconnect() {
    sp<I> newHandle = I::tryGetService();
    if (newHandle) {
        std::lock_guard<std::mutex> lock(mHandleMutex);
        mHandle = std::move(newHandle);
    }
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::on(milliseconds timeout,
                                      const std::function<void()>& completionCallback) {
    auto result = getHal()->on(timeout.count());
    auto ret = HalResult<void>::fromStatus(result.withDefault(V1_0::Status::UNKNOWN_ERROR));
    if (ret.isOk()) {
        mCallbackScheduler->schedule(completionCallback, timeout);
    }
    return ret;
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::off() {
    auto result = getHal()->off();
    return HalResult<void>::fromStatus(result.withDefault(V1_0::Status::UNKNOWN_ERROR));
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::setAmplitude(float amplitude) {
    uint8_t amp = static_cast<uint8_t>(amplitude * std::numeric_limits<uint8_t>::max());
    auto result = getHal()->setAmplitude(amp);
    return HalResult<void>::fromStatus(result.withDefault(V1_0::Status::UNKNOWN_ERROR));
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::setExternalControl(bool) {
    ALOGV("Skipped setExternalControl because Vibrator HAL does not support it");
    return HalResult<void>::unsupported();
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::alwaysOnEnable(int32_t, Effect, EffectStrength) {
    ALOGV("Skipped alwaysOnEnable because Vibrator HAL AIDL is not available");
    return HalResult<void>::unsupported();
}

template <typename I>
HalResult<void> HidlHalWrapper<I>::alwaysOnDisable(int32_t) {
    ALOGV("Skipped alwaysOnDisable because Vibrator HAL AIDL is not available");
    return HalResult<void>::unsupported();
}

template <typename I>
HalResult<Capabilities> HidlHalWrapper<I>::getCapabilitiesInternal() {
    hardware::Return<bool> result = getHal()->supportsAmplitudeControl();
    Capabilities capabilities =
            result.withDefault(false) ? Capabilities::AMPLITUDE_CONTROL : Capabilities::NONE;
    return HalResult<Capabilities>::fromReturn(result, capabilities);
}

template <typename I>
template <typename T>
HalResult<milliseconds> HidlHalWrapper<I>::performInternal(
        perform_fn<T> performFn, sp<I> handle, T effect, EffectStrength strength,
        const std::function<void()>& completionCallback) {
    V1_0::Status status;
    int32_t lengthMs;
    auto effectCallback = [&status, &lengthMs](V1_0::Status retStatus, uint32_t retLengthMs) {
        status = retStatus;
        lengthMs = retLengthMs;
    };

    V1_0::EffectStrength effectStrength = static_cast<V1_0::EffectStrength>(strength);
    auto result = std::invoke(performFn, handle, effect, effectStrength, effectCallback);
    milliseconds length = milliseconds(lengthMs);

    auto ret = HalResult<milliseconds>::fromReturn(result, status, length);
    if (ret.isOk()) {
        mCallbackScheduler->schedule(completionCallback, length);
    }

    return ret;
}

template <typename I>
sp<I> HidlHalWrapper<I>::getHal() {
    std::lock_guard<std::mutex> lock(mHandleMutex);
    return mHandle;
}

// -------------------------------------------------------------------------------------------------

HalResult<milliseconds> HidlHalWrapperV1_0::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    if (isStaticCastValid<V1_0::Effect>(effect)) {
        return performInternal(&V1_0::IVibrator::perform, getHal(),
                               static_cast<V1_0::Effect>(effect), strength, completionCallback);
    }

    ALOGV("Skipped performEffect because Vibrator HAL does not support effect %s",
          Aidl::toString(effect).c_str());
    return HalResult<milliseconds>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<milliseconds> HidlHalWrapperV1_1::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    if (isStaticCastValid<V1_0::Effect>(effect)) {
        return performInternal(&V1_1::IVibrator::perform, getHal(),
                               static_cast<V1_0::Effect>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_1::Effect_1_1>(effect)) {
        return performInternal(&V1_1::IVibrator::perform_1_1, getHal(),
                               static_cast<V1_1::Effect_1_1>(effect), strength, completionCallback);
    }

    ALOGV("Skipped performEffect because Vibrator HAL does not support effect %s",
          Aidl::toString(effect).c_str());
    return HalResult<milliseconds>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<milliseconds> HidlHalWrapperV1_2::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    if (isStaticCastValid<V1_0::Effect>(effect)) {
        return performInternal(&V1_2::IVibrator::perform, getHal(),
                               static_cast<V1_0::Effect>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_1::Effect_1_1>(effect)) {
        return performInternal(&V1_2::IVibrator::perform_1_1, getHal(),
                               static_cast<V1_1::Effect_1_1>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_2::Effect>(effect)) {
        return performInternal(&V1_2::IVibrator::perform_1_2, getHal(),
                               static_cast<V1_2::Effect>(effect), strength, completionCallback);
    }

    ALOGV("Skipped performEffect because Vibrator HAL does not support effect %s",
          Aidl::toString(effect).c_str());
    return HalResult<milliseconds>::unsupported();
}

// -------------------------------------------------------------------------------------------------

HalResult<void> HidlHalWrapperV1_3::setExternalControl(bool enabled) {
    auto result = getHal()->setExternalControl(static_cast<uint32_t>(enabled));
    return HalResult<void>::fromStatus(result.withDefault(V1_0::Status::UNKNOWN_ERROR));
}

HalResult<milliseconds> HidlHalWrapperV1_3::performEffect(
        Effect effect, EffectStrength strength, const std::function<void()>& completionCallback) {
    if (isStaticCastValid<V1_0::Effect>(effect)) {
        return performInternal(&V1_3::IVibrator::perform, getHal(),
                               static_cast<V1_0::Effect>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_1::Effect_1_1>(effect)) {
        return performInternal(&V1_3::IVibrator::perform_1_1, getHal(),
                               static_cast<V1_1::Effect_1_1>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_2::Effect>(effect)) {
        return performInternal(&V1_3::IVibrator::perform_1_2, getHal(),
                               static_cast<V1_2::Effect>(effect), strength, completionCallback);
    }
    if (isStaticCastValid<V1_3::Effect>(effect)) {
        return performInternal(&V1_3::IVibrator::perform_1_3, getHal(),
                               static_cast<V1_3::Effect>(effect), strength, completionCallback);
    }

    ALOGV("Skipped performEffect because Vibrator HAL does not support effect %s",
          Aidl::toString(effect).c_str());
    return HalResult<milliseconds>::unsupported();
}

HalResult<Capabilities> HidlHalWrapperV1_3::getCapabilitiesInternal() {
    Capabilities capabilities = Capabilities::NONE;

    sp<V1_3::IVibrator> hal = getHal();
    auto amplitudeResult = hal->supportsAmplitudeControl();
    if (!amplitudeResult.isOk()) {
        return HalResult<Capabilities>::fromReturn(amplitudeResult, capabilities);
    }

    auto externalControlResult = hal->supportsExternalControl();
    if (amplitudeResult.withDefault(false)) {
        capabilities |= Capabilities::AMPLITUDE_CONTROL;
    }
    if (externalControlResult.withDefault(false)) {
        capabilities |= Capabilities::EXTERNAL_CONTROL;

        if (amplitudeResult.withDefault(false)) {
            capabilities |= Capabilities::EXTERNAL_AMPLITUDE_CONTROL;
        }
    }

    return HalResult<Capabilities>::fromReturn(externalControlResult, capabilities);
}

// -------------------------------------------------------------------------------------------------

}; // namespace vibrator

}; // namespace android
