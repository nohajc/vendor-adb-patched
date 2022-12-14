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

#ifndef VIBRATORSERVICE_UNITTEST_UTIL_H_
#define VIBRATORSERVICE_UNITTEST_UTIL_H_

#include <android/hardware/vibrator/IVibrator.h>

#include <vibratorservice/VibratorHalWrapper.h>

namespace android {

namespace vibrator {

using ::android::hardware::vibrator::ActivePwle;
using ::android::hardware::vibrator::Braking;
using ::android::hardware::vibrator::BrakingPwle;
using ::android::hardware::vibrator::CompositeEffect;
using ::android::hardware::vibrator::CompositePrimitive;
using ::android::hardware::vibrator::PrimitivePwle;

// -------------------------------------------------------------------------------------------------

class MockCallbackScheduler : public vibrator::CallbackScheduler {
public:
    MOCK_METHOD(void, schedule, (std::function<void()> callback, std::chrono::milliseconds delay),
                (override));
};

ACTION(TriggerSchedulerCallback) {
    arg0();
}

// -------------------------------------------------------------------------------------------------

class TestFactory {
public:
    static CompositeEffect createCompositeEffect(CompositePrimitive primitive,
                                                 std::chrono::milliseconds delay, float scale) {
        CompositeEffect effect;
        effect.primitive = primitive;
        effect.delayMs = delay.count();
        effect.scale = scale;
        return effect;
    }

    static PrimitivePwle createActivePwle(float startAmplitude, float startFrequency,
                                          float endAmplitude, float endFrequency,
                                          std::chrono::milliseconds duration) {
        ActivePwle pwle;
        pwle.startAmplitude = startAmplitude;
        pwle.endAmplitude = endAmplitude;
        pwle.startFrequency = startFrequency;
        pwle.endFrequency = endFrequency;
        pwle.duration = duration.count();
        return pwle;
    }

    static PrimitivePwle createBrakingPwle(Braking braking, std::chrono::milliseconds duration) {
        BrakingPwle pwle;
        pwle.braking = braking;
        pwle.duration = duration.count();
        return pwle;
    }

    static std::function<void()> createCountingCallback(int32_t* counter) {
        return [counter]() { *counter += 1; };
    }

private:
    TestFactory() = delete;
    ~TestFactory() = delete;
};

// -------------------------------------------------------------------------------------------------

} // namespace vibrator

} // namespace android

#endif // VIBRATORSERVICE_UNITTEST_UTIL_H_