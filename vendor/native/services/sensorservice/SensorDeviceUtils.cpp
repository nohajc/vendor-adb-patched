/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "SensorDeviceUtils.h"

#include <android/hardware/sensors/1.0/ISensors.h>
#include <android/hardware/sensors/2.1/ISensors.h>
#include <utils/Log.h>

#include <chrono>
#include <thread>

using ::android::hardware::Void;
using SensorTypeV2_1 = android::hardware::sensors::V2_1::SensorType;
using namespace android::hardware::sensors::V1_0;

namespace android {
namespace SensorDeviceUtils {

void quantizeSensorEventValues(sensors_event_t *event, float resolution) {
    LOG_FATAL_IF(resolution == 0, "Resolution must be specified for all sensors!");
    if (resolution == 0) {
        return;
    }

    size_t axes = 0;
    switch ((SensorTypeV2_1)event->type) {
        case SensorTypeV2_1::ACCELEROMETER:
        case SensorTypeV2_1::MAGNETIC_FIELD:
        case SensorTypeV2_1::GYROSCOPE:
        case SensorTypeV2_1::MAGNETIC_FIELD_UNCALIBRATED:
        case SensorTypeV2_1::GYROSCOPE_UNCALIBRATED:
        case SensorTypeV2_1::ACCELEROMETER_UNCALIBRATED:
            axes = 3;
            break;
        case SensorTypeV2_1::DEVICE_ORIENTATION:
        case SensorTypeV2_1::LIGHT:
        case SensorTypeV2_1::PRESSURE:
        case SensorTypeV2_1::TEMPERATURE:
        case SensorTypeV2_1::PROXIMITY:
        case SensorTypeV2_1::RELATIVE_HUMIDITY:
        case SensorTypeV2_1::AMBIENT_TEMPERATURE:
        case SensorTypeV2_1::SIGNIFICANT_MOTION:
        case SensorTypeV2_1::STEP_DETECTOR:
        case SensorTypeV2_1::TILT_DETECTOR:
        case SensorTypeV2_1::WAKE_GESTURE:
        case SensorTypeV2_1::GLANCE_GESTURE:
        case SensorTypeV2_1::PICK_UP_GESTURE:
        case SensorTypeV2_1::WRIST_TILT_GESTURE:
        case SensorTypeV2_1::STATIONARY_DETECT:
        case SensorTypeV2_1::MOTION_DETECT:
        case SensorTypeV2_1::HEART_BEAT:
        case SensorTypeV2_1::LOW_LATENCY_OFFBODY_DETECT:
        case SensorTypeV2_1::HINGE_ANGLE:
            axes = 1;
            break;
        default:
            // No other sensors have data that needs to be quantized.
            break;
    }

    // sensor_event_t is a union so we're able to perform the same quanitization action for most
    // sensors by only knowing the number of axes their output data has.
    for (size_t i = 0; i < axes; i++) {
        quantizeValue(&event->data[i], resolution);
    }
}

float defaultResolutionForType(int type) {
    switch ((SensorTypeV2_1)type) {
        case SensorTypeV2_1::SIGNIFICANT_MOTION:
        case SensorTypeV2_1::STEP_DETECTOR:
        case SensorTypeV2_1::STEP_COUNTER:
        case SensorTypeV2_1::TILT_DETECTOR:
        case SensorTypeV2_1::WAKE_GESTURE:
        case SensorTypeV2_1::GLANCE_GESTURE:
        case SensorTypeV2_1::PICK_UP_GESTURE:
        case SensorTypeV2_1::WRIST_TILT_GESTURE:
        case SensorTypeV2_1::STATIONARY_DETECT:
        case SensorTypeV2_1::MOTION_DETECT:
            return 1.0f;
        default:
            // fall through and return 0 for all other types
            break;
    }
    return 0.0f;
}

HidlServiceRegistrationWaiter::HidlServiceRegistrationWaiter() {
}

void HidlServiceRegistrationWaiter::onFirstRef() {
    // Creating sp<...>(this) in the constructor should be avoided, hence
    // registerForNotifications is called in onFirstRef callback.
    mRegistered = ISensors::registerForNotifications("default", this);
}

Return<void> HidlServiceRegistrationWaiter::onRegistration(
        const hidl_string &fqName, const hidl_string &name, bool preexisting) {
    ALOGV("onRegistration fqName %s, name %s, preexisting %d",
          fqName.c_str(), name.c_str(), preexisting);

    {
        std::lock_guard<std::mutex> lk(mLock);
        mRestartObserved = true;
    }
    mCondition.notify_all();
    return Void();
}

void HidlServiceRegistrationWaiter::reset() {
    std::lock_guard<std::mutex> lk(mLock);
    mRestartObserved = false;
}

bool HidlServiceRegistrationWaiter::wait() {
    constexpr int DEFAULT_WAIT_MS = 100;
    constexpr int TIMEOUT_MS = 1000;

    if (!mRegistered) {
        ALOGW("Cannot register service notification, use default wait(%d ms)", DEFAULT_WAIT_MS);
        std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_WAIT_MS));
        // not sure if service is actually restarted
        return false;
    }

    std::unique_lock<std::mutex> lk(mLock);
    return mCondition.wait_for(lk, std::chrono::milliseconds(TIMEOUT_MS),
            [this]{return mRestartObserved;});
}

} // namespace SensorDeviceUtils
} // namespace android
