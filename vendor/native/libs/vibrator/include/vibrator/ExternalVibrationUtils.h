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

#ifndef ANDROID_EXTERNAL_VIBRATION_UTILS_H
#define ANDROID_EXTERNAL_VIBRATION_UTILS_H

namespace android::os {

// Copied from frameworks/base/core/java/android/os/IExternalVibratorService.aidl
// The values are checked in ExternalVibration.cpp
enum class HapticScale {
    MUTE = -100,
    VERY_LOW = -2,
    LOW = -1,
    NONE = 0,
    HIGH = 1,
    VERY_HIGH = 2,
};

bool isValidHapticScale(HapticScale scale);

/* Scales the haptic data in given buffer using the selected HapticScale and ensuring no absolute
 * value will be larger than the absolute of given limit.
 * The limit will be ignored if it is NaN or zero.
 */
void scaleHapticData(float* buffer, size_t length, HapticScale scale, float limit);

} // namespace android::os

#endif // ANDROID_EXTERNAL_VIBRATION_UTILS_H
