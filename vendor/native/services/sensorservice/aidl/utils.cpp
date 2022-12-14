/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "utils.h"

#include <aidl/android/frameworks/sensorservice/ISensorManager.h>
#include <aidl/sensors/convert.h>

namespace android {
namespace frameworks {
namespace sensorservice {
namespace implementation {

ndk::ScopedAStatus convertResult(status_t src) {
    using ::aidl::android::frameworks::sensorservice::ISensorManager;

    int err = 0;
    switch (src) {
        case OK:
            return ndk::ScopedAStatus::ok();
        case NAME_NOT_FOUND:
            err = ISensorManager::RESULT_NOT_EXIST;
            break;
        case NO_MEMORY:
            err = ISensorManager::RESULT_NO_MEMORY;
            break;
        case NO_INIT:
            err = ISensorManager::RESULT_NO_INIT;
            break;
        case PERMISSION_DENIED:
            err = ISensorManager::RESULT_PERMISSION_DENIED;
            break;
        case BAD_VALUE:
            err = ISensorManager::RESULT_BAD_VALUE;
            break;
        case INVALID_OPERATION:
            err = ISensorManager::RESULT_INVALID_OPERATION;
            break;
        default:
            err = ISensorManager::RESULT_UNKNOWN_ERROR;
    }
    return ndk::ScopedAStatus::fromServiceSpecificError(err);
}

::aidl::android::hardware::sensors::Event convertEvent(const ::ASensorEvent& src) {
    ::aidl::android::hardware::sensors::Event dst;
    ::android::hardware::sensors::implementation::
            convertFromASensorEvent(src, &dst);
    return dst;
}

} // namespace implementation
} // namespace sensorservice
} // namespace frameworks
} // namespace android
