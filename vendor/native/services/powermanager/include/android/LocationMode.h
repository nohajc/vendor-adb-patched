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

#ifndef ANDROID_OS_LOCATION_MODE_H
#define ANDROID_OS_LOCATION_MODE_H

namespace android::os {

enum class LocationMode : int32_t {
    NO_CHANGE = IPowerManager::LOCATION_MODE_NO_CHANGE,
    GPS_DISABLED_WHEN_SCREEN_OFF = IPowerManager::LOCATION_MODE_GPS_DISABLED_WHEN_SCREEN_OFF,
    ALL_DISABLED_WHEN_SCREEN_OFF = IPowerManager::LOCATION_MODE_ALL_DISABLED_WHEN_SCREEN_OFF,
    FOREGROUND_ONLY = IPowerManager::LOCATION_MODE_FOREGROUND_ONLY,
    THROTTLE_REQUESTS_WHEN_SCREEN_OFF =
                IPowerManager::LOCATION_MODE_THROTTLE_REQUESTS_WHEN_SCREEN_OFF,
    MIN = IPowerManager::LOCATION_MODE_NO_CHANGE,
    MAX = IPowerManager::LOCATION_MODE_THROTTLE_REQUESTS_WHEN_SCREEN_OFF,
};

} // namespace android::os

#endif /* ANDROID_OS_LOCATION_MODE_H */
