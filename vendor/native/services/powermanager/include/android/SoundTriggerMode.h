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

#ifndef ANDROID_OS_SOUNDTRIGGER_MODE_H
#define ANDROID_OS_SOUNDTRIGGER_MODE_H

namespace android::os {

enum class SoundTriggerMode : int32_t {
    ALL_ENABLED = IPowerManager::SOUND_TRIGGER_MODE_ALL_ENABLED,
    CRITICAL_ONLY = IPowerManager::SOUND_TRIGGER_MODE_CRITICAL_ONLY,
    ALL_DISABLED = IPowerManager::SOUND_TRIGGER_MODE_ALL_DISABLED,
    MIN = IPowerManager::SOUND_TRIGGER_MODE_ALL_ENABLED,
    MAX = IPowerManager::SOUND_TRIGGER_MODE_ALL_DISABLED,
};

} // namespace android::os

#endif /* ANDROID_OS_SOUNDTRIGGER_MODE_H */
