/*
 * Copyright 2019 The Android Open Source Project
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

#pragma once

#include <cinttypes>
#include <cstdint>

#define ANDROID_PHYSICAL_DISPLAY_ID_FORMAT PRIu64

namespace android {

using PhysicalDisplayId = uint64_t;

constexpr uint8_t getPhysicalDisplayPort(PhysicalDisplayId displayId) {
    return static_cast<uint8_t>(displayId);
}

} // namespace android
