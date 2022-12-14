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

#ifndef _VIBRATION_ELEMENT_H
#define _VIBRATION_ELEMENT_H

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace android {

// evdev FF_RUMBLE effect only supports two channels of vibration.
constexpr size_t CHANNEL_SIZE = 2;
/*
 * Describes a rumble effect
 */
struct VibrationElement {
    std::chrono::milliseconds duration;
    // Channel amplitude range 0-255.
    std::vector<std::pair<int32_t /*vibratorId*/, uint8_t /*amplitude*/>> channels;

    explicit VibrationElement(size_t channelNum);

    VibrationElement(const VibrationElement& other);

    bool operator==(const VibrationElement& other) const;

    bool operator!=(const VibrationElement& other) const;

    void addChannel(int32_t vibratorId, uint8_t amplitude);

    const std::string toString() const;

    uint16_t getMagnitude(int32_t vibratorId) const;

    bool isOn() const;
};

/*
 * Describes a sequence of rumble effect
 */
struct VibrationSequence {
    // Pattern of vibration elements
    std::vector<VibrationElement> pattern;

    explicit VibrationSequence(size_t length);

    void operator=(const VibrationSequence& other);

    bool operator==(const VibrationSequence& other) const;

    void addElement(VibrationElement element);

    const std::string toString() const;
};

} // namespace android

#endif // _VIBRATION_ELEMENT_H
