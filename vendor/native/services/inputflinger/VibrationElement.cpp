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

#include "VibrationElement.h"

#include <android-base/stringprintf.h>

#include <algorithm>
#include <cinttypes>

using android::base::StringPrintf;

namespace android {
// VibrationElement implementations
VibrationElement::VibrationElement(size_t channelNum) {
    channels.reserve(channelNum);
}

VibrationElement::VibrationElement(const VibrationElement& other) {
    duration = other.duration;
    channels.resize(other.channels.size());
    for (size_t i = 0; i < other.channels.size(); i++) {
        channels[i].first = other.channels[i].first;
        channels[i].second = other.channels[i].second;
    }
}

const std::string VibrationElement::toString() const {
    std::string dump;
    dump += StringPrintf("[duration=%lldms, channels=[", duration.count());

    for (auto it = channels.begin(); it != channels.end(); ++it) {
        dump += std::to_string(it->first);
        dump += " : ";
        dump += std::to_string(it->second);
        if (std::next(it) != channels.end()) {
            dump += ", ";
        }
    }

    dump += "]]";
    return dump;
}

uint16_t VibrationElement::getMagnitude(int32_t vibratorId) const {
    auto it =
            std::find_if(channels.begin(), channels.end(),
                         [vibratorId](const std::pair<int32_t /*vibratorId*/, uint8_t /*amplitude*/>
                                              pair) { return pair.first == vibratorId; });
    if (it == channels.end()) {
        return 0;
    }
    // convert range [0,255] to [0,65535] (android framework to linux ff ranges)
    return static_cast<uint16_t>(it->second) << 8;
}

bool VibrationElement::isOn() const {
    return std::any_of(channels.begin(), channels.end(),
                       [](const auto& channel) { return channel.second != 0; });
}

void VibrationElement::addChannel(int32_t vibratorId, uint8_t amplitude) {
    channels.push_back(std::make_pair(vibratorId, amplitude));
}

bool VibrationElement::operator==(const VibrationElement& other) const {
    if (duration != other.duration || channels.size() != other.channels.size()) {
        return false;
    }
    for (size_t i = 0; i < CHANNEL_SIZE; i++) {
        if (channels[i] != other.channels[i]) {
            return false;
        }
    }
    return true;
}

bool VibrationElement::operator!=(const VibrationElement& other) const {
    return !(*this == other);
}

// VibrationSequence implementations
VibrationSequence::VibrationSequence(size_t length) {
    pattern.reserve(length);
}

void VibrationSequence::operator=(const VibrationSequence& other) {
    pattern = other.pattern;
}

bool VibrationSequence::operator==(const VibrationSequence& other) const {
    if (pattern.size() != other.pattern.size()) {
        return false;
    }
    for (size_t i = 0; i < pattern.size(); i++) {
        if (pattern[i] != other.pattern[i]) {
            return false;
        }
    }
    return true;
}

void VibrationSequence::addElement(VibrationElement element) {
    pattern.push_back(element);
}

const std::string VibrationSequence::toString() const {
    std::string dump;
    dump += "[";

    for (const auto& element : pattern) {
        dump += element.toString();
        dump += " ";
    }

    dump += "]";
    return dump;
}

} // namespace android
