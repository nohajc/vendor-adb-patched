/*
 * Copyright (C) 2021 The Android Open Source Project
 * Android BPF library - public API
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

#include "LongArrayMultiStateCounter.h"
#include <log/log.h>

namespace android {
namespace battery {

template <>
bool LongArrayMultiStateCounter::delta(const std::vector<uint64_t>& previousValue,
                                       const std::vector<uint64_t>& newValue,
                                       std::vector<uint64_t>* outValue) const {
    size_t size = previousValue.size();
    if (newValue.size() != size) {
        ALOGE("Incorrect array size: %d, should be %d", (int)newValue.size(), (int)size);
        return false;
    }

    bool is_delta_valid = true;
    for (int i = size - 1; i >= 0; i--) {
        if (newValue[i] >= previousValue[i]) {
            (*outValue)[i] = newValue[i] - previousValue[i];
        } else {
            (*outValue)[i] = 0;
            is_delta_valid = false;
        }
    }
    return is_delta_valid;
}

template <>
void LongArrayMultiStateCounter::add(std::vector<uint64_t>* value1,
                                     const std::vector<uint64_t>& value2, const uint64_t numerator,
                                     const uint64_t denominator) const {
    if (numerator != denominator) {
        for (int i = value2.size() - 1; i >= 0; i--) {
            // The caller ensures that denominator != 0
            (*value1)[i] += value2[i] * numerator / denominator;
        }
    } else {
        for (int i = value2.size() - 1; i >= 0; i--) {
            (*value1)[i] += value2[i];
        }
    }
}

template <>
std::string LongArrayMultiStateCounter::valueToString(const std::vector<uint64_t>& v) const {
    std::stringstream s;
    s << "{";
    bool first = true;
    for (uint64_t n : v) {
        if (!first) {
            s << ", ";
        }
        s << n;
        first = false;
    }
    s << "}";
    return s.str();
}

} // namespace battery
} // namespace android
