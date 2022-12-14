/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "../Macros.h"

#include "InputMapper.h"

#include "InputDevice.h"

namespace android {

InputMapper::InputMapper(InputDeviceContext& deviceContext) : mDeviceContext(deviceContext) {}

InputMapper::~InputMapper() {}

void InputMapper::populateDeviceInfo(InputDeviceInfo* info) {
    info->addSource(getSources());
}

void InputMapper::dump(std::string& dump) {}

void InputMapper::configure(nsecs_t when, const InputReaderConfiguration* config,
                            uint32_t changes) {}

void InputMapper::reset(nsecs_t when) {}

void InputMapper::timeoutExpired(nsecs_t when) {}

int32_t InputMapper::getKeyCodeState(uint32_t sourceMask, int32_t keyCode) {
    return AKEY_STATE_UNKNOWN;
}

int32_t InputMapper::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    return AKEY_STATE_UNKNOWN;
}

int32_t InputMapper::getSwitchState(uint32_t sourceMask, int32_t switchCode) {
    return AKEY_STATE_UNKNOWN;
}

bool InputMapper::markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes,
                                        const int32_t* keyCodes, uint8_t* outFlags) {
    return false;
}

void InputMapper::vibrate(const nsecs_t* pattern, size_t patternSize, ssize_t repeat,
                          int32_t token) {}

void InputMapper::cancelVibrate(int32_t token) {}

void InputMapper::cancelTouch(nsecs_t when) {}

int32_t InputMapper::getMetaState() {
    return 0;
}

void InputMapper::updateMetaState(int32_t keyCode) {}

void InputMapper::updateExternalStylusState(const StylusState& state) {}

status_t InputMapper::getAbsoluteAxisInfo(int32_t axis, RawAbsoluteAxisInfo* axisInfo) {
    return getDeviceContext().getAbsoluteAxisInfo(axis, axisInfo);
}

void InputMapper::bumpGeneration() {
    getDeviceContext().bumpGeneration();
}

void InputMapper::dumpRawAbsoluteAxisInfo(std::string& dump, const RawAbsoluteAxisInfo& axis,
                                          const char* name) {
    if (axis.valid) {
        dump += StringPrintf(INDENT4 "%s: min=%d, max=%d, flat=%d, fuzz=%d, resolution=%d\n", name,
                             axis.minValue, axis.maxValue, axis.flat, axis.fuzz, axis.resolution);
    } else {
        dump += StringPrintf(INDENT4 "%s: unknown range\n", name);
    }
}

void InputMapper::dumpStylusState(std::string& dump, const StylusState& state) {
    dump += StringPrintf(INDENT4 "When: %" PRId64 "\n", state.when);
    dump += StringPrintf(INDENT4 "Pressure: %f\n", state.pressure);
    dump += StringPrintf(INDENT4 "Button State: 0x%08x\n", state.buttons);
    dump += StringPrintf(INDENT4 "Tool Type: %" PRId32 "\n", state.toolType);
}

} // namespace android
