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

#include "SwitchInputMapper.h"

namespace android {

SwitchInputMapper::SwitchInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext), mSwitchValues(0), mUpdatedSwitchMask(0) {}

SwitchInputMapper::~SwitchInputMapper() {}

uint32_t SwitchInputMapper::getSources() {
    return AINPUT_SOURCE_SWITCH;
}

void SwitchInputMapper::process(const RawEvent* rawEvent) {
    switch (rawEvent->type) {
        case EV_SW:
            processSwitch(rawEvent->code, rawEvent->value);
            break;

        case EV_SYN:
            if (rawEvent->code == SYN_REPORT) {
                sync(rawEvent->when);
            }
    }
}

void SwitchInputMapper::processSwitch(int32_t switchCode, int32_t switchValue) {
    if (switchCode >= 0 && switchCode < 32) {
        if (switchValue) {
            mSwitchValues |= 1 << switchCode;
        } else {
            mSwitchValues &= ~(1 << switchCode);
        }
        mUpdatedSwitchMask |= 1 << switchCode;
    }
}

void SwitchInputMapper::sync(nsecs_t when) {
    if (mUpdatedSwitchMask) {
        uint32_t updatedSwitchValues = mSwitchValues & mUpdatedSwitchMask;
        NotifySwitchArgs args(getContext()->getNextId(), when, 0 /*policyFlags*/,
                              updatedSwitchValues, mUpdatedSwitchMask);
        getListener()->notifySwitch(&args);

        mUpdatedSwitchMask = 0;
    }
}

int32_t SwitchInputMapper::getSwitchState(uint32_t sourceMask, int32_t switchCode) {
    return getDeviceContext().getSwitchState(switchCode);
}

void SwitchInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Switch Input Mapper:\n";
    dump += StringPrintf(INDENT3 "SwitchValues: %x\n", mSwitchValues);
}

} // namespace android
