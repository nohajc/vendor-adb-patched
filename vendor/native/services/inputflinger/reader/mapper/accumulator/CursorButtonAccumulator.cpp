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

#include "CursorButtonAccumulator.h"

#include "EventHub.h"
#include "InputDevice.h"

namespace android {

CursorButtonAccumulator::CursorButtonAccumulator() {
    clearButtons();
}

void CursorButtonAccumulator::reset(InputDeviceContext& deviceContext) {
    mBtnLeft = deviceContext.isKeyPressed(BTN_LEFT);
    mBtnRight = deviceContext.isKeyPressed(BTN_RIGHT);
    mBtnMiddle = deviceContext.isKeyPressed(BTN_MIDDLE);
    mBtnBack = deviceContext.isKeyPressed(BTN_BACK);
    mBtnSide = deviceContext.isKeyPressed(BTN_SIDE);
    mBtnForward = deviceContext.isKeyPressed(BTN_FORWARD);
    mBtnExtra = deviceContext.isKeyPressed(BTN_EXTRA);
    mBtnTask = deviceContext.isKeyPressed(BTN_TASK);
}

void CursorButtonAccumulator::clearButtons() {
    mBtnLeft = 0;
    mBtnRight = 0;
    mBtnMiddle = 0;
    mBtnBack = 0;
    mBtnSide = 0;
    mBtnForward = 0;
    mBtnExtra = 0;
    mBtnTask = 0;
}

void CursorButtonAccumulator::process(const RawEvent* rawEvent) {
    if (rawEvent->type == EV_KEY) {
        switch (rawEvent->code) {
            case BTN_LEFT:
                mBtnLeft = rawEvent->value;
                break;
            case BTN_RIGHT:
                mBtnRight = rawEvent->value;
                break;
            case BTN_MIDDLE:
                mBtnMiddle = rawEvent->value;
                break;
            case BTN_BACK:
                mBtnBack = rawEvent->value;
                break;
            case BTN_SIDE:
                mBtnSide = rawEvent->value;
                break;
            case BTN_FORWARD:
                mBtnForward = rawEvent->value;
                break;
            case BTN_EXTRA:
                mBtnExtra = rawEvent->value;
                break;
            case BTN_TASK:
                mBtnTask = rawEvent->value;
                break;
        }
    }
}

uint32_t CursorButtonAccumulator::getButtonState() const {
    uint32_t result = 0;
    if (mBtnLeft) {
        result |= AMOTION_EVENT_BUTTON_PRIMARY;
    }
    if (mBtnRight) {
        result |= AMOTION_EVENT_BUTTON_SECONDARY;
    }
    if (mBtnMiddle) {
        result |= AMOTION_EVENT_BUTTON_TERTIARY;
    }
    if (mBtnBack || mBtnSide) {
        result |= AMOTION_EVENT_BUTTON_BACK;
    }
    if (mBtnForward || mBtnExtra) {
        result |= AMOTION_EVENT_BUTTON_FORWARD;
    }
    return result;
}

} // namespace android
