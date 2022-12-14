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

#include "TouchButtonAccumulator.h"

#include "EventHub.h"
#include "InputDevice.h"

namespace android {

TouchButtonAccumulator::TouchButtonAccumulator() : mHaveBtnTouch(false), mHaveStylus(false) {
    clearButtons();
}

void TouchButtonAccumulator::configure(InputDeviceContext& deviceContext) {
    mHaveBtnTouch = deviceContext.hasScanCode(BTN_TOUCH);
    mHaveStylus = deviceContext.hasScanCode(BTN_TOOL_PEN) ||
            deviceContext.hasScanCode(BTN_TOOL_RUBBER) ||
            deviceContext.hasScanCode(BTN_TOOL_BRUSH) ||
            deviceContext.hasScanCode(BTN_TOOL_PENCIL) ||
            deviceContext.hasScanCode(BTN_TOOL_AIRBRUSH);
}

void TouchButtonAccumulator::reset(InputDeviceContext& deviceContext) {
    mBtnTouch = deviceContext.isKeyPressed(BTN_TOUCH);
    mBtnStylus = deviceContext.isKeyPressed(BTN_STYLUS);
    // BTN_0 is what gets mapped for the HID usage Digitizers.SecondaryBarrelSwitch
    mBtnStylus2 = deviceContext.isKeyPressed(BTN_STYLUS2) || deviceContext.isKeyPressed(BTN_0);
    mBtnToolFinger = deviceContext.isKeyPressed(BTN_TOOL_FINGER);
    mBtnToolPen = deviceContext.isKeyPressed(BTN_TOOL_PEN);
    mBtnToolRubber = deviceContext.isKeyPressed(BTN_TOOL_RUBBER);
    mBtnToolBrush = deviceContext.isKeyPressed(BTN_TOOL_BRUSH);
    mBtnToolPencil = deviceContext.isKeyPressed(BTN_TOOL_PENCIL);
    mBtnToolAirbrush = deviceContext.isKeyPressed(BTN_TOOL_AIRBRUSH);
    mBtnToolMouse = deviceContext.isKeyPressed(BTN_TOOL_MOUSE);
    mBtnToolLens = deviceContext.isKeyPressed(BTN_TOOL_LENS);
    mBtnToolDoubleTap = deviceContext.isKeyPressed(BTN_TOOL_DOUBLETAP);
    mBtnToolTripleTap = deviceContext.isKeyPressed(BTN_TOOL_TRIPLETAP);
    mBtnToolQuadTap = deviceContext.isKeyPressed(BTN_TOOL_QUADTAP);
}

void TouchButtonAccumulator::clearButtons() {
    mBtnTouch = 0;
    mBtnStylus = 0;
    mBtnStylus2 = 0;
    mBtnToolFinger = 0;
    mBtnToolPen = 0;
    mBtnToolRubber = 0;
    mBtnToolBrush = 0;
    mBtnToolPencil = 0;
    mBtnToolAirbrush = 0;
    mBtnToolMouse = 0;
    mBtnToolLens = 0;
    mBtnToolDoubleTap = 0;
    mBtnToolTripleTap = 0;
    mBtnToolQuadTap = 0;
}

void TouchButtonAccumulator::process(const RawEvent* rawEvent) {
    if (rawEvent->type == EV_KEY) {
        switch (rawEvent->code) {
            case BTN_TOUCH:
                mBtnTouch = rawEvent->value;
                break;
            case BTN_STYLUS:
                mBtnStylus = rawEvent->value;
                break;
            case BTN_STYLUS2:
            case BTN_0: // BTN_0 is what gets mapped for the HID usage
                        // Digitizers.SecondaryBarrelSwitch
                mBtnStylus2 = rawEvent->value;
                break;
            case BTN_TOOL_FINGER:
                mBtnToolFinger = rawEvent->value;
                break;
            case BTN_TOOL_PEN:
                mBtnToolPen = rawEvent->value;
                break;
            case BTN_TOOL_RUBBER:
                mBtnToolRubber = rawEvent->value;
                break;
            case BTN_TOOL_BRUSH:
                mBtnToolBrush = rawEvent->value;
                break;
            case BTN_TOOL_PENCIL:
                mBtnToolPencil = rawEvent->value;
                break;
            case BTN_TOOL_AIRBRUSH:
                mBtnToolAirbrush = rawEvent->value;
                break;
            case BTN_TOOL_MOUSE:
                mBtnToolMouse = rawEvent->value;
                break;
            case BTN_TOOL_LENS:
                mBtnToolLens = rawEvent->value;
                break;
            case BTN_TOOL_DOUBLETAP:
                mBtnToolDoubleTap = rawEvent->value;
                break;
            case BTN_TOOL_TRIPLETAP:
                mBtnToolTripleTap = rawEvent->value;
                break;
            case BTN_TOOL_QUADTAP:
                mBtnToolQuadTap = rawEvent->value;
                break;
        }
    }
}

uint32_t TouchButtonAccumulator::getButtonState() const {
    uint32_t result = 0;
    if (mBtnStylus) {
        result |= AMOTION_EVENT_BUTTON_STYLUS_PRIMARY;
    }
    if (mBtnStylus2) {
        result |= AMOTION_EVENT_BUTTON_STYLUS_SECONDARY;
    }
    return result;
}

int32_t TouchButtonAccumulator::getToolType() const {
    if (mBtnToolMouse || mBtnToolLens) {
        return AMOTION_EVENT_TOOL_TYPE_MOUSE;
    }
    if (mBtnToolRubber) {
        return AMOTION_EVENT_TOOL_TYPE_ERASER;
    }
    if (mBtnToolPen || mBtnToolBrush || mBtnToolPencil || mBtnToolAirbrush) {
        return AMOTION_EVENT_TOOL_TYPE_STYLUS;
    }
    if (mBtnToolFinger || mBtnToolDoubleTap || mBtnToolTripleTap || mBtnToolQuadTap) {
        return AMOTION_EVENT_TOOL_TYPE_FINGER;
    }
    return AMOTION_EVENT_TOOL_TYPE_UNKNOWN;
}

bool TouchButtonAccumulator::isToolActive() const {
    return mBtnTouch || mBtnToolFinger || mBtnToolPen || mBtnToolRubber || mBtnToolBrush ||
            mBtnToolPencil || mBtnToolAirbrush || mBtnToolMouse || mBtnToolLens ||
            mBtnToolDoubleTap || mBtnToolTripleTap || mBtnToolQuadTap;
}

bool TouchButtonAccumulator::isHovering() const {
    return mHaveBtnTouch && !mBtnTouch;
}

bool TouchButtonAccumulator::hasStylus() const {
    return mHaveStylus;
}

} // namespace android
