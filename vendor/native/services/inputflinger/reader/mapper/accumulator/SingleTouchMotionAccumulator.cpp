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

#include "SingleTouchMotionAccumulator.h"

#include "EventHub.h"
#include "InputDevice.h"

namespace android {

SingleTouchMotionAccumulator::SingleTouchMotionAccumulator() {
    clearAbsoluteAxes();
}

void SingleTouchMotionAccumulator::reset(InputDeviceContext& deviceContext) {
    mAbsX = deviceContext.getAbsoluteAxisValue(ABS_X);
    mAbsY = deviceContext.getAbsoluteAxisValue(ABS_Y);
    mAbsPressure = deviceContext.getAbsoluteAxisValue(ABS_PRESSURE);
    mAbsToolWidth = deviceContext.getAbsoluteAxisValue(ABS_TOOL_WIDTH);
    mAbsDistance = deviceContext.getAbsoluteAxisValue(ABS_DISTANCE);
    mAbsTiltX = deviceContext.getAbsoluteAxisValue(ABS_TILT_X);
    mAbsTiltY = deviceContext.getAbsoluteAxisValue(ABS_TILT_Y);
}

void SingleTouchMotionAccumulator::clearAbsoluteAxes() {
    mAbsX = 0;
    mAbsY = 0;
    mAbsPressure = 0;
    mAbsToolWidth = 0;
    mAbsDistance = 0;
    mAbsTiltX = 0;
    mAbsTiltY = 0;
}

void SingleTouchMotionAccumulator::process(const RawEvent* rawEvent) {
    if (rawEvent->type == EV_ABS) {
        switch (rawEvent->code) {
            case ABS_X:
                mAbsX = rawEvent->value;
                break;
            case ABS_Y:
                mAbsY = rawEvent->value;
                break;
            case ABS_PRESSURE:
                mAbsPressure = rawEvent->value;
                break;
            case ABS_TOOL_WIDTH:
                mAbsToolWidth = rawEvent->value;
                break;
            case ABS_DISTANCE:
                mAbsDistance = rawEvent->value;
                break;
            case ABS_TILT_X:
                mAbsTiltX = rawEvent->value;
                break;
            case ABS_TILT_Y:
                mAbsTiltY = rawEvent->value;
                break;
        }
    }
}

} // namespace android
