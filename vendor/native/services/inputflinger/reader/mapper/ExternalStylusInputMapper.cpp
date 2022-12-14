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

#include "ExternalStylusInputMapper.h"

#include "SingleTouchMotionAccumulator.h"
#include "TouchButtonAccumulator.h"

namespace android {

ExternalStylusInputMapper::ExternalStylusInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext) {}

uint32_t ExternalStylusInputMapper::getSources() {
    return AINPUT_SOURCE_STYLUS;
}

void ExternalStylusInputMapper::populateDeviceInfo(InputDeviceInfo* info) {
    InputMapper::populateDeviceInfo(info);
    info->addMotionRange(AMOTION_EVENT_AXIS_PRESSURE, AINPUT_SOURCE_STYLUS, 0.0f, 1.0f, 0.0f, 0.0f,
                         0.0f);
}

void ExternalStylusInputMapper::dump(std::string& dump) {
    dump += INDENT2 "External Stylus Input Mapper:\n";
    dump += INDENT3 "Raw Stylus Axes:\n";
    dumpRawAbsoluteAxisInfo(dump, mRawPressureAxis, "Pressure");
    dump += INDENT3 "Stylus State:\n";
    dumpStylusState(dump, mStylusState);
}

void ExternalStylusInputMapper::configure(nsecs_t when, const InputReaderConfiguration* config,
                                          uint32_t changes) {
    getAbsoluteAxisInfo(ABS_PRESSURE, &mRawPressureAxis);
    mTouchButtonAccumulator.configure(getDeviceContext());
}

void ExternalStylusInputMapper::reset(nsecs_t when) {
    mSingleTouchMotionAccumulator.reset(getDeviceContext());
    mTouchButtonAccumulator.reset(getDeviceContext());
    InputMapper::reset(when);
}

void ExternalStylusInputMapper::process(const RawEvent* rawEvent) {
    mSingleTouchMotionAccumulator.process(rawEvent);
    mTouchButtonAccumulator.process(rawEvent);

    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        sync(rawEvent->when);
    }
}

void ExternalStylusInputMapper::sync(nsecs_t when) {
    mStylusState.clear();

    mStylusState.when = when;

    mStylusState.toolType = mTouchButtonAccumulator.getToolType();
    if (mStylusState.toolType == AMOTION_EVENT_TOOL_TYPE_UNKNOWN) {
        mStylusState.toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
    }

    int32_t pressure = mSingleTouchMotionAccumulator.getAbsolutePressure();
    if (mRawPressureAxis.valid) {
        mStylusState.pressure = float(pressure) / mRawPressureAxis.maxValue;
    } else if (mTouchButtonAccumulator.isToolActive()) {
        mStylusState.pressure = 1.0f;
    } else {
        mStylusState.pressure = 0.0f;
    }

    mStylusState.buttons = mTouchButtonAccumulator.getButtonState();

    getContext()->dispatchExternalStylusState(mStylusState);
}

} // namespace android
