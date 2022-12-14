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

#include "SingleTouchInputMapper.h"

namespace android {

SingleTouchInputMapper::SingleTouchInputMapper(InputDeviceContext& deviceContext)
      : TouchInputMapper(deviceContext) {}

SingleTouchInputMapper::~SingleTouchInputMapper() {}

void SingleTouchInputMapper::reset(nsecs_t when) {
    mSingleTouchMotionAccumulator.reset(getDeviceContext());

    TouchInputMapper::reset(when);
}

void SingleTouchInputMapper::process(const RawEvent* rawEvent) {
    TouchInputMapper::process(rawEvent);

    mSingleTouchMotionAccumulator.process(rawEvent);
}

void SingleTouchInputMapper::syncTouch(nsecs_t when, RawState* outState) {
    if (mTouchButtonAccumulator.isToolActive()) {
        outState->rawPointerData.pointerCount = 1;
        outState->rawPointerData.idToIndex[0] = 0;

        bool isHovering = mTouchButtonAccumulator.getToolType() != AMOTION_EVENT_TOOL_TYPE_MOUSE &&
                (mTouchButtonAccumulator.isHovering() ||
                 (mRawPointerAxes.pressure.valid &&
                  mSingleTouchMotionAccumulator.getAbsolutePressure() <= 0));
        outState->rawPointerData.markIdBit(0, isHovering);

        RawPointerData::Pointer& outPointer = outState->rawPointerData.pointers[0];
        outPointer.id = 0;
        outPointer.x = mSingleTouchMotionAccumulator.getAbsoluteX();
        outPointer.y = mSingleTouchMotionAccumulator.getAbsoluteY();
        outPointer.pressure = mSingleTouchMotionAccumulator.getAbsolutePressure();
        outPointer.touchMajor = 0;
        outPointer.touchMinor = 0;
        outPointer.toolMajor = mSingleTouchMotionAccumulator.getAbsoluteToolWidth();
        outPointer.toolMinor = mSingleTouchMotionAccumulator.getAbsoluteToolWidth();
        outPointer.orientation = 0;
        outPointer.distance = mSingleTouchMotionAccumulator.getAbsoluteDistance();
        outPointer.tiltX = mSingleTouchMotionAccumulator.getAbsoluteTiltX();
        outPointer.tiltY = mSingleTouchMotionAccumulator.getAbsoluteTiltY();
        outPointer.toolType = mTouchButtonAccumulator.getToolType();
        if (outPointer.toolType == AMOTION_EVENT_TOOL_TYPE_UNKNOWN) {
            outPointer.toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
        }
        outPointer.isHovering = isHovering;
    }
}

void SingleTouchInputMapper::configureRawPointerAxes() {
    TouchInputMapper::configureRawPointerAxes();

    getAbsoluteAxisInfo(ABS_X, &mRawPointerAxes.x);
    getAbsoluteAxisInfo(ABS_Y, &mRawPointerAxes.y);
    getAbsoluteAxisInfo(ABS_PRESSURE, &mRawPointerAxes.pressure);
    getAbsoluteAxisInfo(ABS_TOOL_WIDTH, &mRawPointerAxes.toolMajor);
    getAbsoluteAxisInfo(ABS_DISTANCE, &mRawPointerAxes.distance);
    getAbsoluteAxisInfo(ABS_TILT_X, &mRawPointerAxes.tiltX);
    getAbsoluteAxisInfo(ABS_TILT_Y, &mRawPointerAxes.tiltY);
}

bool SingleTouchInputMapper::hasStylus() const {
    return mTouchButtonAccumulator.hasStylus();
}

} // namespace android
