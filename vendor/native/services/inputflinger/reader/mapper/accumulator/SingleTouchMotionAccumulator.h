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

#ifndef _UI_INPUTREADER_SINGLE_TOUCH_MOTION_ACCUMULATOR_H
#define _UI_INPUTREADER_SINGLE_TOUCH_MOTION_ACCUMULATOR_H

#include <stdint.h>

namespace android {

class InputDeviceContext;
struct RawEvent;

/* Keeps track of the state of single-touch protocol. */
class SingleTouchMotionAccumulator {
public:
    SingleTouchMotionAccumulator();

    void process(const RawEvent* rawEvent);
    void reset(InputDeviceContext& deviceContext);

    inline int32_t getAbsoluteX() const { return mAbsX; }
    inline int32_t getAbsoluteY() const { return mAbsY; }
    inline int32_t getAbsolutePressure() const { return mAbsPressure; }
    inline int32_t getAbsoluteToolWidth() const { return mAbsToolWidth; }
    inline int32_t getAbsoluteDistance() const { return mAbsDistance; }
    inline int32_t getAbsoluteTiltX() const { return mAbsTiltX; }
    inline int32_t getAbsoluteTiltY() const { return mAbsTiltY; }

private:
    int32_t mAbsX;
    int32_t mAbsY;
    int32_t mAbsPressure;
    int32_t mAbsToolWidth;
    int32_t mAbsDistance;
    int32_t mAbsTiltX;
    int32_t mAbsTiltY;

    void clearAbsoluteAxes();
};

} // namespace android

#endif // _UI_INPUTREADER_SINGLE_TOUCH_MOTION_ACCUMULATOR_H