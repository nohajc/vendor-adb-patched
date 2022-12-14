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

#ifndef _UI_INPUTREADER_CURSOR_SCROLL_ACCUMULATOR_H
#define _UI_INPUTREADER_CURSOR_SCROLL_ACCUMULATOR_H

#include <stdint.h>

namespace android {

class InputDeviceContext;
struct RawEvent;

/* Keeps track of cursor scrolling motions. */

class CursorScrollAccumulator {
public:
    CursorScrollAccumulator();
    void configure(InputDeviceContext& deviceContext);
    void reset(InputDeviceContext& deviceContext);

    void process(const RawEvent* rawEvent);
    void finishSync();

    inline bool haveRelativeVWheel() const { return mHaveRelWheel; }
    inline bool haveRelativeHWheel() const { return mHaveRelHWheel; }

    inline int32_t getRelativeX() const { return mRelX; }
    inline int32_t getRelativeY() const { return mRelY; }
    inline int32_t getRelativeVWheel() const { return mRelWheel; }
    inline int32_t getRelativeHWheel() const { return mRelHWheel; }

private:
    bool mHaveRelWheel;
    bool mHaveRelHWheel;

    int32_t mRelX;
    int32_t mRelY;
    int32_t mRelWheel;
    int32_t mRelHWheel;

    void clearRelativeAxes();
};

} // namespace android

#endif // _UI_INPUTREADER_CURSOR_SCROLL_ACCUMULATOR_H