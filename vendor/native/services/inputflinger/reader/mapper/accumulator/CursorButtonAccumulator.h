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

#ifndef _UI_INPUTREADER_CURSOR_BUTTON_ACCUMULATOR_H
#define _UI_INPUTREADER_CURSOR_BUTTON_ACCUMULATOR_H

#include <stdint.h>

namespace android {

class InputDeviceContext;
struct RawEvent;

/* Keeps track of the state of mouse or touch pad buttons. */
class CursorButtonAccumulator {
public:
    CursorButtonAccumulator();
    void reset(InputDeviceContext& deviceContext);

    void process(const RawEvent* rawEvent);

    uint32_t getButtonState() const;

private:
    bool mBtnLeft;
    bool mBtnRight;
    bool mBtnMiddle;
    bool mBtnBack;
    bool mBtnSide;
    bool mBtnForward;
    bool mBtnExtra;
    bool mBtnTask;

    void clearButtons();
};

} // namespace android

#endif // _UI_INPUTREADER_CURSOR_BUTTON_ACCUMULATOR_H