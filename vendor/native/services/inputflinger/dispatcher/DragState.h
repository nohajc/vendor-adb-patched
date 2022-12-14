/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef _UI_INPUT_INPUTDISPATCHER_DRAGSTATE_H
#define _UI_INPUT_INPUTDISPATCHER_DRAGSTATE_H

#include <gui/WindowInfo.h>
#include <utils/StrongPointer.h>
#include <string>

namespace android {

namespace inputdispatcher {

struct DragState {
    DragState(const sp<android::gui::WindowInfoHandle>& windowHandle, int32_t pointerId)
          : dragWindow(windowHandle), pointerId(pointerId) {}
    void dump(std::string& dump, const char* prefix = "");

    // The window being dragged.
    const sp<android::gui::WindowInfoHandle> dragWindow;
    // The last drag hover window which could receive the drag event.
    sp<android::gui::WindowInfoHandle> dragHoverWindowHandle;
    // Indicates the if received first event to check for button state.
    bool isStartDrag = false;
    // Indicate if the stylus button is down at the start of the drag.
    bool isStylusButtonDownAtStart = false;
    // Indicate which pointer id is tracked by the drag and drop.
    const int32_t pointerId;
};

} // namespace inputdispatcher
} // namespace android

#endif // _UI_INPUT_INPUTDISPATCHER_DRAGSTATE_H