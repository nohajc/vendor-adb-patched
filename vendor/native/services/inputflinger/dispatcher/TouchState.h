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

#ifndef _UI_INPUT_INPUTDISPATCHER_TOUCHSTATE_H
#define _UI_INPUT_INPUTDISPATCHER_TOUCHSTATE_H

#include "Monitor.h"
#include "TouchedWindow.h"

namespace android {

namespace gui {
class WindowInfoHandle;
}

namespace inputdispatcher {

struct TouchState {
    bool down = false;
    bool split = false;
    bool preventNewTargets = false;

    // id of the device that is currently down, others are rejected
    int32_t deviceId = -1;
    // source of the device that is current down, others are rejected
    uint32_t source = 0;
    // id to the display that currently has a touch, others are rejected
    int32_t displayId = ADISPLAY_ID_NONE;

    std::vector<TouchedWindow> windows;

    TouchState() = default;
    ~TouchState() = default;
    TouchState& operator=(const TouchState&) = default;

    void reset();
    void addOrUpdateWindow(const sp<android::gui::WindowInfoHandle>& windowHandle,
                           int32_t targetFlags, BitSet32 pointerIds);
    void removeWindowByToken(const sp<IBinder>& token);
    void filterNonAsIsTouchWindows();
    void filterWindowsExcept(const sp<IBinder>& token);
    sp<android::gui::WindowInfoHandle> getFirstForegroundWindowHandle() const;
    bool isSlippery() const;
    sp<android::gui::WindowInfoHandle> getWallpaperWindow() const;
    sp<android::gui::WindowInfoHandle> getWindow(const sp<IBinder>&) const;
};

} // namespace inputdispatcher
} // namespace android

#endif // _UI_INPUT_INPUTDISPATCHER_TOUCHSTATE_H
