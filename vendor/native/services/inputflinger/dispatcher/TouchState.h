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

class InputWindowHandle;

namespace inputdispatcher {

struct TouchState {
    bool down;
    bool split;
    int32_t deviceId;  // id of the device that is currently down, others are rejected
    uint32_t source;   // source of the device that is current down, others are rejected
    int32_t displayId; // id to the display that currently has a touch, others are rejected
    std::vector<TouchedWindow> windows;

    // This collects the portal windows that the touch has gone through. Each portal window
    // targets a display (embedded display for most cases). With this info, we can add the
    // monitoring channels of the displays touched.
    std::vector<sp<android::InputWindowHandle>> portalWindows;

    std::vector<TouchedMonitor> gestureMonitors;

    TouchState();
    ~TouchState();
    void reset();
    void copyFrom(const TouchState& other);
    void addOrUpdateWindow(const sp<android::InputWindowHandle>& windowHandle, int32_t targetFlags,
                           BitSet32 pointerIds);
    void addPortalWindow(const sp<android::InputWindowHandle>& windowHandle);
    void addGestureMonitors(const std::vector<TouchedMonitor>& monitors);
    void removeWindowByToken(const sp<IBinder>& token);
    void filterNonAsIsTouchWindows();
    void filterNonMonitors();
    sp<InputWindowHandle> getFirstForegroundWindowHandle() const;
    bool isSlippery() const;
};

} // namespace inputdispatcher
} // namespace android

#endif // _UI_INPUT_INPUTDISPATCHER_TOUCHSTATE_H
