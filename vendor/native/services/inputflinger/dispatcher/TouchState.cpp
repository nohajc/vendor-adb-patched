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

#include <input/InputWindow.h>

#include "InputTarget.h"

#include "TouchState.h"

using android::InputWindowHandle;

namespace android::inputdispatcher {

TouchState::TouchState()
      : down(false), split(false), deviceId(-1), source(0), displayId(ADISPLAY_ID_NONE) {}

TouchState::~TouchState() {}

void TouchState::reset() {
    down = false;
    split = false;
    deviceId = -1;
    source = 0;
    displayId = ADISPLAY_ID_NONE;
    windows.clear();
    portalWindows.clear();
    gestureMonitors.clear();
}

void TouchState::copyFrom(const TouchState& other) {
    down = other.down;
    split = other.split;
    deviceId = other.deviceId;
    source = other.source;
    displayId = other.displayId;
    windows = other.windows;
    portalWindows = other.portalWindows;
    gestureMonitors = other.gestureMonitors;
}

void TouchState::addOrUpdateWindow(const sp<InputWindowHandle>& windowHandle, int32_t targetFlags,
                                   BitSet32 pointerIds) {
    if (targetFlags & InputTarget::FLAG_SPLIT) {
        split = true;
    }

    for (size_t i = 0; i < windows.size(); i++) {
        TouchedWindow& touchedWindow = windows[i];
        if (touchedWindow.windowHandle == windowHandle) {
            touchedWindow.targetFlags |= targetFlags;
            if (targetFlags & InputTarget::FLAG_DISPATCH_AS_SLIPPERY_EXIT) {
                touchedWindow.targetFlags &= ~InputTarget::FLAG_DISPATCH_AS_IS;
            }
            touchedWindow.pointerIds.value |= pointerIds.value;
            return;
        }
    }

    TouchedWindow touchedWindow;
    touchedWindow.windowHandle = windowHandle;
    touchedWindow.targetFlags = targetFlags;
    touchedWindow.pointerIds = pointerIds;
    windows.push_back(touchedWindow);
}

void TouchState::addPortalWindow(const sp<InputWindowHandle>& windowHandle) {
    size_t numWindows = portalWindows.size();
    for (size_t i = 0; i < numWindows; i++) {
        if (portalWindows[i] == windowHandle) {
            return;
        }
    }
    portalWindows.push_back(windowHandle);
}

void TouchState::addGestureMonitors(const std::vector<TouchedMonitor>& newMonitors) {
    const size_t newSize = gestureMonitors.size() + newMonitors.size();
    gestureMonitors.reserve(newSize);
    gestureMonitors.insert(std::end(gestureMonitors), std::begin(newMonitors),
                           std::end(newMonitors));
}

void TouchState::removeWindowByToken(const sp<IBinder>& token) {
    for (size_t i = 0; i < windows.size(); i++) {
        if (windows[i].windowHandle->getToken() == token) {
            windows.erase(windows.begin() + i);
            return;
        }
    }
}

void TouchState::filterNonAsIsTouchWindows() {
    for (size_t i = 0; i < windows.size();) {
        TouchedWindow& window = windows[i];
        if (window.targetFlags &
            (InputTarget::FLAG_DISPATCH_AS_IS | InputTarget::FLAG_DISPATCH_AS_SLIPPERY_ENTER)) {
            window.targetFlags &= ~InputTarget::FLAG_DISPATCH_MASK;
            window.targetFlags |= InputTarget::FLAG_DISPATCH_AS_IS;
            i += 1;
        } else {
            windows.erase(windows.begin() + i);
        }
    }
}

void TouchState::filterNonMonitors() {
    windows.clear();
    portalWindows.clear();
}

sp<InputWindowHandle> TouchState::getFirstForegroundWindowHandle() const {
    for (size_t i = 0; i < windows.size(); i++) {
        const TouchedWindow& window = windows[i];
        if (window.targetFlags & InputTarget::FLAG_FOREGROUND) {
            return window.windowHandle;
        }
    }
    return nullptr;
}

bool TouchState::isSlippery() const {
    // Must have exactly one foreground window.
    bool haveSlipperyForegroundWindow = false;
    for (const TouchedWindow& window : windows) {
        if (window.targetFlags & InputTarget::FLAG_FOREGROUND) {
            if (haveSlipperyForegroundWindow ||
                !(window.windowHandle->getInfo()->layoutParamsFlags &
                  InputWindowInfo::FLAG_SLIPPERY)) {
                return false;
            }
            haveSlipperyForegroundWindow = true;
        }
    }
    return haveSlipperyForegroundWindow;
}

} // namespace android::inputdispatcher
