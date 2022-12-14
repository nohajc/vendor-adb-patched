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

#include <gui/WindowInfo.h>

#include "InputTarget.h"

#include "TouchState.h"

using android::gui::WindowInfo;
using android::gui::WindowInfoHandle;

namespace android::inputdispatcher {

void TouchState::reset() {
    *this = TouchState();
}

void TouchState::addOrUpdateWindow(const sp<WindowInfoHandle>& windowHandle, int32_t targetFlags,
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

    if (preventNewTargets) return; // Don't add new TouchedWindows.

    TouchedWindow touchedWindow;
    touchedWindow.windowHandle = windowHandle;
    touchedWindow.targetFlags = targetFlags;
    touchedWindow.pointerIds = pointerIds;
    windows.push_back(touchedWindow);
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

void TouchState::filterWindowsExcept(const sp<IBinder>& token) {
    std::erase_if(windows,
                  [&token](const TouchedWindow& w) { return w.windowHandle->getToken() != token; });
}

sp<WindowInfoHandle> TouchState::getFirstForegroundWindowHandle() const {
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
                !window.windowHandle->getInfo()->inputConfig.test(
                        WindowInfo::InputConfig::SLIPPERY)) {
                return false;
            }
            haveSlipperyForegroundWindow = true;
        }
    }
    return haveSlipperyForegroundWindow;
}

sp<WindowInfoHandle> TouchState::getWallpaperWindow() const {
    for (size_t i = 0; i < windows.size(); i++) {
        const TouchedWindow& window = windows[i];
        if (window.windowHandle->getInfo()->inputConfig.test(
                    gui::WindowInfo::InputConfig::IS_WALLPAPER)) {
            return window.windowHandle;
        }
    }
    return nullptr;
}

sp<WindowInfoHandle> TouchState::getWindow(const sp<IBinder>& token) const {
    for (const TouchedWindow& touchedWindow : windows) {
        const auto& windowHandle = touchedWindow.windowHandle;
        if (windowHandle->getToken() == token) {
            return windowHandle;
        }
    }
    return nullptr;
}

} // namespace android::inputdispatcher
