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

#define LOG_TAG "FocusResolver"
#define ATRACE_TAG ATRACE_TAG_INPUT

#define INDENT "  "
#define INDENT2 "    "

// Log debug messages about input focus tracking.
static constexpr bool DEBUG_FOCUS = false;

#include <inttypes.h>

#include <android-base/stringprintf.h>
#include <binder/Binder.h>
#include <ftl/enum.h>
#include <gui/WindowInfo.h>
#include <log/log.h>

#include "FocusResolver.h"

using android::gui::FocusRequest;
using android::gui::WindowInfoHandle;

namespace android::inputdispatcher {

sp<IBinder> FocusResolver::getFocusedWindowToken(int32_t displayId) const {
    auto it = mFocusedWindowTokenByDisplay.find(displayId);
    return it != mFocusedWindowTokenByDisplay.end() ? it->second.second : nullptr;
}

std::optional<FocusRequest> FocusResolver::getFocusRequest(int32_t displayId) {
    auto it = mFocusRequestByDisplay.find(displayId);
    return it != mFocusRequestByDisplay.end() ? std::make_optional<>(it->second) : std::nullopt;
}

/**
 * 'setInputWindows' is called when the window properties change. Here we will check whether the
 * currently focused window can remain focused. If the currently focused window remains eligible
 * for focus ('isTokenFocusable' returns OK), then we will continue to grant it focus otherwise
 * we will check if the previous focus request is eligible to receive focus.
 */
std::optional<FocusResolver::FocusChanges> FocusResolver::setInputWindows(
        int32_t displayId, const std::vector<sp<WindowInfoHandle>>& windows) {
    std::string removeFocusReason;

    // Check if the currently focused window is still focusable.
    const sp<IBinder> currentFocus = getFocusedWindowToken(displayId);
    if (currentFocus) {
        Focusability result = isTokenFocusable(currentFocus, windows);
        if (result == Focusability::OK) {
            return std::nullopt;
        }
        removeFocusReason = ftl::enum_string(result);
    }

    // We don't have a focused window or the currently focused window is no longer focusable. Check
    // to see if we can grant focus to the window that previously requested focus.
    const std::optional<FocusRequest> request = getFocusRequest(displayId);
    if (request) {
        sp<IBinder> requestedFocus = request->token;
        const Focusability result = isTokenFocusable(requestedFocus, windows);
        const Focusability previousResult = mLastFocusResultByDisplay[displayId];
        mLastFocusResultByDisplay[displayId] = result;
        if (result == Focusability::OK) {
            return updateFocusedWindow(displayId,
                                       "Window became focusable. Previous reason: " +
                                               ftl::enum_string(previousResult),
                                       requestedFocus, request->windowName);
        }
    }

    // Focused window is no longer focusable and we don't have a suitable focus request to grant.
    // Remove focus if needed.
    return updateFocusedWindow(displayId, removeFocusReason, nullptr);
}

std::optional<FocusResolver::FocusChanges> FocusResolver::setFocusedWindow(
        const FocusRequest& request, const std::vector<sp<WindowInfoHandle>>& windows) {
    const int32_t displayId = request.displayId;
    const sp<IBinder> currentFocus = getFocusedWindowToken(displayId);
    if (currentFocus == request.token) {
        ALOGD_IF(DEBUG_FOCUS,
                 "setFocusedWindow %s on display %" PRId32 " ignored, reason: already focused",
                 request.windowName.c_str(), displayId);
        return std::nullopt;
    }

    // Handle conditional focus requests, i.e. requests that have a focused token. These requests
    // are not persistent. If the window is no longer focusable, we expect focus to go back to the
    // previously focused window.
    if (request.focusedToken) {
        if (currentFocus != request.focusedToken) {
            ALOGW("setFocusedWindow %s on display %" PRId32
                  " ignored, reason: focusedToken %s is not focused",
                  request.windowName.c_str(), displayId, request.focusedWindowName.c_str());
            return std::nullopt;
        }
        Focusability result = isTokenFocusable(request.token, windows);
        if (result == Focusability::OK) {
            return updateFocusedWindow(displayId, "setFocusedWindow with focus check",
                                       request.token, request.windowName);
        }
        ALOGW("setFocusedWindow %s on display %" PRId32 " ignored, reason: %s",
              request.windowName.c_str(), displayId, ftl::enum_string(result).c_str());
        return std::nullopt;
    }

    Focusability result = isTokenFocusable(request.token, windows);
    // Update focus request. The focus resolver will always try to handle this request if there is
    // no focused window on the display.
    mFocusRequestByDisplay[displayId] = request;
    mLastFocusResultByDisplay[displayId] = result;

    if (result == Focusability::OK) {
        return updateFocusedWindow(displayId, "setFocusedWindow", request.token,
                                   request.windowName);
    }

    // The requested window is not currently focusable. Wait for the window to become focusable
    // but remove focus from the current window so that input events can go into a pending queue
    // and be sent to the window when it becomes focused.
    return updateFocusedWindow(displayId, "Waiting for window because " + ftl::enum_string(result),
                               nullptr);
}

FocusResolver::Focusability FocusResolver::isTokenFocusable(
        const sp<IBinder>& token, const std::vector<sp<WindowInfoHandle>>& windows) {
    bool allWindowsAreFocusable = true;
    bool visibleWindowFound = false;
    bool windowFound = false;
    for (const sp<WindowInfoHandle>& window : windows) {
        if (window->getToken() != token) {
            continue;
        }
        windowFound = true;
        if (!window->getInfo()->inputConfig.test(gui::WindowInfo::InputConfig::NOT_VISIBLE)) {
            // Check if at least a single window is visible.
            visibleWindowFound = true;
        }
        if (window->getInfo()->inputConfig.test(gui::WindowInfo::InputConfig::NOT_FOCUSABLE)) {
            // Check if all windows with the window token are focusable.
            allWindowsAreFocusable = false;
            break;
        }
    }

    if (!windowFound) {
        return Focusability::NO_WINDOW;
    }
    if (!allWindowsAreFocusable) {
        return Focusability::NOT_FOCUSABLE;
    }
    if (!visibleWindowFound) {
        return Focusability::NOT_VISIBLE;
    }

    return Focusability::OK;
}

std::optional<FocusResolver::FocusChanges> FocusResolver::updateFocusedWindow(
        int32_t displayId, const std::string& reason, const sp<IBinder>& newFocus,
        const std::string& tokenName) {
    sp<IBinder> oldFocus = getFocusedWindowToken(displayId);
    if (newFocus == oldFocus) {
        return std::nullopt;
    }
    if (newFocus) {
        mFocusedWindowTokenByDisplay[displayId] = {tokenName, newFocus};
    } else {
        mFocusedWindowTokenByDisplay.erase(displayId);
    }

    return {{oldFocus, newFocus, displayId, reason}};
}

std::string FocusResolver::dumpFocusedWindows() const {
    if (mFocusedWindowTokenByDisplay.empty()) {
        return INDENT "FocusedWindows: <none>\n";
    }

    std::string dump;
    dump += INDENT "FocusedWindows:\n";
    for (const auto& [displayId, namedToken] : mFocusedWindowTokenByDisplay) {
        dump += base::StringPrintf(INDENT2 "displayId=%" PRId32 ", name='%s'\n", displayId,
                                   namedToken.first.c_str());
    }
    return dump;
}

std::string FocusResolver::dump() const {
    std::string dump = dumpFocusedWindows();
    if (mFocusRequestByDisplay.empty()) {
        return dump + INDENT "FocusRequests: <none>\n";
    }

    dump += INDENT "FocusRequests:\n";
    for (const auto& [displayId, request] : mFocusRequestByDisplay) {
        auto it = mLastFocusResultByDisplay.find(displayId);
        std::string result =
                it != mLastFocusResultByDisplay.end() ? ftl::enum_string(it->second) : "";
        dump += base::StringPrintf(INDENT2 "displayId=%" PRId32 ", name='%s' result='%s'\n",
                                   displayId, request.windowName.c_str(), result.c_str());
    }
    return dump;
}

void FocusResolver::displayRemoved(int32_t displayId) {
    mFocusRequestByDisplay.erase(displayId);
    mLastFocusResultByDisplay.erase(displayId);
}

} // namespace android::inputdispatcher
