/*
 * Copyright 2021 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "TunnelModeEnabledReporter"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <algorithm>

#include "Layer.h"
#include "SurfaceFlinger.h"
#include "TunnelModeEnabledReporter.h"

namespace android {

TunnelModeEnabledReporter::TunnelModeEnabledReporter() {}

void TunnelModeEnabledReporter::updateTunnelModeStatus() {
    bool tunnelModeEnabled = mTunnelModeCount > 0;
    dispatchTunnelModeEnabled(tunnelModeEnabled);
}

void TunnelModeEnabledReporter::dispatchTunnelModeEnabled(bool tunnelModeEnabled) {
    std::vector<sp<gui::ITunnelModeEnabledListener>> localListeners;
    {
        std::scoped_lock lock(mMutex);
        if (mTunnelModeEnabled == tunnelModeEnabled) {
            return;
        }
        mTunnelModeEnabled = tunnelModeEnabled;

        std::transform(mListeners.begin(), mListeners.end(), std::back_inserter(localListeners),
                       [](const std::pair<wp<IBinder>, sp<gui::ITunnelModeEnabledListener>>&
                                  entry) { return entry.second; });
    }

    for (sp<gui::ITunnelModeEnabledListener>& listener : localListeners) {
        listener->onTunnelModeEnabledChanged(tunnelModeEnabled);
    }
}

void TunnelModeEnabledReporter::binderDied(const wp<IBinder>& who) {
    std::scoped_lock lock(mMutex);
    mListeners.erase(who);
}

void TunnelModeEnabledReporter::addListener(const sp<gui::ITunnelModeEnabledListener>& listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(this);
    bool tunnelModeEnabled = false;
    {
        std::scoped_lock lock(mMutex);
        mListeners.emplace(wp<IBinder>(asBinder), listener);
        tunnelModeEnabled = mTunnelModeEnabled;
    }
    listener->onTunnelModeEnabledChanged(tunnelModeEnabled);
}

void TunnelModeEnabledReporter::removeListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    std::lock_guard lock(mMutex);
    mListeners.erase(wp<IBinder>(IInterface::asBinder(listener)));
}

} // namespace android
