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

#pragma once

#include <android-base/thread_annotations.h>
#include <android/gui/ITunnelModeEnabledListener.h>
#include <binder/IBinder.h>

#include <unordered_map>

#include "WpHash.h"

namespace android {

class Layer;
class SurfaceFlinger;

class TunnelModeEnabledReporter : public IBinder::DeathRecipient {
public:
    TunnelModeEnabledReporter();

    // Checks if there is a tunnel mode enabled state change and if so, dispatches the updated
    // tunnel mode enabled/disabled state to the registered listeners
    // This method performs layer stack traversals, so mStateLock must be held when calling this
    // method.
    void updateTunnelModeStatus();

    // Dispatches tunnelModeEnabled to all registered listeners
    void dispatchTunnelModeEnabled(bool tunnelModeEnabled);

    // Override for IBinder::DeathRecipient
    void binderDied(const wp<IBinder>&) override;

    // Registers a TunnelModeEnabled listener
    void addListener(const sp<gui::ITunnelModeEnabledListener>& listener);

    // Deregisters a TunnelModeEnabled listener
    void removeListener(const sp<gui::ITunnelModeEnabledListener>& listener);

    inline void incrementTunnelModeCount() { mTunnelModeCount++; }
    inline void decrementTunnelModeCount() { mTunnelModeCount--; }

private:
    mutable std::mutex mMutex;

    std::unordered_map<wp<IBinder>, sp<gui::ITunnelModeEnabledListener>, WpHash> mListeners
            GUARDED_BY(mMutex);
    bool mTunnelModeEnabled GUARDED_BY(mMutex) = false;
    uint32_t mTunnelModeCount = 0;
};

} // namespace android
