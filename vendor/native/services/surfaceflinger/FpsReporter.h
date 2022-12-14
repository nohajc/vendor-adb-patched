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
#include <android/gui/IFpsListener.h>
#include <binder/IBinder.h>

#include <unordered_map>

#include "Clock.h"
#include "FrameTimeline/FrameTimeline.h"

namespace android {

class Layer;
class SurfaceFlinger;

class FpsReporter : public IBinder::DeathRecipient {
public:
    FpsReporter(frametimeline::FrameTimeline& frameTimeline, SurfaceFlinger& flinger,
                std::unique_ptr<Clock> clock = std::make_unique<SteadyClock>());

    // Dispatches updated layer fps values for the registered listeners
    // This method promotes Layer weak pointers and performs layer stack traversals, so mStateLock
    // must be held when calling this method.
    void dispatchLayerFps() EXCLUDES(mMutex);

    // Override for IBinder::DeathRecipient
    void binderDied(const wp<IBinder>&) override;

    // Registers an Fps listener that listens to fps updates for the provided layer
    void addListener(const sp<gui::IFpsListener>& listener, int32_t taskId);
    // Deregisters an Fps listener
    void removeListener(const sp<gui::IFpsListener>& listener);

private:
    mutable std::mutex mMutex;
    struct WpHash {
        size_t operator()(const wp<IBinder>& p) const {
            return std::hash<IBinder*>()(p.unsafe_get());
        }
    };

    struct TrackedListener {
        sp<gui::IFpsListener> listener;
        int32_t taskId;
    };

    frametimeline::FrameTimeline& mFrameTimeline;
    SurfaceFlinger& mFlinger;
    static const constexpr std::chrono::steady_clock::duration kMinDispatchDuration =
            std::chrono::milliseconds(500);
    std::unique_ptr<Clock> mClock;
    std::chrono::steady_clock::time_point mLastDispatch;
    std::unordered_map<wp<IBinder>, TrackedListener, WpHash> mListeners GUARDED_BY(mMutex);
};

} // namespace android