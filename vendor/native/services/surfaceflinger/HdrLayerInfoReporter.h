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
#include <android/gui/IHdrLayerInfoListener.h>
#include <binder/IBinder.h>

#include <unordered_map>

namespace android {

class HdrLayerInfoReporter final : public IBinder::DeathRecipient {
public:
    struct HdrLayerInfo {
        int32_t numberOfHdrLayers = 0;
        int32_t maxW = 0;
        int32_t maxH = 0;
        int32_t flags = 0;

        bool operator==(const HdrLayerInfo& other) const {
            return numberOfHdrLayers == other.numberOfHdrLayers && maxW == other.maxW &&
                    maxH == other.maxH && flags == other.flags;
        }

        bool operator!=(const HdrLayerInfo& other) const { return !(*this == other); }
    };

    HdrLayerInfoReporter() = default;
    ~HdrLayerInfoReporter() final = default;

    // Dispatches updated layer fps values for the registered listeners
    // This method promotes Layer weak pointers and performs layer stack traversals, so mStateLock
    // must be held when calling this method.
    void dispatchHdrLayerInfo(const HdrLayerInfo& info) EXCLUDES(mMutex);

    // Override for IBinder::DeathRecipient
    void binderDied(const wp<IBinder>&) override EXCLUDES(mMutex);

    // Registers an Fps listener that listens to fps updates for the provided layer
    void addListener(const sp<gui::IHdrLayerInfoListener>& listener) EXCLUDES(mMutex);
    // Deregisters an Fps listener
    void removeListener(const sp<gui::IHdrLayerInfoListener>& listener) EXCLUDES(mMutex);

    bool hasListeners() const EXCLUDES(mMutex) {
        std::scoped_lock lock(mMutex);
        return !mListeners.empty();
    }

private:
    mutable std::mutex mMutex;
    struct WpHash {
        size_t operator()(const wp<IBinder>& p) const {
            return std::hash<IBinder*>()(p.unsafe_get());
        }
    };

    struct TrackedListener {
        sp<gui::IHdrLayerInfoListener> listener;
        HdrLayerInfo lastInfo;
    };

    std::unordered_map<wp<IBinder>, TrackedListener, WpHash> mListeners GUARDED_BY(mMutex);
};

} // namespace android