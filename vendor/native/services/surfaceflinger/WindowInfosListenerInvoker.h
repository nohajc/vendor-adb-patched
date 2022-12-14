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

#include <android/gui/BnWindowInfosReportedListener.h>
#include <android/gui/IWindowInfosListener.h>
#include <android/gui/IWindowInfosReportedListener.h>
#include <binder/IBinder.h>
#include <utils/Mutex.h>
#include <unordered_map>

namespace android {

class SurfaceFlinger;

class WindowInfosListenerInvoker : public IBinder::DeathRecipient {
public:
    WindowInfosListenerInvoker(const sp<SurfaceFlinger>& sf);
    void addWindowInfosListener(const sp<gui::IWindowInfosListener>& windowInfosListener);
    void removeWindowInfosListener(const sp<gui::IWindowInfosListener>& windowInfosListener);

    void windowInfosChanged(const std::vector<gui::WindowInfo>& windowInfos, bool shouldSync);

protected:
    void binderDied(const wp<IBinder>& who) override;

private:
    void windowInfosReported();

    struct WpHash {
        size_t operator()(const wp<IBinder>& p) const {
            return std::hash<IBinder*>()(p.unsafe_get());
        }
    };

    const sp<SurfaceFlinger> mSf;
    std::mutex mListenersMutex;
    std::unordered_map<wp<IBinder>, const sp<gui::IWindowInfosListener>, WpHash>
            mWindowInfosListeners GUARDED_BY(mListenersMutex);
    sp<gui::IWindowInfosReportedListener> mWindowInfosReportedListener;
    std::atomic<size_t> mCallbacksPending{0};
};
} // namespace android