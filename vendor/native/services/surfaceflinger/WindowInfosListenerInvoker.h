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
#include <ftl/small_map.h>
#include <utils/Mutex.h>

namespace android {

class SurfaceFlinger;

class WindowInfosListenerInvoker : public IBinder::DeathRecipient {
public:
    explicit WindowInfosListenerInvoker(SurfaceFlinger&);

    void addWindowInfosListener(sp<gui::IWindowInfosListener>);
    void removeWindowInfosListener(const sp<gui::IWindowInfosListener>& windowInfosListener);

    void windowInfosChanged(std::vector<gui::WindowInfo>, std::vector<gui::DisplayInfo>,
                            bool shouldSync, bool forceImmediateCall);

protected:
    void binderDied(const wp<IBinder>& who) override;

private:
    struct WindowInfosReportedListener;
    void windowInfosReported(bool shouldSync);

    SurfaceFlinger& mFlinger;
    std::mutex mListenersMutex;

    static constexpr size_t kStaticCapacity = 3;
    ftl::SmallMap<wp<IBinder>, const sp<gui::IWindowInfosListener>, kStaticCapacity>
            mWindowInfosListeners GUARDED_BY(mListenersMutex);

    std::mutex mMessagesMutex;
    uint32_t mActiveMessageCount GUARDED_BY(mMessagesMutex) = 0;
    std::function<void(bool)> mWindowInfosChangedDelayed GUARDED_BY(mMessagesMutex);
    bool mShouldSyncDelayed;
};

} // namespace android
