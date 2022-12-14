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

#include <android/gui/BnWindowInfosListener.h>
#include <android/gui/IWindowInfosReportedListener.h>
#include <binder/IBinder.h>
#include <gui/ISurfaceComposer.h>
#include <gui/WindowInfosListener.h>
#include <utils/Mutex.h>
#include <unordered_set>

namespace android {
class ISurfaceComposer;

class WindowInfosListenerReporter : public gui::BnWindowInfosListener {
public:
    static sp<WindowInfosListenerReporter> getInstance();
    binder::Status onWindowInfosChanged(const std::vector<gui::WindowInfo>& windowInfos,
                                        const sp<gui::IWindowInfosReportedListener>&) override;

    status_t addWindowInfosListener(const sp<gui::WindowInfosListener>& windowInfosListener,
                                    const sp<ISurfaceComposer>&);
    status_t removeWindowInfosListener(const sp<gui::WindowInfosListener>& windowInfosListener,
                                       const sp<ISurfaceComposer>&);
    void reconnect(const sp<ISurfaceComposer>&);

private:
    std::mutex mListenersMutex;
    std::unordered_set<sp<gui::WindowInfosListener>,
                       ISurfaceComposer::SpHash<gui::WindowInfosListener>>
            mWindowInfosListeners GUARDED_BY(mListenersMutex);
};
} // namespace android