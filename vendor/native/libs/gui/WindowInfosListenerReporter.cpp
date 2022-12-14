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

#include <gui/ISurfaceComposer.h>
#include <gui/WindowInfosListenerReporter.h>

namespace android {

using gui::DisplayInfo;
using gui::IWindowInfosReportedListener;
using gui::WindowInfo;
using gui::WindowInfosListener;

sp<WindowInfosListenerReporter> WindowInfosListenerReporter::getInstance() {
    static sp<WindowInfosListenerReporter> sInstance = new WindowInfosListenerReporter;
    return sInstance;
}

status_t WindowInfosListenerReporter::addWindowInfosListener(
        const sp<WindowInfosListener>& windowInfosListener,
        const sp<ISurfaceComposer>& surfaceComposer,
        std::pair<std::vector<gui::WindowInfo>, std::vector<gui::DisplayInfo>>* outInitialInfo) {
    status_t status = OK;
    {
        std::scoped_lock lock(mListenersMutex);
        if (mWindowInfosListeners.empty()) {
            status = surfaceComposer->addWindowInfosListener(this);
        }

        if (status == OK) {
            mWindowInfosListeners.insert(windowInfosListener);
        }

        if (outInitialInfo != nullptr) {
            outInitialInfo->first = mLastWindowInfos;
            outInitialInfo->second = mLastDisplayInfos;
        }
    }

    return status;
}

status_t WindowInfosListenerReporter::removeWindowInfosListener(
        const sp<WindowInfosListener>& windowInfosListener,
        const sp<ISurfaceComposer>& surfaceComposer) {
    status_t status = OK;
    {
        std::scoped_lock lock(mListenersMutex);
        if (mWindowInfosListeners.size() == 1) {
            status = surfaceComposer->removeWindowInfosListener(this);
            // Clear the last stored state since we're disabling updates and don't want to hold
            // stale values
            mLastWindowInfos.clear();
            mLastDisplayInfos.clear();
        }

        if (status == OK) {
            mWindowInfosListeners.erase(windowInfosListener);
        }
    }

    return status;
}

binder::Status WindowInfosListenerReporter::onWindowInfosChanged(
        const std::vector<WindowInfo>& windowInfos, const std::vector<DisplayInfo>& displayInfos,
        const sp<IWindowInfosReportedListener>& windowInfosReportedListener) {
    std::unordered_set<sp<WindowInfosListener>, SpHash<WindowInfosListener>> windowInfosListeners;

    {
        std::scoped_lock lock(mListenersMutex);
        for (auto listener : mWindowInfosListeners) {
            windowInfosListeners.insert(listener);
        }

        mLastWindowInfos = windowInfos;
        mLastDisplayInfos = displayInfos;
    }

    for (auto listener : windowInfosListeners) {
        listener->onWindowInfosChanged(windowInfos, displayInfos);
    }

    if (windowInfosReportedListener) {
        windowInfosReportedListener->onWindowInfosReported();
    }

    return binder::Status::ok();
}

void WindowInfosListenerReporter::reconnect(const sp<ISurfaceComposer>& composerService) {
    std::scoped_lock lock(mListenersMutex);
    if (!mWindowInfosListeners.empty()) {
        composerService->addWindowInfosListener(this);
    }
}

} // namespace android
