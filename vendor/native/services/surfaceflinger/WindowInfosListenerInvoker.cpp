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

#include <ftl/small_vector.h>
#include <gui/ISurfaceComposer.h>

#include "SurfaceFlinger.h"
#include "WindowInfosListenerInvoker.h"

namespace android {

using gui::DisplayInfo;
using gui::IWindowInfosListener;
using gui::WindowInfo;

struct WindowInfosListenerInvoker::WindowInfosReportedListener
      : gui::BnWindowInfosReportedListener {
    explicit WindowInfosReportedListener(WindowInfosListenerInvoker& invoker, size_t callbackCount,
                                         bool shouldSync)
          : mInvoker(invoker), mCallbacksPending(callbackCount), mShouldSync(shouldSync) {}

    binder::Status onWindowInfosReported() override {
        mCallbacksPending--;
        if (mCallbacksPending == 0) {
            mInvoker.windowInfosReported(mShouldSync);
        }
        return binder::Status::ok();
    }

private:
    WindowInfosListenerInvoker& mInvoker;
    std::atomic<size_t> mCallbacksPending;
    bool mShouldSync;
};

WindowInfosListenerInvoker::WindowInfosListenerInvoker(SurfaceFlinger& flinger)
      : mFlinger(flinger) {}

void WindowInfosListenerInvoker::addWindowInfosListener(sp<IWindowInfosListener> listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(this);

    std::scoped_lock lock(mListenersMutex);
    mWindowInfosListeners.try_emplace(asBinder, std::move(listener));
}

void WindowInfosListenerInvoker::removeWindowInfosListener(
        const sp<IWindowInfosListener>& listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);

    std::scoped_lock lock(mListenersMutex);
    asBinder->unlinkToDeath(this);
    mWindowInfosListeners.erase(asBinder);
}

void WindowInfosListenerInvoker::binderDied(const wp<IBinder>& who) {
    std::scoped_lock lock(mListenersMutex);
    mWindowInfosListeners.erase(who);
}

void WindowInfosListenerInvoker::windowInfosChanged(std::vector<WindowInfo> windowInfos,
                                                    std::vector<DisplayInfo> displayInfos,
                                                    bool shouldSync, bool forceImmediateCall) {
    auto callListeners = [this, windowInfos = std::move(windowInfos),
                          displayInfos = std::move(displayInfos)](bool shouldSync) mutable {
        ftl::SmallVector<const sp<IWindowInfosListener>, kStaticCapacity> windowInfosListeners;
        {
            std::scoped_lock lock(mListenersMutex);
            for (const auto& [_, listener] : mWindowInfosListeners) {
                windowInfosListeners.push_back(listener);
            }
        }

        auto reportedListener =
                sp<WindowInfosReportedListener>::make(*this, windowInfosListeners.size(),
                                                      shouldSync);

        for (const auto& listener : windowInfosListeners) {
            auto status =
                    listener->onWindowInfosChanged(windowInfos, displayInfos, reportedListener);
            if (!status.isOk()) {
                reportedListener->onWindowInfosReported();
            }
        }
    };

    {
        std::scoped_lock lock(mMessagesMutex);
        // If there are unacked messages and this isn't a forced call, then return immediately.
        // If a forced window infos change doesn't happen first, the update will be sent after
        // the WindowInfosReportedListeners are called. If a forced window infos change happens or
        // if there are subsequent delayed messages before this update is sent, then this message
        // will be dropped and the listeners will only be called with the latest info. This is done
        // to reduce the amount of binder memory used.
        if (mActiveMessageCount > 0 && !forceImmediateCall) {
            mWindowInfosChangedDelayed = std::move(callListeners);
            mShouldSyncDelayed |= shouldSync;
            return;
        }

        mWindowInfosChangedDelayed = nullptr;
        shouldSync |= mShouldSyncDelayed;
        mShouldSyncDelayed = false;
        mActiveMessageCount++;
    }
    callListeners(shouldSync);
}

void WindowInfosListenerInvoker::windowInfosReported(bool shouldSync) {
    if (shouldSync) {
        mFlinger.windowInfosReported();
    }

    std::function<void(bool)> callListeners;
    bool shouldSyncDelayed;
    {
        std::scoped_lock lock{mMessagesMutex};
        mActiveMessageCount--;
        if (!mWindowInfosChangedDelayed || mActiveMessageCount > 0) {
            return;
        }

        mActiveMessageCount++;
        callListeners = std::move(mWindowInfosChangedDelayed);
        mWindowInfosChangedDelayed = nullptr;
        shouldSyncDelayed = mShouldSyncDelayed;
        mShouldSyncDelayed = false;
    }

    callListeners(shouldSyncDelayed);
}

} // namespace android
