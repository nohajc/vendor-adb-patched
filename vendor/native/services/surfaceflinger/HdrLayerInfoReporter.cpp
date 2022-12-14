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
#define LOG_TAG "HdrLayerInfoReporter"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <utils/Trace.h>

#include "HdrLayerInfoReporter.h"

namespace android {

void HdrLayerInfoReporter::dispatchHdrLayerInfo(const HdrLayerInfo& info) {
    ATRACE_CALL();
    std::vector<sp<gui::IHdrLayerInfoListener>> toInvoke;
    {
        std::scoped_lock lock(mMutex);
        toInvoke.reserve(mListeners.size());
        for (auto& [key, it] : mListeners) {
            if (it.lastInfo != info) {
                it.lastInfo = info;
                toInvoke.push_back(it.listener);
            }
        }
    }

    for (const auto& listener : toInvoke) {
        ATRACE_NAME("invoking onHdrLayerInfoChanged");
        listener->onHdrLayerInfoChanged(info.numberOfHdrLayers, info.maxW, info.maxH, info.flags);
    }
}

void HdrLayerInfoReporter::binderDied(const wp<IBinder>& who) {
    std::scoped_lock lock(mMutex);
    mListeners.erase(who);
}

void HdrLayerInfoReporter::addListener(const sp<gui::IHdrLayerInfoListener>& listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(this);
    std::lock_guard lock(mMutex);
    mListeners.emplace(wp<IBinder>(asBinder), TrackedListener{listener, HdrLayerInfo{}});
}

void HdrLayerInfoReporter::removeListener(const sp<gui::IHdrLayerInfoListener>& listener) {
    std::lock_guard lock(mMutex);
    mListeners.erase(wp<IBinder>(IInterface::asBinder(listener)));
}

} // namespace android