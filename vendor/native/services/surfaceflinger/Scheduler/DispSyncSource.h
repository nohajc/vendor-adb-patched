/*
 * Copyright 2018 The Android Open Source Project
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

#include <mutex>
#include <string>

#include "EventThread.h"
#include "TracedOrdinal.h"
#include "VSyncDispatch.h"

namespace android::scheduler {
class CallbackRepeater;
class VSyncTracker;

class DispSyncSource final : public VSyncSource {
public:
    DispSyncSource(VSyncDispatch& vSyncDispatch, VSyncTracker& vSyncTracker,
                   std::chrono::nanoseconds workDuration, std::chrono::nanoseconds readyDuration,
                   bool traceVsync, const char* name);

    ~DispSyncSource() override;

    // The following methods are implementation of VSyncSource.
    const char* getName() const override { return mName; }
    void setVSyncEnabled(bool enable) override;
    void setCallback(VSyncSource::Callback* callback) override;
    void setDuration(std::chrono::nanoseconds workDuration,
                     std::chrono::nanoseconds readyDuration) override;
    VSyncData getLatestVSyncData() const override;

    void dump(std::string&) const override;

private:
    void onVsyncCallback(nsecs_t vsyncTime, nsecs_t targetWakeupTime, nsecs_t readyTime);

    const char* const mName;
    TracedOrdinal<int> mValue;

    const bool mTraceVsync;
    const std::string mVsyncOnLabel;

    const VSyncTracker& mVSyncTracker;

    std::unique_ptr<CallbackRepeater> mCallbackRepeater;

    std::mutex mCallbackMutex;
    VSyncSource::Callback* mCallback GUARDED_BY(mCallbackMutex) = nullptr;

    mutable std::mutex mVsyncMutex;
    TracedOrdinal<std::chrono::nanoseconds> mWorkDuration GUARDED_BY(mVsyncMutex);
    std::chrono::nanoseconds mReadyDuration GUARDED_BY(mVsyncMutex);
    bool mEnabled GUARDED_BY(mVsyncMutex) = false;
};

} // namespace android::scheduler
