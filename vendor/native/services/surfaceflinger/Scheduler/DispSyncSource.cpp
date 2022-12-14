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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "DispSyncSource.h"

#include <android-base/stringprintf.h>
#include <utils/Trace.h>
#include <mutex>

#include "EventThread.h"
#include "VSyncTracker.h"
#include "VsyncController.h"

namespace android::scheduler {
using base::StringAppendF;
using namespace std::chrono_literals;

class CallbackRepeater {
public:
    CallbackRepeater(VSyncDispatch& dispatch, VSyncDispatch::Callback cb, const char* name,
                     std::chrono::nanoseconds workDuration, std::chrono::nanoseconds readyDuration,
                     std::chrono::nanoseconds notBefore)
          : mName(name),
            mCallback(cb),
            mRegistration(dispatch,
                          std::bind(&CallbackRepeater::callback, this, std::placeholders::_1,
                                    std::placeholders::_2, std::placeholders::_3),
                          mName),
            mStarted(false),
            mWorkDuration(workDuration),
            mReadyDuration(readyDuration),
            mLastCallTime(notBefore) {}

    ~CallbackRepeater() {
        std::lock_guard lock(mMutex);
        mRegistration.cancel();
    }

    void start(std::chrono::nanoseconds workDuration, std::chrono::nanoseconds readyDuration) {
        std::lock_guard lock(mMutex);
        mStarted = true;
        mWorkDuration = workDuration;
        mReadyDuration = readyDuration;

        auto const scheduleResult =
                mRegistration.schedule({.workDuration = mWorkDuration.count(),
                                        .readyDuration = mReadyDuration.count(),
                                        .earliestVsync = mLastCallTime.count()});
        LOG_ALWAYS_FATAL_IF((!scheduleResult.has_value()), "Error scheduling callback");
    }

    void stop() {
        std::lock_guard lock(mMutex);
        LOG_ALWAYS_FATAL_IF(!mStarted, "DispSyncInterface misuse: callback already stopped");
        mStarted = false;
        mRegistration.cancel();
    }

    void dump(std::string& result) const {
        std::lock_guard lock(mMutex);
        const auto relativeLastCallTime =
                mLastCallTime - std::chrono::steady_clock::now().time_since_epoch();
        StringAppendF(&result, "\t%s: ", mName.c_str());
        StringAppendF(&result, "mWorkDuration=%.2f mReadyDuration=%.2f last vsync time ",
                      mWorkDuration.count() / 1e6f, mReadyDuration.count() / 1e6f);
        StringAppendF(&result, "%.2fms relative to now (%s)\n", relativeLastCallTime.count() / 1e6f,
                      mStarted ? "running" : "stopped");
    }

private:
    void callback(nsecs_t vsyncTime, nsecs_t wakeupTime, nsecs_t readyTime) {
        {
            std::lock_guard lock(mMutex);
            mLastCallTime = std::chrono::nanoseconds(vsyncTime);
        }

        mCallback(vsyncTime, wakeupTime, readyTime);

        {
            std::lock_guard lock(mMutex);
            if (!mStarted) {
                return;
            }
            auto const scheduleResult =
                    mRegistration.schedule({.workDuration = mWorkDuration.count(),
                                            .readyDuration = mReadyDuration.count(),
                                            .earliestVsync = vsyncTime});
            LOG_ALWAYS_FATAL_IF(!scheduleResult.has_value(), "Error rescheduling callback");
        }
    }

    const std::string mName;
    scheduler::VSyncDispatch::Callback mCallback;

    mutable std::mutex mMutex;
    VSyncCallbackRegistration mRegistration GUARDED_BY(mMutex);
    bool mStarted GUARDED_BY(mMutex) = false;
    std::chrono::nanoseconds mWorkDuration GUARDED_BY(mMutex) = 0ns;
    std::chrono::nanoseconds mReadyDuration GUARDED_BY(mMutex) = 0ns;
    std::chrono::nanoseconds mLastCallTime GUARDED_BY(mMutex) = 0ns;
};

DispSyncSource::DispSyncSource(VSyncDispatch& vSyncDispatch, VSyncTracker& vSyncTracker,
                               std::chrono::nanoseconds workDuration,
                               std::chrono::nanoseconds readyDuration, bool traceVsync,
                               const char* name)
      : mName(name),
        mValue(base::StringPrintf("VSYNC-%s", name), 0),
        mTraceVsync(traceVsync),
        mVsyncOnLabel(base::StringPrintf("VsyncOn-%s", name)),
        mVSyncTracker(vSyncTracker),
        mWorkDuration(base::StringPrintf("VsyncWorkDuration-%s", name), workDuration),
        mReadyDuration(readyDuration) {
    mCallbackRepeater =
            std::make_unique<CallbackRepeater>(vSyncDispatch,
                                               std::bind(&DispSyncSource::onVsyncCallback, this,
                                                         std::placeholders::_1,
                                                         std::placeholders::_2,
                                                         std::placeholders::_3),
                                               name, workDuration, readyDuration,
                                               std::chrono::steady_clock::now().time_since_epoch());
}

DispSyncSource::~DispSyncSource() = default;

void DispSyncSource::setVSyncEnabled(bool enable) {
    std::lock_guard lock(mVsyncMutex);
    if (enable) {
        mCallbackRepeater->start(mWorkDuration, mReadyDuration);
        // ATRACE_INT(mVsyncOnLabel.c_str(), 1);
    } else {
        mCallbackRepeater->stop();
        // ATRACE_INT(mVsyncOnLabel.c_str(), 0);
    }
    mEnabled = enable;
}

void DispSyncSource::setCallback(VSyncSource::Callback* callback) {
    std::lock_guard lock(mCallbackMutex);
    mCallback = callback;
}

void DispSyncSource::setDuration(std::chrono::nanoseconds workDuration,
                                 std::chrono::nanoseconds readyDuration) {
    std::lock_guard lock(mVsyncMutex);
    mWorkDuration = workDuration;
    mReadyDuration = readyDuration;

    // If we're not enabled, we don't need to mess with the listeners
    if (!mEnabled) {
        return;
    }

    mCallbackRepeater->start(mWorkDuration, mReadyDuration);
}

void DispSyncSource::onVsyncCallback(nsecs_t vsyncTime, nsecs_t targetWakeupTime,
                                     nsecs_t readyTime) {
    VSyncSource::Callback* callback;
    {
        std::lock_guard lock(mCallbackMutex);
        callback = mCallback;
    }

    if (mTraceVsync) {
        mValue = (mValue + 1) % 2;
    }

    if (callback != nullptr) {
        callback->onVSyncEvent(targetWakeupTime, {vsyncTime, readyTime});
    }
}

VSyncSource::VSyncData DispSyncSource::getLatestVSyncData() const {
    std::lock_guard lock(mVsyncMutex);
    nsecs_t expectedPresentationTime = mVSyncTracker.nextAnticipatedVSyncTimeFrom(
            systemTime() + mWorkDuration.get().count() + mReadyDuration.count());
    nsecs_t deadline = expectedPresentationTime - mReadyDuration.count();
    return {expectedPresentationTime, deadline};
}

void DispSyncSource::dump(std::string& result) const {
    std::lock_guard lock(mVsyncMutex);
    StringAppendF(&result, "DispSyncSource: %s(%s)\n", mName, mEnabled ? "enabled" : "disabled");
}

} // namespace android::scheduler
