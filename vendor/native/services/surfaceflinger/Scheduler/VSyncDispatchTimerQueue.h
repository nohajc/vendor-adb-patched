/*
 * Copyright 2019 The Android Open Source Project
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

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <android-base/thread_annotations.h>

#include "VSyncDispatch.h"

namespace android::scheduler {

class TimeKeeper;
class VSyncTracker;

// VSyncDispatchTimerQueueEntry is a helper class representing internal state for each entry in
// VSyncDispatchTimerQueue hoisted to public for unit testing.
class VSyncDispatchTimerQueueEntry {
public:
    // This is the state of the entry. There are 3 states, armed, running, disarmed.
    // Valid transition: disarmed -> armed ( when scheduled )
    // Valid transition: armed -> running -> disarmed ( when timer is called)
    // Valid transition: armed -> disarmed ( when cancelled )
    VSyncDispatchTimerQueueEntry(std::string name, VSyncDispatch::Callback,
                                 nsecs_t minVsyncDistance);
    std::string_view name() const;

    // Start: functions that are not threadsafe.
    // Return the last vsync time this callback was invoked.
    std::optional<nsecs_t> lastExecutedVsyncTarget() const;

    // This moves the state from disarmed->armed and will calculate the wakeupTime.
    ScheduleResult schedule(VSyncDispatch::ScheduleTiming, VSyncTracker&, nsecs_t now);
    // This will update armed entries with the latest vsync information. Entry remains armed.
    void update(VSyncTracker&, nsecs_t now);

    // This will return empty if not armed, or the next calculated wakeup time if armed.
    // It will not update the wakeupTime.
    std::optional<nsecs_t> wakeupTime() const;

    std::optional<nsecs_t> readyTime() const;

    std::optional<nsecs_t> targetVsync() const;

    // This moves state from armed->disarmed.
    void disarm();

    // This moves the state from armed->running.
    // Store the timestamp that this was intended for as the last called timestamp.
    nsecs_t executing();

    // Adds a pending upload of the earliestVSync and workDuration that will be applied on the next
    // call to update()
    void addPendingWorkloadUpdate(VSyncDispatch::ScheduleTiming);

    // Checks if there is a pending update to the workload, returning true if so.
    bool hasPendingWorkloadUpdate() const;
    // End: functions that are not threadsafe.

    // Invoke the callback with the two given timestamps, moving the state from running->disarmed.
    void callback(nsecs_t vsyncTimestamp, nsecs_t wakeupTimestamp, nsecs_t deadlineTimestamp);
    // Block calling thread while the callback is executing.
    void ensureNotRunning();

    void dump(std::string& result) const;

private:
    const std::string mName;
    const VSyncDispatch::Callback mCallback;

    VSyncDispatch::ScheduleTiming mScheduleTiming;
    const nsecs_t mMinVsyncDistance;

    struct ArmingInfo {
        nsecs_t mActualWakeupTime;
        nsecs_t mActualVsyncTime;
        nsecs_t mActualReadyTime;
    };
    std::optional<ArmingInfo> mArmedInfo;
    std::optional<nsecs_t> mLastDispatchTime;

    std::optional<VSyncDispatch::ScheduleTiming> mWorkloadUpdateInfo;

    mutable std::mutex mRunningMutex;
    std::condition_variable mCv;
    bool mRunning GUARDED_BY(mRunningMutex) = false;
};

/*
 * VSyncDispatchTimerQueue is a class that will dispatch callbacks as per VSyncDispatch interface
 * using a single timer queue.
 */
class VSyncDispatchTimerQueue : public VSyncDispatch {
public:
    // Constructs a VSyncDispatchTimerQueue.
    // \param[in] tk                    A timekeeper.
    // \param[in] tracker               A tracker.
    // \param[in] timerSlack            The threshold at which different similarly timed callbacks
    //                                  should be grouped into one wakeup.
    // \param[in] minVsyncDistance      The minimum distance between two vsync estimates before the
    //                                  vsyncs are considered the same vsync event.
    VSyncDispatchTimerQueue(std::unique_ptr<TimeKeeper>, VSyncTracker&, nsecs_t timerSlack,
                            nsecs_t minVsyncDistance);
    ~VSyncDispatchTimerQueue();

    CallbackToken registerCallback(Callback, std::string callbackName) final;
    void unregisterCallback(CallbackToken) final;
    ScheduleResult schedule(CallbackToken, ScheduleTiming) final;
    CancelResult cancel(CallbackToken) final;
    void dump(std::string&) const final;

private:
    VSyncDispatchTimerQueue(const VSyncDispatchTimerQueue&) = delete;
    VSyncDispatchTimerQueue& operator=(const VSyncDispatchTimerQueue&) = delete;

    using CallbackMap =
            std::unordered_map<CallbackToken, std::shared_ptr<VSyncDispatchTimerQueueEntry>>;

    void timerCallback();
    void setTimer(nsecs_t, nsecs_t) REQUIRES(mMutex);
    void rearmTimer(nsecs_t now) REQUIRES(mMutex);
    void rearmTimerSkippingUpdateFor(nsecs_t now, CallbackMap::iterator const& skipUpdate)
            REQUIRES(mMutex);
    void cancelTimer() REQUIRES(mMutex);

    static constexpr nsecs_t kInvalidTime = std::numeric_limits<int64_t>::max();
    std::unique_ptr<TimeKeeper> const mTimeKeeper;
    VSyncTracker& mTracker;
    nsecs_t const mTimerSlack;
    nsecs_t const mMinVsyncDistance;

    std::mutex mutable mMutex;
    size_t mCallbackToken GUARDED_BY(mMutex) = 0;

    CallbackMap mCallbacks GUARDED_BY(mMutex);
    nsecs_t mIntendedWakeupTime GUARDED_BY(mMutex) = kInvalidTime;

    // For debugging purposes
    nsecs_t mLastTimerCallback GUARDED_BY(mMutex) = kInvalidTime;
    nsecs_t mLastTimerSchedule GUARDED_BY(mMutex) = kInvalidTime;
};

} // namespace android::scheduler
