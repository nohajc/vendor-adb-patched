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

#include <android-base/thread_annotations.h>
#include <array>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "SchedulerUtils.h"
#include "VSyncDispatch.h"

namespace android::scheduler {

// VSyncDispatchTimerQueueEntry is a helper class representing internal state for each entry in
// VSyncDispatchTimerQueue hoisted to public for unit testing.
class VSyncDispatchTimerQueueEntry {
public:
    // This is the state of the entry. There are 3 states, armed, running, disarmed.
    // Valid transition: disarmed -> armed ( when scheduled )
    // Valid transition: armed -> running -> disarmed ( when timer is called)
    // Valid transition: armed -> disarmed ( when cancelled )
    VSyncDispatchTimerQueueEntry(std::string const& name, VSyncDispatch::Callback const& fn,
                                 nsecs_t minVsyncDistance);
    std::string_view name() const;

    // Start: functions that are not threadsafe.
    // Return the last vsync time this callback was invoked.
    std::optional<nsecs_t> lastExecutedVsyncTarget() const;

    // This moves the state from disarmed->armed and will calculate the wakeupTime.
    ScheduleResult schedule(nsecs_t workDuration, nsecs_t earliestVsync, VSyncTracker& tracker,
                            nsecs_t now);
    // This will update armed entries with the latest vsync information. Entry remains armed.
    void update(VSyncTracker& tracker, nsecs_t now);

    // This will return empty if not armed, or the next calculated wakeup time if armed.
    // It will not update the wakeupTime.
    std::optional<nsecs_t> wakeupTime() const;

    std::optional<nsecs_t> targetVsync() const;

    // This moves state from armed->disarmed.
    void disarm();

    // This moves the state from armed->running.
    // Store the timestamp that this was intended for as the last called timestamp.
    nsecs_t executing();

    // Adds a pending upload of the earliestVSync and workDuration that will be applied on the next
    // call to update()
    void addPendingWorkloadUpdate(nsecs_t workDuration, nsecs_t earliestVsync);

    // Checks if there is a pending update to the workload, returning true if so.
    bool hasPendingWorkloadUpdate() const;
    // End: functions that are not threadsafe.

    // Invoke the callback with the two given timestamps, moving the state from running->disarmed.
    void callback(nsecs_t vsyncTimestamp, nsecs_t wakeupTimestamp);
    // Block calling thread while the callback is executing.
    void ensureNotRunning();

    void dump(std::string& result) const;

private:
    std::string const mName;
    VSyncDispatch::Callback const mCallback;

    nsecs_t mWorkDuration;
    nsecs_t mEarliestVsync;
    nsecs_t const mMinVsyncDistance;

    struct ArmingInfo {
        nsecs_t mActualWakeupTime;
        nsecs_t mActualVsyncTime;
    };
    std::optional<ArmingInfo> mArmedInfo;
    std::optional<nsecs_t> mLastDispatchTime;

    struct WorkloadUpdateInfo {
        nsecs_t duration;
        nsecs_t earliestVsync;
    };
    std::optional<WorkloadUpdateInfo> mWorkloadUpdateInfo;

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
    explicit VSyncDispatchTimerQueue(std::unique_ptr<TimeKeeper> tk, VSyncTracker& tracker,
                                     nsecs_t timerSlack, nsecs_t minVsyncDistance);
    ~VSyncDispatchTimerQueue();

    CallbackToken registerCallback(Callback const& callbackFn, std::string callbackName) final;
    void unregisterCallback(CallbackToken token) final;
    ScheduleResult schedule(CallbackToken token, nsecs_t workDuration, nsecs_t earliestVsync) final;
    CancelResult cancel(CallbackToken token) final;
    void dump(std::string& result) const final;

private:
    VSyncDispatchTimerQueue(VSyncDispatchTimerQueue const&) = delete;
    VSyncDispatchTimerQueue& operator=(VSyncDispatchTimerQueue const&) = delete;

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

    struct TraceBuffer {
        static constexpr char const kTraceNamePrefix[] = "-alarm in:";
        static constexpr char const kTraceNameSeparator[] = " for vs:";
        static constexpr size_t kMaxNamePrint = 4;
        static constexpr size_t kNumTsPrinted = 2;
        static constexpr size_t maxlen = kMaxNamePrint + arrayLen(kTraceNamePrefix) +
                arrayLen(kTraceNameSeparator) - 1 + (kNumTsPrinted * max64print);
        std::array<char, maxlen> str_buffer;
        void note(std::string_view name, nsecs_t in, nsecs_t vs);
    } mTraceBuffer GUARDED_BY(mMutex);

    // For debugging purposes
    nsecs_t mLastTimerCallback GUARDED_BY(mMutex) = kInvalidTime;
    nsecs_t mLastTimerSchedule GUARDED_BY(mMutex) = kInvalidTime;
};

} // namespace android::scheduler
