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

#include <utils/Timers.h>
#include <functional>
#include <string>

#include "StrongTyping.h"

namespace android::scheduler {
class TimeKeeper;
class VSyncTracker;

enum class ScheduleResult { Scheduled, CannotSchedule, Error };
enum class CancelResult { Cancelled, TooLate, Error };

/*
 * VSyncDispatch is a class that will dispatch callbacks relative to system vsync events.
 */
class VSyncDispatch {
public:
    using CallbackToken = StrongTyping<size_t, class CallbackTokenTag, Compare, Hash>;

    virtual ~VSyncDispatch();

    /*
     * A callback that can be registered to be awoken at a given time relative to a vsync event.
     * \param [in] vsyncTime The timestamp of the vsync the callback is for.
     * \param [in] targetWakeupTime The timestamp of intended wakeup time of the cb.
     *
     */
    using Callback = std::function<void(nsecs_t vsyncTime, nsecs_t targetWakeupTime)>;

    /*
     * Registers a callback that will be called at designated points on the vsync timeline.
     * The callback can be scheduled, rescheduled targeting vsync times, or cancelled.
     * The token returned must be cleaned up via unregisterCallback.
     *
     * \param [in] callbackFn   A function to schedule for callback. The resources needed to invoke
     *                          callbackFn must have lifetimes encompassing the lifetime of the
     *                          CallbackToken returned.
     * \param [in] callbackName A human-readable, unique name to identify the callback.
     * \return                  A token that can be used to schedule, reschedule, or cancel the
     *                          invocation of callbackFn.
     *
     */
    virtual CallbackToken registerCallback(Callback const& callbackFn,
                                           std::string callbackName) = 0;

    /*
     * Unregisters a callback.
     *
     * \param [in] token        The callback to unregister.
     *
     */
    virtual void unregisterCallback(CallbackToken token) = 0;

    /*
     * Schedules the registered callback to be dispatched.
     *
     * The callback will be dispatched at 'workDuration' nanoseconds before a vsync event.
     *
     * The caller designates the earliest vsync event that should be targeted by the earliestVsync
     * parameter.
     * The callback will be scheduled at (workDuration - predictedVsync), where predictedVsync
     * is the first vsync event time where ( predictedVsync >= earliestVsync ).
     *
     * If (workDuration - earliestVsync) is in the past, or if a callback has already been
     * dispatched for the predictedVsync, an error will be returned.
     *
     * It is valid to reschedule a callback to a different time.
     *
     * \param [in] token           The callback to schedule.
     * \param [in] workDuration    The time before the actual vsync time to invoke the callback
     *                             associated with token.
     * \param [in] earliestVsync   The targeted display time. This will be snapped to the closest
     *                             predicted vsync time after earliestVsync.
     * \return                     A ScheduleResult::Scheduled if callback was scheduled.
     *                             A ScheduleResult::CannotSchedule
     *                             if (workDuration - earliestVsync) is in the past, or
     *                             if a callback was dispatched for the predictedVsync already.
     *                             A ScheduleResult::Error if there was another error.
     */
    virtual ScheduleResult schedule(CallbackToken token, nsecs_t workDuration,
                                    nsecs_t earliestVsync) = 0;

    /* Cancels a scheduled callback, if possible.
     *
     * \param [in] token    The callback to cancel.
     * \return              A CancelResult::TooLate if the callback was already dispatched.
     *                      A CancelResult::Cancelled if the callback was successfully cancelled.
     *                      A CancelResult::Error if there was an pre-condition violation.
     */
    virtual CancelResult cancel(CallbackToken token) = 0;

    virtual void dump(std::string& result) const = 0;

protected:
    VSyncDispatch() = default;
    VSyncDispatch(VSyncDispatch const&) = delete;
    VSyncDispatch& operator=(VSyncDispatch const&) = delete;
};

/*
 * Helper class to operate on registered callbacks. It is up to user of the class to ensure
 * that VsyncDispatch lifetime exceeds the lifetime of VSyncCallbackRegistation.
 */
class VSyncCallbackRegistration {
public:
    VSyncCallbackRegistration(VSyncDispatch&, VSyncDispatch::Callback const& callbackFn,
                              std::string const& callbackName);
    VSyncCallbackRegistration(VSyncCallbackRegistration&&);
    VSyncCallbackRegistration& operator=(VSyncCallbackRegistration&&);
    ~VSyncCallbackRegistration();

    // See documentation for VSyncDispatch::schedule.
    ScheduleResult schedule(nsecs_t workDuration, nsecs_t earliestVsync);

    // See documentation for VSyncDispatch::cancel.
    CancelResult cancel();

private:
    VSyncCallbackRegistration(VSyncCallbackRegistration const&) = delete;
    VSyncCallbackRegistration& operator=(VSyncCallbackRegistration const&) = delete;

    std::reference_wrapper<VSyncDispatch> mDispatch;
    VSyncDispatch::CallbackToken mToken;
    bool mValidToken;
};

} // namespace android::scheduler
