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
#include <string>

#include <utils/Timers.h>

namespace android::scheduler {

class Clock {
public:
    virtual ~Clock();

    /*
     * Returns the SYSTEM_TIME_MONOTONIC, used by testing infra to stub time.
     */
    virtual nsecs_t now() const = 0;

protected:
    Clock() = default;

    Clock(const Clock&) = delete;
    Clock& operator=(const Clock&) = delete;
};

/*
 * TimeKeeper is the interface for a single-shot timer primitive.
 */
class TimeKeeper : public Clock {
public:
    virtual ~TimeKeeper();

    /*
     * Arms callback to fired when time is current based on CLOCK_MONOTONIC
     * There is only one timer, and subsequent calls will reset the callback function and the time.
     */
    virtual void alarmAt(std::function<void()>, nsecs_t time) = 0;

    /*
     * Cancels an existing pending callback
     */
    virtual void alarmCancel() = 0;

    virtual void dump(std::string&) const = 0;

protected:
    TimeKeeper() = default;

    TimeKeeper(const TimeKeeper&) = delete;
    TimeKeeper& operator=(const TimeKeeper&) = delete;
};

} // namespace android::scheduler
