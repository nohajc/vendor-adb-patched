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

#include <chrono>
#include <cinttypes>
#include <cstdlib>
#include <string>

#include <android-base/stringprintf.h>
#include <ftl/small_map.h>
#include <utils/Timers.h>

#include <scheduler/Fps.h>

#include "DisplayHardware/Hal.h"
#include "TimeStats/TimeStats.h"

namespace android::scheduler {

/**
 * Class to encapsulate statistics about refresh rates that the display is using. When the power
 * mode is set to HWC_POWER_MODE_NORMAL, SF is switching between refresh rates that are stored in
 * the device's configs. Otherwise, we assume the HWC is running in power saving mode under the
 * hood (eg. the device is in DOZE, or screen off mode).
 */
class RefreshRateStats {
    static constexpr int64_t MS_PER_S = 1000;
    static constexpr int64_t MS_PER_MIN = 60 * MS_PER_S;
    static constexpr int64_t MS_PER_HOUR = 60 * MS_PER_MIN;
    static constexpr int64_t MS_PER_DAY = 24 * MS_PER_HOUR;

    using PowerMode = android::hardware::graphics::composer::hal::PowerMode;

public:
    // TODO(b/185535769): Inject clock to avoid sleeping in tests.
    RefreshRateStats(TimeStats& timeStats, Fps currentRefreshRate, PowerMode currentPowerMode)
          : mTimeStats(timeStats),
            mCurrentRefreshRate(currentRefreshRate),
            mCurrentPowerMode(currentPowerMode) {}

    void setPowerMode(PowerMode mode) {
        if (mCurrentPowerMode == mode) {
            return;
        }
        flushTime();
        mCurrentPowerMode = mode;
    }

    // Sets config mode. If the mode has changed, it records how much time was spent in the previous
    // mode.
    void setRefreshRate(Fps currRefreshRate) {
        if (isApproxEqual(mCurrentRefreshRate, currRefreshRate)) {
            return;
        }
        mTimeStats.incrementRefreshRateSwitches();
        flushTime();
        mCurrentRefreshRate = currRefreshRate;
    }

    // Maps stringified refresh rate to total time spent in that mode.
    using TotalTimes = ftl::SmallMap<std::string, std::chrono::milliseconds, 3>;

    TotalTimes getTotalTimes() {
        // If the power mode is on, then we are probably switching between the config modes. If
        // it's not then the screen is probably off. Make sure to flush times before printing
        // them.
        flushTime();

        TotalTimes totalTimes = ftl::init::map("ScreenOff", mScreenOffTime);
        const auto zero = std::chrono::milliseconds::zero();

        // Sum the times for modes that map to the same name, e.g. "60 Hz".
        for (const auto& [fps, time] : mFpsTotalTimes) {
            const auto string = to_string(fps);
            const auto total = std::as_const(totalTimes).get(string).value_or(std::cref(zero));
            totalTimes.emplace_or_replace(string, total.get() + time);
        }

        return totalTimes;
    }

    // Traverses through the map of config modes and returns how long they've been running in easy
    // to read format.
    void dump(std::string& result) const {
        std::ostringstream stream("+  Refresh rate: running time in seconds\n");

        for (const auto& [name, time] : const_cast<RefreshRateStats*>(this)->getTotalTimes()) {
            stream << name << ": " << getDateFormatFromMs(time) << '\n';
        }
        result.append(stream.str());
    }

private:
    // Calculates the time that passed in ms between the last time we recorded time and the time
    // this method was called.
    void flushTime() {
        const nsecs_t currentTime = systemTime();
        const nsecs_t timeElapsed = currentTime - mPreviousRecordedTime;
        mPreviousRecordedTime = currentTime;

        const auto duration = std::chrono::milliseconds{ns2ms(timeElapsed)};
        const auto zero = std::chrono::milliseconds::zero();

        uint32_t fps = 0;

        if (mCurrentPowerMode == PowerMode::ON) {
            // Normal power mode is counted under different config modes.
            const auto total = std::as_const(mFpsTotalTimes)
                                       .get(mCurrentRefreshRate)
                                       .value_or(std::cref(zero));
            mFpsTotalTimes.emplace_or_replace(mCurrentRefreshRate, total.get() + duration);

            fps = static_cast<uint32_t>(mCurrentRefreshRate.getIntValue());
        } else {
            mScreenOffTime += duration;
        }
        mTimeStats.recordRefreshRate(fps, timeElapsed);
    }

    // Formats the time in milliseconds into easy to read format.
    static std::string getDateFormatFromMs(std::chrono::milliseconds time) {
        auto [days, dayRemainderMs] = std::div(static_cast<int64_t>(time.count()), MS_PER_DAY);
        auto [hours, hourRemainderMs] = std::div(dayRemainderMs, MS_PER_HOUR);
        auto [mins, minsRemainderMs] = std::div(hourRemainderMs, MS_PER_MIN);
        auto [sec, secRemainderMs] = std::div(minsRemainderMs, MS_PER_S);
        return base::StringPrintf("%" PRId64 "d%02" PRId64 ":%02" PRId64 ":%02" PRId64
                                  ".%03" PRId64,
                                  days, hours, mins, sec, secRemainderMs);
    }

    // Aggregate refresh rate statistics for telemetry.
    TimeStats& mTimeStats;

    Fps mCurrentRefreshRate;
    PowerMode mCurrentPowerMode;

    ftl::SmallMap<Fps, std::chrono::milliseconds, 2, FpsApproxEqual> mFpsTotalTimes;
    std::chrono::milliseconds mScreenOffTime = std::chrono::milliseconds::zero();

    nsecs_t mPreviousRecordedTime = systemTime();
};

} // namespace android::scheduler
