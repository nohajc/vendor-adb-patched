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

#include "OneShotTimer.h"

#include <chrono>
#include <sstream>
#include <thread>

namespace android {
namespace scheduler {

OneShotTimer::OneShotTimer(const Interval& interval, const ResetCallback& resetCallback,
                           const TimeoutCallback& timeoutCallback)
      : mInterval(interval), mResetCallback(resetCallback), mTimeoutCallback(timeoutCallback) {}

OneShotTimer::~OneShotTimer() {
    stop();
}

void OneShotTimer::start() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = TimerState::RESET;
    }
    mThread = std::thread(&OneShotTimer::loop, this);
}

void OneShotTimer::stop() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = TimerState::STOPPED;
    }
    mCondition.notify_all();
    if (mThread.joinable()) {
        mThread.join();
    }
}

void OneShotTimer::loop() {
    while (true) {
        bool triggerReset = false;
        bool triggerTimeout = false;
        {
            std::lock_guard<std::mutex> lock(mMutex);
            if (mState == TimerState::STOPPED) {
                break;
            }

            if (mState == TimerState::IDLE) {
                mCondition.wait(mMutex);
                continue;
            }

            if (mState == TimerState::RESET) {
                triggerReset = true;
            }
        }
        if (triggerReset && mResetCallback) {
            mResetCallback();
        }

        { // lock the mutex again. someone might have called stop meanwhile
            std::lock_guard<std::mutex> lock(mMutex);
            if (mState == TimerState::STOPPED) {
                break;
            }

            auto triggerTime = std::chrono::steady_clock::now() + mInterval;
            mState = TimerState::WAITING;
            while (mState == TimerState::WAITING) {
                constexpr auto zero = std::chrono::steady_clock::duration::zero();
                auto waitTime = triggerTime - std::chrono::steady_clock::now();
                if (waitTime > zero) mCondition.wait_for(mMutex, waitTime);
                if (mState == TimerState::RESET) {
                    triggerTime = std::chrono::steady_clock::now() + mInterval;
                    mState = TimerState::WAITING;
                } else if (mState == TimerState::WAITING &&
                           (triggerTime - std::chrono::steady_clock::now()) <= zero) {
                    triggerTimeout = true;
                    mState = TimerState::IDLE;
                }
            }
        }
        if (triggerTimeout && mTimeoutCallback) {
            mTimeoutCallback();
        }
    }
}

void OneShotTimer::reset() {
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mState = TimerState::RESET;
    }
    mCondition.notify_all();
}

std::string OneShotTimer::dump() const {
    std::ostringstream stream;
    stream << mInterval.count() << " ms";
    return stream.str();
}

} // namespace scheduler
} // namespace android
