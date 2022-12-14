/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *            http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "VibratorHalWrapperAidlTest"

#include <android-base/thread_annotations.h>
#include <android/hardware/vibrator/IVibrator.h>
#include <condition_variable>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/Log.h>
#include <thread>

#include <vibratorservice/VibratorCallbackScheduler.h>

using std::chrono::milliseconds;
using std::chrono::steady_clock;
using std::chrono::time_point;

using namespace android;
using namespace std::chrono_literals;
using namespace testing;

// -------------------------------------------------------------------------------------------------

class VibratorCallbackSchedulerTest : public Test {
public:
    void SetUp() override {
        mScheduler = std::make_unique<vibrator::CallbackScheduler>();
        std::lock_guard<std::mutex> lock(mMutex);
        mExpiredCallbacks.clear();
    }

protected:
    std::mutex mMutex;
    std::condition_variable_any mCondition;
    std::unique_ptr<vibrator::CallbackScheduler> mScheduler = nullptr;
    std::vector<int32_t> mExpiredCallbacks GUARDED_BY(mMutex);

    std::function<void()> createCallback(int32_t id) {
        return [=]() {
            {
                std::lock_guard<std::mutex> lock(mMutex);
                mExpiredCallbacks.push_back(id);
            }
            mCondition.notify_all();
        };
    }

    std::vector<int32_t> getExpiredCallbacks() {
        std::lock_guard<std::mutex> lock(mMutex);
        return std::vector<int32_t>(mExpiredCallbacks);
    }

    bool waitForCallbacks(uint32_t callbackCount, milliseconds timeout) {
        time_point<steady_clock> expiration = steady_clock::now() + timeout;
        while (steady_clock::now() < expiration) {
            std::lock_guard<std::mutex> lock(mMutex);
            if (callbackCount <= mExpiredCallbacks.size()) {
                return true;
            }
            mCondition.wait_until(mMutex, expiration);
        }
        return false;
    }
};

// -------------------------------------------------------------------------------------------------

TEST_F(VibratorCallbackSchedulerTest, TestScheduleRunsOnlyAfterDelay) {
    mScheduler->schedule(createCallback(1), 15ms);

    // Not triggered before delay.
    ASSERT_FALSE(waitForCallbacks(1, 10ms));
    ASSERT_TRUE(getExpiredCallbacks().empty());

    ASSERT_TRUE(waitForCallbacks(1, 10ms));
    ASSERT_THAT(getExpiredCallbacks(), ElementsAre(1));
}

TEST_F(VibratorCallbackSchedulerTest, TestScheduleMultipleCallbacksRunsInDelayOrder) {
    mScheduler->schedule(createCallback(1), 10ms);
    mScheduler->schedule(createCallback(2), 5ms);
    mScheduler->schedule(createCallback(3), 1ms);

    ASSERT_TRUE(waitForCallbacks(3, 15ms));
    ASSERT_THAT(getExpiredCallbacks(), ElementsAre(3, 2, 1));
}

TEST_F(VibratorCallbackSchedulerTest, TestScheduleInParallelRunsInDelayOrder) {
    std::vector<std::thread> threads;
    for (int i = 0; i < 5; i++) {
        threads.push_back(std::thread(
                [=]() { mScheduler->schedule(createCallback(i), milliseconds(10 + 2 * i)); }));
    }
    std::for_each(threads.begin(), threads.end(), [](std::thread& t) { t.join(); });

    ASSERT_TRUE(waitForCallbacks(5, 25ms));
    ASSERT_THAT(getExpiredCallbacks(), ElementsAre(0, 1, 2, 3, 4));
}

TEST_F(VibratorCallbackSchedulerTest, TestDestructorDropsPendingCallbacksAndKillsThread) {
    mScheduler->schedule(createCallback(1), 5ms);
    mScheduler.reset(nullptr);

    // Should time out waiting for callback to run.
    ASSERT_FALSE(waitForCallbacks(1, 10ms));
    ASSERT_TRUE(getExpiredCallbacks().empty());
}
