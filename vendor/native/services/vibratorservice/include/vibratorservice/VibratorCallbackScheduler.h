/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_VIBRATOR_CALLBACK_SCHEDULER_H
#define ANDROID_VIBRATOR_CALLBACK_SCHEDULER_H

#include <android-base/thread_annotations.h>
#include <chrono>
#include <condition_variable>
#include <queue>
#include <thread>

namespace android {

namespace vibrator {

// Wrapper for a callback to be executed after a delay.
class DelayedCallback {
public:
    using Timestamp = std::chrono::time_point<std::chrono::steady_clock>;

    DelayedCallback(std::function<void()> callback, std::chrono::milliseconds delay)
          : mCallback(callback), mExpiration(std::chrono::steady_clock::now() + delay) {}
    ~DelayedCallback() = default;

    void run() const;
    bool isExpired() const;
    Timestamp getExpiration() const;

    // Compare by expiration time, where A < B when A expires first.
    bool operator<(const DelayedCallback& other) const;
    bool operator>(const DelayedCallback& other) const;

private:
    std::function<void()> mCallback;
    Timestamp mExpiration;
};

// Schedules callbacks to be executed after a delay.
class CallbackScheduler {
public:
    CallbackScheduler() : mCallbackThread(nullptr), mFinished(false) {}
    virtual ~CallbackScheduler();

    virtual void schedule(std::function<void()> callback, std::chrono::milliseconds delay);

private:
    std::condition_variable_any mCondition;
    std::mutex mMutex;

    // Lazily instantiated only at the first time this scheduler is used.
    std::unique_ptr<std::thread> mCallbackThread;

    // Used to quit the callback thread when this instance is being destroyed.
    bool mFinished GUARDED_BY(mMutex);

    // Priority queue with reverse comparator, so tasks that expire first will be on top.
    std::priority_queue<DelayedCallback, std::vector<DelayedCallback>,
                        std::greater<DelayedCallback>>
            mQueue GUARDED_BY(mMutex);

    void loop();
};

}; // namespace vibrator

}; // namespace android

#endif // ANDROID_VIBRATOR_CALLBACK_SCHEDULER_H
