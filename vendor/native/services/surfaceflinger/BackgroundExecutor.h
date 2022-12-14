/*
 * Copyright 2021 The Android Open Source Project
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

#include <Tracing/LocklessStack.h>
#include <android-base/thread_annotations.h>
#include <ftl/small_vector.h>
#include <semaphore.h>
#include <utils/Singleton.h>
#include <mutex>
#include <queue>
#include <thread>

namespace android {

// Executes tasks off the main thread.
class BackgroundExecutor : public Singleton<BackgroundExecutor> {
public:
    BackgroundExecutor();
    ~BackgroundExecutor();
    using Callbacks = ftl::SmallVector<std::function<void()>, 10>;
    // Queues callbacks onto a work queue to be executed by a background thread.
    // Note that this is not thread-safe - a single producer is assumed.
    void sendCallbacks(Callbacks&& tasks);

private:
    sem_t mSemaphore;
    std::atomic_bool mDone = false;

    // Sequence number for work items.
    // Work items are batched by sequence number. Work items for earlier sequence numbers are
    // executed first. Work items with the same sequence number are executed in the same order they
    // were added to the stack (meaning the stack must reverse the order after popping from the
    // queue)
    int32_t mSequence = 0;
    struct Work {
        int32_t sequence = 0;
        Callbacks tasks;
    };
    LocklessStack<Work> mWorks;
    std::thread mThread;
};

} // namespace android
