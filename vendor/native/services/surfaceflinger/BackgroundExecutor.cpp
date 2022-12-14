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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "BackgroundExecutor"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <utils/Log.h>

#include "BackgroundExecutor.h"

namespace android {

ANDROID_SINGLETON_STATIC_INSTANCE(BackgroundExecutor);

BackgroundExecutor::BackgroundExecutor() : Singleton<BackgroundExecutor>() {
    mThread = std::thread([&]() {
        LOG_ALWAYS_FATAL_IF(sem_init(&mSemaphore, 0, 0), "sem_init failed");
        while (!mDone) {
            LOG_ALWAYS_FATAL_IF(sem_wait(&mSemaphore), "sem_wait failed (%d)", errno);

            ftl::SmallVector<Work*, 10> workItems;

            Work* work = mWorks.pop();
            while (work) {
                workItems.push_back(work);
                work = mWorks.pop();
            }

            // Sequence numbers are guaranteed to be in intended order, as we assume a single
            // producer and single consumer.
            std::stable_sort(workItems.begin(), workItems.end(), [](Work* left, Work* right) {
                return left->sequence < right->sequence;
            });
            for (Work* work : workItems) {
                for (auto& task : work->tasks) {
                    task();
                }
                delete work;
            }
        }
    });
}

BackgroundExecutor::~BackgroundExecutor() {
    mDone = true;
    LOG_ALWAYS_FATAL_IF(sem_post(&mSemaphore), "sem_post failed");
    if (mThread.joinable()) {
        mThread.join();
        LOG_ALWAYS_FATAL_IF(sem_destroy(&mSemaphore), "sem_destroy failed");
    }
}

void BackgroundExecutor::sendCallbacks(Callbacks&& tasks) {
    Work* work = new Work();
    work->sequence = mSequence;
    work->tasks = std::move(tasks);
    mWorks.push(work);
    mSequence++;
    LOG_ALWAYS_FATAL_IF(sem_post(&mSemaphore), "sem_post failed");
}

} // namespace android