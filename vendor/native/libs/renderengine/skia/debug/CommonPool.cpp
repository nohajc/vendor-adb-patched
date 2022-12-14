/*
 * Copyright 2020 The Android Open Source Project
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

#include "CommonPool.h"

#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <sys/resource.h>
#include <utils/Trace.h>

#include <system/thread_defs.h>
#include <array>

namespace android {
namespace renderengine {
namespace skia {

CommonPool::CommonPool() {
    ATRACE_CALL();

    CommonPool* pool = this;
    // Create 2 workers
    for (int i = 0; i < THREAD_COUNT; i++) {
        std::thread worker([pool, i] {
            {
                std::array<char, 20> name{"reTask"};
                snprintf(name.data(), name.size(), "reTask%d", i);
                auto self = pthread_self();
                pthread_setname_np(self, name.data());
                setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_FOREGROUND);
            }
            pool->workerLoop();
        });
        worker.detach();
    }
}

CommonPool& CommonPool::instance() {
    static CommonPool pool;
    return pool;
}

void CommonPool::post(Task&& task) {
    instance().enqueue(std::move(task));
}

void CommonPool::enqueue(Task&& task) {
    std::unique_lock lock(mLock);
    while (mWorkQueue.size() > QUEUE_SIZE) {
        lock.unlock();
        ALOGW("Queue is full: %d, waiting before adding more tasks.", QUEUE_SIZE);
        usleep(100);
        lock.lock();
    }
    mWorkQueue.push(std::move(task));
    if (mWaitingThreads == THREAD_COUNT || (mWaitingThreads > 0 && mWorkQueue.size() > 1)) {
        mCondition.notify_one();
    }
}

void CommonPool::workerLoop() {
    std::unique_lock lock(mLock);
    while (true) {
        if (mWorkQueue.size() == 0) {
            mWaitingThreads++;
            mCondition.wait(lock);
            mWaitingThreads--;
        }
        // Need to double-check that work is still available now that we have the lock
        // It may have already been grabbed by a different thread
        while (mWorkQueue.size() > 0) {
            auto work = mWorkQueue.front();
            mWorkQueue.pop();
            lock.unlock();
            work();
            lock.lock();
        }
    }
}

} // namespace skia
} // namespace renderengine
} // namespace android