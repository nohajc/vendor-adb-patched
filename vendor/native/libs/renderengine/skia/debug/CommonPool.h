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

#pragma once

#include <log/log.h>

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>

namespace android {
namespace renderengine {
namespace skia {

namespace {
#define PREVENT_COPY_AND_ASSIGN(Type) \
private:                              \
    Type(const Type&) = delete;       \
    void operator=(const Type&) = delete
} // namespace

/**
 * Shamelessly copied from HWUI to execute Skia Capturing on the back thread in
 * a safe manner.
 */
class CommonPool {
    PREVENT_COPY_AND_ASSIGN(CommonPool);

public:
    using Task = std::function<void()>;
    static constexpr auto THREAD_COUNT = 2;
    static constexpr auto QUEUE_SIZE = 128;

    static void post(Task&& func);

private:
    static CommonPool& instance();

    CommonPool();
    ~CommonPool() {}

    void enqueue(Task&&);

    void workerLoop();

    std::mutex mLock;
    std::condition_variable mCondition;
    int mWaitingThreads = 0;
    std::queue<Task> mWorkQueue;
};

} // namespace skia
} // namespace renderengine
} // namespace android
