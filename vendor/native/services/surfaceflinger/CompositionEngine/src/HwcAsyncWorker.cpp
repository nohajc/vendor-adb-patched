/*
 * Copyright 2022 The Android Open Source Project
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

#include <compositionengine/impl/HwcAsyncWorker.h>
#include <processgroup/sched_policy.h>
#include <pthread.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <system/thread_defs.h>

#include <android-base/thread_annotations.h>
#include <cutils/sched_policy.h>

namespace android::compositionengine::impl {

HwcAsyncWorker::HwcAsyncWorker() {
    mThread = std::thread(&HwcAsyncWorker::run, this);
    pthread_setname_np(mThread.native_handle(), "HwcAsyncWorker");
}

HwcAsyncWorker::~HwcAsyncWorker() {
    {
        std::scoped_lock lock(mMutex);
        mDone = true;
        mCv.notify_all();
    }
    if (mThread.joinable()) {
        mThread.join();
    }
}
std::future<bool> HwcAsyncWorker::send(std::function<bool()> task) {
    std::unique_lock<std::mutex> lock(mMutex);
    android::base::ScopedLockAssertion assumeLock(mMutex);
    mTask = std::packaged_task<bool()>([task = std::move(task)]() { return task(); });
    mTaskRequested = true;
    mCv.notify_one();
    return mTask.get_future();
}

void HwcAsyncWorker::run() {
    set_sched_policy(0, SP_FOREGROUND);
    struct sched_param param = {0};
    param.sched_priority = 2;
    sched_setscheduler(gettid(), SCHED_FIFO, &param);

    std::unique_lock<std::mutex> lock(mMutex);
    android::base::ScopedLockAssertion assumeLock(mMutex);
    while (!mDone) {
        mCv.wait(lock);
        if (mTaskRequested && mTask.valid()) {
            mTask();
            mTaskRequested = false;
        }
    }
}

} // namespace android::compositionengine::impl
