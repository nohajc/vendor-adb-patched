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

#include "TimeKeeper.h"

#include <android-base/thread_annotations.h>
#include <array>
#include <thread>

namespace android::scheduler {

class Timer : public TimeKeeper {
public:
    Timer();
    ~Timer();
    nsecs_t now() const final;

    // NB: alarmAt and alarmCancel are threadsafe; with the last-returning function being effectual
    //     Most users will want to serialize thes calls so as to be aware of the timer state.
    void alarmAt(std::function<void()> const& cb, nsecs_t time) final;
    void alarmCancel() final;
    void dump(std::string& result) const final;

private:
    enum class DebugState { Reset, Running, Waiting, Reading, InCallback, Terminated };
    void reset();
    void cleanup();
    void setDebugState(DebugState state) EXCLUDES(mMutex);
    const char* strDebugState(DebugState state) const;

    int mTimerFd = -1;
    int mEpollFd = -1;
    std::array<int, 2> mPipes = {-1, -1};

    std::thread mDispatchThread;
    void threadMain();
    bool dispatch();
    void endDispatch();

    mutable std::mutex mMutex;
    std::function<void()> mCallback GUARDED_BY(mMutex);
    DebugState mDebugState GUARDED_BY(mMutex);
};

} // namespace android::scheduler
