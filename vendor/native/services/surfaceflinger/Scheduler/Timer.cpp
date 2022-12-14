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

#undef LOG_TAG
#define LOG_TAG "SchedulerTimer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/unistd.h>
#include <utils/Trace.h>
#include <chrono>
#include <cstdint>

#include "SchedulerUtils.h"
#include "Timer.h"

namespace android::scheduler {
using base::StringAppendF;

static constexpr size_t kReadPipe = 0;
static constexpr size_t kWritePipe = 1;

Timer::Timer() {
    reset();
    mDispatchThread = std::thread([this]() { threadMain(); });
}

Timer::~Timer() {
    endDispatch();
    mDispatchThread.join();
    cleanup();
}

void Timer::reset() {
    cleanup();
    mTimerFd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    mEpollFd = epoll_create1(EPOLL_CLOEXEC);
    if (pipe2(mPipes.data(), O_CLOEXEC | O_NONBLOCK)) {
        ALOGE("could not create TimerDispatch mPipes");
        return;
    };
    setDebugState(DebugState::Reset);
}

void Timer::cleanup() {
    if (mTimerFd != -1) {
        close(mTimerFd);
        mTimerFd = -1;
    }

    if (mEpollFd != -1) {
        close(mEpollFd);
        mEpollFd = -1;
    }

    if (mPipes[kReadPipe] != -1) {
        close(mPipes[kReadPipe]);
        mPipes[kReadPipe] = -1;
    }

    if (mPipes[kWritePipe] != -1) {
        close(mPipes[kWritePipe]);
        mPipes[kWritePipe] = -1;
    }
}

void Timer::endDispatch() {
    static constexpr unsigned char end = 'e';
    write(mPipes[kWritePipe], &end, sizeof(end));
}

nsecs_t Timer::now() const {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

void Timer::alarmAt(std::function<void()> const& cb, nsecs_t time) {
    std::lock_guard<decltype(mMutex)> lk(mMutex);
    using namespace std::literals;
    static constexpr int ns_per_s =
            std::chrono::duration_cast<std::chrono::nanoseconds>(1s).count();

    mCallback = cb;

    struct itimerspec old_timer;
    struct itimerspec new_timer {
        .it_interval = {.tv_sec = 0, .tv_nsec = 0},
        .it_value = {.tv_sec = static_cast<long>(time / ns_per_s),
                     .tv_nsec = static_cast<long>(time % ns_per_s)},
    };

    if (timerfd_settime(mTimerFd, TFD_TIMER_ABSTIME, &new_timer, &old_timer)) {
        ALOGW("Failed to set timerfd %s (%i)", strerror(errno), errno);
    }
}

void Timer::alarmCancel() {
    std::lock_guard<decltype(mMutex)> lk(mMutex);

    struct itimerspec old_timer;
    struct itimerspec new_timer {
        .it_interval = {.tv_sec = 0, .tv_nsec = 0},
        .it_value = {
                .tv_sec = 0,
                .tv_nsec = 0,
        },
    };

    if (timerfd_settime(mTimerFd, 0, &new_timer, &old_timer)) {
        ALOGW("Failed to disarm timerfd");
    }
}

void Timer::threadMain() {
    while (dispatch()) {
        reset();
    }
}

bool Timer::dispatch() {
    setDebugState(DebugState::Running);
    struct sched_param param = {0};
    param.sched_priority = 2;
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
        ALOGW("Failed to set SCHED_FIFO on dispatch thread");
    }

    if (pthread_setname_np(pthread_self(), "TimerDispatch")) {
        ALOGW("Failed to set thread name on dispatch thread");
    }

    enum DispatchType : uint32_t { TIMER, TERMINATE, MAX_DISPATCH_TYPE };
    epoll_event timerEvent;
    timerEvent.events = EPOLLIN;
    timerEvent.data.u32 = DispatchType::TIMER;
    if (epoll_ctl(mEpollFd, EPOLL_CTL_ADD, mTimerFd, &timerEvent) == -1) {
        ALOGE("Error adding timer fd to epoll dispatch loop");
        return true;
    }

    epoll_event terminateEvent;
    terminateEvent.events = EPOLLIN;
    terminateEvent.data.u32 = DispatchType::TERMINATE;
    if (epoll_ctl(mEpollFd, EPOLL_CTL_ADD, mPipes[kReadPipe], &terminateEvent) == -1) {
        ALOGE("Error adding control fd to dispatch loop");
        return true;
    }

    uint64_t iteration = 0;
    char const traceNamePrefix[] = "TimerIteration #";
    static constexpr size_t maxlen = arrayLen(traceNamePrefix) + max64print;
    std::array<char, maxlen> str_buffer;

    while (true) {
        setDebugState(DebugState::Waiting);
        epoll_event events[DispatchType::MAX_DISPATCH_TYPE];
        int nfds = epoll_wait(mEpollFd, events, DispatchType::MAX_DISPATCH_TYPE, -1);

        setDebugState(DebugState::Running);
        if (ATRACE_ENABLED()) {
            snprintf(str_buffer.data(), str_buffer.size(), "%s%" PRIu64, traceNamePrefix,
                     iteration++);
            ATRACE_NAME(str_buffer.data());
        }

        if (nfds == -1) {
            if (errno != EINTR) {
                ALOGE("Error waiting on epoll: %s", strerror(errno));
                return true;
            }
        }

        for (auto i = 0; i < nfds; i++) {
            if (events[i].data.u32 == DispatchType::TIMER) {
                static uint64_t mIgnored = 0;
                setDebugState(DebugState::Reading);
                read(mTimerFd, &mIgnored, sizeof(mIgnored));
                setDebugState(DebugState::Running);
                std::function<void()> cb;
                {
                    std::lock_guard<decltype(mMutex)> lk(mMutex);
                    cb = mCallback;
                }
                if (cb) {
                    setDebugState(DebugState::InCallback);
                    cb();
                    setDebugState(DebugState::Running);
                }
            }
            if (events[i].data.u32 == DispatchType::TERMINATE) {
                ALOGE("Terminated");
                setDebugState(DebugState::Running);
                return false;
            }
        }
    }
}

void Timer::setDebugState(DebugState state) {
    std::lock_guard lk(mMutex);
    mDebugState = state;
}

const char* Timer::strDebugState(DebugState state) const {
    switch (state) {
        case DebugState::Reset:
            return "Reset";
        case DebugState::Running:
            return "Running";
        case DebugState::Waiting:
            return "Waiting";
        case DebugState::Reading:
            return "Reading";
        case DebugState::InCallback:
            return "InCallback";
        case DebugState::Terminated:
            return "Terminated";
    }
}

void Timer::dump(std::string& result) const {
    std::lock_guard lk(mMutex);
    StringAppendF(&result, "\t\tDebugState: %s\n", strDebugState(mDebugState));
}

} // namespace android::scheduler
