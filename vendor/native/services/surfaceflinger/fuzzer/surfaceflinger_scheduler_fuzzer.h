/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
    Reference for some of the classes and functions has been taken from unittests
    present in frameworks/native/services/surfaceflinger/tests/unittests
*/

#pragma once

#include <scheduler/TimeKeeper.h>

#include "Clock.h"
#include "Layer.h"
#include "Scheduler/EventThread.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "Scheduler/Scheduler.h"
#include "Scheduler/VSyncTracker.h"
#include "Scheduler/VsyncModulator.h"

namespace android::fuzz {

class FuzzImplClock : public android::scheduler::Clock {
public:
    nsecs_t now() const { return 1; }
};

class ClockWrapper : public android::scheduler::Clock {
public:
    ClockWrapper(std::shared_ptr<android::scheduler::Clock> const& clock) : mClock(clock) {}

    nsecs_t now() const { return mClock->now(); }

private:
    std::shared_ptr<android::scheduler::Clock> const mClock;
};

} // namespace android::fuzz

namespace android {

using namespace std::chrono_literals;

class FakeClock : public Clock {
public:
    virtual ~FakeClock() = default;
    std::chrono::steady_clock::time_point now() const override { return mNow; }

    void advanceTime(std::chrono::nanoseconds delta) { mNow += delta; }

private:
    std::chrono::steady_clock::time_point mNow;
};

class FuzzImplLayer : public Layer {
public:
    FuzzImplLayer(SurfaceFlinger* flinger, std::string name)
          : Layer(LayerCreationArgs(flinger, nullptr, std::move(name), 0, {})) {}
    explicit FuzzImplLayer(SurfaceFlinger* flinger) : FuzzImplLayer(flinger, "FuzzLayer") {}

    const char* getType() const override { return ""; }

    bool isVisible() const override { return true; }

    sp<Layer> createClone() override { return nullptr; }
};

class FuzzImplVSyncSource : public VSyncSource {
public:
    const char* getName() const override { return "fuzz"; }

    void setVSyncEnabled(bool /* enable */) override {}

    void setCallback(Callback* /* callback */) override {}

    void setDuration(std::chrono::nanoseconds /* workDuration */,
                     std::chrono::nanoseconds /* readyDuration */) override {}

    VSyncData getLatestVSyncData() const override { return {}; }

    void dump(std::string& /* result */) const override {}
};

class FuzzImplVSyncTracker : public scheduler::VSyncTracker {
public:
    FuzzImplVSyncTracker(nsecs_t period) { mPeriod = period; }

    FuzzImplVSyncTracker() = default;

    bool addVsyncTimestamp(nsecs_t /* timestamp */) override { return true; }

    nsecs_t nextAnticipatedVSyncTimeFrom(nsecs_t /* timePoint */) const override { return 1; }

    nsecs_t currentPeriod() const override { return 1; }

    void setPeriod(nsecs_t /* period */) override {}

    void resetModel() override {}

    bool needsMoreSamples() const override { return true; }

    bool isVSyncInPhase(nsecs_t /* timePoint */, Fps /* frameRate */) const override {
        return true;
    }

    nsecs_t nextVSyncTime(nsecs_t timePoint) const {
        if (timePoint % mPeriod == 0) {
            return timePoint;
        }
        return (timePoint - (timePoint % mPeriod) + mPeriod);
    }

    void dump(std::string& /* result */) const override {}

protected:
    nsecs_t mPeriod;
};

class FuzzImplVSyncDispatch : public scheduler::VSyncDispatch {
public:
    CallbackToken registerCallback(Callback /* callbackFn */,
                                   std::string /* callbackName */) override {
        return CallbackToken{};
    }

    void unregisterCallback(CallbackToken /* token */) override {}

    scheduler::ScheduleResult schedule(CallbackToken /* token */,
                                       ScheduleTiming /* scheduleTiming */) override {
        return (scheduler::ScheduleResult)0;
    }

    scheduler::CancelResult cancel(CallbackToken /* token */) override {
        return (scheduler::CancelResult)0;
    }

    void dump(std::string& /* result */) const override {}
};

} // namespace android

namespace android::scheduler {

class ControllableClock : public TimeKeeper {
public:
    nsecs_t now() const { return 1; };
    void alarmAt(std::function<void()> /* callback */, nsecs_t /* time */) override {}
    void alarmCancel() override {}
    void dump(std::string& /* result */) const override {}

    void alarmAtDefaultBehavior(std::function<void()> const& callback, nsecs_t time) {
        mCallback = callback;
        mNextCallbackTime = time;
    }

    nsecs_t fakeTime() const { return mCurrentTime; }

    void advanceToNextCallback() {
        mCurrentTime = mNextCallbackTime;
        if (mCallback) {
            mCallback();
        }
    }

    void advanceBy(nsecs_t advancement) {
        mCurrentTime += advancement;
        if (mCurrentTime >= (mNextCallbackTime + mLag) && mCallback) {
            mCallback();
        }
    };

    void setLag(nsecs_t lag) { mLag = lag; }

private:
    std::function<void()> mCallback;
    nsecs_t mNextCallbackTime = 0;
    nsecs_t mCurrentTime = 0;
    nsecs_t mLag = 0;
};

static VsyncModulator::TimePoint Now() {
    static VsyncModulator::TimePoint now;
    return now += VsyncModulator::MIN_EARLY_TRANSACTION_TIME;
}

class FuzzImplVsyncModulator : public VsyncModulator {
public:
    FuzzImplVsyncModulator(const VsyncConfigSet& config, Now now) : VsyncModulator(config, now) {}

    void binderDied(const wp<IBinder>& token) { VsyncModulator::binderDied(token); }
};
} // namespace android::scheduler
