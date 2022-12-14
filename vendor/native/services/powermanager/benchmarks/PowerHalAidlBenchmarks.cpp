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

#define LOG_TAG "PowerHalAidlBenchmarks"

#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/IPowerHintSession.h>
#include <android/hardware/power/Mode.h>
#include <android/hardware/power/WorkDuration.h>
#include <benchmark/benchmark.h>
#include <binder/IServiceManager.h>
#include <testUtil.h>
#include <chrono>

using android::hardware::power::Boost;
using android::hardware::power::IPower;
using android::hardware::power::IPowerHintSession;
using android::hardware::power::Mode;
using android::hardware::power::WorkDuration;
using std::chrono::microseconds;

using namespace android;
using namespace std::chrono_literals;

// Values from Boost.aidl and Mode.aidl.
static constexpr int64_t FIRST_BOOST = static_cast<int64_t>(Boost::INTERACTION);
static constexpr int64_t LAST_BOOST = static_cast<int64_t>(Boost::CAMERA_SHOT);
static constexpr int64_t FIRST_MODE = static_cast<int64_t>(Mode::DOUBLE_TAP_TO_WAKE);
static constexpr int64_t LAST_MODE = static_cast<int64_t>(Mode::CAMERA_STREAMING_HIGH);

class DurationWrapper : public WorkDuration {
public:
    DurationWrapper(int64_t dur, int64_t time) {
        durationNanos = dur;
        timeStampNanos = time;
    }
};

static const std::vector<WorkDuration> DURATIONS = {
        DurationWrapper(1L, 1L),
        DurationWrapper(1000L, 2L),
        DurationWrapper(1000000L, 3L),
        DurationWrapper(1000000000L, 4L),
};

// Delay between oneway method calls to avoid overflowing the binder buffers.
static constexpr microseconds ONEWAY_API_DELAY = 100us;

template <class R, class... Args0, class... Args1>
static void runBenchmark(benchmark::State& state, microseconds delay, R (IPower::*fn)(Args0...),
                         Args1&&... args1) {
    sp<IPower> hal = waitForVintfService<IPower>();

    if (hal == nullptr) {
        ALOGI("Power HAL not available, skipping test...");
        return;
    }

    binder::Status ret = (*hal.*fn)(std::forward<Args1>(args1)...);
    if (ret.exceptionCode() == binder::Status::Exception::EX_UNSUPPORTED_OPERATION) {
        ALOGI("Power HAL does not support this operation, skipping test...");
        return;
    }

    while (state.KeepRunning()) {
        ret = (*hal.*fn)(std::forward<Args1>(args1)...);
        state.PauseTiming();
        if (!ret.isOk()) state.SkipWithError(ret.toString8().c_str());
        if (delay > 0us) {
            testDelaySpin(std::chrono::duration_cast<std::chrono::duration<float>>(delay).count());
        }
        state.ResumeTiming();
    }
}

template <class R, class... Args0, class... Args1>
static void runSessionBenchmark(benchmark::State& state, R (IPowerHintSession::*fn)(Args0...),
                                Args1&&... args1) {
    sp<IPower> pwHal = waitForVintfService<IPower>();

    if (pwHal == nullptr) {
        ALOGI("Power HAL not available, skipping test...");
        return;
    }

    // do not use tid from the benchmark process, use 1 for init
    std::vector<int32_t> threadIds{1};
    int64_t durationNanos = 16666666L;
    sp<IPowerHintSession> hal;

    auto status = pwHal->createHintSession(1, 0, threadIds, durationNanos, &hal);

    if (hal == nullptr) {
        ALOGI("Power HAL doesn't support session, skipping test...");
        return;
    }

    binder::Status ret = (*hal.*fn)(std::forward<Args1>(args1)...);
    if (ret.exceptionCode() == binder::Status::Exception::EX_UNSUPPORTED_OPERATION) {
        ALOGI("Power HAL does not support this operation, skipping test...");
        return;
    }

    while (state.KeepRunning()) {
        ret = (*hal.*fn)(std::forward<Args1>(args1)...);
        state.PauseTiming();
        if (!ret.isOk()) state.SkipWithError(ret.toString8().c_str());
        if (ONEWAY_API_DELAY > 0us) {
            testDelaySpin(std::chrono::duration_cast<std::chrono::duration<float>>(ONEWAY_API_DELAY)
                                  .count());
        }
        state.ResumeTiming();
    }
    hal->close();
}

static void BM_PowerHalAidlBenchmarks_isBoostSupported(benchmark::State& state) {
    bool isSupported;
    Boost boost = static_cast<Boost>(state.range(0));
    runBenchmark(state, 0us, &IPower::isBoostSupported, boost, &isSupported);
}

static void BM_PowerHalAidlBenchmarks_isModeSupported(benchmark::State& state) {
    bool isSupported;
    Mode mode = static_cast<Mode>(state.range(0));
    runBenchmark(state, 0us, &IPower::isModeSupported, mode, &isSupported);
}

static void BM_PowerHalAidlBenchmarks_setBoost(benchmark::State& state) {
    Boost boost = static_cast<Boost>(state.range(0));
    runBenchmark(state, ONEWAY_API_DELAY, &IPower::setBoost, boost, 1);
}

static void BM_PowerHalAidlBenchmarks_setMode(benchmark::State& state) {
    Mode mode = static_cast<Mode>(state.range(0));
    runBenchmark(state, ONEWAY_API_DELAY, &IPower::setMode, mode, false);
}

static void BM_PowerHalAidlBenchmarks_createHintSession(benchmark::State& state) {
    std::vector<int32_t> threadIds{static_cast<int32_t>(state.range(0))};
    int64_t durationNanos = 16666666L;
    int32_t tgid = 999;
    int32_t uid = 1001;
    sp<IPowerHintSession> appSession;
    sp<IPower> hal = waitForVintfService<IPower>();

    if (hal == nullptr) {
        ALOGI("Power HAL not available, skipping test...");
        return;
    }

    binder::Status ret = hal->createHintSession(tgid, uid, threadIds, durationNanos, &appSession);
    if (ret.exceptionCode() == binder::Status::Exception::EX_UNSUPPORTED_OPERATION) {
        ALOGI("Power HAL does not support this operation, skipping test...");
        return;
    }

    while (state.KeepRunning()) {
        ret = hal->createHintSession(tgid, uid, threadIds, durationNanos, &appSession);
        state.PauseTiming();
        if (!ret.isOk()) state.SkipWithError(ret.toString8().c_str());
        appSession->close();
        state.ResumeTiming();
    }
}

static void BM_PowerHalAidlBenchmarks_getHintSessionPreferredRate(benchmark::State& state) {
    int64_t rate;
    runBenchmark(state, 0us, &IPower::getHintSessionPreferredRate, &rate);
}

static void BM_PowerHalAidlBenchmarks_updateTargetWorkDuration(benchmark::State& state) {
    int64_t duration = 1000;
    runSessionBenchmark(state, &IPowerHintSession::updateTargetWorkDuration, duration);
}

static void BM_PowerHalAidlBenchmarks_reportActualWorkDuration(benchmark::State& state) {
    runSessionBenchmark(state, &IPowerHintSession::reportActualWorkDuration, DURATIONS);
}

BENCHMARK(BM_PowerHalAidlBenchmarks_isBoostSupported)->DenseRange(FIRST_BOOST, LAST_BOOST, 1);
BENCHMARK(BM_PowerHalAidlBenchmarks_isModeSupported)->DenseRange(FIRST_MODE, LAST_MODE, 1);
BENCHMARK(BM_PowerHalAidlBenchmarks_setBoost)->DenseRange(FIRST_BOOST, LAST_BOOST, 1);
BENCHMARK(BM_PowerHalAidlBenchmarks_setMode)->DenseRange(FIRST_MODE, LAST_MODE, 1);
BENCHMARK(BM_PowerHalAidlBenchmarks_createHintSession)->Arg(1);
BENCHMARK(BM_PowerHalAidlBenchmarks_getHintSessionPreferredRate);
BENCHMARK(BM_PowerHalAidlBenchmarks_updateTargetWorkDuration);
BENCHMARK(BM_PowerHalAidlBenchmarks_reportActualWorkDuration);
