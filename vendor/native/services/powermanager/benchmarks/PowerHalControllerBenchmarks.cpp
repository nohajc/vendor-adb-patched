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

#define LOG_TAG "PowerHalControllerBenchmarks"

#include <android/hardware/power/Boost.h>
#include <android/hardware/power/Mode.h>
#include <benchmark/benchmark.h>
#include <powermanager/PowerHalController.h>
#include <testUtil.h>
#include <chrono>

using android::hardware::power::Boost;
using android::hardware::power::Mode;
using android::power::HalResult;
using android::power::PowerHalController;

using namespace android;
using namespace std::chrono_literals;

// Values from Boost.aidl and Mode.aidl.
static constexpr int64_t FIRST_BOOST = static_cast<int64_t>(Boost::INTERACTION);
static constexpr int64_t LAST_BOOST = static_cast<int64_t>(Boost::CAMERA_SHOT);
static constexpr int64_t FIRST_MODE = static_cast<int64_t>(Mode::DOUBLE_TAP_TO_WAKE);
static constexpr int64_t LAST_MODE = static_cast<int64_t>(Mode::CAMERA_STREAMING_HIGH);

// Delay between oneway method calls to avoid overflowing the binder buffers.
static constexpr std::chrono::microseconds ONEWAY_API_DELAY = 100us;

template <typename T, class... Args0, class... Args1>
static void runBenchmark(benchmark::State& state, HalResult<T> (PowerHalController::*fn)(Args0...),
                         Args1&&... args1) {
    while (state.KeepRunning()) {
        PowerHalController controller;
        HalResult<T> ret = (controller.*fn)(std::forward<Args1>(args1)...);
        state.PauseTiming();
        if (ret.isFailed()) state.SkipWithError("Power HAL request failed");
        state.ResumeTiming();
    }
}

template <typename T, class... Args0, class... Args1>
static void runCachedBenchmark(benchmark::State& state,
                               HalResult<T> (PowerHalController::*fn)(Args0...), Args1&&... args1) {
    PowerHalController controller;
    // First call out of test, to cache HAL service and isSupported result.
    (controller.*fn)(std::forward<Args1>(args1)...);

    while (state.KeepRunning()) {
        HalResult<T> ret = (controller.*fn)(std::forward<Args1>(args1)...);
        state.PauseTiming();
        if (ret.isFailed()) {
            state.SkipWithError("Power HAL request failed");
        }
        testDelaySpin(
                std::chrono::duration_cast<std::chrono::duration<float>>(ONEWAY_API_DELAY).count());
        state.ResumeTiming();
    }
}

static void BM_PowerHalControllerBenchmarks_init(benchmark::State& state) {
    while (state.KeepRunning()) {
        PowerHalController controller;
        controller.init();
    }
}

static void BM_PowerHalControllerBenchmarks_initCached(benchmark::State& state) {
    PowerHalController controller;
    // First connection out of test.
    controller.init();

    while (state.KeepRunning()) {
        controller.init();
    }
}

static void BM_PowerHalControllerBenchmarks_setBoost(benchmark::State& state) {
    Boost boost = static_cast<Boost>(state.range(0));
    runBenchmark(state, &PowerHalController::setBoost, boost, 0);
}

static void BM_PowerHalControllerBenchmarks_setBoostCached(benchmark::State& state) {
    Boost boost = static_cast<Boost>(state.range(0));
    runCachedBenchmark(state, &PowerHalController::setBoost, boost, 0);
}

static void BM_PowerHalControllerBenchmarks_setMode(benchmark::State& state) {
    Mode mode = static_cast<Mode>(state.range(0));
    runBenchmark(state, &PowerHalController::setMode, mode, false);
}

static void BM_PowerHalControllerBenchmarks_setModeCached(benchmark::State& state) {
    Mode mode = static_cast<Mode>(state.range(0));
    runCachedBenchmark(state, &PowerHalController::setMode, mode, false);
}

BENCHMARK(BM_PowerHalControllerBenchmarks_init);
BENCHMARK(BM_PowerHalControllerBenchmarks_initCached);
BENCHMARK(BM_PowerHalControllerBenchmarks_setBoost)->DenseRange(FIRST_BOOST, LAST_BOOST, 1);
BENCHMARK(BM_PowerHalControllerBenchmarks_setBoostCached)->DenseRange(FIRST_BOOST, LAST_BOOST, 1);
BENCHMARK(BM_PowerHalControllerBenchmarks_setMode)->DenseRange(FIRST_MODE, LAST_MODE, 1);
BENCHMARK(BM_PowerHalControllerBenchmarks_setModeCached)->DenseRange(FIRST_MODE, LAST_MODE, 1);
