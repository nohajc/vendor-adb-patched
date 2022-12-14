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

#define LOG_TAG "PowerHalHidlBenchmarks"

#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/Mode.h>
#include <benchmark/benchmark.h>
#include <hardware/power.h>
#include <hardware_legacy/power.h>
#include <testUtil.h>
#include <chrono>

using android::hardware::Return;
using android::hardware::power::Boost;
using android::hardware::power::Mode;
using android::hardware::power::V1_0::Feature;
using android::hardware::power::V1_0::PowerHint;
using std::chrono::microseconds;
using IPower1_0 = android::hardware::power::V1_0::IPower;
using IPower1_1 = android::hardware::power::V1_1::IPower;

using namespace android;
using namespace std::chrono_literals;

// Values from types.hal from versions 1.0 to 1.3.
static constexpr int64_t FIRST_POWER_HINT = static_cast<int64_t>(PowerHint::VSYNC);
static constexpr int64_t LAST_POWER_HINT = static_cast<int64_t>(PowerHint::LAUNCH);

// Delay between oneway method calls to avoid overflowing the binder buffers.
static constexpr microseconds ONEWAY_API_DELAY = 100us;

template <class R, class I, class... Args0, class... Args1>
static void runBenchmark(benchmark::State& state, microseconds delay, Return<R> (I::*fn)(Args0...),
                         Args1&&... args1) {
    sp<I> hal = I::getService();

    if (hal == nullptr) {
        ALOGV("Power HAL HIDL not available, skipping test...");
        return;
    }

    while (state.KeepRunning()) {
        Return<R> ret = (*hal.*fn)(std::forward<Args1>(args1)...);
        state.PauseTiming();
        if (!ret.isOk()) state.SkipWithError(ret.description().c_str());
        if (delay > 0us) {
            testDelaySpin(std::chrono::duration_cast<std::chrono::duration<float>>(delay).count());
        }
        state.ResumeTiming();
    }
}

static void BM_PowerHalHidlBenchmarks_setFeature(benchmark::State& state) {
    runBenchmark(state, 0us, &IPower1_0::setFeature, Feature::POWER_FEATURE_DOUBLE_TAP_TO_WAKE,
                 false);
}

static void BM_PowerHalHidlBenchmarks_setInteractive(benchmark::State& state) {
    runBenchmark(state, 0us, &IPower1_0::setInteractive, false);
}

static void BM_PowerHalHidlBenchmarks_powerHint(benchmark::State& state) {
    PowerHint powerHint = static_cast<PowerHint>(state.range(0));
    runBenchmark(state, 0us, &IPower1_0::powerHint, powerHint, 0);
}

static void BM_PowerHalHidlBenchmarks_powerHintAsync(benchmark::State& state) {
    PowerHint powerHint = static_cast<PowerHint>(state.range(0));
    runBenchmark(state, ONEWAY_API_DELAY, &IPower1_1::powerHintAsync, powerHint, 0);
}

BENCHMARK(BM_PowerHalHidlBenchmarks_setFeature);
BENCHMARK(BM_PowerHalHidlBenchmarks_setInteractive);
BENCHMARK(BM_PowerHalHidlBenchmarks_powerHint)->DenseRange(FIRST_POWER_HINT, LAST_POWER_HINT, 1);
BENCHMARK(BM_PowerHalHidlBenchmarks_powerHintAsync)
        ->DenseRange(FIRST_POWER_HINT, LAST_POWER_HINT, 1);
