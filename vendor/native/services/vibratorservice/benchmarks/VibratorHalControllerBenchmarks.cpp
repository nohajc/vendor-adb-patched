/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "PowerHalControllerBenchmarks"

#include <benchmark/benchmark.h>
#include <vibratorservice/VibratorHalController.h>

using ::android::enum_range;
using ::android::hardware::vibrator::CompositeEffect;
using ::android::hardware::vibrator::CompositePrimitive;
using ::android::hardware::vibrator::Effect;
using ::android::hardware::vibrator::EffectStrength;
using ::benchmark::Counter;
using ::benchmark::Fixture;
using ::benchmark::kMicrosecond;
using ::benchmark::State;
using ::benchmark::internal::Benchmark;

using namespace android;
using namespace std::chrono_literals;

class VibratorBench : public Fixture {
public:
    void SetUp(State& /*state*/) override { mController.init(); }

    void TearDown(State& state) override { turnVibratorOff(state); }

    static void DefaultConfig(Benchmark* b) { b->Unit(kMicrosecond); }

    static void DefaultArgs(Benchmark* /*b*/) {
        // none
    }

protected:
    vibrator::HalController mController;

    auto getOtherArg(const State& state, std::size_t index) const { return state.range(index + 0); }

    bool hasCapabilities(vibrator::Capabilities&& query, State& state) {
        auto result = mController.getInfo().capabilities;
        if (result.isFailed()) {
            state.SkipWithError(result.errorMessage());
            return false;
        }
        if (!result.isOk()) {
            return false;
        }
        return (result.value() & query) == query;
    }

    void turnVibratorOff(State& state) {
        checkHalResult(halCall<void>(mController, [](auto hal) { return hal->off(); }), state);
    }

    template <class R>
    bool checkHalResult(const vibrator::HalResult<R>& result, State& state) {
        if (result.isFailed()) {
            state.SkipWithError(result.errorMessage());
            return false;
        }
        return true;
    }

    template <class R>
    vibrator::HalResult<R> halCall(vibrator::HalController& controller,
                                   const vibrator::HalFunction<vibrator::HalResult<R>>& halFn) {
        return controller.doWithRetry<R>(halFn, "benchmark");
    }
};

#define BENCHMARK_WRAPPER(fixt, test, code)                \
    BENCHMARK_DEFINE_F(fixt, test)                         \
    /* NOLINTNEXTLINE */                                   \
    (State& state){code} BENCHMARK_REGISTER_F(fixt, test) \
            ->Apply(fixt::DefaultConfig)                   \
            ->Apply(fixt::DefaultArgs)

BENCHMARK_WRAPPER(VibratorBench, init, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        state.ResumeTiming();
        controller.init();
    }
});

BENCHMARK_WRAPPER(VibratorBench, initCached, {
    for (auto _ : state) {
        mController.init();
    }
});

BENCHMARK_WRAPPER(VibratorBench, ping, {
    for (auto _ : state) {
        state.ResumeTiming();
        auto ret = halCall<void>(mController, [](auto hal) { return hal->ping(); });
        state.PauseTiming();
        checkHalResult(ret, state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, tryReconnect, {
    for (auto _ : state) {
        mController.tryReconnect();
    }
});

BENCHMARK_WRAPPER(VibratorBench, on, {
    auto duration = 60s;
    auto callback = []() {};

    for (auto _ : state) {
        state.ResumeTiming();
        auto ret =
                halCall<void>(mController, [&](auto hal) { return hal->on(duration, callback); });
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            turnVibratorOff(state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, off, {
    auto duration = 60s;
    auto callback = []() {};

    for (auto _ : state) {
        state.PauseTiming();
        auto ret =
                halCall<void>(mController, [&](auto hal) { return hal->on(duration, callback); });
        if (!checkHalResult(ret, state)) {
            continue;
        }
        state.ResumeTiming();
        turnVibratorOff(state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, setAmplitude, {
    if (!hasCapabilities(vibrator::Capabilities::AMPLITUDE_CONTROL, state)) {
        return;
    }

    auto duration = 60s;
    auto callback = []() {};
    auto amplitude = 1.0f;

    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        auto result =
                halCall<void>(controller, [&](auto hal) { return hal->on(duration, callback); });
        if (!checkHalResult(result, state)) {
            continue;
        }
        state.ResumeTiming();
        auto ret =
                halCall<void>(controller, [&](auto hal) { return hal->setAmplitude(amplitude); });
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            turnVibratorOff(state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, setAmplitudeCached, {
    if (!hasCapabilities(vibrator::Capabilities::AMPLITUDE_CONTROL, state)) {
        return;
    }

    auto duration = 6000s;
    auto callback = []() {};
    auto amplitude = 1.0f;

    auto onResult =
            halCall<void>(mController, [&](auto hal) { return hal->on(duration, callback); });
    checkHalResult(onResult, state);

    for (auto _ : state) {
        auto ret =
                halCall<void>(mController, [&](auto hal) { return hal->setAmplitude(amplitude); });
        checkHalResult(ret, state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalControl, {
    if (!hasCapabilities(vibrator::Capabilities::EXTERNAL_CONTROL, state)) {
        return;
    }

    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        auto ret =
                halCall<void>(controller, [](auto hal) { return hal->setExternalControl(true); });
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            auto result = halCall<void>(controller,
                                        [](auto hal) { return hal->setExternalControl(false); });
            checkHalResult(result, state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalControlCached, {
    if (!hasCapabilities(vibrator::Capabilities::EXTERNAL_CONTROL, state)) {
        return;
    }

    for (auto _ : state) {
        state.ResumeTiming();
        auto result =
                halCall<void>(mController, [](auto hal) { return hal->setExternalControl(true); });
        state.PauseTiming();
        if (checkHalResult(result, state)) {
            auto ret = halCall<void>(mController,
                                     [](auto hal) { return hal->setExternalControl(false); });
            checkHalResult(ret, state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorBench, setExternalAmplitudeCached, {
    if (!hasCapabilities(vibrator::Capabilities::EXTERNAL_AMPLITUDE_CONTROL, state)) {
        return;
    }

    auto amplitude = 1.0f;

    auto onResult =
            halCall<void>(mController, [](auto hal) { return hal->setExternalControl(true); });
    checkHalResult(onResult, state);

    for (auto _ : state) {
        auto ret =
                halCall<void>(mController, [&](auto hal) { return hal->setAmplitude(amplitude); });
        checkHalResult(ret, state);
    }

    auto offResult =
            halCall<void>(mController, [](auto hal) { return hal->setExternalControl(false); });
    checkHalResult(offResult, state);
});

BENCHMARK_WRAPPER(VibratorBench, getInfo, {
    for (auto _ : state) {
        state.PauseTiming();
        vibrator::HalController controller;
        controller.init();
        state.ResumeTiming();
        auto result = controller.getInfo();
        checkHalResult(result.capabilities, state);
        checkHalResult(result.supportedEffects, state);
        checkHalResult(result.supportedPrimitives, state);
        checkHalResult(result.primitiveDurations, state);
        checkHalResult(result.resonantFrequency, state);
        checkHalResult(result.qFactor, state);
    }
});

BENCHMARK_WRAPPER(VibratorBench, getInfoCached, {
    // First call to cache values.
    mController.getInfo();

    for (auto _ : state) {
        auto result = mController.getInfo();
        checkHalResult(result.capabilities, state);
        checkHalResult(result.supportedEffects, state);
        checkHalResult(result.supportedPrimitives, state);
        checkHalResult(result.primitiveDurations, state);
        checkHalResult(result.resonantFrequency, state);
        checkHalResult(result.qFactor, state);
    }
});

class VibratorEffectsBench : public VibratorBench {
public:
    static void DefaultArgs(Benchmark* b) {
        vibrator::HalController controller;
        auto effectsResult = controller.getInfo().supportedEffects;
        if (!effectsResult.isOk()) {
            return;
        }

        std::vector<Effect> supported = effectsResult.value();
        b->ArgNames({"Effect", "Strength"});

        if (supported.empty()) {
            b->Args({static_cast<long>(-1), static_cast<long>(-1)});
            return;
        }

        for (const auto& effect : enum_range<Effect>()) {
            if (std::find(supported.begin(), supported.end(), effect) == supported.end()) {
                continue;
            }
            for (const auto& strength : enum_range<EffectStrength>()) {
                b->Args({static_cast<long>(effect), static_cast<long>(strength)});
            }
        }
    }

protected:
    bool hasArgs(const State& state) const { return this->getOtherArg(state, 0) >= 0; }

    auto getEffect(const State& state) const {
        return static_cast<Effect>(this->getOtherArg(state, 0));
    }

    auto getStrength(const State& state) const {
        return static_cast<EffectStrength>(this->getOtherArg(state, 1));
    }
};

BENCHMARK_WRAPPER(VibratorEffectsBench, alwaysOnEnable, {
    if (!hasCapabilities(vibrator::Capabilities::ALWAYS_ON_CONTROL, state)) {
        return;
    }
    if (!hasArgs(state)) {
        return;
    }

    int32_t id = 1;
    auto effect = getEffect(state);
    auto strength = getStrength(state);

    for (auto _ : state) {
        state.ResumeTiming();
        auto ret = halCall<void>(mController, [&](auto hal) {
            return hal->alwaysOnEnable(id, effect, strength);
        });
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            auto disableResult =
                    halCall<void>(mController, [&](auto hal) { return hal->alwaysOnDisable(id); });
            checkHalResult(disableResult, state);
        }
    }
});

BENCHMARK_WRAPPER(VibratorEffectsBench, alwaysOnDisable, {
    if (!hasCapabilities(vibrator::Capabilities::ALWAYS_ON_CONTROL, state)) {
        return;
    }
    if (!hasArgs(state)) {
        return;
    }

    int32_t id = 1;
    auto effect = getEffect(state);
    auto strength = getStrength(state);

    for (auto _ : state) {
        state.PauseTiming();
        auto enableResult = halCall<void>(mController, [&](auto hal) {
            return hal->alwaysOnEnable(id, effect, strength);
        });
        if (!checkHalResult(enableResult, state)) {
            continue;
        }
        state.ResumeTiming();
        auto disableResult =
                halCall<void>(mController, [&](auto hal) { return hal->alwaysOnDisable(id); });
        checkHalResult(disableResult, state);
    }
});

BENCHMARK_WRAPPER(VibratorEffectsBench, performEffect, {
    if (!hasArgs(state)) {
        return;
    }

    auto effect = getEffect(state);
    auto strength = getStrength(state);
    auto callback = []() {};

    for (auto _ : state) {
        state.ResumeTiming();
        auto ret = halCall<std::chrono::milliseconds>(mController, [&](auto hal) {
            return hal->performEffect(effect, strength, callback);
        });
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            turnVibratorOff(state);
        }
    }
});

class VibratorPrimitivesBench : public VibratorBench {
public:
    static void DefaultArgs(Benchmark* b) {
        vibrator::HalController controller;
        auto primitivesResult = controller.getInfo().supportedPrimitives;
        if (!primitivesResult.isOk()) {
            return;
        }

        std::vector<CompositePrimitive> supported = primitivesResult.value();
        b->ArgNames({"Primitive"});

        if (supported.empty()) {
            b->Args({static_cast<long>(-1)});
            return;
        }

        for (const auto& primitive : enum_range<CompositePrimitive>()) {
            if (std::find(supported.begin(), supported.end(), primitive) == supported.end()) {
                continue;
            }
            if (primitive == CompositePrimitive::NOOP) {
                continue;
            }
            b->Args({static_cast<long>(primitive)});
        }
    }

protected:
    bool hasArgs(const State& state) const { return this->getOtherArg(state, 0) >= 0; }

    auto getPrimitive(const State& state) const {
        return static_cast<CompositePrimitive>(this->getOtherArg(state, 0));
    }
};

BENCHMARK_WRAPPER(VibratorPrimitivesBench, performComposedEffect, {
    if (!hasCapabilities(vibrator::Capabilities::COMPOSE_EFFECTS, state)) {
        return;
    }
    if (!hasArgs(state)) {
        return;
    }

    CompositeEffect effect;
    effect.primitive = getPrimitive(state);
    effect.scale = 1.0f;
    effect.delayMs = static_cast<int32_t>(0);

    std::vector<CompositeEffect> effects;
    effects.push_back(effect);
    auto callback = []() {};

    for (auto _ : state) {
        state.ResumeTiming();
        auto ret = halCall<std::chrono::milliseconds>(mController, [&](auto hal) {
            return hal->performComposedEffect(effects, callback);
        });
        state.PauseTiming();
        if (checkHalResult(ret, state)) {
            turnVibratorOff(state);
        }
    }
});

BENCHMARK_MAIN();