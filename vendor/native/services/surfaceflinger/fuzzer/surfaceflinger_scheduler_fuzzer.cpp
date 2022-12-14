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

#include <ftl/enum.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <processgroup/sched_policy.h>

#include "Scheduler/DispSyncSource.h"
#include "Scheduler/OneShotTimer.h"
#include "Scheduler/VSyncDispatchTimerQueue.h"
#include "Scheduler/VSyncPredictor.h"
#include "Scheduler/VSyncReactor.h"

#include "surfaceflinger_fuzzers_utils.h"
#include "surfaceflinger_scheduler_fuzzer.h"

namespace android::fuzz {

using hardware::graphics::composer::hal::PowerMode;

constexpr nsecs_t kVsyncPeriods[] = {(30_Hz).getPeriodNsecs(), (60_Hz).getPeriodNsecs(),
                                     (72_Hz).getPeriodNsecs(), (90_Hz).getPeriodNsecs(),
                                     (120_Hz).getPeriodNsecs()};

constexpr auto kLayerVoteTypes = ftl::enum_range<scheduler::RefreshRateConfigs::LayerVoteType>();

constexpr PowerMode kPowerModes[] = {PowerMode::ON, PowerMode::DOZE, PowerMode::OFF,
                                     PowerMode::DOZE_SUSPEND, PowerMode::ON_SUSPEND};

constexpr uint16_t kRandomStringLength = 256;
constexpr std::chrono::duration kSyncPeriod(16ms);

template <typename T>
void dump(T* component, FuzzedDataProvider* fdp) {
    std::string res = fdp->ConsumeRandomLengthString(kRandomStringLength);
    component->dump(res);
}

class SchedulerFuzzer : private VSyncSource::Callback {
public:
    SchedulerFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

private:
    void fuzzRefreshRateSelection();
    void fuzzRefreshRateConfigs();
    void fuzzVSyncModulator();
    void fuzzVSyncPredictor();
    void fuzzVSyncReactor();
    void fuzzLayerHistory();
    void fuzzDispSyncSource();
    void fuzzCallbackToken(scheduler::VSyncDispatchTimerQueue* dispatch);
    void fuzzVSyncDispatchTimerQueue();
    void fuzzOneShotTimer();
    void fuzzEventThread();
    PhysicalDisplayId getPhysicalDisplayId();

    FuzzedDataProvider mFdp;

protected:
    void onVSyncEvent(nsecs_t /* when */, VSyncSource::VSyncData) {}
};

PhysicalDisplayId SchedulerFuzzer::getPhysicalDisplayId() {
    PhysicalDisplayId internalDispId = PhysicalDisplayId::fromPort(111u);
    PhysicalDisplayId externalDispId = PhysicalDisplayId::fromPort(222u);
    PhysicalDisplayId randomDispId = PhysicalDisplayId::fromPort(mFdp.ConsumeIntegral<uint16_t>());
    PhysicalDisplayId dispId64Bit = PhysicalDisplayId::fromEdid(0xffu, 0xffffu, 0xffff'ffffu);
    PhysicalDisplayId displayId = mFdp.PickValueInArray<PhysicalDisplayId>(
            {internalDispId, externalDispId, dispId64Bit, randomDispId});
    return displayId;
}

void SchedulerFuzzer::fuzzEventThread() {
    const auto getVsyncPeriod = [](uid_t /* uid */) { return kSyncPeriod.count(); };
    std::unique_ptr<android::impl::EventThread> thread = std::make_unique<
            android::impl::EventThread>(std::move(std::make_unique<FuzzImplVSyncSource>()), nullptr,
                                        nullptr, nullptr, getVsyncPeriod);

    thread->onHotplugReceived(getPhysicalDisplayId(), mFdp.ConsumeBool());
    sp<EventThreadConnection> connection =
            new EventThreadConnection(thread.get(), mFdp.ConsumeIntegral<uint16_t>(), nullptr,
                                      {} /*eventRegistration*/);
    thread->requestNextVsync(connection);
    thread->setVsyncRate(mFdp.ConsumeIntegral<uint32_t>() /*rate*/, connection);

    thread->setDuration((std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>(),
                        (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>());
    thread->registerDisplayEventConnection(connection);
    thread->onScreenAcquired();
    thread->onScreenReleased();
    dump<android::impl::EventThread>(thread.get(), &mFdp);
}

void SchedulerFuzzer::fuzzDispSyncSource() {
    std::unique_ptr<FuzzImplVSyncDispatch> vSyncDispatch =
            std::make_unique<FuzzImplVSyncDispatch>();
    std::unique_ptr<FuzzImplVSyncTracker> vSyncTracker = std::make_unique<FuzzImplVSyncTracker>();
    std::unique_ptr<scheduler::DispSyncSource> dispSyncSource = std::make_unique<
            scheduler::DispSyncSource>(*vSyncDispatch, *vSyncTracker,
                                       (std::chrono::nanoseconds)
                                               mFdp.ConsumeIntegral<uint64_t>() /*workDuration*/,
                                       (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>()
                                       /*readyDuration*/,
                                       mFdp.ConsumeBool(),
                                       mFdp.ConsumeRandomLengthString(kRandomStringLength).c_str());
    dispSyncSource->setVSyncEnabled(true);
    dispSyncSource->setCallback(this);
    dispSyncSource->setDuration((std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>(), 0ns);
    dump<scheduler::DispSyncSource>(dispSyncSource.get(), &mFdp);
}

void SchedulerFuzzer::fuzzCallbackToken(scheduler::VSyncDispatchTimerQueue* dispatch) {
    scheduler::VSyncDispatch::CallbackToken tmp = dispatch->registerCallback(
            [&](auto, auto, auto) {
                dispatch->schedule(tmp,
                                   {.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                                    .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                                    .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()});
            },
            "o.o");
    dispatch->schedule(tmp,
                       {.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                        .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                        .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()});
    dispatch->unregisterCallback(tmp);
    dispatch->cancel(tmp);
}

void SchedulerFuzzer::fuzzVSyncDispatchTimerQueue() {
    FuzzImplVSyncTracker stubTracker{mFdp.ConsumeIntegral<nsecs_t>()};
    scheduler::VSyncDispatchTimerQueue
            mDispatch{std::make_unique<scheduler::ControllableClock>(), stubTracker,
                      mFdp.ConsumeIntegral<nsecs_t>() /*dispatchGroupThreshold*/,
                      mFdp.ConsumeIntegral<nsecs_t>() /*vSyncMoveThreshold*/};

    fuzzCallbackToken(&mDispatch);

    dump<scheduler::VSyncDispatchTimerQueue>(&mDispatch, &mFdp);

    scheduler::VSyncDispatchTimerQueueEntry entry(
            "fuzz", [](auto, auto, auto) {},
            mFdp.ConsumeIntegral<nsecs_t>() /*vSyncMoveThreshold*/);
    entry.update(stubTracker, 0);
    entry.schedule({.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                    .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                    .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()},
                   stubTracker, 0);
    entry.disarm();
    entry.ensureNotRunning();
    entry.schedule({.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                    .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                    .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()},
                   stubTracker, 0);
    auto const wakeup = entry.wakeupTime();
    auto const ready = entry.readyTime();
    entry.callback(entry.executing(), *wakeup, *ready);
    entry.addPendingWorkloadUpdate({.workDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                                    .readyDuration = mFdp.ConsumeIntegral<nsecs_t>(),
                                    .earliestVsync = mFdp.ConsumeIntegral<nsecs_t>()});
    dump<scheduler::VSyncDispatchTimerQueueEntry>(&entry, &mFdp);
}

void SchedulerFuzzer::fuzzVSyncPredictor() {
    uint16_t now = mFdp.ConsumeIntegral<uint16_t>();
    uint16_t historySize = mFdp.ConsumeIntegralInRange<uint16_t>(1, UINT16_MAX);
    uint16_t minimumSamplesForPrediction = mFdp.ConsumeIntegralInRange<uint16_t>(1, UINT16_MAX);
    scheduler::VSyncPredictor tracker{mFdp.ConsumeIntegral<uint16_t>() /*period*/, historySize,
                                      minimumSamplesForPrediction,
                                      mFdp.ConsumeIntegral<uint32_t>() /*outlierTolerancePercent*/};
    uint16_t period = mFdp.ConsumeIntegral<uint16_t>();
    tracker.setPeriod(period);
    for (uint16_t i = 0; i < minimumSamplesForPrediction; ++i) {
        if (!tracker.needsMoreSamples()) {
            break;
        }
        tracker.addVsyncTimestamp(now += period);
    }
    tracker.nextAnticipatedVSyncTimeFrom(now);
    tracker.resetModel();
}

void SchedulerFuzzer::fuzzOneShotTimer() {
    FakeClock* clock = new FakeClock();
    std::unique_ptr<scheduler::OneShotTimer> idleTimer = std::make_unique<scheduler::OneShotTimer>(
            mFdp.ConsumeRandomLengthString(kRandomStringLength) /*name*/,
            (std::chrono::milliseconds)mFdp.ConsumeIntegral<uint8_t>() /*val*/,
            [] {} /*resetCallback*/, [] {} /*timeoutCallback*/, std::unique_ptr<FakeClock>(clock));
    idleTimer->start();
    idleTimer->reset();
    idleTimer->stop();
}

void SchedulerFuzzer::fuzzLayerHistory() {
    TestableSurfaceFlinger flinger;
    flinger.setupScheduler(std::make_unique<android::mock::VsyncController>(),
                           std::make_unique<android::mock::VSyncTracker>(),
                           std::make_unique<android::mock::EventThread>(),
                           std::make_unique<android::mock::EventThread>());
    flinger.setupTimeStats(std::make_unique<android::mock::TimeStats>());
    std::unique_ptr<android::renderengine::RenderEngine> renderEngine =
            std::make_unique<android::renderengine::mock::RenderEngine>();
    flinger.setupRenderEngine(std::move(renderEngine));
    flinger.setupComposer(std::make_unique<android::Hwc2::mock::Composer>());

    scheduler::TestableScheduler* scheduler = flinger.scheduler();

    scheduler::LayerHistory& historyV1 = scheduler->mutableLayerHistory();
    nsecs_t time1 = systemTime();
    nsecs_t time2 = time1;
    uint8_t historySize = mFdp.ConsumeIntegral<uint8_t>();

    sp<FuzzImplLayer> layer1 = new FuzzImplLayer(flinger.flinger());
    sp<FuzzImplLayer> layer2 = new FuzzImplLayer(flinger.flinger());

    for (int i = 0; i < historySize; ++i) {
        historyV1.record(layer1.get(), time1, time1,
                         scheduler::LayerHistory::LayerUpdateType::Buffer);
        historyV1.record(layer2.get(), time2, time2,
                         scheduler::LayerHistory::LayerUpdateType::Buffer);
        time1 += mFdp.PickValueInArray(kVsyncPeriods);
        time2 += mFdp.PickValueInArray(kVsyncPeriods);
    }
    historyV1.summarize(*scheduler->refreshRateConfigs(), time1);
    historyV1.summarize(*scheduler->refreshRateConfigs(), time2);

    scheduler->createConnection(std::make_unique<android::mock::EventThread>());

    scheduler::ConnectionHandle handle;
    scheduler->createDisplayEventConnection(handle);
    scheduler->setDuration(handle, (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>(),
                           (std::chrono::nanoseconds)mFdp.ConsumeIntegral<uint64_t>());

    dump<scheduler::TestableScheduler>(scheduler, &mFdp);
}

void SchedulerFuzzer::fuzzVSyncReactor() {
    std::shared_ptr<FuzzImplVSyncTracker> vSyncTracker = std::make_shared<FuzzImplVSyncTracker>();
    scheduler::VSyncReactor reactor(std::make_unique<ClockWrapper>(
                                            std::make_shared<FuzzImplClock>()),
                                    *vSyncTracker, mFdp.ConsumeIntegral<uint8_t>() /*pendingLimit*/,
                                    false);

    reactor.startPeriodTransition(mFdp.ConsumeIntegral<nsecs_t>());
    bool periodFlushed = mFdp.ConsumeBool();
    reactor.addHwVsyncTimestamp(0, std::nullopt, &periodFlushed);
    reactor.addHwVsyncTimestamp(mFdp.ConsumeIntegral<nsecs_t>() /*newPeriod*/, std::nullopt,
                                &periodFlushed);
    sp<Fence> fence = new Fence(memfd_create("fd", MFD_ALLOW_SEALING));
    std::shared_ptr<FenceTime> ft = std::make_shared<FenceTime>(fence);
    vSyncTracker->addVsyncTimestamp(mFdp.ConsumeIntegral<nsecs_t>());
    FenceTime::Snapshot snap(mFdp.ConsumeIntegral<nsecs_t>());
    ft->applyTrustedSnapshot(snap);
    reactor.setIgnorePresentFences(mFdp.ConsumeBool());
    reactor.addPresentFence(ft);
    dump<scheduler::VSyncReactor>(&reactor, &mFdp);
}

void SchedulerFuzzer::fuzzVSyncModulator() {
    enum {
        SF_OFFSET_LATE,
        APP_OFFSET_LATE,
        SF_DURATION_LATE,
        APP_DURATION_LATE,
        SF_OFFSET_EARLY,
        APP_OFFSET_EARLY,
        SF_DURATION_EARLY,
        APP_DURATION_EARLY,
        SF_OFFSET_EARLY_GPU,
        APP_OFFSET_EARLY_GPU,
        SF_DURATION_EARLY_GPU,
        APP_DURATION_EARLY_GPU,
        HWC_MIN_WORK_DURATION,
    };
    using Schedule = scheduler::TransactionSchedule;
    using nanos = std::chrono::nanoseconds;
    using VsyncModulator = scheduler::VsyncModulator;
    using FuzzImplVsyncModulator = scheduler::FuzzImplVsyncModulator;
    const VsyncModulator::VsyncConfig early{SF_OFFSET_EARLY, APP_OFFSET_EARLY,
                                            nanos(SF_DURATION_LATE), nanos(APP_DURATION_LATE)};
    const VsyncModulator::VsyncConfig earlyGpu{SF_OFFSET_EARLY_GPU, APP_OFFSET_EARLY_GPU,
                                               nanos(SF_DURATION_EARLY), nanos(APP_DURATION_EARLY)};
    const VsyncModulator::VsyncConfig late{SF_OFFSET_LATE, APP_OFFSET_LATE,
                                           nanos(SF_DURATION_EARLY_GPU),
                                           nanos(APP_DURATION_EARLY_GPU)};
    const VsyncModulator::VsyncConfigSet offsets = {early, earlyGpu, late,
                                                    nanos(HWC_MIN_WORK_DURATION)};
    sp<FuzzImplVsyncModulator> vSyncModulator =
            sp<FuzzImplVsyncModulator>::make(offsets, scheduler::Now);
    (void)vSyncModulator->setVsyncConfigSet(offsets);
    (void)vSyncModulator->setTransactionSchedule(Schedule::Late);
    const auto token = sp<BBinder>::make();
    (void)vSyncModulator->setTransactionSchedule(Schedule::EarlyStart, token);
    vSyncModulator->binderDied(token);
}

void SchedulerFuzzer::fuzzRefreshRateSelection() {
    TestableSurfaceFlinger flinger;
    flinger.setupScheduler(std::make_unique<android::mock::VsyncController>(),
                           std::make_unique<android::mock::VSyncTracker>(),
                           std::make_unique<android::mock::EventThread>(),
                           std::make_unique<android::mock::EventThread>());

    sp<Client> client;
    LayerCreationArgs args(flinger.flinger(), client,
                           mFdp.ConsumeRandomLengthString(kRandomStringLength) /*name*/,
                           mFdp.ConsumeIntegral<uint16_t>() /*layerFlags*/, LayerMetadata());
    sp<Layer> layer = new BufferQueueLayer(args);

    layer->setFrameRateSelectionPriority(mFdp.ConsumeIntegral<int16_t>());
}

void SchedulerFuzzer::fuzzRefreshRateConfigs() {
    using RefreshRateConfigs = scheduler::RefreshRateConfigs;
    using LayerRequirement = RefreshRateConfigs::LayerRequirement;
    using RefreshRateStats = scheduler::RefreshRateStats;

    const uint16_t minRefreshRate = mFdp.ConsumeIntegralInRange<uint16_t>(1, UINT16_MAX >> 1);
    const uint16_t maxRefreshRate =
            mFdp.ConsumeIntegralInRange<uint16_t>(minRefreshRate + 1, UINT16_MAX);

    const DisplayModeId modeId{mFdp.ConsumeIntegralInRange<uint8_t>(0, 10)};

    DisplayModes displayModes;
    for (uint16_t fps = minRefreshRate; fps < maxRefreshRate; ++fps) {
        displayModes.try_emplace(modeId,
                                 mock::createDisplayMode(modeId,
                                                         Fps::fromValue(static_cast<float>(fps))));
    }

    RefreshRateConfigs refreshRateConfigs(displayModes, modeId);

    const RefreshRateConfigs::GlobalSignals globalSignals = {.touch = false, .idle = false};
    std::vector<LayerRequirement> layers = {{.weight = mFdp.ConsumeFloatingPoint<float>()}};

    refreshRateConfigs.getBestRefreshRate(layers, globalSignals);

    layers[0].name = mFdp.ConsumeRandomLengthString(kRandomStringLength);
    layers[0].ownerUid = mFdp.ConsumeIntegral<uint16_t>();
    layers[0].desiredRefreshRate = Fps::fromValue(mFdp.ConsumeFloatingPoint<float>());
    layers[0].vote = mFdp.PickValueInArray(kLayerVoteTypes.values);
    auto frameRateOverrides =
            refreshRateConfigs.getFrameRateOverrides(layers,
                                                     Fps::fromValue(
                                                             mFdp.ConsumeFloatingPoint<float>()),
                                                     globalSignals);

    refreshRateConfigs.setDisplayManagerPolicy(
            {modeId,
             {Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()),
              Fps::fromValue(mFdp.ConsumeFloatingPoint<float>())}});
    refreshRateConfigs.setActiveModeId(modeId);

    RefreshRateConfigs::isFractionalPairOrMultiple(Fps::fromValue(
                                                           mFdp.ConsumeFloatingPoint<float>()),
                                                   Fps::fromValue(
                                                           mFdp.ConsumeFloatingPoint<float>()));
    RefreshRateConfigs::getFrameRateDivisor(Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()),
                                            Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()));

    android::mock::TimeStats timeStats;
    RefreshRateStats refreshRateStats(timeStats, Fps::fromValue(mFdp.ConsumeFloatingPoint<float>()),
                                      PowerMode::OFF);

    const auto fpsOpt = displayModes.get(modeId, [](const auto& mode) { return mode->getFps(); });
    refreshRateStats.setRefreshRate(*fpsOpt);

    refreshRateStats.setPowerMode(mFdp.PickValueInArray(kPowerModes));
}

void SchedulerFuzzer::process() {
    fuzzRefreshRateSelection();
    fuzzRefreshRateConfigs();
    fuzzVSyncModulator();
    fuzzVSyncPredictor();
    fuzzVSyncReactor();
    fuzzLayerHistory();
    fuzzDispSyncSource();
    fuzzEventThread();
    fuzzVSyncDispatchTimerQueue();
    fuzzOneShotTimer();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    SchedulerFuzzer schedulerFuzzer(data, size);
    schedulerFuzzer.process();
    return 0;
}

} // namespace android::fuzz
