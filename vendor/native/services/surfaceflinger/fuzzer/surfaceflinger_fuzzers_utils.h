/*
 * Copyright 2021 The Android Open Source Project
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

#include <compositionengine/Display.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/CompositionEngine.h>
#include <compositionengine/impl/Display.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <ftl/fake_guard.h>
#include <gui/LayerDebugInfo.h>
#include <gui/ScreenCaptureResults.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/mock/GraphicBufferProducer.h>
#include <ui/DisplayStatInfo.h>
#include <ui/DynamicDisplayInfo.h>

#include "BufferQueueLayer.h"
#include "BufferStateLayer.h"
#include "ContainerLayer.h"
#include "DisplayDevice.h"
#include "DisplayHardware/ComposerHal.h"
#include "EffectLayer.h"
#include "FrameTimeline/FrameTimeline.h"
#include "FrameTracer/FrameTracer.h"
#include "Layer.h"
#include "NativeWindowSurface.h"
#include "Scheduler/EventThread.h"
#include "Scheduler/MessageQueue.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "Scheduler/VSyncTracker.h"
#include "Scheduler/VsyncConfiguration.h"
#include "Scheduler/VsyncController.h"
#include "Scheduler/VsyncModulator.h"
#include "StartPropertySetThread.h"
#include "SurfaceFlinger.h"
#include "SurfaceFlingerDefaultFactory.h"
#include "SurfaceInterceptor.h"
#include "ThreadContext.h"
#include "TimeStats/TimeStats.h"

#include "renderengine/mock/RenderEngine.h"
#include "scheduler/TimeKeeper.h"
#include "tests/unittests/mock/DisplayHardware/MockComposer.h"
#include "tests/unittests/mock/DisplayHardware/MockDisplayMode.h"
#include "tests/unittests/mock/DisplayHardware/MockHWC2.h"
#include "tests/unittests/mock/DisplayHardware/MockPowerAdvisor.h"
#include "tests/unittests/mock/MockEventThread.h"
#include "tests/unittests/mock/MockFrameTimeline.h"
#include "tests/unittests/mock/MockFrameTracer.h"
#include "tests/unittests/mock/MockNativeWindowSurface.h"
#include "tests/unittests/mock/MockSurfaceInterceptor.h"
#include "tests/unittests/mock/MockTimeStats.h"
#include "tests/unittests/mock/MockVSyncTracker.h"
#include "tests/unittests/mock/MockVsyncController.h"

namespace android {
namespace Hwc2 {

class Composer;

namespace types = hardware::graphics::common;

namespace V2_1 = hardware::graphics::composer::V2_1;
namespace V2_2 = hardware::graphics::composer::V2_2;
namespace V2_3 = hardware::graphics::composer::V2_3;
namespace V2_4 = hardware::graphics::composer::V2_4;

using types::V1_0::ColorTransform;
using types::V1_0::Transform;
using types::V1_1::RenderIntent;
using types::V1_2::ColorMode;
using types::V1_2::Dataspace;
using types::V1_2::Hdr;
using types::V1_2::PixelFormat;

using V2_1::Config;
using V2_1::Display;
using V2_1::Error;
using V2_1::Layer;
using V2_4::CommandReaderBase;
using V2_4::CommandWriterBase;
using V2_4::IComposer;
using V2_4::IComposerCallback;
using V2_4::IComposerClient;
using V2_4::VsyncPeriodChangeTimeline;
using V2_4::VsyncPeriodNanos;
using DisplayCapability = IComposerClient::DisplayCapability;
using PerFrameMetadata = IComposerClient::PerFrameMetadata;
using PerFrameMetadataKey = IComposerClient::PerFrameMetadataKey;
using PerFrameMetadataBlob = IComposerClient::PerFrameMetadataBlob;
}; // namespace Hwc2

static constexpr hal::HWDisplayId kHwDisplayId = 1000;

static constexpr ui::Hdr kHdrTypes[] = {ui::Hdr::DOLBY_VISION, ui::Hdr::HDR10, ui::Hdr::HLG,
                                        ui::Hdr::HDR10_PLUS};

static constexpr ui::ColorMode kColormodes[] = {ui::ColorMode::NATIVE,
                                                ui::ColorMode::STANDARD_BT601_625,
                                                ui::ColorMode::STANDARD_BT601_625_UNADJUSTED,
                                                ui::ColorMode::STANDARD_BT601_525,
                                                ui::ColorMode::STANDARD_BT601_525_UNADJUSTED,
                                                ui::ColorMode::STANDARD_BT709,
                                                ui::ColorMode::DCI_P3,
                                                ui::ColorMode::SRGB,
                                                ui::ColorMode::ADOBE_RGB,
                                                ui::ColorMode::DISPLAY_P3,
                                                ui::ColorMode::BT2020,
                                                ui::ColorMode::BT2100_PQ,
                                                ui::ColorMode::BT2100_HLG,
                                                ui::ColorMode::DISPLAY_BT2020};

static constexpr ui::PixelFormat kPixelFormats[] = {ui::PixelFormat::RGBA_8888,
                                                    ui::PixelFormat::RGBX_8888,
                                                    ui::PixelFormat::RGB_888,
                                                    ui::PixelFormat::RGB_565,
                                                    ui::PixelFormat::BGRA_8888,
                                                    ui::PixelFormat::YCBCR_422_SP,
                                                    ui::PixelFormat::YCRCB_420_SP,
                                                    ui::PixelFormat::YCBCR_422_I,
                                                    ui::PixelFormat::RGBA_FP16,
                                                    ui::PixelFormat::RAW16,
                                                    ui::PixelFormat::BLOB,
                                                    ui::PixelFormat::IMPLEMENTATION_DEFINED,
                                                    ui::PixelFormat::YCBCR_420_888,
                                                    ui::PixelFormat::RAW_OPAQUE,
                                                    ui::PixelFormat::RAW10,
                                                    ui::PixelFormat::RAW12,
                                                    ui::PixelFormat::RGBA_1010102,
                                                    ui::PixelFormat::Y8,
                                                    ui::PixelFormat::Y16,
                                                    ui::PixelFormat::YV12,
                                                    ui::PixelFormat::DEPTH_16,
                                                    ui::PixelFormat::DEPTH_24,
                                                    ui::PixelFormat::DEPTH_24_STENCIL_8,
                                                    ui::PixelFormat::DEPTH_32F,
                                                    ui::PixelFormat::DEPTH_32F_STENCIL_8,
                                                    ui::PixelFormat::STENCIL_8,
                                                    ui::PixelFormat::YCBCR_P010,
                                                    ui::PixelFormat::HSV_888};

FloatRect getFuzzedFloatRect(FuzzedDataProvider *fdp) {
    return FloatRect(fdp->ConsumeFloatingPoint<float>() /*left*/,
                     fdp->ConsumeFloatingPoint<float>() /*right*/,
                     fdp->ConsumeFloatingPoint<float>() /*top*/,
                     fdp->ConsumeFloatingPoint<float>() /*bottom*/);
}

HdrMetadata getFuzzedHdrMetadata(FuzzedDataProvider *fdp) {
    HdrMetadata hdrMetadata;
    if (fdp->ConsumeBool()) {
        hdrMetadata.cta8613.maxContentLightLevel = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.cta8613.maxFrameAverageLightLevel = fdp->ConsumeFloatingPoint<float>();

        hdrMetadata.validTypes |= HdrMetadata::CTA861_3;
    } else {
        hdrMetadata.smpte2086.displayPrimaryRed.x = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryRed.y = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryGreen.x = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryGreen.y = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryBlue.x = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.displayPrimaryBlue.y = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.whitePoint.x = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.whitePoint.y = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.minLuminance = fdp->ConsumeFloatingPoint<float>();
        hdrMetadata.smpte2086.maxLuminance = fdp->ConsumeFloatingPoint<float>();

        hdrMetadata.validTypes |= HdrMetadata::SMPTE2086;
    }
    return hdrMetadata;
}

class EventThread;

namespace hal = android::hardware::graphics::composer::hal;

struct FakePhaseOffsets : scheduler::VsyncConfiguration {
    static constexpr nsecs_t FAKE_PHASE_OFFSET_NS = 0;
    static constexpr auto FAKE_DURATION_OFFSET_NS = std::chrono::nanoseconds(0);

    VsyncConfigSet getConfigsForRefreshRate(Fps) const override { return getCurrentConfigs(); }

    VsyncConfigSet getCurrentConfigs() const override {
        return {{FAKE_PHASE_OFFSET_NS, FAKE_PHASE_OFFSET_NS, FAKE_DURATION_OFFSET_NS,
                 FAKE_DURATION_OFFSET_NS},
                {FAKE_PHASE_OFFSET_NS, FAKE_PHASE_OFFSET_NS, FAKE_DURATION_OFFSET_NS,
                 FAKE_DURATION_OFFSET_NS},
                {FAKE_PHASE_OFFSET_NS, FAKE_PHASE_OFFSET_NS, FAKE_DURATION_OFFSET_NS,
                 FAKE_DURATION_OFFSET_NS},
                FAKE_DURATION_OFFSET_NS};
    }

    void reset() override {}
    void setRefreshRateFps(Fps) override {}
    void dump(std::string &) const override {}
};

namespace scheduler {

class TestableScheduler : public Scheduler, private ICompositor {
public:
    TestableScheduler(const std::shared_ptr<scheduler::RefreshRateConfigs> &refreshRateConfigs,
                      ISchedulerCallback &callback)
          : TestableScheduler(std::make_unique<android::mock::VsyncController>(),
                              std::make_unique<android::mock::VSyncTracker>(), refreshRateConfigs,
                              callback) {}

    TestableScheduler(std::unique_ptr<VsyncController> controller,
                      std::unique_ptr<VSyncTracker> tracker,
                      std::shared_ptr<RefreshRateConfigs> configs, ISchedulerCallback &callback)
          : Scheduler(*this, callback, Feature::kContentDetection) {
        mVsyncSchedule.emplace(VsyncSchedule(std::move(tracker), nullptr, std::move(controller)));
        setRefreshRateConfigs(std::move(configs));
    }

    ConnectionHandle createConnection(std::unique_ptr<EventThread> eventThread) {
        return Scheduler::createConnection(std::move(eventThread));
    }

    auto &mutablePrimaryHWVsyncEnabled() { return mPrimaryHWVsyncEnabled; }
    auto &mutableHWVsyncAvailable() { return mHWVsyncAvailable; }

    auto &mutableLayerHistory() { return mLayerHistory; }

    auto refreshRateConfigs() { return holdRefreshRateConfigs(); }

    void replaceTouchTimer(int64_t millis) {
        if (mTouchTimer) {
            mTouchTimer.reset();
        }
        mTouchTimer.emplace(
                "Testable Touch timer", std::chrono::milliseconds(millis),
                [this] { touchTimerCallback(TimerState::Reset); },
                [this] { touchTimerCallback(TimerState::Expired); });
        mTouchTimer->start();
    }

    bool isTouchActive() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        return mPolicy.touch == Scheduler::TouchState::Active;
    }

    void dispatchCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        return Scheduler::dispatchCachedReportedMode();
    }

    void clearCachedReportedMode() {
        std::lock_guard<std::mutex> lock(mPolicyLock);
        mPolicy.cachedModeChangedParams.reset();
    }

    void onNonPrimaryDisplayModeChanged(ConnectionHandle handle, DisplayModePtr mode) {
        return Scheduler::onNonPrimaryDisplayModeChanged(handle, mode);
    }

private:
    // ICompositor overrides:
    bool commit(nsecs_t, int64_t, nsecs_t) override { return false; }
    void composite(nsecs_t, int64_t) override {}
    void sample() override {}

    // MessageQueue overrides:
    void scheduleFrame() override {}
    void postMessage(sp<MessageHandler>&&) override {}
};

} // namespace scheduler

namespace surfaceflinger::test {

class Factory final : public surfaceflinger::Factory {
public:
    ~Factory() = default;

    std::unique_ptr<HWComposer> createHWComposer(const std::string &) override { return nullptr; }

    std::unique_ptr<MessageQueue> createMessageQueue(ICompositor &compositor) {
        return std::make_unique<android::impl::MessageQueue>(compositor);
    }

    std::unique_ptr<scheduler::VsyncConfiguration> createVsyncConfiguration(
            Fps /*currentRefreshRate*/) override {
        return std::make_unique<FakePhaseOffsets>();
    }

    std::unique_ptr<scheduler::Scheduler> createScheduler(
            const std::shared_ptr<scheduler::RefreshRateConfigs> &,
            scheduler::ISchedulerCallback &) {
        return nullptr;
    }

    sp<SurfaceInterceptor> createSurfaceInterceptor() override {
        return new android::impl::SurfaceInterceptor();
    }

    sp<StartPropertySetThread> createStartPropertySetThread(bool timestampPropertyValue) override {
        return new StartPropertySetThread(timestampPropertyValue);
    }

    sp<DisplayDevice> createDisplayDevice(DisplayDeviceCreationArgs &creationArgs) override {
        return new DisplayDevice(creationArgs);
    }

    sp<GraphicBuffer> createGraphicBuffer(uint32_t width, uint32_t height, PixelFormat format,
                                          uint32_t layerCount, uint64_t usage,
                                          std::string requestorName) override {
        return new GraphicBuffer(width, height, format, layerCount, usage, requestorName);
    }

    void createBufferQueue(sp<IGraphicBufferProducer> *outProducer,
                           sp<IGraphicBufferConsumer> *outConsumer,
                           bool consumerIsSurfaceFlinger) override {
        if (!mCreateBufferQueue) {
            BufferQueue::createBufferQueue(outProducer, outConsumer, consumerIsSurfaceFlinger);
            return;
        }
        mCreateBufferQueue(outProducer, outConsumer, consumerIsSurfaceFlinger);
    }

    sp<IGraphicBufferProducer> createMonitoredProducer(const sp<IGraphicBufferProducer> &producer,
                                                       const sp<SurfaceFlinger> &flinger,
                                                       const wp<Layer> &layer) override {
        return new MonitoredProducer(producer, flinger, layer);
    }

    sp<BufferLayerConsumer> createBufferLayerConsumer(const sp<IGraphicBufferConsumer> &consumer,
                                                      renderengine::RenderEngine &renderEngine,
                                                      uint32_t textureName, Layer *layer) override {
        return new BufferLayerConsumer(consumer, renderEngine, textureName, layer);
    }

    std::unique_ptr<surfaceflinger::NativeWindowSurface> createNativeWindowSurface(
            const sp<IGraphicBufferProducer> &producer) override {
        if (!mCreateNativeWindowSurface) return nullptr;
        return mCreateNativeWindowSurface(producer);
    }

    std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine() override {
        return compositionengine::impl::createCompositionEngine();
    }

    sp<BufferQueueLayer> createBufferQueueLayer(const LayerCreationArgs &) override {
        return nullptr;
    }

    sp<BufferStateLayer> createBufferStateLayer(const LayerCreationArgs &) override {
        return nullptr;
    }

    sp<EffectLayer> createEffectLayer(const LayerCreationArgs &args) override {
        return new EffectLayer(args);
    }

    sp<ContainerLayer> createContainerLayer(const LayerCreationArgs &args) override {
        return new ContainerLayer(args);
    }

    std::unique_ptr<FrameTracer> createFrameTracer() override {
        return std::make_unique<android::mock::FrameTracer>();
    }

    std::unique_ptr<frametimeline::FrameTimeline> createFrameTimeline(
            std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid = 0) override {
        return std::make_unique<android::mock::FrameTimeline>(timeStats, surfaceFlingerPid);
    }

    using CreateBufferQueueFunction =
            std::function<void(sp<IGraphicBufferProducer> * /* outProducer */,
                               sp<IGraphicBufferConsumer> * /* outConsumer */,
                               bool /* consumerIsSurfaceFlinger */)>;
    CreateBufferQueueFunction mCreateBufferQueue;

    using CreateNativeWindowSurfaceFunction =
            std::function<std::unique_ptr<surfaceflinger::NativeWindowSurface>(
                    const sp<IGraphicBufferProducer> &)>;
    CreateNativeWindowSurfaceFunction mCreateNativeWindowSurface;

    using CreateCompositionEngineFunction =
            std::function<std::unique_ptr<compositionengine::CompositionEngine>()>;
    CreateCompositionEngineFunction mCreateCompositionEngine;
};

} // namespace surfaceflinger::test

// TODO(b/189053744) : Create a common test/mock library for surfaceflinger
class TestableSurfaceFlinger final : private scheduler::ISchedulerCallback {
public:
    using HotplugEvent = SurfaceFlinger::HotplugEvent;

    SurfaceFlinger *flinger() { return mFlinger.get(); }
    scheduler::TestableScheduler *scheduler() { return mScheduler; }

    // Allow reading display state without locking, as if called on the SF main thread.
    auto onInitializeDisplays() NO_THREAD_SAFETY_ANALYSIS {
        return mFlinger->onInitializeDisplays();
    }

    void setGlobalShadowSettings(FuzzedDataProvider *fdp) {
        const half4 ambientColor{fdp->ConsumeFloatingPoint<float>(),
                                 fdp->ConsumeFloatingPoint<float>(),
                                 fdp->ConsumeFloatingPoint<float>(),
                                 fdp->ConsumeFloatingPoint<float>()};
        const half4 spotColor{fdp->ConsumeFloatingPoint<float>(),
                              fdp->ConsumeFloatingPoint<float>(),
                              fdp->ConsumeFloatingPoint<float>(),
                              fdp->ConsumeFloatingPoint<float>()};
        float lightPosY = fdp->ConsumeFloatingPoint<float>();
        float lightPosZ = fdp->ConsumeFloatingPoint<float>();
        float lightRadius = fdp->ConsumeFloatingPoint<float>();
        mFlinger->setGlobalShadowSettings(ambientColor, spotColor, lightPosY, lightPosZ,
                                          lightRadius);
    }

    void onPullAtom(FuzzedDataProvider *fdp) {
        const int32_t atomId = fdp->ConsumeIntegral<uint8_t>();
        std::string pulledData = fdp->ConsumeRandomLengthString().c_str();
        bool success = fdp->ConsumeBool();
        mFlinger->onPullAtom(atomId, &pulledData, &success);
    }

    void fuzzDumpsysAndDebug(FuzzedDataProvider *fdp) {
        std::string result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->appendSfConfigString(result);
        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->listLayersLocked(result);

        using DumpArgs = Vector<String16>;
        DumpArgs dumpArgs;
        dumpArgs.push_back(String16(fdp->ConsumeRandomLengthString().c_str()));
        mFlinger->clearStatsLocked(dumpArgs, result);

        mFlinger->dumpTimeStats(dumpArgs, fdp->ConsumeBool(), result);
        FTL_FAKE_GUARD(kMainThreadContext, mFlinger->logFrameStats());

        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->dumpFrameTimeline(dumpArgs, result);

        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->dumpStaticScreenStats(result);

        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->dumpRawDisplayIdentificationData(dumpArgs, result);

        LayersProto layersProto = mFlinger->dumpDrawingStateProto(fdp->ConsumeIntegral<uint32_t>());
        mFlinger->dumpOffscreenLayersProto(layersProto);
        LayersTraceProto layersTraceProto{};
        mFlinger->dumpDisplayProto(layersTraceProto);

        result = fdp->ConsumeRandomLengthString().c_str();
        mFlinger->dumpHwc(result);

        mFlinger->calculateColorMatrix(fdp->ConsumeFloatingPoint<float>());
        mFlinger->updateColorMatrixLocked();
        mFlinger->CheckTransactCodeCredentials(fdp->ConsumeIntegral<uint32_t>());

        const CountDownLatch transactionCommittedSignal(fdp->ConsumeIntegral<uint32_t>());
        mFlinger->waitForSynchronousTransaction(transactionCommittedSignal);
        mFlinger->signalSynchronousTransactions(fdp->ConsumeIntegral<uint32_t>());
    }

    void getCompositionPreference() {
        ui::Dataspace outDataspace;
        ui::PixelFormat outPixelFormat;
        ui::Dataspace outWideColorGamutDataspace;
        ui::PixelFormat outWideColorGamutPixelFormat;
        mFlinger->getCompositionPreference(&outDataspace, &outPixelFormat,
                                           &outWideColorGamutDataspace,
                                           &outWideColorGamutPixelFormat);
    }

    void overrideHdrTypes(sp<IBinder> &display, FuzzedDataProvider *fdp) {
        std::vector<ui::Hdr> hdrTypes;
        hdrTypes.push_back(fdp->PickValueInArray(kHdrTypes));
        mFlinger->overrideHdrTypes(display, hdrTypes);
    }

    void getDisplayedContentSample(sp<IBinder> &display, FuzzedDataProvider *fdp) {
        DisplayedFrameStats outDisplayedFrameStats;
        mFlinger->getDisplayedContentSample(display, fdp->ConsumeIntegral<uint64_t>(),
                                            fdp->ConsumeIntegral<uint64_t>(),
                                            &outDisplayedFrameStats);
    }

    void getDisplayStats(sp<IBinder> &display) {
        android::DisplayStatInfo stats;
        mFlinger->getDisplayStats(display, &stats);
    }

    void getDisplayState(sp<IBinder> &display) {
        ui::DisplayState displayState;
        mFlinger->getDisplayState(display, &displayState);
    }

    void getStaticDisplayInfo(sp<IBinder> &display) {
        ui::StaticDisplayInfo staticDisplayInfo;
        mFlinger->getStaticDisplayInfo(display, &staticDisplayInfo);
    }

    void getDynamicDisplayInfo(sp<IBinder> &display) {
        android::ui::DynamicDisplayInfo dynamicDisplayInfo;
        mFlinger->getDynamicDisplayInfo(display, &dynamicDisplayInfo);
    }
    void getDisplayNativePrimaries(sp<IBinder> &display) {
        android::ui::DisplayPrimaries displayPrimaries;
        mFlinger->getDisplayNativePrimaries(display, displayPrimaries);
    }

    void getDesiredDisplayModeSpecs(sp<IBinder> &display) {
        ui::DisplayModeId outDefaultMode;
        bool outAllowGroupSwitching;
        float outPrimaryRefreshRateMin;
        float outPrimaryRefreshRateMax;
        float outAppRequestRefreshRateMin;
        float outAppRequestRefreshRateMax;
        mFlinger->getDesiredDisplayModeSpecs(display, &outDefaultMode, &outAllowGroupSwitching,
                                             &outPrimaryRefreshRateMin, &outPrimaryRefreshRateMax,
                                             &outAppRequestRefreshRateMin,
                                             &outAppRequestRefreshRateMax);
    }

    void setVsyncConfig(FuzzedDataProvider *fdp) {
        const scheduler::VsyncModulator::VsyncConfig vsyncConfig{};
        mFlinger->setVsyncConfig(vsyncConfig, fdp->ConsumeIntegral<nsecs_t>());
    }

    void updateCompositorTiming(FuzzedDataProvider *fdp) {
        std::shared_ptr<FenceTime> presentFenceTime = FenceTime::NO_FENCE;
        mFlinger->updateCompositorTiming({}, fdp->ConsumeIntegral<nsecs_t>(), presentFenceTime);
    }

    void getCompositorTiming() {
        CompositorTiming compositorTiming;
        mFlinger->getCompositorTiming(&compositorTiming);
    }

    sp<IBinder> fuzzBoot(FuzzedDataProvider *fdp) {
        mFlinger->callingThreadHasUnscopedSurfaceFlingerAccess(fdp->ConsumeBool());
        mFlinger->createConnection();

        DisplayIdGenerator<HalVirtualDisplayId> kGenerator;
        HalVirtualDisplayId halVirtualDisplayId = kGenerator.generateId().value();

        ui::Size uiSize{fdp->ConsumeIntegral<int32_t>(), fdp->ConsumeIntegral<int32_t>()};
        ui::PixelFormat pixelFormat{};
        mFlinger->getHwComposer().allocateVirtualDisplay(halVirtualDisplayId, uiSize, &pixelFormat);

        PhysicalDisplayId physicalDisplayId = SurfaceComposerClient::getInternalDisplayId().value();
        mFlinger->getHwComposer().allocatePhysicalDisplay(kHwDisplayId, physicalDisplayId);

        sp<IBinder> display =
                mFlinger->createDisplay(String8(fdp->ConsumeRandomLengthString().c_str()),
                                        fdp->ConsumeBool());

        onInitializeDisplays();
        mFlinger->getPhysicalDisplayToken(physicalDisplayId);

        mFlinger->mStartPropertySetThread =
                mFlinger->getFactory().createStartPropertySetThread(fdp->ConsumeBool());

        mFlinger->bootFinished();

        return display;
    }

    void fuzzSurfaceFlinger(const uint8_t *data, size_t size) {
        FuzzedDataProvider mFdp(data, size);

        sp<IBinder> display = fuzzBoot(&mFdp);

        sp<IGraphicBufferProducer> bufferProducer = sp<mock::GraphicBufferProducer>::make();
        mFlinger->authenticateSurfaceTexture(bufferProducer.get());

        mFlinger->createDisplayEventConnection();

        getDisplayStats(display);
        getDisplayState(display);
        getStaticDisplayInfo(display);
        getDynamicDisplayInfo(display);
        getDisplayNativePrimaries(display);

        mFlinger->setAutoLowLatencyMode(display, mFdp.ConsumeBool());
        mFlinger->setGameContentType(display, mFdp.ConsumeBool());
        mFlinger->setPowerMode(display, mFdp.ConsumeIntegral<int>());
        mFlinger->clearAnimationFrameStats();

        overrideHdrTypes(display, &mFdp);

        onPullAtom(&mFdp);

        mFlinger->injectVSync(mFdp.ConsumeIntegral<nsecs_t>());

        getCompositionPreference();
        getDisplayedContentSample(display, &mFdp);
        getDesiredDisplayModeSpecs(display);

        bool outSupport;
        mFlinger->getDisplayBrightnessSupport(display, &outSupport);

        mFlinger->notifyPowerBoost(mFdp.ConsumeIntegral<int32_t>());

        setGlobalShadowSettings(&mFdp);

        mFlinger->binderDied(display);
        mFlinger->onFirstRef();

        mFlinger->commitTransactions();
        mFlinger->updateInputFlinger();
        mFlinger->updateCursorAsync();

        setVsyncConfig(&mFdp);

        mFlinger->flushTransactionQueues(0);

        mFlinger->setTransactionFlags(mFdp.ConsumeIntegral<uint32_t>());
        mFlinger->clearTransactionFlags(mFdp.ConsumeIntegral<uint32_t>());
        mFlinger->commitOffscreenLayers();

        mFlinger->frameIsEarly(mFdp.ConsumeIntegral<nsecs_t>(), mFdp.ConsumeIntegral<int64_t>());
        mFlinger->computeLayerBounds();
        mFlinger->startBootAnim();

        mFlinger->readPersistentProperties();

        mFlinger->exceedsMaxRenderTargetSize(mFdp.ConsumeIntegral<uint32_t>(),
                                             mFdp.ConsumeIntegral<uint32_t>());

        mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(mFdp.ConsumeIntegral<uid_t>());

        mFlinger->postComposition();

        getCompositorTiming();

        updateCompositorTiming(&mFdp);

        mFlinger->setCompositorTimingSnapped({}, mFdp.ConsumeIntegral<nsecs_t>());
        FTL_FAKE_GUARD(kMainThreadContext, mFlinger->postFrame());
        mFlinger->calculateExpectedPresentTime({});

        mFlinger->enableHalVirtualDisplays(mFdp.ConsumeBool());

        fuzzDumpsysAndDebug(&mFdp);

        mFlinger->destroyDisplay(display);
    }

    void setupRenderEngine(std::unique_ptr<renderengine::RenderEngine> renderEngine) {
        mFlinger->mCompositionEngine->setRenderEngine(std::move(renderEngine));
    }

    void setupComposer(std::unique_ptr<Hwc2::Composer> composer) {
        mFlinger->mCompositionEngine->setHwComposer(
                std::make_unique<impl::HWComposer>(std::move(composer)));
    }

    void setupTimeStats(const std::shared_ptr<TimeStats> &timeStats) {
        mFlinger->mCompositionEngine->setTimeStats(timeStats);
    }

    // The ISchedulerCallback argument can be nullptr for a no-op implementation.
    void setupScheduler(std::unique_ptr<scheduler::VsyncController> vsyncController,
                        std::unique_ptr<scheduler::VSyncTracker> vsyncTracker,
                        std::unique_ptr<EventThread> appEventThread,
                        std::unique_ptr<EventThread> sfEventThread,
                        scheduler::ISchedulerCallback *callback = nullptr,
                        bool hasMultipleModes = false) {
        constexpr DisplayModeId kModeId60{0};
        DisplayModes modes = makeModes(mock::createDisplayMode(kModeId60, 60_Hz));

        if (hasMultipleModes) {
            constexpr DisplayModeId kModeId90{1};
            modes.try_emplace(kModeId90, mock::createDisplayMode(kModeId90, 90_Hz));
        }

        mRefreshRateConfigs = std::make_shared<scheduler::RefreshRateConfigs>(modes, kModeId60);
        const auto fps = mRefreshRateConfigs->getActiveMode()->getFps();
        mFlinger->mVsyncConfiguration = mFactory.createVsyncConfiguration(fps);
        mFlinger->mVsyncModulator = sp<scheduler::VsyncModulator>::make(
                mFlinger->mVsyncConfiguration->getCurrentConfigs());
        mFlinger->mRefreshRateStats =
                std::make_unique<scheduler::RefreshRateStats>(*mFlinger->mTimeStats, fps,
                                                              hal::PowerMode::OFF);

        mScheduler = new scheduler::TestableScheduler(std::move(vsyncController),
                                                      std::move(vsyncTracker), mRefreshRateConfigs,
                                                      *(callback ?: this));

        mFlinger->mAppConnectionHandle = mScheduler->createConnection(std::move(appEventThread));
        mFlinger->mSfConnectionHandle = mScheduler->createConnection(std::move(sfEventThread));
        resetScheduler(mScheduler);
    }

    void resetScheduler(scheduler::Scheduler *scheduler) { mFlinger->mScheduler.reset(scheduler); }

    scheduler::TestableScheduler &mutableScheduler() const { return *mScheduler; }

    using CreateBufferQueueFunction = surfaceflinger::test::Factory::CreateBufferQueueFunction;
    void setCreateBufferQueueFunction(CreateBufferQueueFunction f) {
        mFactory.mCreateBufferQueue = f;
    }

    using CreateNativeWindowSurfaceFunction =
            surfaceflinger::test::Factory::CreateNativeWindowSurfaceFunction;
    void setCreateNativeWindowSurface(CreateNativeWindowSurfaceFunction f) {
        mFactory.mCreateNativeWindowSurface = f;
    }

    void setInternalDisplayPrimaries(const ui::DisplayPrimaries &primaries) {
        memcpy(&mFlinger->mInternalDisplayPrimaries, &primaries, sizeof(ui::DisplayPrimaries));
    }

    static auto &mutableLayerDrawingState(const sp<Layer> &layer) { return layer->mDrawingState; }

    auto &mutableStateLock() { return mFlinger->mStateLock; }

    static auto findOutputLayerForDisplay(const sp<Layer> &layer,
                                          const sp<const DisplayDevice> &display) {
        return layer->findOutputLayerForDisplay(display.get());
    }

    /* ------------------------------------------------------------------------
     * Forwarding for functions being tested
     */

    void enableHalVirtualDisplays(bool enable) { mFlinger->enableHalVirtualDisplays(enable); }

    auto commitTransactionsLocked(uint32_t transactionFlags) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        return mFlinger->commitTransactionsLocked(transactionFlags);
    }

    auto setDisplayStateLocked(const DisplayState &s) {
        Mutex::Autolock lock(mFlinger->mStateLock);
        return mFlinger->setDisplayStateLocked(s);
    }

    auto notifyPowerBoost(int32_t boostId) { return mFlinger->notifyPowerBoost(boostId); }

    // Allow reading display state without locking, as if called on the SF main thread.
    auto setPowerModeInternal(const sp<DisplayDevice> &display,
                              hal::PowerMode mode) NO_THREAD_SAFETY_ANALYSIS {
        return mFlinger->setPowerModeInternal(display, mode);
    }

    auto &getTransactionQueue() { return mFlinger->mTransactionQueue; }
    auto &getPendingTransactionQueue() { return mFlinger->mPendingTransactionQueues; }

    auto setTransactionState(
            const FrameTimelineInfo &frameTimelineInfo, const Vector<ComposerState> &states,
            const Vector<DisplayState> &displays, uint32_t flags, const sp<IBinder> &applyToken,
            const InputWindowCommands &inputWindowCommands, int64_t desiredPresentTime,
            bool isAutoTimestamp, const client_cache_t &uncacheBuffer, bool hasListenerCallbacks,
            std::vector<ListenerCallbacks> &listenerCallbacks, uint64_t transactionId) {
        return mFlinger->setTransactionState(frameTimelineInfo, states, displays, flags, applyToken,
                                             inputWindowCommands, desiredPresentTime,
                                             isAutoTimestamp, uncacheBuffer, hasListenerCallbacks,
                                             listenerCallbacks, transactionId);
    }

    auto flushTransactionQueues() { return mFlinger->flushTransactionQueues(0); };

    auto onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) {
        return mFlinger->onTransact(code, data, reply, flags);
    }

    auto getGPUContextPriority() { return mFlinger->getGPUContextPriority(); }

    auto calculateMaxAcquiredBufferCount(Fps refreshRate,
                                         std::chrono::nanoseconds presentLatency) const {
        return SurfaceFlinger::calculateMaxAcquiredBufferCount(refreshRate, presentLatency);
    }

    /* Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */

    auto &mutableCurrentState() { return mFlinger->mCurrentState; }
    auto &mutableDisplays() { return mFlinger->mDisplays; }
    auto &mutableDrawingState() { return mFlinger->mDrawingState; }
    auto &mutableInterceptor() { return mFlinger->mInterceptor; }

    auto fromHandle(const sp<IBinder> &handle) { return mFlinger->fromHandle(handle); }

    ~TestableSurfaceFlinger() {
        mutableDisplays().clear();
        mutableCurrentState().displays.clear();
        mutableDrawingState().displays.clear();
        mutableInterceptor().clear();
        mFlinger->mScheduler.reset();
        mFlinger->mCompositionEngine->setHwComposer(std::unique_ptr<HWComposer>());
        mFlinger->mCompositionEngine->setRenderEngine(
                std::unique_ptr<renderengine::RenderEngine>());
    }

private:
    void setVsyncEnabled(bool) override {}
    void requestDisplayMode(DisplayModePtr, DisplayModeEvent) override {}
    void kernelTimerChanged(bool) override {}
    void triggerOnFrameRateOverridesChanged() override {}

    surfaceflinger::test::Factory mFactory;
    sp<SurfaceFlinger> mFlinger = new SurfaceFlinger(mFactory, SurfaceFlinger::SkipInitialization);
    scheduler::TestableScheduler *mScheduler = nullptr;
    std::shared_ptr<scheduler::RefreshRateConfigs> mRefreshRateConfigs;
};

} // namespace android
