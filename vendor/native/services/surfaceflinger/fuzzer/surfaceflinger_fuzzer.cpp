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

#include <FuzzableDataspaces.h>
#include <binder/IServiceManager.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <ui/DisplayStatInfo.h>
#include "surfaceflinger_fuzzers_utils.h"

namespace android::fuzz {

static constexpr LatchUnsignaledConfig kLatchUnsignaledConfig[] = {
        LatchUnsignaledConfig::Always,
        LatchUnsignaledConfig::AutoSingleLayer,
        LatchUnsignaledConfig::Disabled,
};

static constexpr BnSurfaceComposer::ISurfaceComposerTag kSurfaceComposerTags[]{
        BnSurfaceComposer::BOOT_FINISHED,
        BnSurfaceComposer::CREATE_CONNECTION,
        BnSurfaceComposer::GET_STATIC_DISPLAY_INFO,
        BnSurfaceComposer::CREATE_DISPLAY_EVENT_CONNECTION,
        BnSurfaceComposer::CREATE_DISPLAY,
        BnSurfaceComposer::DESTROY_DISPLAY,
        BnSurfaceComposer::GET_PHYSICAL_DISPLAY_TOKEN,
        BnSurfaceComposer::SET_TRANSACTION_STATE,
        BnSurfaceComposer::AUTHENTICATE_SURFACE,
        BnSurfaceComposer::GET_SUPPORTED_FRAME_TIMESTAMPS,
        BnSurfaceComposer::GET_DISPLAY_MODES,
        BnSurfaceComposer::GET_ACTIVE_DISPLAY_MODE,
        BnSurfaceComposer::GET_DISPLAY_STATE,
        BnSurfaceComposer::CAPTURE_DISPLAY,
        BnSurfaceComposer::CAPTURE_LAYERS,
        BnSurfaceComposer::CLEAR_ANIMATION_FRAME_STATS,
        BnSurfaceComposer::GET_ANIMATION_FRAME_STATS,
        BnSurfaceComposer::SET_POWER_MODE,
        BnSurfaceComposer::GET_DISPLAY_STATS,
        BnSurfaceComposer::GET_HDR_CAPABILITIES,
        BnSurfaceComposer::GET_DISPLAY_COLOR_MODES,
        BnSurfaceComposer::GET_ACTIVE_COLOR_MODE,
        BnSurfaceComposer::SET_ACTIVE_COLOR_MODE,
        BnSurfaceComposer::ENABLE_VSYNC_INJECTIONS,
        BnSurfaceComposer::INJECT_VSYNC,
        BnSurfaceComposer::GET_LAYER_DEBUG_INFO,
        BnSurfaceComposer::GET_COMPOSITION_PREFERENCE,
        BnSurfaceComposer::GET_COLOR_MANAGEMENT,
        BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES,
        BnSurfaceComposer::SET_DISPLAY_CONTENT_SAMPLING_ENABLED,
        BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLE,
        BnSurfaceComposer::GET_PROTECTED_CONTENT_SUPPORT,
        BnSurfaceComposer::IS_WIDE_COLOR_DISPLAY,
        BnSurfaceComposer::GET_DISPLAY_NATIVE_PRIMARIES,
        BnSurfaceComposer::GET_PHYSICAL_DISPLAY_IDS,
        BnSurfaceComposer::ADD_REGION_SAMPLING_LISTENER,
        BnSurfaceComposer::REMOVE_REGION_SAMPLING_LISTENER,
        BnSurfaceComposer::SET_DESIRED_DISPLAY_MODE_SPECS,
        BnSurfaceComposer::GET_DESIRED_DISPLAY_MODE_SPECS,
        BnSurfaceComposer::GET_DISPLAY_BRIGHTNESS_SUPPORT,
        BnSurfaceComposer::SET_DISPLAY_BRIGHTNESS,
        BnSurfaceComposer::CAPTURE_DISPLAY_BY_ID,
        BnSurfaceComposer::NOTIFY_POWER_BOOST,
        BnSurfaceComposer::SET_GLOBAL_SHADOW_SETTINGS,
        BnSurfaceComposer::GET_AUTO_LOW_LATENCY_MODE_SUPPORT,
        BnSurfaceComposer::SET_AUTO_LOW_LATENCY_MODE,
        BnSurfaceComposer::GET_GAME_CONTENT_TYPE_SUPPORT,
        BnSurfaceComposer::SET_GAME_CONTENT_TYPE,
        BnSurfaceComposer::SET_FRAME_RATE,
        BnSurfaceComposer::ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN,
        BnSurfaceComposer::SET_FRAME_TIMELINE_INFO,
        BnSurfaceComposer::ADD_TRANSACTION_TRACE_LISTENER,
        BnSurfaceComposer::GET_GPU_CONTEXT_PRIORITY,
        BnSurfaceComposer::GET_MAX_ACQUIRED_BUFFER_COUNT,
        BnSurfaceComposer::GET_DYNAMIC_DISPLAY_INFO,
        BnSurfaceComposer::ADD_FPS_LISTENER,
        BnSurfaceComposer::REMOVE_FPS_LISTENER,
        BnSurfaceComposer::OVERRIDE_HDR_TYPES,
        BnSurfaceComposer::ADD_HDR_LAYER_INFO_LISTENER,
        BnSurfaceComposer::REMOVE_HDR_LAYER_INFO_LISTENER,
        BnSurfaceComposer::ON_PULL_ATOM,
        BnSurfaceComposer::ADD_TUNNEL_MODE_ENABLED_LISTENER,
        BnSurfaceComposer::REMOVE_TUNNEL_MODE_ENABLED_LISTENER,
        BnSurfaceComposer::ADD_WINDOW_INFOS_LISTENER,
        BnSurfaceComposer::REMOVE_WINDOW_INFOS_LISTENER,
};

static constexpr uint32_t kMinCode = 1000;
static constexpr uint32_t kMaxCode = 1050;

class SurfaceFlingerFuzzer {
public:
    SurfaceFlingerFuzzer(const uint8_t *data, size_t size) : mFdp(data, size) {
        mFlinger = mTestableFlinger.flinger();
    };
    void process(const uint8_t *data, size_t size);

private:
    void setUp();
    void invokeFlinger();
    void setTransactionState();
    void setInternalDisplayPrimaries();
    void setDisplayStateLocked();
    void onTransact(const uint8_t *data, size_t size);

    FuzzedDataProvider mFdp;
    TestableSurfaceFlinger mTestableFlinger;
    sp<SurfaceFlinger> mFlinger = nullptr;
};

void SurfaceFlingerFuzzer::invokeFlinger() {
    mFlinger->setSchedFifo(mFdp.ConsumeBool());
    mFlinger->setSchedAttr(mFdp.ConsumeBool());
    mFlinger->getServiceName();
    mFlinger->hasSyncFramework = mFdp.ConsumeBool();
    mFlinger->dispSyncPresentTimeOffset = mFdp.ConsumeIntegral<int64_t>();
    mFlinger->useHwcForRgbToYuv = mFdp.ConsumeBool();
    mFlinger->maxFrameBufferAcquiredBuffers = mFdp.ConsumeIntegral<int64_t>();
    mFlinger->maxGraphicsWidth = mFdp.ConsumeIntegral<uint32_t>();
    mFlinger->maxGraphicsHeight = mFdp.ConsumeIntegral<uint32_t>();
    mFlinger->hasWideColorDisplay = mFdp.ConsumeBool();
    mFlinger->useContextPriority = mFdp.ConsumeBool();

    mFlinger->defaultCompositionDataspace = mFdp.PickValueInArray(kDataspaces);
    mFlinger->defaultCompositionPixelFormat = mFdp.PickValueInArray(kPixelFormats);
    mFlinger->wideColorGamutCompositionDataspace = mFdp.PickValueInArray(kDataspaces);
    mFlinger->wideColorGamutCompositionPixelFormat = mFdp.PickValueInArray(kPixelFormats);

    mFlinger->enableLatchUnsignaledConfig = mFdp.PickValueInArray(kLatchUnsignaledConfig);

    using FrameHint = SurfaceFlinger::FrameHint;
    mFlinger->scheduleComposite(mFdp.ConsumeBool() ? FrameHint::kActive : FrameHint::kNone);
    mFlinger->scheduleRepaint();
    mFlinger->scheduleSample();

    uint32_t texture = mFlinger->getNewTexture();
    mFlinger->deleteTextureAsync(texture);

    sp<IBinder> handle = defaultServiceManager()->checkService(
            String16(mFdp.ConsumeRandomLengthString().c_str()));
    mFlinger->fromHandle(handle);
    mFlinger->windowInfosReported();
    mFlinger->disableExpensiveRendering();
}

void SurfaceFlingerFuzzer::setInternalDisplayPrimaries() {
    ui::DisplayPrimaries primaries;
    primaries.red.X = mFdp.ConsumeFloatingPoint<float>();
    primaries.red.Y = mFdp.ConsumeFloatingPoint<float>();
    primaries.red.Z = mFdp.ConsumeFloatingPoint<float>();
    primaries.green.X = mFdp.ConsumeFloatingPoint<float>();
    primaries.green.Y = mFdp.ConsumeFloatingPoint<float>();
    primaries.green.Z = mFdp.ConsumeFloatingPoint<float>();
    primaries.blue.X = mFdp.ConsumeFloatingPoint<float>();
    primaries.blue.Y = mFdp.ConsumeFloatingPoint<float>();
    primaries.blue.Z = mFdp.ConsumeFloatingPoint<float>();
    primaries.white.X = mFdp.ConsumeFloatingPoint<float>();
    primaries.white.Y = mFdp.ConsumeFloatingPoint<float>();
    primaries.white.Z = mFdp.ConsumeFloatingPoint<float>();
    mTestableFlinger.setInternalDisplayPrimaries(primaries);
}

void SurfaceFlingerFuzzer::setTransactionState() {
    Vector<ComposerState> states;
    Vector<DisplayState> displays;
    ComposerState composerState;
    composerState.state.what = layer_state_t::eLayerChanged;
    composerState.state.surface = nullptr;
    states.add(composerState);
    uint32_t flags = mFdp.ConsumeIntegral<uint32_t>();
    const sp<IBinder> applyToken = nullptr;
    int64_t desiredPresentTime = mFdp.ConsumeIntegral<int64_t>();
    bool isAutoTimestamp = mFdp.ConsumeBool();
    bool hasListenerCallbacks = mFdp.ConsumeBool();
    std::vector<ListenerCallbacks> listenerCallbacks{};
    uint64_t transactionId = mFdp.ConsumeIntegral<uint64_t>();

    mTestableFlinger.setTransactionState(FrameTimelineInfo{}, states, displays, flags, applyToken,
                                         InputWindowCommands{}, desiredPresentTime, isAutoTimestamp,
                                         {}, hasListenerCallbacks, listenerCallbacks,
                                         transactionId);
}

void SurfaceFlingerFuzzer::setDisplayStateLocked() {
    DisplayState state{};
    mTestableFlinger.setDisplayStateLocked(state);
}

void SurfaceFlingerFuzzer::onTransact(const uint8_t *data, size_t size) {
    Parcel fuzzedData, reply;
    fuzzedData.writeInterfaceToken(String16("android.ui.ISurfaceComposer"));
    fuzzedData.setData(data, size);
    fuzzedData.setDataPosition(0);
    uint32_t code = mFdp.ConsumeBool() ? mFdp.PickValueInArray(kSurfaceComposerTags)
                                       : mFdp.ConsumeIntegralInRange<uint32_t>(kMinCode, kMaxCode);
    mTestableFlinger.onTransact(code, fuzzedData, &reply, 0);
}

void SurfaceFlingerFuzzer::setUp() {
    mTestableFlinger.setupScheduler(std::make_unique<android::mock::VsyncController>(),
                                    std::make_unique<android::mock::VSyncTracker>(),
                                    std::make_unique<android::mock::EventThread>(),
                                    std::make_unique<android::mock::EventThread>());

    mTestableFlinger.setupTimeStats(std::make_unique<android::mock::TimeStats>());

    std::unique_ptr<android::renderengine::RenderEngine> renderEngine =
            std::make_unique<android::renderengine::mock::RenderEngine>();
    mTestableFlinger.setupRenderEngine(std::move(renderEngine));
    mTestableFlinger.setupComposer(std::make_unique<android::Hwc2::mock::Composer>());
}

void SurfaceFlingerFuzzer::process(const uint8_t *data, size_t size) {
    setUp();

    invokeFlinger();

    mTestableFlinger.fuzzSurfaceFlinger(data, size);

    mTestableFlinger.setCreateBufferQueueFunction(
            surfaceflinger::test::Factory::CreateBufferQueueFunction());
    mTestableFlinger.setCreateNativeWindowSurface(
            surfaceflinger::test::Factory::CreateNativeWindowSurfaceFunction());

    setInternalDisplayPrimaries();

    mTestableFlinger.enableHalVirtualDisplays(mFdp.ConsumeBool());

    mTestableFlinger.commitTransactionsLocked(mFdp.ConsumeIntegral<uint32_t>());

    mTestableFlinger.notifyPowerBoost(mFdp.ConsumeIntegral<int32_t>());

    setDisplayStateLocked();

    setTransactionState();
    mTestableFlinger.flushTransactionQueues();

    onTransact(data, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    android::fuzz::SurfaceFlingerFuzzer surfaceFlingerFuzzer(data, size);
    surfaceFlingerFuzzer.process(data, size);
    return 0;
}

} // namespace android::fuzz
