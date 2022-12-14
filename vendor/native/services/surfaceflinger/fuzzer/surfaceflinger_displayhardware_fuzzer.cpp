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

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gui/BLASTBufferQueue.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/IProducerListener.h>
#include <gui/LayerDebugInfo.h>
#include <gui/SurfaceComposerClient.h>
#include <hidl/ServiceManagement.h>
#include <hwbinder/ProcessState.h>
#include <ui/DisplayIdentification.h>

#include "DisplayHardware/AidlComposerHal.h"
#include "DisplayHardware/DisplayMode.h"
#include "DisplayHardware/FramebufferSurface.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/PowerAdvisor.h"
#include "DisplayHardware/VirtualDisplaySurface.h"
#include "SurfaceFlinger.h"
#include "surfaceflinger_displayhardware_fuzzer_utils.h"

#include <FuzzableDataspaces.h>

namespace android::fuzz {

using namespace android::hardware::graphics::common;
using namespace android::hardware::graphics::composer;
namespace aidl = aidl::android::hardware::graphics::composer3;
namespace hal = android::hardware::graphics::composer::hal;
using Config = hal::V2_1::Config;
using Display = hal::V2_1::Display;
using RenderIntent = V1_1::RenderIntent;
using IComposerClient = hal::V2_4::IComposerClient;
using VsyncPeriodChangeTimeline = hal::V2_4::VsyncPeriodChangeTimeline;
using PerFrameMetadata = IComposerClient::PerFrameMetadata;
using PerFrameMetadataBlob = IComposerClient::PerFrameMetadataBlob;
using Vsync = IComposerClient::Vsync;

static constexpr hal::Transform kTransforms[] = {hal::Transform::FLIP_H, hal::Transform::FLIP_V,
                                                 hal::Transform::ROT_90, hal::Transform::ROT_180,
                                                 hal::Transform::ROT_270};

static constexpr aidl::Capability kCapability[] = {aidl::Capability::INVALID,
                                                   aidl::Capability::SIDEBAND_STREAM,
                                                   aidl::Capability::SKIP_CLIENT_COLOR_TRANSFORM,
                                                   aidl::Capability::PRESENT_FENCE_IS_NOT_RELIABLE,
                                                   aidl::Capability::SKIP_VALIDATE};

static constexpr hal::BlendMode kBlendModes[] = {hal::BlendMode::INVALID, hal::BlendMode::NONE,
                                                 hal::BlendMode::PREMULTIPLIED,
                                                 hal::BlendMode::COVERAGE};

static constexpr Composition kCompositions[] = {Composition::INVALID, Composition::CLIENT,
                                                Composition::DEVICE,  Composition::SOLID_COLOR,
                                                Composition::CURSOR,  Composition::SIDEBAND};

static constexpr DisplayCapability kDisplayCapability[] =
        {DisplayCapability::INVALID,
         DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM,
         DisplayCapability::DOZE,
         DisplayCapability::BRIGHTNESS,
         DisplayCapability::PROTECTED_CONTENTS,
         DisplayCapability::AUTO_LOW_LATENCY_MODE};

static constexpr VirtualDisplaySurface::CompositionType kCompositionTypes[] =
        {VirtualDisplaySurface::CompositionType::Unknown,
         VirtualDisplaySurface::CompositionType::Gpu, VirtualDisplaySurface::CompositionType::Hwc,
         VirtualDisplaySurface::CompositionType::Mixed};

static constexpr ui::RenderIntent kRenderIntents[] = {ui::RenderIntent::COLORIMETRIC,
                                                      ui::RenderIntent::ENHANCE,
                                                      ui::RenderIntent::TONE_MAP_COLORIMETRIC,
                                                      ui::RenderIntent::TONE_MAP_ENHANCE};

static constexpr hal::PowerMode kPowerModes[] = {hal::PowerMode::OFF, hal::PowerMode::DOZE,
                                                 hal::PowerMode::DOZE_SUSPEND, hal::PowerMode::ON,
                                                 hal::PowerMode::ON_SUSPEND};

static constexpr hal::ContentType kContentTypes[] = {hal::ContentType::NONE,
                                                     hal::ContentType::GRAPHICS,
                                                     hal::ContentType::PHOTO,
                                                     hal::ContentType::CINEMA,
                                                     hal::ContentType::GAME};

const unsigned char kInternalEdid[] =
        "\x00\xff\xff\xff\xff\xff\xff\x00\x4c\xa3\x42\x31\x00\x00\x00\x00"
        "\x00\x15\x01\x03\x80\x1a\x10\x78\x0a\xd3\xe5\x95\x5c\x60\x90\x27"
        "\x19\x50\x54\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x9e\x1b\x00\xa0\x50\x20\x12\x30\x10\x30"
        "\x13\x00\x05\xa3\x10\x00\x00\x19\x00\x00\x00\x0f\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x23\x87\x02\x64\x00\x00\x00\x00\xfe\x00\x53"
        "\x41\x4d\x53\x55\x4e\x47\x0a\x20\x20\x20\x20\x20\x00\x00\x00\xfe"
        "\x00\x31\x32\x31\x41\x54\x31\x31\x2d\x38\x30\x31\x0a\x20\x00\x45";

static constexpr hal::HWConfigId kActiveConfig = 0;

class DisplayHardwareFuzzer {
public:
    DisplayHardwareFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        mPhysicalDisplayId = SurfaceComposerClient::getInternalDisplayId().value();
    };
    void process();

private:
    void invokeComposer();
    void invokeDisplayIdentification();
    void invokeLayer(HWC2::Layer* layer);
    void setSidebandStream(HWC2::Layer* layer);
    void setCursorPosition(HWC2::Layer* layer);
    void setBuffer(HWC2::Layer* layer);
    void setSurfaceDamage(HWC2::Layer* layer);
    void setDisplayFrame(HWC2::Layer* layer);
    void setVisibleRegion(HWC2::Layer* layer);
    void setLayerGenericMetadata(HWC2::Layer* layer);
    void invokeFrameBufferSurface();
    void invokeVirtualDisplaySurface();
    void invokeAidlComposer();
    Display createVirtualDisplay(Hwc2::AidlComposer*);
    void validateDisplay(Hwc2::AidlComposer*, Display);
    void presentOrValidateDisplay(Hwc2::AidlComposer*, Display);
    void setOutputBuffer(Hwc2::AidlComposer*, Display);
    void setLayerSidebandStream(Hwc2::AidlComposer*, Display, Hwc2::V2_4::hal::Layer);
    void invokeComposerHal2_2(Hwc2::AidlComposer*, Display, Hwc2::V2_4::hal::Layer);
    void invokeComposerHal2_3(Hwc2::AidlComposer*, Display, Hwc2::V2_4::hal::Layer);
    void invokeComposerHal2_4(Hwc2::AidlComposer*, Display, Hwc2::V2_4::hal::Layer);
    void getDisplayVsyncPeriod();
    void setActiveModeWithConstraints();
    void getDisplayIdentificationData();
    void dumpHwc();
    void getDisplayedContentSamplingAttributes(HalDisplayId);
    void getDeviceCompositionChanges(HalDisplayId);
    void getHdrCapabilities(HalDisplayId);
    void getDisplayedContentSample(HalDisplayId);
    void getSupportedContentTypes();
    ui::Size getFuzzedSize();
    mat4 getFuzzedMatrix();

    DisplayIdGenerator<HalVirtualDisplayId> mGenerator;
    FuzzedDataProvider mFdp;
    PhysicalDisplayId mPhysicalDisplayId;
    android::impl::HWComposer mHwc{std::make_unique<Hwc2::mock::Composer>()};
};

void DisplayHardwareFuzzer::validateDisplay(Hwc2::AidlComposer* composer, Display display) {
    uint32_t outNumTypes, outNumRequests;
    composer->validateDisplay(display, mFdp.ConsumeIntegral<nsecs_t>(), &outNumTypes,
                              &outNumRequests);
}

void DisplayHardwareFuzzer::presentOrValidateDisplay(Hwc2::AidlComposer* composer,
                                                     Display display) {
    int32_t outPresentFence;
    uint32_t outNumTypes, outNumRequests, state;
    composer->presentOrValidateDisplay(display, mFdp.ConsumeIntegral<nsecs_t>(), &outNumTypes,
                                       &outNumRequests, &outPresentFence, &state);
}

void DisplayHardwareFuzzer::setOutputBuffer(Hwc2::AidlComposer* composer, Display display) {
    const native_handle_t buffer{};
    composer->setOutputBuffer(display, &buffer, mFdp.ConsumeIntegral<int32_t>() /*releaseFence*/);
}

void DisplayHardwareFuzzer::setLayerSidebandStream(Hwc2::AidlComposer* composer, Display display,
                                                   Hwc2::V2_4::hal::Layer outLayer) {
    const native_handle_t stream{};
    composer->setLayerSidebandStream(display, outLayer, &stream);
}

Display DisplayHardwareFuzzer::createVirtualDisplay(Hwc2::AidlComposer* composer) {
    namespace types = hardware::graphics::common;
    using types::V1_2::PixelFormat;
    PixelFormat format{};
    Display display;
    composer->createVirtualDisplay(mFdp.ConsumeIntegral<uint32_t>() /*width*/,
                                   mFdp.ConsumeIntegral<uint32_t>() /*height*/, &format, &display);
    return display;
}

void DisplayHardwareFuzzer::getDisplayVsyncPeriod() {
    nsecs_t outVsyncPeriod;
    mHwc.getDisplayVsyncPeriod(mPhysicalDisplayId, &outVsyncPeriod);
}

void DisplayHardwareFuzzer::setActiveModeWithConstraints() {
    hal::VsyncPeriodChangeTimeline outTimeline;
    mHwc.setActiveModeWithConstraints(mPhysicalDisplayId, kActiveConfig, {} /*constraints*/,
                                      &outTimeline);
}

void DisplayHardwareFuzzer::getDisplayIdentificationData() {
    uint8_t outPort;
    DisplayIdentificationData outData;
    mHwc.getDisplayIdentificationData(kHwDisplayId, &outPort, &outData);
}

void DisplayHardwareFuzzer::dumpHwc() {
    std::string string = mFdp.ConsumeRandomLengthString().c_str();
    mHwc.dump(string);
}

void DisplayHardwareFuzzer::getDeviceCompositionChanges(HalDisplayId halDisplayID) {
    std::optional<impl::HWComposer::DeviceRequestedChanges> outChanges;
    mHwc.getDeviceCompositionChanges(halDisplayID,
                                     mFdp.ConsumeBool() /*frameUsesClientComposition*/,
                                     std::chrono::steady_clock::now(), FenceTime::NO_FENCE,
                                     mFdp.ConsumeIntegral<nsecs_t>(), &outChanges);
}

void DisplayHardwareFuzzer::getDisplayedContentSamplingAttributes(HalDisplayId halDisplayID) {
    uint8_t outComponentMask;
    ui::Dataspace dataSpace;
    ui::PixelFormat pixelFormat;
    mHwc.getDisplayedContentSamplingAttributes(halDisplayID, &pixelFormat, &dataSpace,
                                               &outComponentMask);
}

void DisplayHardwareFuzzer::getHdrCapabilities(HalDisplayId halDisplayID) {
    HdrCapabilities outCapabilities;
    mHwc.getHdrCapabilities(halDisplayID, &outCapabilities);
}

void DisplayHardwareFuzzer::getDisplayedContentSample(HalDisplayId halDisplayID) {
    DisplayedFrameStats outStats;
    mHwc.getDisplayedContentSample(halDisplayID, mFdp.ConsumeIntegral<uint64_t>() /* maxFrames*/,
                                   mFdp.ConsumeIntegral<uint64_t>() /*timestamps*/, &outStats);
}

void DisplayHardwareFuzzer::getSupportedContentTypes() {
    std::vector<hal::ContentType> contentType{};
    mHwc.getSupportedContentTypes(mPhysicalDisplayId, &contentType);
}

void DisplayHardwareFuzzer::invokeAidlComposer() {
    hardware::ProcessState::self()->startThreadPool();
    ProcessState::self()->startThreadPool();

    if (!Hwc2::AidlComposer::isDeclared("default")) {
        return;
    }

    Hwc2::AidlComposer composer("default");

    android::hardware::graphics::composer::hal::TestHWC2ComposerCallback composerCallback{};
    composer.registerCallback(composerCallback);

    Display display = createVirtualDisplay(&composer);

    composer.acceptDisplayChanges(display);

    Hwc2::V2_4::hal::Layer outLayer;
    composer.createLayer(display, &outLayer);

    int32_t outPresentFence;
    composer.presentDisplay(display, &outPresentFence);

    composer.setActiveConfig(display, Config{});

    composer.setClientTarget(display, mFdp.ConsumeIntegral<uint32_t>(), sp<GraphicBuffer>(),
                             mFdp.ConsumeIntegral<int32_t>(), mFdp.PickValueInArray(kDataspaces),
                             {});

    composer.setColorMode(display, mFdp.PickValueInArray(kColormodes),
                          mFdp.PickValueInArray(kRenderIntents));

    setOutputBuffer(&composer, display);

    composer.setPowerMode(display, mFdp.PickValueInArray(kPowerModes));
    composer.setVsyncEnabled(display, mFdp.ConsumeBool() ? Vsync::ENABLE : Vsync::DISABLE);

    composer.setClientTargetSlotCount(display);

    validateDisplay(&composer, display);

    presentOrValidateDisplay(&composer, display);

    composer.setCursorPosition(display, outLayer, mFdp.ConsumeIntegral<uint8_t>() /*x*/,
                               mFdp.ConsumeIntegral<uint8_t>() /*y*/);

    composer.setLayerBuffer(display, outLayer, mFdp.ConsumeIntegral<uint32_t>() /*slot*/,
                            sp<GraphicBuffer>(), mFdp.ConsumeIntegral<int32_t>() /*acquireFence*/);

    composer.setLayerSurfaceDamage(display, outLayer, {} /*damage*/);

    composer.setLayerBlendMode(display, outLayer, mFdp.PickValueInArray(kBlendModes));

    composer.setLayerColor(display, outLayer,
                           {mFdp.ConsumeFloatingPoint<float>() /*red*/,
                            mFdp.ConsumeFloatingPoint<float>() /*green*/,
                            mFdp.ConsumeFloatingPoint<float>() /*blue*/,
                            mFdp.ConsumeFloatingPoint<float>() /*alpha*/});
    composer.setLayerCompositionType(display, outLayer, mFdp.PickValueInArray(kCompositions));
    composer.setLayerDataspace(display, outLayer, mFdp.PickValueInArray(kDataspaces));
    composer.setLayerDisplayFrame(display, outLayer, {} /*frame*/);
    composer.setLayerPlaneAlpha(display, outLayer, mFdp.ConsumeFloatingPoint<float>());

    setLayerSidebandStream(&composer, display, outLayer);

    composer.setLayerSourceCrop(display, outLayer, {} /*crop*/);

    composer.setLayerTransform(display, outLayer, mFdp.PickValueInArray(kTransforms));

    composer.setLayerVisibleRegion(display, outLayer, std::vector<IComposerClient::Rect>{});
    composer.setLayerZOrder(display, outLayer, mFdp.ConsumeIntegral<uint32_t>());

    invokeComposerHal2_2(&composer, display, outLayer);
    invokeComposerHal2_3(&composer, display, outLayer);
    invokeComposerHal2_4(&composer, display, outLayer);

    composer.executeCommands();
    composer.resetCommands();

    composer.destroyLayer(display, outLayer);
    composer.destroyVirtualDisplay(display);
}

void DisplayHardwareFuzzer::invokeComposerHal2_2(Hwc2::AidlComposer* composer, Display display,
                                                 Hwc2::V2_4::hal::Layer outLayer) {
    const std::vector<PerFrameMetadata> perFrameMetadatas;
    composer->setLayerPerFrameMetadata(display, outLayer, perFrameMetadatas);

    composer->getPerFrameMetadataKeys(display);
    std::vector<RenderIntent> outRenderIntents;

    composer->getRenderIntents(display, mFdp.PickValueInArray(kColormodes), &outRenderIntents);
    mat4 outMatrix;
    composer->getDataspaceSaturationMatrix(mFdp.PickValueInArray(kDataspaces), &outMatrix);
}

void DisplayHardwareFuzzer::invokeComposerHal2_3(Hwc2::AidlComposer* composer, Display display,
                                                 Hwc2::V2_4::hal::Layer outLayer) {
    composer->setDisplayContentSamplingEnabled(display, mFdp.ConsumeBool() /*enabled*/,
                                               mFdp.ConsumeIntegral<uint8_t>() /*componentMask*/,
                                               mFdp.ConsumeIntegral<uint64_t>() /*maxFrames*/);

    DisplayedFrameStats outStats;
    composer->getDisplayedContentSample(display, mFdp.ConsumeIntegral<uint64_t>() /*maxFrames*/,
                                        mFdp.ConsumeIntegral<uint64_t>() /*timestamp*/, &outStats);

    composer->setLayerPerFrameMetadataBlobs(display, outLayer, std::vector<PerFrameMetadataBlob>{});

    composer->setDisplayBrightness(display, mFdp.ConsumeFloatingPoint<float>(),
                                   mFdp.ConsumeFloatingPoint<float>(),
                                   Hwc2::Composer::DisplayBrightnessOptions{
                                           .applyImmediately = mFdp.ConsumeIntegral<bool>()});
}

void DisplayHardwareFuzzer::invokeComposerHal2_4(Hwc2::AidlComposer* composer, Display display,
                                                 Hwc2::V2_4::hal::Layer outLayer) {
    VsyncPeriodChangeTimeline outTimeline;
    composer->setActiveConfigWithConstraints(display, Config{},
                                             IComposerClient::VsyncPeriodChangeConstraints{},
                                             &outTimeline);

    composer->setAutoLowLatencyMode(display, mFdp.ConsumeBool());

    composer->setContentType(display, mFdp.PickValueInArray(kContentTypes));

    std::vector<uint8_t> value;
    value.push_back(mFdp.ConsumeIntegral<uint8_t>());
    composer->setLayerGenericMetadata(display, outLayer, mFdp.ConsumeRandomLengthString() /*key*/,
                                      mFdp.ConsumeBool() /*mandatory*/, value);
}

ui::Size DisplayHardwareFuzzer::getFuzzedSize() {
    ui::Size size{mFdp.ConsumeIntegral<int32_t>() /*width*/,
                  mFdp.ConsumeIntegral<int32_t>() /*height*/};
    return size;
}

mat4 DisplayHardwareFuzzer::getFuzzedMatrix() {
    mat4 matrix{mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>()};
    return matrix;
}

void DisplayHardwareFuzzer::setCursorPosition(HWC2::Layer* layer) {
    layer->setCursorPosition(mFdp.ConsumeIntegral<int32_t>() /*x*/,
                             mFdp.ConsumeIntegral<int32_t>() /*y*/);
}

void DisplayHardwareFuzzer::setBuffer(HWC2::Layer* layer) {
    layer->setBuffer(mFdp.ConsumeIntegral<uint32_t>() /*slot*/, sp<GraphicBuffer>(),
                     sp<Fence>::make());
}

void DisplayHardwareFuzzer::setSurfaceDamage(HWC2::Layer* layer) {
    Rect rhs{mFdp.ConsumeIntegral<uint32_t>() /*width*/,
             mFdp.ConsumeIntegral<uint32_t>() /*height*/};
    const Region damage{rhs};
    layer->setSurfaceDamage(damage);
}

void DisplayHardwareFuzzer::setVisibleRegion(HWC2::Layer* layer) {
    uint32_t width = mFdp.ConsumeIntegral<uint32_t>();
    uint32_t height = mFdp.ConsumeIntegral<uint32_t>();
    Rect rect{width, height};
    const Region region{rect};
    layer->setVisibleRegion(region);
}

void DisplayHardwareFuzzer::setDisplayFrame(HWC2::Layer* layer) {
    uint32_t width = mFdp.ConsumeIntegral<uint32_t>();
    uint32_t height = mFdp.ConsumeIntegral<uint32_t>();
    const Rect frame{width, height};
    layer->setDisplayFrame(frame);
}

void DisplayHardwareFuzzer::setLayerGenericMetadata(HWC2::Layer* layer) {
    std::vector<uint8_t> value;
    value.push_back(mFdp.ConsumeIntegral<uint8_t>());
    layer->setLayerGenericMetadata(mFdp.ConsumeRandomLengthString().c_str() /*name*/,
                                   mFdp.ConsumeBool() /*mandatory*/, value);
}

void DisplayHardwareFuzzer::setSidebandStream(HWC2::Layer* layer) {
    const native_handle_t stream{};
    layer->setSidebandStream(&stream);
}

void DisplayHardwareFuzzer::invokeLayer(HWC2::Layer* layer) {
    setCursorPosition(layer);
    setBuffer(layer);
    setSurfaceDamage(layer);

    layer->setBlendMode(mFdp.PickValueInArray(kBlendModes));
    layer->setColor({mFdp.ConsumeFloatingPoint<float>() /*red*/,
                     mFdp.ConsumeFloatingPoint<float>() /*green*/,
                     mFdp.ConsumeFloatingPoint<float>() /*blue*/,
                     mFdp.ConsumeFloatingPoint<float>() /*alpha*/});
    layer->setCompositionType(mFdp.PickValueInArray(kCompositions));
    layer->setDataspace(mFdp.PickValueInArray(kDataspaces));

    layer->setPerFrameMetadata(mFdp.ConsumeIntegral<int32_t>(), getFuzzedHdrMetadata(&mFdp));
    setDisplayFrame(layer);

    layer->setPlaneAlpha(mFdp.ConsumeFloatingPoint<float>());

    setSidebandStream(layer);

    layer->setSourceCrop(getFuzzedFloatRect(&mFdp));
    layer->setTransform(mFdp.PickValueInArray(kTransforms));

    setVisibleRegion(layer);

    layer->setZOrder(mFdp.ConsumeIntegral<uint32_t>());

    layer->setColorTransform(getFuzzedMatrix());

    setLayerGenericMetadata(layer);
}

void DisplayHardwareFuzzer::invokeFrameBufferSurface() {
    sp<IGraphicBufferProducer> bqProducer = sp<mock::GraphicBufferProducer>::make();
    sp<IGraphicBufferConsumer> bqConsumer;
    BufferQueue::createBufferQueue(&bqProducer, &bqConsumer);

    sp<FramebufferSurface> surface =
            new FramebufferSurface(mHwc, mPhysicalDisplayId, bqConsumer, getFuzzedSize() /*size*/,
                                   getFuzzedSize() /*maxSize*/);
    surface->beginFrame(mFdp.ConsumeBool());

    surface->prepareFrame(mFdp.PickValueInArray(kCompositionTypes));
    surface->advanceFrame();
    surface->onFrameCommitted();
    String8 result = String8(mFdp.ConsumeRandomLengthString().c_str());
    surface->dumpAsString(result);
    surface->resizeBuffers(getFuzzedSize());
    surface->getClientTargetAcquireFence();
}

void DisplayHardwareFuzzer::invokeVirtualDisplaySurface() {
    DisplayIdGenerator<HalVirtualDisplayId> mGenerator;
    VirtualDisplayId VirtualDisplayId = mGenerator.generateId().value();

    sp<SurfaceComposerClient> mClient = new SurfaceComposerClient();
    sp<SurfaceControl> mSurfaceControl =
            mClient->createSurface(String8("TestSurface"), 100, 100, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceBufferState,
                                   /*parent*/ nullptr);

    sp<BLASTBufferQueue> mBlastBufferQueueAdapter =
            new BLASTBufferQueue("TestBLASTBufferQueue", mSurfaceControl, 100, 100,
                                 PIXEL_FORMAT_RGBA_8888);

    sp<IGraphicBufferProducer> sink = mBlastBufferQueueAdapter->getIGraphicBufferProducer();
    sp<IGraphicBufferProducer> bqProducer = mBlastBufferQueueAdapter->getIGraphicBufferProducer();
    sp<IGraphicBufferConsumer> bqConsumer;
    BufferQueue::createBufferQueue(&bqProducer, &bqConsumer);
    BufferQueue::createBufferQueue(&sink, &bqConsumer);

    sp<VirtualDisplaySurface> surface =
            new VirtualDisplaySurface(mHwc, VirtualDisplayId, sink, bqProducer, bqConsumer,
                                      mFdp.ConsumeRandomLengthString().c_str() /*name*/);

    surface->beginFrame(mFdp.ConsumeBool());
    surface->prepareFrame(mFdp.PickValueInArray(kCompositionTypes));
    surface->resizeBuffers(getFuzzedSize());
    surface->getClientTargetAcquireFence();
    surface->advanceFrame();
    surface->onFrameCommitted();
    String8 result = String8(mFdp.ConsumeRandomLengthString().c_str());
    surface->dumpAsString(result);
}

void DisplayHardwareFuzzer::invokeComposer() {
    HalVirtualDisplayId halVirtualDisplayId = mGenerator.generateId().value();
    HalDisplayId halDisplayID = HalDisplayId{halVirtualDisplayId};

    android::hardware::graphics::composer::hal::TestHWC2ComposerCallback composerCallback{};
    mHwc.setCallback(composerCallback);

    ui::PixelFormat pixelFormat{};
    if (!mHwc.allocateVirtualDisplay(halVirtualDisplayId, getFuzzedSize(), &pixelFormat)) {
        return;
    }

    getDisplayIdentificationData();

    mHwc.hasDisplayCapability(halDisplayID, mFdp.PickValueInArray(kDisplayCapability));

    mHwc.allocatePhysicalDisplay(kHwDisplayId, mPhysicalDisplayId);

    static auto hwcLayer = mHwc.createLayer(halDisplayID);
    HWC2::Layer* layer = hwcLayer.get();
    invokeLayer(layer);

    getDeviceCompositionChanges(halDisplayID);

    mHwc.setClientTarget(halDisplayID, mFdp.ConsumeIntegral<uint32_t>(), Fence::NO_FENCE,
                         sp<GraphicBuffer>::make(), mFdp.PickValueInArray(kDataspaces));

    mHwc.presentAndGetReleaseFences(halDisplayID, std::chrono::steady_clock::now(),
                                    FenceTime::NO_FENCE);

    mHwc.setPowerMode(mPhysicalDisplayId, mFdp.PickValueInArray(kPowerModes));

    mHwc.setColorTransform(halDisplayID, getFuzzedMatrix());

    mHwc.getPresentFence(halDisplayID);

    mHwc.getLayerReleaseFence(halDisplayID, layer);

    mHwc.setOutputBuffer(halVirtualDisplayId, sp<Fence>::make().get(), sp<GraphicBuffer>::make());

    mHwc.clearReleaseFences(halDisplayID);

    getHdrCapabilities(halDisplayID);

    mHwc.getSupportedPerFrameMetadata(halDisplayID);

    mHwc.getRenderIntents(halDisplayID, ui::ColorMode());

    mHwc.getDataspaceSaturationMatrix(halDisplayID, ui::Dataspace());

    getDisplayedContentSamplingAttributes(halDisplayID);

    mHwc.setDisplayContentSamplingEnabled(halDisplayID, mFdp.ConsumeBool() /*enabled*/,
                                          mFdp.ConsumeIntegral<uint8_t>() /*componentMask*/,
                                          mFdp.ConsumeIntegral<uint64_t>() /*maxFrames*/);

    getDisplayedContentSample(halDisplayID);

    mHwc.setDisplayBrightness(mPhysicalDisplayId, mFdp.ConsumeFloatingPoint<float>(),
                              mFdp.ConsumeFloatingPoint<float>(),
                              Hwc2::Composer::DisplayBrightnessOptions{
                                      .applyImmediately = mFdp.ConsumeIntegral<bool>()});

    mHwc.onHotplug(kHwDisplayId, hal::Connection::CONNECTED);
    mHwc.updatesDeviceProductInfoOnHotplugReconnect();

    mHwc.onVsync(kHwDisplayId, mFdp.ConsumeIntegral<int64_t>());
    mHwc.setVsyncEnabled(mPhysicalDisplayId,
                         mFdp.ConsumeBool() ? hal::Vsync::ENABLE : hal::Vsync::DISABLE);

    mHwc.isConnected(mPhysicalDisplayId);
    mHwc.getModes(mPhysicalDisplayId);
    mHwc.getActiveMode(mPhysicalDisplayId);
    mHwc.getColorModes(mPhysicalDisplayId);
    mHwc.hasCapability(mFdp.PickValueInArray(kCapability));

    mHwc.setActiveColorMode(mPhysicalDisplayId, mFdp.PickValueInArray(kColormodes),
                            mFdp.PickValueInArray(kRenderIntents));

    mHwc.getDisplayConnectionType(mPhysicalDisplayId);
    mHwc.isVsyncPeriodSwitchSupported(mPhysicalDisplayId);

    getDisplayVsyncPeriod();

    setActiveModeWithConstraints();

    mHwc.setAutoLowLatencyMode(mPhysicalDisplayId, mFdp.ConsumeBool());

    getSupportedContentTypes();

    mHwc.setContentType(mPhysicalDisplayId, mFdp.PickValueInArray(kContentTypes));

    dumpHwc();

    mHwc.toPhysicalDisplayId(kHwDisplayId);
    mHwc.fromPhysicalDisplayId(mPhysicalDisplayId);
    mHwc.disconnectDisplay(halDisplayID);

    static hal::HWDisplayId displayId = mFdp.ConsumeIntegral<hal::HWDisplayId>();
    mHwc.onHotplug(displayId,
                   mFdp.ConsumeBool() ? hal::Connection::DISCONNECTED : hal::Connection::CONNECTED);
}

template <size_t N>
DisplayIdentificationData asDisplayIdentificationData(const unsigned char (&bytes)[N]) {
    return DisplayIdentificationData(bytes, bytes + N - 1);
}

void DisplayHardwareFuzzer::invokeDisplayIdentification() {
    static const DisplayIdentificationData data = asDisplayIdentificationData(kInternalEdid);
    isEdid(data);
    parseEdid(data);
    parseDisplayIdentificationData(mFdp.ConsumeIntegral<uint8_t>(), data);
    getPnpId(getVirtualDisplayId(mFdp.ConsumeIntegral<uint32_t>()));
    getPnpId(mFdp.ConsumeIntegral<uint8_t>());
}

void DisplayHardwareFuzzer::process() {
    invokeComposer();
    invokeAidlComposer();
    invokeDisplayIdentification();
    invokeFrameBufferSurface();
    invokeVirtualDisplaySurface();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    DisplayHardwareFuzzer displayHardwareFuzzer(data, size);
    displayHardwareFuzzer.process();
    return 0;
}

} // namespace android::fuzz
