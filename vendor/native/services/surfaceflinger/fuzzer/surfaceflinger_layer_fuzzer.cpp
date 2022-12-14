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
#include <BufferStateLayer.h>
#include <Client.h>
#include <DisplayDevice.h>
#include <EffectLayer.h>
#include <LayerRejecter.h>
#include <LayerRenderArea.h>
#include <MonitoredProducer.h>
#include <ftl/future.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gui/IProducerListener.h>
#include <gui/LayerDebugInfo.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/WindowInfo.h>
#include <renderengine/mock/FakeExternalTexture.h>
#include <ui/DisplayStatInfo.h>

#include <FuzzableDataspaces.h>
#include <surfaceflinger_fuzzers_utils.h>

namespace android::fuzzer {
using namespace renderengine;

constexpr uint16_t kRandomStringLength = 256;

class LayerFuzzer {
public:
    LayerFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void init();
    void invokeBufferStateLayer();
    void invokeEffectLayer();
    LayerCreationArgs createLayerCreationArgs(TestableSurfaceFlinger* flinger, sp<Client> client);
    Rect getFuzzedRect();
    FrameTimelineInfo getFuzzedFrameTimelineInfo();

private:
    FuzzedDataProvider mFdp;
};

Rect LayerFuzzer::getFuzzedRect() {
    return Rect(mFdp.ConsumeIntegral<int32_t>() /*left*/, mFdp.ConsumeIntegral<int32_t>() /*top*/,
                mFdp.ConsumeIntegral<int32_t>() /*right*/,
                mFdp.ConsumeIntegral<int32_t>() /*bottom*/);
}

FrameTimelineInfo LayerFuzzer::getFuzzedFrameTimelineInfo() {
    return FrameTimelineInfo{.vsyncId = mFdp.ConsumeIntegral<int64_t>(),
                             .inputEventId = mFdp.ConsumeIntegral<int32_t>()};
}

LayerCreationArgs LayerFuzzer::createLayerCreationArgs(TestableSurfaceFlinger* flinger,
                                                       sp<Client> client) {
    flinger->setupScheduler(std::make_unique<android::mock::VsyncController>(),
                            std::make_unique<android::mock::VSyncTracker>(),
                            std::make_unique<android::mock::EventThread>(),
                            std::make_unique<android::mock::EventThread>());

    return LayerCreationArgs(flinger->flinger(), client,
                             mFdp.ConsumeRandomLengthString(kRandomStringLength) /*name*/,
                             mFdp.ConsumeIntegral<uint32_t>() /*flags*/, {} /*metadata*/);
}

void LayerFuzzer::invokeEffectLayer() {
    TestableSurfaceFlinger flinger;
    sp<Client> client = sp<Client>::make(flinger.flinger());
    const LayerCreationArgs layerCreationArgs = createLayerCreationArgs(&flinger, client);
    sp<EffectLayer> effectLayer = sp<EffectLayer>::make(layerCreationArgs);

    effectLayer->setColor({(mFdp.ConsumeFloatingPointInRange<float>(0, 255) /*x*/,
                            mFdp.ConsumeFloatingPointInRange<float>(0, 255) /*y*/,
                            mFdp.ConsumeFloatingPointInRange<float>(0, 255) /*z*/)});
    effectLayer->setDataspace(mFdp.PickValueInArray(kDataspaces));
    sp<EffectLayer> parent = sp<EffectLayer>::make(layerCreationArgs);
    effectLayer->setChildrenDrawingParent(parent);

    const FrameTimelineInfo frameInfo = getFuzzedFrameTimelineInfo();
    const int64_t postTime = mFdp.ConsumeIntegral<int64_t>();
    effectLayer->setFrameTimelineVsyncForBufferTransaction(frameInfo, postTime);
    effectLayer->setFrameTimelineVsyncForBufferlessTransaction(frameInfo, postTime);
    auto surfaceFrame = effectLayer->createSurfaceFrameForTransaction(frameInfo, postTime);
    auto surfaceFrame1 =
            effectLayer->createSurfaceFrameForBuffer(frameInfo, postTime,
                                                     mFdp.ConsumeRandomLengthString(
                                                             kRandomStringLength) /*bufferName*/);
    effectLayer->addSurfaceFramePresentedForBuffer(surfaceFrame,
                                                   mFdp.ConsumeIntegral<int64_t>() /*acquireTime*/,
                                                   mFdp.ConsumeIntegral<int64_t>() /*currentTime*/);
    effectLayer->addSurfaceFrameDroppedForBuffer(surfaceFrame1);

    parent.clear();
    client.clear();
    effectLayer.clear();
}

void LayerFuzzer::invokeBufferStateLayer() {
    TestableSurfaceFlinger flinger;
    sp<Client> client = sp<Client>::make(flinger.flinger());
    sp<BufferStateLayer> layer =
            sp<BufferStateLayer>::make(createLayerCreationArgs(&flinger, client));
    sp<Fence> fence = sp<Fence>::make();
    const std::shared_ptr<FenceTime> fenceTime = std::make_shared<FenceTime>(fence);

    const CompositorTiming compositor = {mFdp.ConsumeIntegral<int64_t>(),
                                         mFdp.ConsumeIntegral<int64_t>(),
                                         mFdp.ConsumeIntegral<int64_t>()};

    layer->onLayerDisplayed(ftl::yield<FenceResult>(fence).share());
    layer->onLayerDisplayed(
            ftl::yield<FenceResult>(base::unexpected(mFdp.ConsumeIntegral<status_t>())).share());

    layer->releasePendingBuffer(mFdp.ConsumeIntegral<int64_t>());
    layer->finalizeFrameEventHistory(fenceTime, compositor);
    layer->onPostComposition(nullptr, fenceTime, fenceTime, compositor);
    layer->isBufferDue(mFdp.ConsumeIntegral<int64_t>());

    layer->setTransform(mFdp.ConsumeIntegral<uint32_t>());
    layer->setTransformToDisplayInverse(mFdp.ConsumeBool());
    layer->setCrop(getFuzzedRect());

    layer->setHdrMetadata(getFuzzedHdrMetadata(&mFdp));
    layer->setDataspace(mFdp.PickValueInArray(kDataspaces));
    if (mFdp.ConsumeBool()) {
        layer->setSurfaceDamageRegion(Region());
        layer->setTransparentRegionHint(Region());
    } else {
        layer->setSurfaceDamageRegion(Region(getFuzzedRect()));
        layer->setTransparentRegionHint(Region(getFuzzedRect()));
    }
    layer->setApi(mFdp.ConsumeIntegral<int32_t>());

    native_handle_t* testHandle = native_handle_create(0, 1);
    const bool ownsHandle = mFdp.ConsumeBool();
    sp<NativeHandle> nativeHandle = sp<NativeHandle>::make(testHandle, ownsHandle);
    layer->setSidebandStream(nativeHandle);
    layer->computeSourceBounds(getFuzzedFloatRect(&mFdp));

    layer->fenceHasSignaled();
    layer->framePresentTimeIsCurrent(mFdp.ConsumeIntegral<int64_t>());
    layer->onPreComposition(mFdp.ConsumeIntegral<int64_t>());
    const std::vector<sp<CallbackHandle>> callbacks;
    layer->setTransactionCompletedListeners(callbacks);

    std::shared_ptr<renderengine::ExternalTexture> texture = std::make_shared<
            renderengine::mock::FakeExternalTexture>(mFdp.ConsumeIntegral<uint32_t>(),
                                                     mFdp.ConsumeIntegral<uint32_t>(),
                                                     mFdp.ConsumeIntegral<uint64_t>(),
                                                     static_cast<android::PixelFormat>(
                                                             mFdp.PickValueInArray(kPixelFormats)),
                                                     mFdp.ConsumeIntegral<uint64_t>());
    layer->setBuffer(texture, {} /*bufferData*/, mFdp.ConsumeIntegral<nsecs_t>() /*postTime*/,
                     mFdp.ConsumeIntegral<nsecs_t>() /*desiredTime*/,
                     mFdp.ConsumeBool() /*isAutoTimestamp*/,
                     {mFdp.ConsumeIntegral<nsecs_t>()} /*dequeue*/, {} /*info*/);

    LayerRenderArea layerArea(*(flinger.flinger()), layer, getFuzzedRect(),
                              {mFdp.ConsumeIntegral<int32_t>(),
                               mFdp.ConsumeIntegral<int32_t>()} /*reqSize*/,
                              mFdp.PickValueInArray(kDataspaces), mFdp.ConsumeBool(),
                              getFuzzedRect(), mFdp.ConsumeBool());
    layerArea.render([]() {} /*drawLayers*/);

    if (!ownsHandle) {
        native_handle_close(testHandle);
        native_handle_delete(testHandle);
    }
    nativeHandle.clear();
    fence.clear();
    client.clear();
    layer.clear();
}

void LayerFuzzer::init() {
    invokeBufferStateLayer();
    invokeEffectLayer();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    LayerFuzzer layerFuzzer(data, size);
    layerFuzzer.init();
    return 0;
}

} // namespace android::fuzzer
