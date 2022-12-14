/*
 * Copyright (C) 2022 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LayerTraceGenerator"

#include <TestableSurfaceFlinger.h>
#include <Tracing/TransactionProtoParser.h>
#include <binder/IPCThreadState.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <gui/LayerState.h>
#include <log/log.h>
#include <mock/MockEventThread.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/mock/FakeExternalTexture.h>
#include <renderengine/mock/RenderEngine.h>
#include <utils/String16.h>
#include <string>

#include "LayerTraceGenerator.h"

namespace android {

class Factory final : public surfaceflinger::Factory {
public:
    ~Factory() = default;

    std::unique_ptr<HWComposer> createHWComposer(const std::string&) override { return nullptr; }

    std::unique_ptr<scheduler::VsyncConfiguration> createVsyncConfiguration(
            Fps /*currentRefreshRate*/) override {
        return std::make_unique<scheduler::FakePhaseOffsets>();
    }

    sp<SurfaceInterceptor> createSurfaceInterceptor() override {
        return new android::impl::SurfaceInterceptor();
    }

    sp<StartPropertySetThread> createStartPropertySetThread(
            bool /* timestampPropertyValue */) override {
        return nullptr;
    }

    sp<DisplayDevice> createDisplayDevice(DisplayDeviceCreationArgs& /* creationArgs */) override {
        return nullptr;
    }

    sp<GraphicBuffer> createGraphicBuffer(uint32_t /* width */, uint32_t /* height */,
                                          PixelFormat /* format */, uint32_t /* layerCount */,
                                          uint64_t /* usage */,
                                          std::string /* requestorName */) override {
        return nullptr;
    }

    void createBufferQueue(sp<IGraphicBufferProducer>* /* outProducer */,
                           sp<IGraphicBufferConsumer>* /* outConsumer */,
                           bool /* consumerIsSurfaceFlinger */) override {}

    sp<IGraphicBufferProducer> createMonitoredProducer(
            const sp<IGraphicBufferProducer>& /* producer */,
            const sp<SurfaceFlinger>& /* flinger */, const wp<Layer>& /* layer */) override {
        return nullptr;
    }

    sp<BufferLayerConsumer> createBufferLayerConsumer(
            const sp<IGraphicBufferConsumer>& /* consumer */,
            renderengine::RenderEngine& /* renderEngine */, uint32_t /* textureName */,
            Layer* /* layer */) override {
        return nullptr;
    }

    std::unique_ptr<surfaceflinger::NativeWindowSurface> createNativeWindowSurface(
            const sp<IGraphicBufferProducer>& /* producer */) override {
        return nullptr;
    }

    std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine() override {
        return compositionengine::impl::createCompositionEngine();
    }

    sp<ContainerLayer> createContainerLayer(const LayerCreationArgs& args) {
        return sp<ContainerLayer>::make(args);
    }

    sp<BufferStateLayer> createBufferStateLayer(const LayerCreationArgs& args) {
        return new BufferStateLayer(args);
    }

    sp<EffectLayer> createEffectLayer(const LayerCreationArgs& args) {
        return new EffectLayer(args);
    }

    sp<BufferQueueLayer> createBufferQueueLayer(const LayerCreationArgs&) override {
        return nullptr;
    }

    std::unique_ptr<FrameTracer> createFrameTracer() override {
        return std::make_unique<testing::NiceMock<mock::FrameTracer>>();
    }

    std::unique_ptr<frametimeline::FrameTimeline> createFrameTimeline(
            std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid = 0) override {
        return std::make_unique<testing::NiceMock<mock::FrameTimeline>>(timeStats,
                                                                        surfaceFlingerPid);
    }
};

class MockSurfaceFlinger : public SurfaceFlinger {
public:
    MockSurfaceFlinger(Factory& factory)
          : SurfaceFlinger(factory, SurfaceFlinger::SkipInitialization) {}
    std::shared_ptr<renderengine::ExternalTexture> getExternalTextureFromBufferData(
            const BufferData& bufferData, const char* /* layerName */) const override {
        return std::make_shared<renderengine::mock::FakeExternalTexture>(bufferData.getWidth(),
                                                                         bufferData.getHeight(),
                                                                         bufferData.getId(),
                                                                         bufferData
                                                                                 .getPixelFormat(),
                                                                         bufferData.getUsage());
    };

    // b/220017192 migrate from transact codes to ISurfaceComposer apis
    void setLayerTracingFlags(int32_t flags) {
        Parcel data;
        Parcel reply;
        data.writeInterfaceToken(String16("android.ui.ISurfaceComposer"));
        data.writeInt32(flags);
        transact(1033, data, &reply, 0 /* flags */);
    }

    void startLayerTracing(int64_t traceStartTime) {
        Parcel data;
        Parcel reply;
        data.writeInterfaceToken(String16("android.ui.ISurfaceComposer"));
        data.writeInt32(1);
        data.writeInt64(traceStartTime);
        transact(1025, data, &reply, 0 /* flags */);
    }

    void stopLayerTracing(const char* tracePath) {
        Parcel data;
        Parcel reply;
        data.writeInterfaceToken(String16("android.ui.ISurfaceComposer"));
        data.writeInt32(2);
        data.writeCString(tracePath);
        transact(1025, data, &reply, 0 /* flags */);
    }
};

class TraceGenFlingerDataMapper : public TransactionProtoParser::FlingerDataMapper {
public:
    std::unordered_map<int32_t /*layerId*/, sp<IBinder> /* handle */> mLayerHandles;
    sp<IBinder> getLayerHandle(int32_t layerId) const override {
        if (layerId == -1) {
            ALOGE("Error: Called with layer=%d", layerId);
            return nullptr;
        }
        auto it = mLayerHandles.find(layerId);
        if (it == mLayerHandles.end()) {
            ALOGE("Error: Could not find handle for layer=%d", layerId);
            return nullptr;
        }
        return it->second;
    }
};

bool LayerTraceGenerator::generate(const proto::TransactionTraceFile& traceFile,
                                   const char* outputLayersTracePath) {
    if (traceFile.entry_size() == 0) {
        return false;
    }

    Factory mFactory;
    sp<MockSurfaceFlinger> flinger = new MockSurfaceFlinger(mFactory);
    TestableSurfaceFlinger mFlinger(flinger);
    mFlinger.setupRenderEngine(
            std::make_unique<testing::NiceMock<renderengine::mock::RenderEngine>>());
    mock::VsyncController* mVsyncController = new testing::NiceMock<mock::VsyncController>();
    mock::VSyncTracker* mVSyncTracker = new testing::NiceMock<mock::VSyncTracker>();
    mock::EventThread* mEventThread = new testing::NiceMock<mock::EventThread>();
    mock::EventThread* mSFEventThread = new testing::NiceMock<mock::EventThread>();
    mFlinger.setupScheduler(std::unique_ptr<scheduler::VsyncController>(mVsyncController),
                            std::unique_ptr<scheduler::VSyncTracker>(mVSyncTracker),
                            std::unique_ptr<EventThread>(mEventThread),
                            std::unique_ptr<EventThread>(mSFEventThread),
                            TestableSurfaceFlinger::SchedulerCallbackImpl::kNoOp,
                            TestableSurfaceFlinger::kOneDisplayMode, true /* useNiceMock */);

    Hwc2::mock::Composer* mComposer = new testing::NiceMock<Hwc2::mock::Composer>();
    mFlinger.setupComposer(std::unique_ptr<Hwc2::Composer>(mComposer));
    mFlinger.mutableMaxRenderTargetSize() = 16384;

    flinger->setLayerTracingFlags(LayerTracing::TRACE_INPUT | LayerTracing::TRACE_BUFFERS);
    flinger->startLayerTracing(traceFile.entry(0).elapsed_realtime_nanos());
    std::unique_ptr<TraceGenFlingerDataMapper> mapper =
            std::make_unique<TraceGenFlingerDataMapper>();
    TraceGenFlingerDataMapper* dataMapper = mapper.get();
    TransactionProtoParser parser(std::move(mapper));

    nsecs_t frameTime;
    int64_t vsyncId;
    ALOGD("Generating %d transactions...", traceFile.entry_size());
    for (int i = 0; i < traceFile.entry_size(); i++) {
        proto::TransactionTraceEntry entry = traceFile.entry(i);
        ALOGV("    Entry %04d/%04d for time=%" PRId64 " vsyncid=%" PRId64
              " layers +%d -%d transactions=%d",
              i, traceFile.entry_size(), entry.elapsed_realtime_nanos(), entry.vsync_id(),
              entry.added_layers_size(), entry.removed_layers_size(), entry.transactions_size());

        for (int j = 0; j < entry.added_layers_size(); j++) {
            // create layers
            TracingLayerCreationArgs tracingArgs;
            parser.fromProto(entry.added_layers(j), tracingArgs);

            sp<IBinder> outHandle;
            int32_t outLayerId;
            LayerCreationArgs args(mFlinger.flinger(), nullptr /* client */, tracingArgs.name,
                                   tracingArgs.flags, LayerMetadata());
            args.sequence = std::make_optional<int32_t>(tracingArgs.layerId);

            if (tracingArgs.mirrorFromId == -1) {
                sp<IBinder> parentHandle = nullptr;
                if ((tracingArgs.parentId != -1) &&
                    (dataMapper->mLayerHandles.find(tracingArgs.parentId) ==
                     dataMapper->mLayerHandles.end())) {
                    args.addToRoot = false;
                } else {
                    parentHandle = dataMapper->getLayerHandle(tracingArgs.parentId);
                }
                mFlinger.createLayer(args, &outHandle, parentHandle, &outLayerId,
                                     nullptr /* parentLayer */, nullptr /* outTransformHint */);
            } else {
                sp<IBinder> mirrorFromHandle = dataMapper->getLayerHandle(tracingArgs.mirrorFromId);
                mFlinger.mirrorLayer(args, mirrorFromHandle, &outHandle, &outLayerId);
            }
            LOG_ALWAYS_FATAL_IF(outLayerId != tracingArgs.layerId,
                                "Could not create layer expected:%d actual:%d", tracingArgs.layerId,
                                outLayerId);
            dataMapper->mLayerHandles[tracingArgs.layerId] = outHandle;
        }

        for (int j = 0; j < entry.transactions_size(); j++) {
            // apply transactions
            TransactionState transaction = parser.fromProto(entry.transactions(j));
            mFlinger.setTransactionState(transaction.frameTimelineInfo, transaction.states,
                                         transaction.displays, transaction.flags,
                                         transaction.applyToken, transaction.inputWindowCommands,
                                         transaction.desiredPresentTime,
                                         transaction.isAutoTimestamp, {},
                                         transaction.hasListenerCallbacks,
                                         transaction.listenerCallbacks, transaction.id);
        }

        for (int j = 0; j < entry.removed_layer_handles_size(); j++) {
            dataMapper->mLayerHandles.erase(entry.removed_layer_handles(j));
        }

        frameTime = entry.elapsed_realtime_nanos();
        vsyncId = entry.vsync_id();
        mFlinger.commit(frameTime, vsyncId);
    }

    flinger->stopLayerTracing(outputLayersTracePath);
    ALOGD("End of generating trace file. File written to %s", outputLayersTracePath);
    dataMapper->mLayerHandles.clear();
    return true;
}

} // namespace android