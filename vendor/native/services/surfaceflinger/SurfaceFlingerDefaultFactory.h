/*
 * Copyright 2019 The Android Open Source Project
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

#include "SurfaceFlingerFactory.h"

namespace android::surfaceflinger {

// A default implementation of the factory which creates the standard
// implementation types for each interface.
class DefaultFactory : public surfaceflinger::Factory {
public:
    virtual ~DefaultFactory();

    std::unique_ptr<DispSync> createDispSync(const char* name, bool hasSyncFramework) override;
    std::unique_ptr<EventControlThread> createEventControlThread(SetVSyncEnabled) override;
    std::unique_ptr<HWComposer> createHWComposer(const std::string& serviceName) override;
    std::unique_ptr<MessageQueue> createMessageQueue() override;
    std::unique_ptr<scheduler::PhaseConfiguration> createPhaseConfiguration(
            const scheduler::RefreshRateConfigs&) override;
    std::unique_ptr<Scheduler> createScheduler(SetVSyncEnabled,
                                               const scheduler::RefreshRateConfigs&,
                                               ISchedulerCallback&) override;
    std::unique_ptr<SurfaceInterceptor> createSurfaceInterceptor(SurfaceFlinger*) override;
    sp<StartPropertySetThread> createStartPropertySetThread(bool timestampPropertyValue) override;
    sp<DisplayDevice> createDisplayDevice(DisplayDeviceCreationArgs&) override;
    sp<GraphicBuffer> createGraphicBuffer(uint32_t width, uint32_t height, PixelFormat format,
                                          uint32_t layerCount, uint64_t usage,
                                          std::string requestorName) override;
    void createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
                           sp<IGraphicBufferConsumer>* outConsumer,
                           bool consumerIsSurfaceFlinger) override;
    sp<IGraphicBufferProducer> createMonitoredProducer(const sp<IGraphicBufferProducer>&,
                                                       const sp<SurfaceFlinger>&,
                                                       const wp<Layer>&) override;
    sp<BufferLayerConsumer> createBufferLayerConsumer(const sp<IGraphicBufferConsumer>&,
                                                      renderengine::RenderEngine&, uint32_t tex,
                                                      Layer*) override;
    std::unique_ptr<surfaceflinger::NativeWindowSurface> createNativeWindowSurface(
            const sp<IGraphicBufferProducer>&) override;
    std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine() override;
    sp<BufferQueueLayer> createBufferQueueLayer(const LayerCreationArgs& args) override;
    sp<BufferStateLayer> createBufferStateLayer(const LayerCreationArgs& args) override;
    sp<EffectLayer> createEffectLayer(const LayerCreationArgs& args) override;
    sp<ContainerLayer> createContainerLayer(const LayerCreationArgs& args) override;
};

} // namespace android::surfaceflinger
