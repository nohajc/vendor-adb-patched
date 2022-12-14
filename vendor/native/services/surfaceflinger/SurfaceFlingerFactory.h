/*
 * Copyright 2018 The Android Open Source Project
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

#include <cinttypes>
#include <functional>
#include <memory>
#include <string>

#include <cutils/compiler.h>
#include <utils/StrongPointer.h>

#include <scheduler/Fps.h>

namespace android {

typedef int32_t PixelFormat;

class BufferQueueLayer;
class BufferLayerConsumer;
class BufferStateLayer;
class ContainerLayer;
class DisplayDevice;
class EffectLayer;
class FrameTracer;
class GraphicBuffer;
class HWComposer;
class IGraphicBufferConsumer;
class IGraphicBufferProducer;
class Layer;
class StartPropertySetThread;
class SurfaceFlinger;
class SurfaceInterceptor;
class TimeStats;

struct DisplayDeviceCreationArgs;
struct LayerCreationArgs;

namespace compositionengine {
class CompositionEngine;
} // namespace compositionengine

namespace scheduler {
class VsyncConfiguration;
class VsyncController;
class RefreshRateConfigs;
} // namespace scheduler

namespace frametimeline {
class FrameTimeline;
} // namespace frametimeline

namespace surfaceflinger {

class NativeWindowSurface;

// The interface that SurfaceFlinger uses to create all of the implementations
// of each interface.
class Factory {
public:
    virtual std::unique_ptr<HWComposer> createHWComposer(const std::string& serviceName) = 0;
    virtual std::unique_ptr<scheduler::VsyncConfiguration> createVsyncConfiguration(
            Fps currentRefreshRate) = 0;
    virtual sp<SurfaceInterceptor> createSurfaceInterceptor() = 0;

    virtual sp<StartPropertySetThread> createStartPropertySetThread(
            bool timestampPropertyValue) = 0;
    virtual sp<DisplayDevice> createDisplayDevice(DisplayDeviceCreationArgs&) = 0;
    virtual sp<GraphicBuffer> createGraphicBuffer(uint32_t width, uint32_t height,
                                                  PixelFormat format, uint32_t layerCount,
                                                  uint64_t usage, std::string requestorName) = 0;
    virtual void createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
                                   sp<IGraphicBufferConsumer>* outConsumer,
                                   bool consumerIsSurfaceFlinger) = 0;
    virtual sp<IGraphicBufferProducer> createMonitoredProducer(const sp<IGraphicBufferProducer>&,
                                                               const sp<SurfaceFlinger>&,
                                                               const wp<Layer>&) = 0;
    virtual sp<BufferLayerConsumer> createBufferLayerConsumer(const sp<IGraphicBufferConsumer>&,
                                                              renderengine::RenderEngine&,
                                                              uint32_t tex, Layer*) = 0;

    virtual std::unique_ptr<surfaceflinger::NativeWindowSurface> createNativeWindowSurface(
            const sp<IGraphicBufferProducer>&) = 0;

    virtual std::unique_ptr<compositionengine::CompositionEngine> createCompositionEngine() = 0;

    virtual sp<BufferQueueLayer> createBufferQueueLayer(const LayerCreationArgs& args) = 0;
    virtual sp<BufferStateLayer> createBufferStateLayer(const LayerCreationArgs& args) = 0;
    virtual sp<EffectLayer> createEffectLayer(const LayerCreationArgs& args) = 0;
    virtual sp<ContainerLayer> createContainerLayer(const LayerCreationArgs& args) = 0;
    virtual std::unique_ptr<FrameTracer> createFrameTracer() = 0;
    virtual std::unique_ptr<frametimeline::FrameTimeline> createFrameTimeline(
            std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid) = 0;

protected:
    ~Factory() = default;
};

ANDROID_API sp<SurfaceFlinger> createSurfaceFlinger();

} // namespace surfaceflinger
} // namespace android
