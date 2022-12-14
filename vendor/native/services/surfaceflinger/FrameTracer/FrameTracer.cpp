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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "FrameTracer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "FrameTracer.h"

#include <android-base/stringprintf.h>
#include <perfetto/trace/clock_snapshot.pbzero.h>

#include <algorithm>
#include <mutex>

PERFETTO_DEFINE_DATA_SOURCE_STATIC_MEMBERS(android::FrameTracer::FrameTracerDataSource);

namespace android {

using Clock = perfetto::protos::pbzero::ClockSnapshot::Clock;
void FrameTracer::initialize() {
    std::call_once(mInitializationFlag, [this]() {
        perfetto::TracingInitArgs args;
        args.backends = perfetto::kSystemBackend;
        perfetto::Tracing::Initialize(args);
        registerDataSource();
    });
}

void FrameTracer::registerDataSource() {
    perfetto::DataSourceDescriptor dsd;
    dsd.set_name(kFrameTracerDataSource);
    FrameTracerDataSource::Register(dsd);
}

void FrameTracer::traceNewLayer(int32_t layerId, const std::string& layerName) {
    FrameTracerDataSource::Trace([this, layerId, &layerName](FrameTracerDataSource::TraceContext) {
        if (mTraceTracker.find(layerId) == mTraceTracker.end()) {
            std::lock_guard<std::mutex> lock(mTraceMutex);
            mTraceTracker[layerId].layerName = layerName;
        }
    });
}

void FrameTracer::traceTimestamp(int32_t layerId, uint64_t bufferID, uint64_t frameNumber,
                                 nsecs_t timestamp, FrameEvent::BufferEventType type,
                                 nsecs_t duration) {
    FrameTracerDataSource::Trace([this, layerId, bufferID, frameNumber, timestamp, type,
                                  duration](FrameTracerDataSource::TraceContext ctx) {
        std::lock_guard<std::mutex> lock(mTraceMutex);
        if (mTraceTracker.find(layerId) == mTraceTracker.end()) {
            return;
        }

        // Handle any pending fences for this buffer.
        tracePendingFencesLocked(ctx, layerId, bufferID);

        // Complete current trace.
        traceLocked(ctx, layerId, bufferID, frameNumber, timestamp, type, duration);
    });
}

void FrameTracer::traceFence(int32_t layerId, uint64_t bufferID, uint64_t frameNumber,
                             const std::shared_ptr<FenceTime>& fence,
                             FrameEvent::BufferEventType type, nsecs_t startTime) {
    FrameTracerDataSource::Trace([this, layerId, bufferID, frameNumber, &fence, type,
                                  startTime](FrameTracerDataSource::TraceContext ctx) {
        const nsecs_t signalTime = fence->getSignalTime();
        if (signalTime != Fence::SIGNAL_TIME_INVALID) {
            std::lock_guard<std::mutex> lock(mTraceMutex);
            if (mTraceTracker.find(layerId) == mTraceTracker.end()) {
                return;
            }

            // Handle any pending fences for this buffer.
            tracePendingFencesLocked(ctx, layerId, bufferID);

            if (signalTime != Fence::SIGNAL_TIME_PENDING) {
                traceSpanLocked(ctx, layerId, bufferID, frameNumber, type, startTime, signalTime);
            } else {
                mTraceTracker[layerId].pendingFences[bufferID].push_back(
                        {.frameNumber = frameNumber,
                         .type = type,
                         .fence = fence,
                         .startTime = startTime});
            }
        }
    });
}

void FrameTracer::tracePendingFencesLocked(FrameTracerDataSource::TraceContext& ctx,
                                           int32_t layerId, uint64_t bufferID) {
    if (mTraceTracker[layerId].pendingFences.count(bufferID)) {
        auto& pendingFences = mTraceTracker[layerId].pendingFences[bufferID];
        for (size_t i = 0; i < pendingFences.size(); ++i) {
            auto& pendingFence = pendingFences[i];

            nsecs_t signalTime = Fence::SIGNAL_TIME_INVALID;
            if (pendingFence.fence && pendingFence.fence->isValid()) {
                signalTime = pendingFence.fence->getSignalTime();
                if (signalTime == Fence::SIGNAL_TIME_PENDING) {
                    continue;
                }
            }

            if (signalTime != Fence::SIGNAL_TIME_INVALID &&
                systemTime() - signalTime < kFenceSignallingDeadline) {
                traceSpanLocked(ctx, layerId, bufferID, pendingFence.frameNumber, pendingFence.type,
                                pendingFence.startTime, signalTime);
            }

            pendingFences.erase(pendingFences.begin() + i);
            --i;
        }
    }
}

void FrameTracer::traceLocked(FrameTracerDataSource::TraceContext& ctx, int32_t layerId,
                              uint64_t bufferID, uint64_t frameNumber, nsecs_t timestamp,
                              FrameEvent::BufferEventType type, nsecs_t duration) {
    auto packet = ctx.NewTracePacket();
    packet->set_timestamp_clock_id(Clock::MONOTONIC);
    packet->set_timestamp(timestamp);
    auto* event = packet->set_graphics_frame_event()->set_buffer_event();
    event->set_buffer_id(static_cast<uint32_t>(bufferID));
    if (frameNumber != UNSPECIFIED_FRAME_NUMBER) {
        event->set_frame_number(frameNumber);
    }
    event->set_type(type);

    if (mTraceTracker.find(layerId) != mTraceTracker.end() &&
        !mTraceTracker[layerId].layerName.empty()) {
        const std::string& layerName = mTraceTracker[layerId].layerName;
        event->set_layer_name(layerName.c_str(), layerName.size());
    }

    if (duration > 0) {
        event->set_duration_ns(duration);
    }
}

void FrameTracer::traceSpanLocked(FrameTracerDataSource::TraceContext& ctx, int32_t layerId,
                                  uint64_t bufferID, uint64_t frameNumber,
                                  FrameEvent::BufferEventType type, nsecs_t startTime,
                                  nsecs_t endTime) {
    nsecs_t timestamp = endTime;
    nsecs_t duration = 0;
    if (startTime > 0 && startTime < endTime) {
        timestamp = startTime;
        duration = endTime - startTime;
    }
    traceLocked(ctx, layerId, bufferID, frameNumber, timestamp, type, duration);
}

void FrameTracer::onDestroy(int32_t layerId) {
    std::lock_guard<std::mutex> traceLock(mTraceMutex);
    mTraceTracker.erase(layerId);
}

std::string FrameTracer::miniDump() {
    std::string result = "FrameTracer miniDump:\n";
    std::lock_guard<std::mutex> lock(mTraceMutex);
    android::base::StringAppendF(&result, "Number of layers currently being traced is %zu\n",
                                 mTraceTracker.size());
    return result;
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
