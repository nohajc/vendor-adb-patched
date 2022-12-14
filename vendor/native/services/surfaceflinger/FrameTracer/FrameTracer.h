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

#include <perfetto/trace/android/graphics_frame_event.pbzero.h>
#include <perfetto/tracing.h>
#include <ui/FenceTime.h>

#include <mutex>
#include <unordered_map>

namespace android {

class FrameTracer {
public:
    class FrameTracerDataSource : public perfetto::DataSource<FrameTracerDataSource> {
        virtual void OnSetup(const SetupArgs&) override{};
        virtual void OnStart(const StartArgs&) override{};
        virtual void OnStop(const StopArgs&) override{};
    };

    static const uint64_t UNSPECIFIED_FRAME_NUMBER = std::numeric_limits<uint64_t>::max();

    using FrameEvent = perfetto::protos::pbzero::GraphicsFrameEvent;

    ~FrameTracer() = default;

    // Sets up the perfetto tracing backend and data source.
    void initialize();
    // Registers the data source with the perfetto backend. Called as part of initialize()
    // and should not be called manually outside of tests. Public to allow for substituting a
    // perfetto::kInProcessBackend in tests.
    void registerDataSource();
    // Starts tracking a new layer for tracing. Needs to be called once before traceTimestamp() or
    // traceFence() for each layer.
    void traceNewLayer(int32_t layerId, const std::string& layerName);
    // Creates a trace point at the timestamp provided.
    void traceTimestamp(int32_t layerId, uint64_t bufferID, uint64_t frameNumber, nsecs_t timestamp,
                        FrameEvent::BufferEventType type, nsecs_t duration = 0);
    // Creates a trace point after the provided fence has been signalled. If a startTime is provided
    // the trace will have be timestamped from startTime until fence signalling time. If no
    // startTime is provided, a durationless trace point will be created timestamped at fence
    // signalling time. If the fence hasn't signalled yet, the trace point will be created the next
    // time after signalling a trace call for this buffer occurs.
    void traceFence(int32_t layerId, uint64_t bufferID, uint64_t frameNumber,
                    const std::shared_ptr<FenceTime>& fence, FrameEvent::BufferEventType type,
                    nsecs_t startTime = 0);

    // Takes care of cleanup when a layer is destroyed.
    void onDestroy(int32_t layerId);

    std::string miniDump();

    static constexpr char kFrameTracerDataSource[] = "android.surfaceflinger.frame";

    // The maximum amount of time a fence has to signal before it is discarded.
    // Used to avoid fences from previous traces generating new trace points in later ones.
    // Public for testing.
    static constexpr nsecs_t kFenceSignallingDeadline = 60'000'000'000; // 60 seconds

private:
    struct PendingFence {
        uint64_t frameNumber;
        FrameEvent::BufferEventType type;
        std::shared_ptr<FenceTime> fence;
        nsecs_t startTime;
    };

    struct TraceRecord {
        std::string layerName;
        using BufferID = uint64_t;
        std::unordered_map<BufferID, std::vector<PendingFence>> pendingFences;
    };

    // Checks if any pending fences for a layer and buffer have signalled and, if they have, creates
    // trace points for them.
    void tracePendingFencesLocked(FrameTracerDataSource::TraceContext& ctx, int32_t layerId,
                                  uint64_t bufferID);
    // Creates a trace point by translating a start time and an end time to a timestamp and
    // duration. If startTime is later than end time it sets end time as the timestamp and the
    // duration to 0. Used by traceFence().
    void traceSpanLocked(FrameTracerDataSource::TraceContext& ctx, int32_t layerId,
                         uint64_t bufferID, uint64_t frameNumber, FrameEvent::BufferEventType type,
                         nsecs_t startTime, nsecs_t endTime);
    void traceLocked(FrameTracerDataSource::TraceContext& ctx, int32_t layerId, uint64_t bufferID,
                     uint64_t frameNumber, nsecs_t timestamp, FrameEvent::BufferEventType type,
                     nsecs_t duration = 0);

    std::mutex mTraceMutex;
    std::unordered_map<int32_t, TraceRecord> mTraceTracker;
    std::once_flag mInitializationFlag;
};

} // namespace android
