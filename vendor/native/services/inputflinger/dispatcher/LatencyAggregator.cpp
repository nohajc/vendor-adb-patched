/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "LatencyAggregator"
#include "LatencyAggregator.h"

#include <inttypes.h>

#include <android-base/stringprintf.h>
#include <input/Input.h>
#include <log/log.h>
#include <server_configurable_flags/get_flags.h>

using android::base::StringPrintf;
using dist_proc::aggregation::KllQuantile;
using std::chrono_literals::operator""ms;

// Convert the provided nanoseconds into hundreds of microseconds.
// Use hundreds of microseconds (as opposed to microseconds) to preserve space.
static inline int64_t ns2hus(nsecs_t nanos) {
    return ns2us(nanos) / 100;
}

// The maximum number of events that we will store in the statistics. Any events that we will
// receive after we have reached this number will be ignored. We could also implement this by
// checking the actual size of the current data and making sure that we do not go over. However,
// the serialization process of sketches is too heavy (1 ms for all 14 sketches), and would be too
// much to do (even if infrequently).
// The value here has been determined empirically.
static constexpr size_t MAX_EVENTS_FOR_STATISTICS = 20000;

// Category (=namespace) name for the input settings that are applied at boot time
static const char* INPUT_NATIVE_BOOT = "input_native_boot";
// Feature flag name for the threshold of end-to-end touch latency that would trigger
// SlowEventReported atom to be pushed
static const char* SLOW_EVENT_MIN_REPORTING_LATENCY_MILLIS =
        "slow_event_min_reporting_latency_millis";
// Feature flag name for the minimum delay before reporting a slow event after having just reported
// a slow event. This helps limit the amount of data sent to the server
static const char* SLOW_EVENT_MIN_REPORTING_INTERVAL_MILLIS =
        "slow_event_min_reporting_interval_millis";

// If an event has end-to-end latency > 200 ms, it will get reported as a slow event.
std::chrono::milliseconds DEFAULT_SLOW_EVENT_MIN_REPORTING_LATENCY = 200ms;
// If we receive two slow events less than 1 min apart, we will only report 1 of them.
std::chrono::milliseconds DEFAULT_SLOW_EVENT_MIN_REPORTING_INTERVAL = 60000ms;

static std::chrono::milliseconds getSlowEventMinReportingLatency() {
    std::string millis = server_configurable_flags::
            GetServerConfigurableFlag(INPUT_NATIVE_BOOT, SLOW_EVENT_MIN_REPORTING_LATENCY_MILLIS,
                                      std::to_string(
                                              DEFAULT_SLOW_EVENT_MIN_REPORTING_LATENCY.count()));
    return std::chrono::milliseconds(std::stoi(millis));
}

static std::chrono::milliseconds getSlowEventMinReportingInterval() {
    std::string millis = server_configurable_flags::
            GetServerConfigurableFlag(INPUT_NATIVE_BOOT, SLOW_EVENT_MIN_REPORTING_INTERVAL_MILLIS,
                                      std::to_string(
                                              DEFAULT_SLOW_EVENT_MIN_REPORTING_INTERVAL.count()));
    return std::chrono::milliseconds(std::stoi(millis));
}

namespace android::inputdispatcher {

/**
 * Same as android::util::BytesField, but doesn't store raw pointers, and therefore deletes its
 * resources automatically.
 */
class SafeBytesField {
public:
    explicit SafeBytesField(dist_proc::aggregation::KllQuantile& quantile) {
        const zetasketch::android::AggregatorStateProto aggProto = quantile.SerializeToProto();
        mBuffer.resize(aggProto.ByteSizeLong());
        aggProto.SerializeToArray(mBuffer.data(), mBuffer.size());
    }
    android::util::BytesField getBytesField() {
        return android::util::BytesField(mBuffer.data(), mBuffer.size());
    }

private:
    std::vector<char> mBuffer;
};

LatencyAggregator::LatencyAggregator() {
    AStatsManager_setPullAtomCallback(android::util::INPUT_EVENT_LATENCY_SKETCH, nullptr,
                                      LatencyAggregator::pullAtomCallback, this);
    dist_proc::aggregation::KllQuantileOptions options;
    options.set_inv_eps(100); // Request precision of 1.0%, instead of default 0.1%
    for (size_t i = 0; i < SketchIndex::SIZE; i++) {
        mDownSketches[i] = KllQuantile::Create(options);
        mMoveSketches[i] = KllQuantile::Create(options);
    }
}

LatencyAggregator::~LatencyAggregator() {
    AStatsManager_clearPullAtomCallback(android::util::INPUT_EVENT_LATENCY_SKETCH);
}

AStatsManager_PullAtomCallbackReturn LatencyAggregator::pullAtomCallback(int32_t atomTag,
                                                                         AStatsEventList* data,
                                                                         void* cookie) {
    LatencyAggregator* pAggregator = reinterpret_cast<LatencyAggregator*>(cookie);
    if (pAggregator == nullptr) {
        LOG_ALWAYS_FATAL("pAggregator is null!");
    }
    return pAggregator->pullData(data);
}

void LatencyAggregator::processTimeline(const InputEventTimeline& timeline) {
    processStatistics(timeline);
    processSlowEvent(timeline);
}

void LatencyAggregator::processStatistics(const InputEventTimeline& timeline) {
    // Before we do any processing, check that we have not yet exceeded MAX_SIZE
    if (mNumSketchEventsProcessed >= MAX_EVENTS_FOR_STATISTICS) {
        return;
    }
    mNumSketchEventsProcessed++;

    std::array<std::unique_ptr<KllQuantile>, SketchIndex::SIZE>& sketches =
            timeline.isDown ? mDownSketches : mMoveSketches;

    // Process common ones first
    const nsecs_t eventToRead = timeline.readTime - timeline.eventTime;
    sketches[SketchIndex::EVENT_TO_READ]->Add(ns2hus(eventToRead));

    // Now process per-connection ones
    for (const auto& [connectionToken, connectionTimeline] : timeline.connectionTimelines) {
        if (!connectionTimeline.isComplete()) {
            continue;
        }
        const nsecs_t readToDeliver = connectionTimeline.deliveryTime - timeline.readTime;
        const nsecs_t deliverToConsume =
                connectionTimeline.consumeTime - connectionTimeline.deliveryTime;
        const nsecs_t consumeToFinish =
                connectionTimeline.finishTime - connectionTimeline.consumeTime;
        const nsecs_t gpuCompletedTime =
                connectionTimeline.graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME];
        const nsecs_t presentTime =
                connectionTimeline.graphicsTimeline[GraphicsTimeline::PRESENT_TIME];
        const nsecs_t consumeToGpuComplete = gpuCompletedTime - connectionTimeline.consumeTime;
        const nsecs_t gpuCompleteToPresent = presentTime - gpuCompletedTime;
        const nsecs_t endToEnd = presentTime - timeline.eventTime;

        sketches[SketchIndex::READ_TO_DELIVER]->Add(ns2hus(readToDeliver));
        sketches[SketchIndex::DELIVER_TO_CONSUME]->Add(ns2hus(deliverToConsume));
        sketches[SketchIndex::CONSUME_TO_FINISH]->Add(ns2hus(consumeToFinish));
        sketches[SketchIndex::CONSUME_TO_GPU_COMPLETE]->Add(ns2hus(consumeToGpuComplete));
        sketches[SketchIndex::GPU_COMPLETE_TO_PRESENT]->Add(ns2hus(gpuCompleteToPresent));
        sketches[SketchIndex::END_TO_END]->Add(ns2hus(endToEnd));
    }
}

AStatsManager_PullAtomCallbackReturn LatencyAggregator::pullData(AStatsEventList* data) {
    std::array<std::unique_ptr<SafeBytesField>, SketchIndex::SIZE> serializedDownData;
    std::array<std::unique_ptr<SafeBytesField>, SketchIndex::SIZE> serializedMoveData;
    for (size_t i = 0; i < SketchIndex::SIZE; i++) {
        serializedDownData[i] = std::make_unique<SafeBytesField>(*mDownSketches[i]);
        serializedMoveData[i] = std::make_unique<SafeBytesField>(*mMoveSketches[i]);
    }
    android::util::
            addAStatsEvent(data, android::util::INPUT_EVENT_LATENCY_SKETCH,
                           // DOWN sketches
                           serializedDownData[SketchIndex::EVENT_TO_READ]->getBytesField(),
                           serializedDownData[SketchIndex::READ_TO_DELIVER]->getBytesField(),
                           serializedDownData[SketchIndex::DELIVER_TO_CONSUME]->getBytesField(),
                           serializedDownData[SketchIndex::CONSUME_TO_FINISH]->getBytesField(),
                           serializedDownData[SketchIndex::CONSUME_TO_GPU_COMPLETE]
                                   ->getBytesField(),
                           serializedDownData[SketchIndex::GPU_COMPLETE_TO_PRESENT]
                                   ->getBytesField(),
                           serializedDownData[SketchIndex::END_TO_END]->getBytesField(),
                           // MOVE sketches
                           serializedMoveData[SketchIndex::EVENT_TO_READ]->getBytesField(),
                           serializedMoveData[SketchIndex::READ_TO_DELIVER]->getBytesField(),
                           serializedMoveData[SketchIndex::DELIVER_TO_CONSUME]->getBytesField(),
                           serializedMoveData[SketchIndex::CONSUME_TO_FINISH]->getBytesField(),
                           serializedMoveData[SketchIndex::CONSUME_TO_GPU_COMPLETE]
                                   ->getBytesField(),
                           serializedMoveData[SketchIndex::GPU_COMPLETE_TO_PRESENT]
                                   ->getBytesField(),
                           serializedMoveData[SketchIndex::END_TO_END]->getBytesField());

    for (size_t i = 0; i < SketchIndex::SIZE; i++) {
        mDownSketches[i]->Reset();
        mMoveSketches[i]->Reset();
    }
    // Start new aggregations
    mNumSketchEventsProcessed = 0;
    return AStatsManager_PULL_SUCCESS;
}

void LatencyAggregator::processSlowEvent(const InputEventTimeline& timeline) {
    static const std::chrono::duration sSlowEventThreshold = getSlowEventMinReportingLatency();
    static const std::chrono::duration sSlowEventReportingInterval =
            getSlowEventMinReportingInterval();
    for (const auto& [token, connectionTimeline] : timeline.connectionTimelines) {
        if (!connectionTimeline.isComplete()) {
            continue;
        }
        mNumEventsSinceLastSlowEventReport++;
        const nsecs_t presentTime =
                connectionTimeline.graphicsTimeline[GraphicsTimeline::PRESENT_TIME];
        const std::chrono::nanoseconds endToEndLatency =
                std::chrono::nanoseconds(presentTime - timeline.eventTime);
        if (endToEndLatency < sSlowEventThreshold) {
            continue;
        }
        // This is a slow event. Before we report it, check if we are reporting too often
        const std::chrono::duration elapsedSinceLastReport =
                std::chrono::nanoseconds(timeline.eventTime - mLastSlowEventTime);
        if (elapsedSinceLastReport < sSlowEventReportingInterval) {
            mNumSkippedSlowEvents++;
            continue;
        }

        const nsecs_t eventToRead = timeline.readTime - timeline.eventTime;
        const nsecs_t readToDeliver = connectionTimeline.deliveryTime - timeline.readTime;
        const nsecs_t deliverToConsume =
                connectionTimeline.consumeTime - connectionTimeline.deliveryTime;
        const nsecs_t consumeToFinish =
                connectionTimeline.finishTime - connectionTimeline.consumeTime;
        const nsecs_t gpuCompletedTime =
                connectionTimeline.graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME];
        const nsecs_t consumeToGpuComplete = gpuCompletedTime - connectionTimeline.consumeTime;
        const nsecs_t gpuCompleteToPresent = presentTime - gpuCompletedTime;

        android::util::stats_write(android::util::SLOW_INPUT_EVENT_REPORTED, timeline.isDown,
                                   static_cast<int32_t>(ns2us(eventToRead)),
                                   static_cast<int32_t>(ns2us(readToDeliver)),
                                   static_cast<int32_t>(ns2us(deliverToConsume)),
                                   static_cast<int32_t>(ns2us(consumeToFinish)),
                                   static_cast<int32_t>(ns2us(consumeToGpuComplete)),
                                   static_cast<int32_t>(ns2us(gpuCompleteToPresent)),
                                   static_cast<int32_t>(ns2us(endToEndLatency.count())),
                                   static_cast<int32_t>(mNumEventsSinceLastSlowEventReport),
                                   static_cast<int32_t>(mNumSkippedSlowEvents));
        mNumEventsSinceLastSlowEventReport = 0;
        mNumSkippedSlowEvents = 0;
        mLastSlowEventTime = timeline.readTime;
    }
}

std::string LatencyAggregator::dump(const char* prefix) {
    std::string sketchDump = StringPrintf("%s  Sketches:\n", prefix);
    for (size_t i = 0; i < SketchIndex::SIZE; i++) {
        const int64_t numDown = mDownSketches[i]->num_values();
        SafeBytesField downBytesField(*mDownSketches[i]);
        const float downBytesKb = downBytesField.getBytesField().arg_length * 1E-3;
        const int64_t numMove = mMoveSketches[i]->num_values();
        SafeBytesField moveBytesField(*mMoveSketches[i]);
        const float moveBytesKb = moveBytesField.getBytesField().arg_length * 1E-3;
        sketchDump +=
                StringPrintf("%s    mDownSketches[%zu]->num_values = %" PRId64 " size = %.1fKB"
                             " mMoveSketches[%zu]->num_values = %" PRId64 " size = %.1fKB\n",
                             prefix, i, numDown, downBytesKb, i, numMove, moveBytesKb);
    }

    return StringPrintf("%sLatencyAggregator:\n", prefix) + sketchDump +
            StringPrintf("%s  mNumSketchEventsProcessed=%zu\n", prefix, mNumSketchEventsProcessed) +
            StringPrintf("%s  mLastSlowEventTime=%" PRId64 "\n", prefix, mLastSlowEventTime) +
            StringPrintf("%s  mNumEventsSinceLastSlowEventReport = %zu\n", prefix,
                         mNumEventsSinceLastSlowEventReport) +
            StringPrintf("%s  mNumSkippedSlowEvents = %zu\n", prefix, mNumSkippedSlowEvents);
}

} // namespace android::inputdispatcher
