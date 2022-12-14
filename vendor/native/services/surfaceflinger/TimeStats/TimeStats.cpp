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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#undef LOG_TAG
#define LOG_TAG "TimeStats"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "TimeStats.h"

#include <android-base/stringprintf.h>
#include <android/util/ProtoOutputStream.h>
#include <log/log.h>
#include <utils/String8.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <algorithm>
#include <chrono>

namespace android {

namespace impl {

AStatsManager_PullAtomCallbackReturn TimeStats::pullAtomCallback(int32_t atom_tag,
                                                                 AStatsEventList* data,
                                                                 void* cookie) {
    impl::TimeStats* timeStats = reinterpret_cast<impl::TimeStats*>(cookie);
    AStatsManager_PullAtomCallbackReturn result = AStatsManager_PULL_SKIP;
    if (atom_tag == android::util::SURFACEFLINGER_STATS_GLOBAL_INFO) {
        result = timeStats->populateGlobalAtom(data);
    } else if (atom_tag == android::util::SURFACEFLINGER_STATS_LAYER_INFO) {
        result = timeStats->populateLayerAtom(data);
    }

    // Enable timestats now. The first full pull for a given build is expected to
    // have empty or very little stats, as stats are first enabled after the
    // first pull is completed for either the global or layer stats.
    timeStats->enable();
    return result;
}

namespace {
// Histograms align with the order of fields in SurfaceflingerStatsLayerInfo.
const std::array<std::string, 6> kHistogramNames = {
        "present2present", "post2present",    "acquire2present",
        "latch2present",   "desired2present", "post2acquire",
};

std::string histogramToProtoByteString(const std::unordered_map<int32_t, int32_t>& histogram,
                                       size_t maxPulledHistogramBuckets) {
    auto buckets = std::vector<std::pair<int32_t, int32_t>>(histogram.begin(), histogram.end());
    std::sort(buckets.begin(), buckets.end(),
              [](std::pair<int32_t, int32_t>& left, std::pair<int32_t, int32_t>& right) {
                  return left.second > right.second;
              });

    util::ProtoOutputStream proto;
    int histogramSize = 0;
    for (const auto& bucket : buckets) {
        if (++histogramSize > maxPulledHistogramBuckets) {
            break;
        }
        proto.write(android::util::FIELD_TYPE_INT32 | android::util::FIELD_COUNT_REPEATED |
                            1 /* field id */,
                    (int32_t)bucket.first);
        proto.write(android::util::FIELD_TYPE_INT64 | android::util::FIELD_COUNT_REPEATED |
                            2 /* field id */,
                    (int64_t)bucket.second);
    }

    std::string byteString;
    proto.serializeToString(&byteString);
    return byteString;
}
} // namespace

AStatsManager_PullAtomCallbackReturn TimeStats::populateGlobalAtom(AStatsEventList* data) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (mTimeStats.statsStart == 0) {
        return AStatsManager_PULL_SKIP;
    }
    flushPowerTimeLocked();

    AStatsEvent* event = mStatsDelegate->addStatsEventToPullData(data);
    mStatsDelegate->statsEventSetAtomId(event, android::util::SURFACEFLINGER_STATS_GLOBAL_INFO);
    mStatsDelegate->statsEventWriteInt64(event, mTimeStats.totalFrames);
    mStatsDelegate->statsEventWriteInt64(event, mTimeStats.missedFrames);
    mStatsDelegate->statsEventWriteInt64(event, mTimeStats.clientCompositionFrames);
    mStatsDelegate->statsEventWriteInt64(event, mTimeStats.displayOnTime);
    mStatsDelegate->statsEventWriteInt64(event, mTimeStats.presentToPresent.totalTime());
    mStatsDelegate->statsEventWriteInt32(event, mTimeStats.displayEventConnectionsCount);
    std::string frameDurationBytes =
            histogramToProtoByteString(mTimeStats.frameDuration.hist, mMaxPulledHistogramBuckets);
    mStatsDelegate->statsEventWriteByteArray(event, (const uint8_t*)frameDurationBytes.c_str(),
                                             frameDurationBytes.size());
    std::string renderEngineTimingBytes =
            histogramToProtoByteString(mTimeStats.renderEngineTiming.hist,
                                       mMaxPulledHistogramBuckets);
    mStatsDelegate->statsEventWriteByteArray(event, (const uint8_t*)renderEngineTimingBytes.c_str(),
                                             renderEngineTimingBytes.size());
    mStatsDelegate->statsEventBuild(event);
    clearGlobalLocked();

    return AStatsManager_PULL_SUCCESS;
}

AStatsManager_PullAtomCallbackReturn TimeStats::populateLayerAtom(AStatsEventList* data) {
    std::lock_guard<std::mutex> lock(mMutex);

    std::vector<TimeStatsHelper::TimeStatsLayer const*> dumpStats;
    for (const auto& ele : mTimeStats.stats) {
        dumpStats.push_back(&ele.second);
    }

    std::sort(dumpStats.begin(), dumpStats.end(),
              [](TimeStatsHelper::TimeStatsLayer const* l,
                 TimeStatsHelper::TimeStatsLayer const* r) {
                  return l->totalFrames > r->totalFrames;
              });

    if (mMaxPulledLayers < dumpStats.size()) {
        dumpStats.resize(mMaxPulledLayers);
    }

    for (const auto& layer : dumpStats) {
        AStatsEvent* event = mStatsDelegate->addStatsEventToPullData(data);
        mStatsDelegate->statsEventSetAtomId(event, android::util::SURFACEFLINGER_STATS_LAYER_INFO);
        mStatsDelegate->statsEventWriteString8(event, layer->layerName.c_str());
        mStatsDelegate->statsEventWriteInt64(event, layer->totalFrames);
        mStatsDelegate->statsEventWriteInt64(event, layer->droppedFrames);

        for (const auto& name : kHistogramNames) {
            const auto& histogram = layer->deltas.find(name);
            if (histogram == layer->deltas.cend()) {
                mStatsDelegate->statsEventWriteByteArray(event, nullptr, 0);
            } else {
                std::string bytes = histogramToProtoByteString(histogram->second.hist,
                                                               mMaxPulledHistogramBuckets);
                mStatsDelegate->statsEventWriteByteArray(event, (const uint8_t*)bytes.c_str(),
                                                         bytes.size());
            }
        }

        mStatsDelegate->statsEventWriteInt64(event, layer->lateAcquireFrames);
        mStatsDelegate->statsEventWriteInt64(event, layer->badDesiredPresentFrames);

        mStatsDelegate->statsEventBuild(event);
    }
    clearLayersLocked();

    return AStatsManager_PULL_SUCCESS;
}

TimeStats::TimeStats() : TimeStats(nullptr, std::nullopt, std::nullopt) {}

TimeStats::TimeStats(std::unique_ptr<StatsEventDelegate> statsDelegate,
                     std::optional<size_t> maxPulledLayers,
                     std::optional<size_t> maxPulledHistogramBuckets) {
    if (statsDelegate != nullptr) {
        mStatsDelegate = std::move(statsDelegate);
    }

    if (maxPulledLayers) {
        mMaxPulledLayers = *maxPulledLayers;
    }

    if (maxPulledHistogramBuckets) {
        mMaxPulledHistogramBuckets = *maxPulledHistogramBuckets;
    }
}

TimeStats::~TimeStats() {
    std::lock_guard<std::mutex> lock(mMutex);
    mStatsDelegate->clearStatsPullAtomCallback(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO);
    mStatsDelegate->clearStatsPullAtomCallback(android::util::SURFACEFLINGER_STATS_LAYER_INFO);
}

void TimeStats::onBootFinished() {
    std::lock_guard<std::mutex> lock(mMutex);
    mStatsDelegate->setStatsPullAtomCallback(android::util::SURFACEFLINGER_STATS_GLOBAL_INFO,
                                             nullptr, TimeStats::pullAtomCallback, this);
    mStatsDelegate->setStatsPullAtomCallback(android::util::SURFACEFLINGER_STATS_LAYER_INFO,
                                             nullptr, TimeStats::pullAtomCallback, this);
}

void TimeStats::parseArgs(bool asProto, const Vector<String16>& args, std::string& result) {
    ATRACE_CALL();

    std::unordered_map<std::string, int32_t> argsMap;
    for (size_t index = 0; index < args.size(); ++index) {
        argsMap[std::string(String8(args[index]).c_str())] = index;
    }

    if (argsMap.count("-disable")) {
        disable();
    }

    if (argsMap.count("-dump")) {
        std::optional<uint32_t> maxLayers = std::nullopt;
        auto iter = argsMap.find("-maxlayers");
        if (iter != argsMap.end() && iter->second + 1 < static_cast<int32_t>(args.size())) {
            int64_t value = strtol(String8(args[iter->second + 1]).c_str(), nullptr, 10);
            value = std::clamp(value, int64_t(0), int64_t(UINT32_MAX));
            maxLayers = static_cast<uint32_t>(value);
        }

        dump(asProto, maxLayers, result);
    }

    if (argsMap.count("-clear")) {
        clearAll();
    }

    if (argsMap.count("-enable")) {
        enable();
    }
}

std::string TimeStats::miniDump() {
    ATRACE_CALL();

    std::string result = "TimeStats miniDump:\n";
    std::lock_guard<std::mutex> lock(mMutex);
    android::base::StringAppendF(&result, "Number of layers currently being tracked is %zu\n",
                                 mTimeStatsTracker.size());
    android::base::StringAppendF(&result, "Number of layers in the stats pool is %zu\n",
                                 mTimeStats.stats.size());
    return result;
}

void TimeStats::incrementTotalFrames() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.totalFrames++;
}

void TimeStats::incrementMissedFrames() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.missedFrames++;
}

void TimeStats::incrementClientCompositionFrames() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.clientCompositionFrames++;
}

void TimeStats::incrementClientCompositionReusedFrames() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.clientCompositionReusedFrames++;
}

void TimeStats::incrementRefreshRateSwitches() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.refreshRateSwitches++;
}

void TimeStats::incrementCompositionStrategyChanges() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.compositionStrategyChanges++;
}

void TimeStats::recordDisplayEventConnectionCount(int32_t count) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.displayEventConnectionsCount =
            std::max(mTimeStats.displayEventConnectionsCount, count);
}

static int32_t msBetween(nsecs_t start, nsecs_t end) {
    int64_t delta = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::nanoseconds(end - start))
                            .count();
    delta = std::clamp(delta, int64_t(INT32_MIN), int64_t(INT32_MAX));
    return static_cast<int32_t>(delta);
}

void TimeStats::recordFrameDuration(nsecs_t startTime, nsecs_t endTime) {
    if (!mEnabled.load()) return;

    std::lock_guard<std::mutex> lock(mMutex);
    if (mPowerTime.powerMode == PowerMode::ON) {
        mTimeStats.frameDuration.insert(msBetween(startTime, endTime));
    }
}

void TimeStats::recordRenderEngineDuration(nsecs_t startTime, nsecs_t endTime) {
    if (!mEnabled.load()) return;

    std::lock_guard<std::mutex> lock(mMutex);
    if (mGlobalRecord.renderEngineDurations.size() == MAX_NUM_TIME_RECORDS) {
        ALOGE("RenderEngineTimes are already at its maximum size[%zu]", MAX_NUM_TIME_RECORDS);
        mGlobalRecord.renderEngineDurations.pop_front();
    }
    mGlobalRecord.renderEngineDurations.push_back({startTime, endTime});
}

void TimeStats::recordRenderEngineDuration(nsecs_t startTime,
                                           const std::shared_ptr<FenceTime>& endTime) {
    if (!mEnabled.load()) return;

    std::lock_guard<std::mutex> lock(mMutex);
    if (mGlobalRecord.renderEngineDurations.size() == MAX_NUM_TIME_RECORDS) {
        ALOGE("RenderEngineTimes are already at its maximum size[%zu]", MAX_NUM_TIME_RECORDS);
        mGlobalRecord.renderEngineDurations.pop_front();
    }
    mGlobalRecord.renderEngineDurations.push_back({startTime, endTime});
}

bool TimeStats::recordReadyLocked(int32_t layerId, TimeRecord* timeRecord) {
    if (!timeRecord->ready) {
        ALOGV("[%d]-[%" PRIu64 "]-presentFence is still not received", layerId,
              timeRecord->frameTime.frameNumber);
        return false;
    }

    if (timeRecord->acquireFence != nullptr) {
        if (timeRecord->acquireFence->getSignalTime() == Fence::SIGNAL_TIME_PENDING) {
            return false;
        }
        if (timeRecord->acquireFence->getSignalTime() != Fence::SIGNAL_TIME_INVALID) {
            timeRecord->frameTime.acquireTime = timeRecord->acquireFence->getSignalTime();
            timeRecord->acquireFence = nullptr;
        } else {
            ALOGV("[%d]-[%" PRIu64 "]-acquireFence signal time is invalid", layerId,
                  timeRecord->frameTime.frameNumber);
        }
    }

    if (timeRecord->presentFence != nullptr) {
        if (timeRecord->presentFence->getSignalTime() == Fence::SIGNAL_TIME_PENDING) {
            return false;
        }
        if (timeRecord->presentFence->getSignalTime() != Fence::SIGNAL_TIME_INVALID) {
            timeRecord->frameTime.presentTime = timeRecord->presentFence->getSignalTime();
            timeRecord->presentFence = nullptr;
        } else {
            ALOGV("[%d]-[%" PRIu64 "]-presentFence signal time invalid", layerId,
                  timeRecord->frameTime.frameNumber);
        }
    }

    return true;
}

void TimeStats::flushAvailableRecordsToStatsLocked(int32_t layerId) {
    ATRACE_CALL();

    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    TimeRecord& prevTimeRecord = layerRecord.prevTimeRecord;
    std::deque<TimeRecord>& timeRecords = layerRecord.timeRecords;
    while (!timeRecords.empty()) {
        if (!recordReadyLocked(layerId, &timeRecords[0])) break;
        ALOGV("[%d]-[%" PRIu64 "]-presentFenceTime[%" PRId64 "]", layerId,
              timeRecords[0].frameTime.frameNumber, timeRecords[0].frameTime.presentTime);

        if (prevTimeRecord.ready) {
            const std::string& layerName = layerRecord.layerName;
            if (!mTimeStats.stats.count(layerName)) {
                mTimeStats.stats[layerName].layerName = layerName;
            }
            TimeStatsHelper::TimeStatsLayer& timeStatsLayer = mTimeStats.stats[layerName];
            timeStatsLayer.totalFrames++;
            timeStatsLayer.droppedFrames += layerRecord.droppedFrames;
            timeStatsLayer.lateAcquireFrames += layerRecord.lateAcquireFrames;
            timeStatsLayer.badDesiredPresentFrames += layerRecord.badDesiredPresentFrames;

            layerRecord.droppedFrames = 0;
            layerRecord.lateAcquireFrames = 0;
            layerRecord.badDesiredPresentFrames = 0;

            const int32_t postToAcquireMs = msBetween(timeRecords[0].frameTime.postTime,
                                                      timeRecords[0].frameTime.acquireTime);
            ALOGV("[%d]-[%" PRIu64 "]-post2acquire[%d]", layerId,
                  timeRecords[0].frameTime.frameNumber, postToAcquireMs);
            timeStatsLayer.deltas["post2acquire"].insert(postToAcquireMs);

            const int32_t postToPresentMs = msBetween(timeRecords[0].frameTime.postTime,
                                                      timeRecords[0].frameTime.presentTime);
            ALOGV("[%d]-[%" PRIu64 "]-post2present[%d]", layerId,
                  timeRecords[0].frameTime.frameNumber, postToPresentMs);
            timeStatsLayer.deltas["post2present"].insert(postToPresentMs);

            const int32_t acquireToPresentMs = msBetween(timeRecords[0].frameTime.acquireTime,
                                                         timeRecords[0].frameTime.presentTime);
            ALOGV("[%d]-[%" PRIu64 "]-acquire2present[%d]", layerId,
                  timeRecords[0].frameTime.frameNumber, acquireToPresentMs);
            timeStatsLayer.deltas["acquire2present"].insert(acquireToPresentMs);

            const int32_t latchToPresentMs = msBetween(timeRecords[0].frameTime.latchTime,
                                                       timeRecords[0].frameTime.presentTime);
            ALOGV("[%d]-[%" PRIu64 "]-latch2present[%d]", layerId,
                  timeRecords[0].frameTime.frameNumber, latchToPresentMs);
            timeStatsLayer.deltas["latch2present"].insert(latchToPresentMs);

            const int32_t desiredToPresentMs = msBetween(timeRecords[0].frameTime.desiredTime,
                                                         timeRecords[0].frameTime.presentTime);
            ALOGV("[%d]-[%" PRIu64 "]-desired2present[%d]", layerId,
                  timeRecords[0].frameTime.frameNumber, desiredToPresentMs);
            timeStatsLayer.deltas["desired2present"].insert(desiredToPresentMs);

            const int32_t presentToPresentMs = msBetween(prevTimeRecord.frameTime.presentTime,
                                                         timeRecords[0].frameTime.presentTime);
            ALOGV("[%d]-[%" PRIu64 "]-present2present[%d]", layerId,
                  timeRecords[0].frameTime.frameNumber, presentToPresentMs);
            timeStatsLayer.deltas["present2present"].insert(presentToPresentMs);
        }
        prevTimeRecord = timeRecords[0];
        timeRecords.pop_front();
        layerRecord.waitData--;
    }
}

static constexpr const char* kPopupWindowPrefix = "PopupWindow";
static const size_t kMinLenLayerName = std::strlen(kPopupWindowPrefix);

// Avoid tracking the "PopupWindow:<random hash>#<number>" layers
static bool layerNameIsValid(const std::string& layerName) {
    return layerName.length() >= kMinLenLayerName &&
            layerName.compare(0, kMinLenLayerName, kPopupWindowPrefix) != 0;
}

void TimeStats::setPostTime(int32_t layerId, uint64_t frameNumber, const std::string& layerName,
                            nsecs_t postTime) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-[%s]-PostTime[%" PRId64 "]", layerId, frameNumber, layerName.c_str(),
          postTime);

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStats.stats.count(layerName) && mTimeStats.stats.size() >= MAX_NUM_LAYER_STATS) {
        return;
    }
    if (!mTimeStatsTracker.count(layerId) && mTimeStatsTracker.size() < MAX_NUM_LAYER_RECORDS &&
        layerNameIsValid(layerName)) {
        mTimeStatsTracker[layerId].layerName = layerName;
    }
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    if (layerRecord.timeRecords.size() == MAX_NUM_TIME_RECORDS) {
        ALOGE("[%d]-[%s]-timeRecords is at its maximum size[%zu]. Ignore this when unittesting.",
              layerId, layerRecord.layerName.c_str(), MAX_NUM_TIME_RECORDS);
        mTimeStatsTracker.erase(layerId);
        return;
    }
    // For most media content, the acquireFence is invalid because the buffer is
    // ready at the queueBuffer stage. In this case, acquireTime should be given
    // a default value as postTime.
    TimeRecord timeRecord = {
            .frameTime =
                    {
                            .frameNumber = frameNumber,
                            .postTime = postTime,
                            .latchTime = postTime,
                            .acquireTime = postTime,
                            .desiredTime = postTime,
                    },
    };
    layerRecord.timeRecords.push_back(timeRecord);
    if (layerRecord.waitData < 0 ||
        layerRecord.waitData >= static_cast<int32_t>(layerRecord.timeRecords.size()))
        layerRecord.waitData = layerRecord.timeRecords.size() - 1;
}

void TimeStats::setLatchTime(int32_t layerId, uint64_t frameNumber, nsecs_t latchTime) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-LatchTime[%" PRId64 "]", layerId, frameNumber, latchTime);

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    if (layerRecord.waitData < 0 ||
        layerRecord.waitData >= static_cast<int32_t>(layerRecord.timeRecords.size()))
        return;
    TimeRecord& timeRecord = layerRecord.timeRecords[layerRecord.waitData];
    if (timeRecord.frameTime.frameNumber == frameNumber) {
        timeRecord.frameTime.latchTime = latchTime;
    }
}

void TimeStats::incrementLatchSkipped(int32_t layerId, LatchSkipReason reason) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-LatchSkipped-Reason[%d]", layerId,
          static_cast<std::underlying_type<LatchSkipReason>::type>(reason));

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];

    switch (reason) {
        case LatchSkipReason::LateAcquire:
            layerRecord.lateAcquireFrames++;
            break;
    }
}

void TimeStats::incrementBadDesiredPresent(int32_t layerId) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-BadDesiredPresent", layerId);

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    layerRecord.badDesiredPresentFrames++;
}

void TimeStats::setDesiredTime(int32_t layerId, uint64_t frameNumber, nsecs_t desiredTime) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-DesiredTime[%" PRId64 "]", layerId, frameNumber, desiredTime);

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    if (layerRecord.waitData < 0 ||
        layerRecord.waitData >= static_cast<int32_t>(layerRecord.timeRecords.size()))
        return;
    TimeRecord& timeRecord = layerRecord.timeRecords[layerRecord.waitData];
    if (timeRecord.frameTime.frameNumber == frameNumber) {
        timeRecord.frameTime.desiredTime = desiredTime;
    }
}

void TimeStats::setAcquireTime(int32_t layerId, uint64_t frameNumber, nsecs_t acquireTime) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-AcquireTime[%" PRId64 "]", layerId, frameNumber, acquireTime);

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    if (layerRecord.waitData < 0 ||
        layerRecord.waitData >= static_cast<int32_t>(layerRecord.timeRecords.size()))
        return;
    TimeRecord& timeRecord = layerRecord.timeRecords[layerRecord.waitData];
    if (timeRecord.frameTime.frameNumber == frameNumber) {
        timeRecord.frameTime.acquireTime = acquireTime;
    }
}

void TimeStats::setAcquireFence(int32_t layerId, uint64_t frameNumber,
                                const std::shared_ptr<FenceTime>& acquireFence) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-AcquireFenceTime[%" PRId64 "]", layerId, frameNumber,
          acquireFence->getSignalTime());

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    if (layerRecord.waitData < 0 ||
        layerRecord.waitData >= static_cast<int32_t>(layerRecord.timeRecords.size()))
        return;
    TimeRecord& timeRecord = layerRecord.timeRecords[layerRecord.waitData];
    if (timeRecord.frameTime.frameNumber == frameNumber) {
        timeRecord.acquireFence = acquireFence;
    }
}

void TimeStats::setPresentTime(int32_t layerId, uint64_t frameNumber, nsecs_t presentTime) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-PresentTime[%" PRId64 "]", layerId, frameNumber, presentTime);

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    if (layerRecord.waitData < 0 ||
        layerRecord.waitData >= static_cast<int32_t>(layerRecord.timeRecords.size()))
        return;
    TimeRecord& timeRecord = layerRecord.timeRecords[layerRecord.waitData];
    if (timeRecord.frameTime.frameNumber == frameNumber) {
        timeRecord.frameTime.presentTime = presentTime;
        timeRecord.ready = true;
        layerRecord.waitData++;
    }

    flushAvailableRecordsToStatsLocked(layerId);
}

void TimeStats::setPresentFence(int32_t layerId, uint64_t frameNumber,
                                const std::shared_ptr<FenceTime>& presentFence) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-PresentFenceTime[%" PRId64 "]", layerId, frameNumber,
          presentFence->getSignalTime());

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    if (layerRecord.waitData < 0 ||
        layerRecord.waitData >= static_cast<int32_t>(layerRecord.timeRecords.size()))
        return;
    TimeRecord& timeRecord = layerRecord.timeRecords[layerRecord.waitData];
    if (timeRecord.frameTime.frameNumber == frameNumber) {
        timeRecord.presentFence = presentFence;
        timeRecord.ready = true;
        layerRecord.waitData++;
    }

    flushAvailableRecordsToStatsLocked(layerId);
}

void TimeStats::onDestroy(int32_t layerId) {
    ATRACE_CALL();
    ALOGV("[%d]-onDestroy", layerId);
    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStatsTracker.erase(layerId);
}

void TimeStats::removeTimeRecord(int32_t layerId, uint64_t frameNumber) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-removeTimeRecord", layerId, frameNumber);

    std::lock_guard<std::mutex> lock(mMutex);
    if (!mTimeStatsTracker.count(layerId)) return;
    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    size_t removeAt = 0;
    for (const TimeRecord& record : layerRecord.timeRecords) {
        if (record.frameTime.frameNumber == frameNumber) break;
        removeAt++;
    }
    if (removeAt == layerRecord.timeRecords.size()) return;
    layerRecord.timeRecords.erase(layerRecord.timeRecords.begin() + removeAt);
    if (layerRecord.waitData > static_cast<int32_t>(removeAt)) {
        layerRecord.waitData--;
    }
    layerRecord.droppedFrames++;
}

void TimeStats::flushPowerTimeLocked() {
    if (!mEnabled.load()) return;

    nsecs_t curTime = systemTime();
    // elapsedTime is in milliseconds.
    int64_t elapsedTime = (curTime - mPowerTime.prevTime) / 1000000;

    switch (mPowerTime.powerMode) {
        case PowerMode::ON:
            mTimeStats.displayOnTime += elapsedTime;
            break;
        case PowerMode::OFF:
        case PowerMode::DOZE:
        case PowerMode::DOZE_SUSPEND:
        case PowerMode::ON_SUSPEND:
        default:
            break;
    }

    mPowerTime.prevTime = curTime;
}

void TimeStats::setPowerMode(PowerMode powerMode) {
    if (!mEnabled.load()) {
        std::lock_guard<std::mutex> lock(mMutex);
        mPowerTime.powerMode = powerMode;
        return;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    if (powerMode == mPowerTime.powerMode) return;

    flushPowerTimeLocked();
    mPowerTime.powerMode = powerMode;
}

void TimeStats::recordRefreshRate(uint32_t fps, nsecs_t duration) {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mTimeStats.refreshRateStats.count(fps)) {
        mTimeStats.refreshRateStats[fps] += duration;
    } else {
        mTimeStats.refreshRateStats.insert({fps, duration});
    }
}

void TimeStats::flushAvailableGlobalRecordsToStatsLocked() {
    ATRACE_CALL();

    while (!mGlobalRecord.presentFences.empty()) {
        const nsecs_t curPresentTime = mGlobalRecord.presentFences.front()->getSignalTime();
        if (curPresentTime == Fence::SIGNAL_TIME_PENDING) break;

        if (curPresentTime == Fence::SIGNAL_TIME_INVALID) {
            ALOGE("GlobalPresentFence is invalid!");
            mGlobalRecord.prevPresentTime = 0;
            mGlobalRecord.presentFences.pop_front();
            continue;
        }

        ALOGV("GlobalPresentFenceTime[%" PRId64 "]",
              mGlobalRecord.presentFences.front()->getSignalTime());

        if (mGlobalRecord.prevPresentTime != 0) {
            const int32_t presentToPresentMs =
                    msBetween(mGlobalRecord.prevPresentTime, curPresentTime);
            ALOGV("Global present2present[%d] prev[%" PRId64 "] curr[%" PRId64 "]",
                  presentToPresentMs, mGlobalRecord.prevPresentTime, curPresentTime);
            mTimeStats.presentToPresent.insert(presentToPresentMs);
        }

        mGlobalRecord.prevPresentTime = curPresentTime;
        mGlobalRecord.presentFences.pop_front();
    }
    while (!mGlobalRecord.renderEngineDurations.empty()) {
        const auto duration = mGlobalRecord.renderEngineDurations.front();
        const auto& endTime = duration.endTime;

        nsecs_t endNs = -1;

        if (auto val = std::get_if<nsecs_t>(&endTime)) {
            endNs = *val;
        } else {
            endNs = std::get<std::shared_ptr<FenceTime>>(endTime)->getSignalTime();
        }

        if (endNs == Fence::SIGNAL_TIME_PENDING) break;

        if (endNs < 0) {
            ALOGE("RenderEngineTiming is invalid!");
            mGlobalRecord.renderEngineDurations.pop_front();
            continue;
        }

        const int32_t renderEngineMs = msBetween(duration.startTime, endNs);
        mTimeStats.renderEngineTiming.insert(renderEngineMs);

        mGlobalRecord.renderEngineDurations.pop_front();
    }
}

void TimeStats::setPresentFenceGlobal(const std::shared_ptr<FenceTime>& presentFence) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mMutex);
    if (presentFence == nullptr || !presentFence->isValid()) {
        mGlobalRecord.prevPresentTime = 0;
        return;
    }

    if (mPowerTime.powerMode != PowerMode::ON) {
        // Try flushing the last present fence on PowerMode::ON.
        flushAvailableGlobalRecordsToStatsLocked();
        mGlobalRecord.presentFences.clear();
        mGlobalRecord.prevPresentTime = 0;
        return;
    }

    if (mGlobalRecord.presentFences.size() == MAX_NUM_TIME_RECORDS) {
        // The front presentFence must be trapped in pending status in this
        // case. Try dequeuing the front one to recover.
        ALOGE("GlobalPresentFences is already at its maximum size[%zu]", MAX_NUM_TIME_RECORDS);
        mGlobalRecord.prevPresentTime = 0;
        mGlobalRecord.presentFences.pop_front();
    }

    mGlobalRecord.presentFences.emplace_back(presentFence);
    flushAvailableGlobalRecordsToStatsLocked();
}

void TimeStats::enable() {
    if (mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mEnabled.store(true);
    mTimeStats.statsStart = static_cast<int64_t>(std::time(0));
    mPowerTime.prevTime = systemTime();
    ALOGD("Enabled");
}

void TimeStats::disable() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    flushPowerTimeLocked();
    mEnabled.store(false);
    mTimeStats.statsEnd = static_cast<int64_t>(std::time(0));
    ALOGD("Disabled");
}

void TimeStats::clearAll() {
    std::lock_guard<std::mutex> lock(mMutex);
    clearGlobalLocked();
    clearLayersLocked();
}

void TimeStats::clearGlobalLocked() {
    ATRACE_CALL();

    mTimeStats.statsStart = (mEnabled.load() ? static_cast<int64_t>(std::time(0)) : 0);
    mTimeStats.statsEnd = 0;
    mTimeStats.totalFrames = 0;
    mTimeStats.missedFrames = 0;
    mTimeStats.clientCompositionFrames = 0;
    mTimeStats.clientCompositionReusedFrames = 0;
    mTimeStats.refreshRateSwitches = 0;
    mTimeStats.compositionStrategyChanges = 0;
    mTimeStats.displayEventConnectionsCount = 0;
    mTimeStats.displayOnTime = 0;
    mTimeStats.presentToPresent.hist.clear();
    mTimeStats.frameDuration.hist.clear();
    mTimeStats.renderEngineTiming.hist.clear();
    mTimeStats.refreshRateStats.clear();
    mPowerTime.prevTime = systemTime();
    mGlobalRecord.prevPresentTime = 0;
    mGlobalRecord.presentFences.clear();
    ALOGD("Cleared global stats");
}

void TimeStats::clearLayersLocked() {
    ATRACE_CALL();

    mTimeStatsTracker.clear();
    mTimeStats.stats.clear();
    ALOGD("Cleared layer stats");
}

bool TimeStats::isEnabled() {
    return mEnabled.load();
}

void TimeStats::dump(bool asProto, std::optional<uint32_t> maxLayers, std::string& result) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    if (mTimeStats.statsStart == 0) {
        return;
    }

    mTimeStats.statsEnd = static_cast<int64_t>(std::time(0));

    flushPowerTimeLocked();

    if (asProto) {
        ALOGD("Dumping TimeStats as proto");
        SFTimeStatsGlobalProto timeStatsProto = mTimeStats.toProto(maxLayers);
        result.append(timeStatsProto.SerializeAsString());
    } else {
        ALOGD("Dumping TimeStats as text");
        result.append(mTimeStats.toString(maxLayers));
        result.append("\n");
    }
}

} // namespace impl

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
