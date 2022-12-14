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

#undef LOG_TAG
#define LOG_TAG "TimeStats"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <android-base/stringprintf.h>
#include <log/log.h>
#include <timestatsatomsproto/TimeStatsAtomsProtoHeader.h>
#include <utils/String8.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <algorithm>
#include <chrono>
#include <unordered_map>

#include "TimeStats.h"
#include "timestatsproto/TimeStatsHelper.h"

namespace android {

namespace impl {

namespace {

FrameTimingHistogram histogramToProto(const std::unordered_map<int32_t, int32_t>& histogram,
                                      size_t maxPulledHistogramBuckets) {
    auto buckets = std::vector<std::pair<int32_t, int32_t>>(histogram.begin(), histogram.end());
    std::sort(buckets.begin(), buckets.end(),
              [](std::pair<int32_t, int32_t>& left, std::pair<int32_t, int32_t>& right) {
                  return left.second > right.second;
              });

    FrameTimingHistogram histogramProto;
    int histogramSize = 0;
    for (const auto& bucket : buckets) {
        if (++histogramSize > maxPulledHistogramBuckets) {
            break;
        }
        histogramProto.add_time_millis_buckets((int32_t)bucket.first);
        histogramProto.add_frame_counts((int64_t)bucket.second);
    }
    return histogramProto;
}

SurfaceflingerStatsLayerInfo_GameMode gameModeToProto(GameMode gameMode) {
    switch (gameMode) {
        case GameMode::Unsupported:
            return SurfaceflingerStatsLayerInfo::GAME_MODE_UNSUPPORTED;
        case GameMode::Standard:
            return SurfaceflingerStatsLayerInfo::GAME_MODE_STANDARD;
        case GameMode::Performance:
            return SurfaceflingerStatsLayerInfo::GAME_MODE_PERFORMANCE;
        case GameMode::Battery:
            return SurfaceflingerStatsLayerInfo::GAME_MODE_BATTERY;
        default:
            return SurfaceflingerStatsLayerInfo::GAME_MODE_UNSPECIFIED;
    }
}

SurfaceflingerStatsLayerInfo_SetFrameRateVote frameRateVoteToProto(
        const TimeStats::SetFrameRateVote& setFrameRateVote) {
    using FrameRateCompatibilityEnum =
            SurfaceflingerStatsLayerInfo::SetFrameRateVote::FrameRateCompatibility;
    using SeamlessnessEnum = SurfaceflingerStatsLayerInfo::SetFrameRateVote::Seamlessness;

    SurfaceflingerStatsLayerInfo_SetFrameRateVote proto;
    proto.set_frame_rate(setFrameRateVote.frameRate);
    proto.set_frame_rate_compatibility(
            static_cast<FrameRateCompatibilityEnum>(setFrameRateVote.frameRateCompatibility));
    proto.set_seamlessness(static_cast<SeamlessnessEnum>(setFrameRateVote.seamlessness));
    return proto;
}
} // namespace

bool TimeStats::populateGlobalAtom(std::string* pulledData) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (mTimeStats.statsStartLegacy == 0) {
        return false;
    }
    flushPowerTimeLocked();
    SurfaceflingerStatsGlobalInfoWrapper atomList;
    for (const auto& globalSlice : mTimeStats.stats) {
        SurfaceflingerStatsGlobalInfo* atom = atomList.add_atom();
        atom->set_total_frames(mTimeStats.totalFramesLegacy);
        atom->set_missed_frames(mTimeStats.missedFramesLegacy);
        atom->set_client_composition_frames(mTimeStats.clientCompositionFramesLegacy);
        atom->set_display_on_millis(mTimeStats.displayOnTimeLegacy);
        atom->set_animation_millis(mTimeStats.presentToPresentLegacy.totalTime());
        atom->set_event_connection_count(mTimeStats.displayEventConnectionsCountLegacy);
        *atom->mutable_frame_duration() =
                histogramToProto(mTimeStats.frameDurationLegacy.hist, mMaxPulledHistogramBuckets);
        *atom->mutable_render_engine_timing() =
                histogramToProto(mTimeStats.renderEngineTimingLegacy.hist,
                                 mMaxPulledHistogramBuckets);
        atom->set_total_timeline_frames(globalSlice.second.jankPayload.totalFrames);
        atom->set_total_janky_frames(globalSlice.second.jankPayload.totalJankyFrames);
        atom->set_total_janky_frames_with_long_cpu(globalSlice.second.jankPayload.totalSFLongCpu);
        atom->set_total_janky_frames_with_long_gpu(globalSlice.second.jankPayload.totalSFLongGpu);
        atom->set_total_janky_frames_sf_unattributed(
                globalSlice.second.jankPayload.totalSFUnattributed);
        atom->set_total_janky_frames_app_unattributed(
                globalSlice.second.jankPayload.totalAppUnattributed);
        atom->set_total_janky_frames_sf_scheduling(
                globalSlice.second.jankPayload.totalSFScheduling);
        atom->set_total_jank_frames_sf_prediction_error(
                globalSlice.second.jankPayload.totalSFPredictionError);
        atom->set_total_jank_frames_app_buffer_stuffing(
                globalSlice.second.jankPayload.totalAppBufferStuffing);
        atom->set_display_refresh_rate_bucket(globalSlice.first.displayRefreshRateBucket);
        *atom->mutable_sf_deadline_misses() =
                histogramToProto(globalSlice.second.displayDeadlineDeltas.hist,
                                 mMaxPulledHistogramBuckets);
        *atom->mutable_sf_prediction_errors() =
                histogramToProto(globalSlice.second.displayPresentDeltas.hist,
                                 mMaxPulledHistogramBuckets);
        atom->set_render_rate_bucket(globalSlice.first.renderRateBucket);
    }

    // Always clear data.
    clearGlobalLocked();

    return atomList.SerializeToString(pulledData);
}

bool TimeStats::populateLayerAtom(std::string* pulledData) {
    std::lock_guard<std::mutex> lock(mMutex);

    std::vector<TimeStatsHelper::TimeStatsLayer*> dumpStats;
    uint32_t numLayers = 0;
    for (const auto& globalSlice : mTimeStats.stats) {
        numLayers += globalSlice.second.stats.size();
    }

    dumpStats.reserve(numLayers);

    for (auto& globalSlice : mTimeStats.stats) {
        for (auto& layerSlice : globalSlice.second.stats) {
            dumpStats.push_back(&layerSlice.second);
        }
    }

    std::sort(dumpStats.begin(), dumpStats.end(),
              [](TimeStatsHelper::TimeStatsLayer const* l,
                 TimeStatsHelper::TimeStatsLayer const* r) {
                  return l->totalFrames > r->totalFrames;
              });

    if (mMaxPulledLayers < dumpStats.size()) {
        dumpStats.resize(mMaxPulledLayers);
    }

    SurfaceflingerStatsLayerInfoWrapper atomList;
    for (auto& layer : dumpStats) {
        SurfaceflingerStatsLayerInfo* atom = atomList.add_atom();
        atom->set_layer_name(layer->layerName);
        atom->set_total_frames(layer->totalFrames);
        atom->set_dropped_frames(layer->droppedFrames);
        const auto& present2PresentHist = layer->deltas.find("present2present");
        if (present2PresentHist != layer->deltas.cend()) {
            *atom->mutable_present_to_present() =
                    histogramToProto(present2PresentHist->second.hist, mMaxPulledHistogramBuckets);
        }
        const auto& post2presentHist = layer->deltas.find("post2present");
        if (post2presentHist != layer->deltas.cend()) {
            *atom->mutable_post_to_present() =
                    histogramToProto(post2presentHist->second.hist, mMaxPulledHistogramBuckets);
        }
        const auto& acquire2presentHist = layer->deltas.find("acquire2present");
        if (acquire2presentHist != layer->deltas.cend()) {
            *atom->mutable_acquire_to_present() =
                    histogramToProto(acquire2presentHist->second.hist, mMaxPulledHistogramBuckets);
        }
        const auto& latch2presentHist = layer->deltas.find("latch2present");
        if (latch2presentHist != layer->deltas.cend()) {
            *atom->mutable_latch_to_present() =
                    histogramToProto(latch2presentHist->second.hist, mMaxPulledHistogramBuckets);
        }
        const auto& desired2presentHist = layer->deltas.find("desired2present");
        if (desired2presentHist != layer->deltas.cend()) {
            *atom->mutable_desired_to_present() =
                    histogramToProto(desired2presentHist->second.hist, mMaxPulledHistogramBuckets);
        }
        const auto& post2acquireHist = layer->deltas.find("post2acquire");
        if (post2acquireHist != layer->deltas.cend()) {
            *atom->mutable_post_to_acquire() =
                    histogramToProto(post2acquireHist->second.hist, mMaxPulledHistogramBuckets);
        }

        atom->set_late_acquire_frames(layer->lateAcquireFrames);
        atom->set_bad_desired_present_frames(layer->badDesiredPresentFrames);
        atom->set_uid(layer->uid);
        atom->set_total_timeline_frames(layer->jankPayload.totalFrames);
        atom->set_total_janky_frames(layer->jankPayload.totalJankyFrames);
        atom->set_total_janky_frames_with_long_cpu(layer->jankPayload.totalSFLongCpu);
        atom->set_total_janky_frames_with_long_gpu(layer->jankPayload.totalSFLongGpu);
        atom->set_total_janky_frames_sf_unattributed(layer->jankPayload.totalSFUnattributed);
        atom->set_total_janky_frames_app_unattributed(layer->jankPayload.totalAppUnattributed);
        atom->set_total_janky_frames_sf_scheduling(layer->jankPayload.totalSFScheduling);
        atom->set_total_jank_frames_sf_prediction_error(layer->jankPayload.totalSFPredictionError);
        atom->set_total_jank_frames_app_buffer_stuffing(layer->jankPayload.totalAppBufferStuffing);
        atom->set_display_refresh_rate_bucket(layer->displayRefreshRateBucket);
        atom->set_render_rate_bucket(layer->renderRateBucket);
        *atom->mutable_set_frame_rate_vote() = frameRateVoteToProto(layer->setFrameRateVote);
        *atom->mutable_app_deadline_misses() =
                histogramToProto(layer->deltas["appDeadlineDeltas"].hist,
                                 mMaxPulledHistogramBuckets);
        atom->set_game_mode(gameModeToProto(layer->gameMode));
    }

    // Always clear data.
    clearLayersLocked();

    return atomList.SerializeToString(pulledData);
}

TimeStats::TimeStats() : TimeStats(std::nullopt, std::nullopt) {}

TimeStats::TimeStats(std::optional<size_t> maxPulledLayers,
                     std::optional<size_t> maxPulledHistogramBuckets) {
    if (maxPulledLayers) {
        mMaxPulledLayers = *maxPulledLayers;
    }

    if (maxPulledHistogramBuckets) {
        mMaxPulledHistogramBuckets = *maxPulledHistogramBuckets;
    }
}

bool TimeStats::onPullAtom(const int atomId, std::string* pulledData) {
    bool success = false;
    if (atomId == 10062) { // SURFACEFLINGER_STATS_GLOBAL_INFO
        success = populateGlobalAtom(pulledData);
    } else if (atomId == 10063) { // SURFACEFLINGER_STATS_LAYER_INFO
        success = populateLayerAtom(pulledData);
    }

    // Enable timestats now. The first full pull for a given build is expected to
    // have empty or very little stats, as stats are first enabled after the
    // first pull is completed for either the global or layer stats.
    enable();
    return success;
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
    mTimeStats.totalFramesLegacy++;
}

void TimeStats::incrementMissedFrames() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.missedFramesLegacy++;
}

void TimeStats::pushCompositionStrategyState(const TimeStats::ClientCompositionRecord& record) {
    if (!mEnabled.load() || !record.hasInterestingData()) {
        return;
    }

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    if (record.changed) mTimeStats.compositionStrategyChangesLegacy++;
    if (record.hadClientComposition) mTimeStats.clientCompositionFramesLegacy++;
    if (record.reused) mTimeStats.clientCompositionReusedFramesLegacy++;
    if (record.predicted) mTimeStats.compositionStrategyPredictedLegacy++;
    if (record.predictionSucceeded) mTimeStats.compositionStrategyPredictionSucceededLegacy++;
}

void TimeStats::incrementRefreshRateSwitches() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.refreshRateSwitchesLegacy++;
}

void TimeStats::recordDisplayEventConnectionCount(int32_t count) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.displayEventConnectionsCountLegacy =
            std::max(mTimeStats.displayEventConnectionsCountLegacy, count);
}

static int32_t toMs(nsecs_t nanos) {
    int64_t millis =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::nanoseconds(nanos))
                    .count();
    millis = std::clamp(millis, int64_t(INT32_MIN), int64_t(INT32_MAX));
    return static_cast<int32_t>(millis);
}

static int32_t msBetween(nsecs_t start, nsecs_t end) {
    return toMs(end - start);
}

void TimeStats::recordFrameDuration(nsecs_t startTime, nsecs_t endTime) {
    if (!mEnabled.load()) return;

    std::lock_guard<std::mutex> lock(mMutex);
    if (mPowerTime.powerMode == PowerMode::ON) {
        mTimeStats.frameDurationLegacy.insert(msBetween(startTime, endTime));
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

static int32_t clampToNearestBucket(Fps fps, size_t bucketWidth) {
    return std::round(fps.getValue() / bucketWidth) * bucketWidth;
}

void TimeStats::flushAvailableRecordsToStatsLocked(int32_t layerId, Fps displayRefreshRate,
                                                   std::optional<Fps> renderRate,
                                                   SetFrameRateVote frameRateVote,
                                                   GameMode gameMode) {
    ATRACE_CALL();
    ALOGV("[%d]-flushAvailableRecordsToStatsLocked", layerId);

    LayerRecord& layerRecord = mTimeStatsTracker[layerId];
    TimeRecord& prevTimeRecord = layerRecord.prevTimeRecord;
    std::deque<TimeRecord>& timeRecords = layerRecord.timeRecords;
    const int32_t refreshRateBucket =
            clampToNearestBucket(displayRefreshRate, REFRESH_RATE_BUCKET_WIDTH);
    const int32_t renderRateBucket =
            clampToNearestBucket(renderRate ? *renderRate : displayRefreshRate,
                                 RENDER_RATE_BUCKET_WIDTH);
    while (!timeRecords.empty()) {
        if (!recordReadyLocked(layerId, &timeRecords[0])) break;
        ALOGV("[%d]-[%" PRIu64 "]-presentFenceTime[%" PRId64 "]", layerId,
              timeRecords[0].frameTime.frameNumber, timeRecords[0].frameTime.presentTime);

        if (prevTimeRecord.ready) {
            uid_t uid = layerRecord.uid;
            const std::string& layerName = layerRecord.layerName;
            TimeStatsHelper::TimelineStatsKey timelineKey = {refreshRateBucket, renderRateBucket};
            if (!mTimeStats.stats.count(timelineKey)) {
                mTimeStats.stats[timelineKey].key = timelineKey;
            }

            TimeStatsHelper::TimelineStats& displayStats = mTimeStats.stats[timelineKey];

            TimeStatsHelper::LayerStatsKey layerKey = {uid, layerName, gameMode};
            if (!displayStats.stats.count(layerKey)) {
                displayStats.stats[layerKey].displayRefreshRateBucket = refreshRateBucket;
                displayStats.stats[layerKey].renderRateBucket = renderRateBucket;
                displayStats.stats[layerKey].uid = uid;
                displayStats.stats[layerKey].layerName = layerName;
                displayStats.stats[layerKey].gameMode = gameMode;
            }
            if (frameRateVote.frameRate > 0.0f) {
                displayStats.stats[layerKey].setFrameRateVote = frameRateVote;
            }
            TimeStatsHelper::TimeStatsLayer& timeStatsLayer = displayStats.stats[layerKey];
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

bool TimeStats::canAddNewAggregatedStats(uid_t uid, const std::string& layerName,
                                         GameMode gameMode) {
    uint32_t layerRecords = 0;
    for (const auto& record : mTimeStats.stats) {
        if (record.second.stats.count({uid, layerName, gameMode}) > 0) {
            return true;
        }

        layerRecords += record.second.stats.size();
    }

    return layerRecords < MAX_NUM_LAYER_STATS;
}

void TimeStats::setPostTime(int32_t layerId, uint64_t frameNumber, const std::string& layerName,
                            uid_t uid, nsecs_t postTime, GameMode gameMode) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    ALOGV("[%d]-[%" PRIu64 "]-[%s]-PostTime[%" PRId64 "]", layerId, frameNumber, layerName.c_str(),
          postTime);

    std::lock_guard<std::mutex> lock(mMutex);
    if (!canAddNewAggregatedStats(uid, layerName, gameMode)) {
        return;
    }
    if (!mTimeStatsTracker.count(layerId) && mTimeStatsTracker.size() < MAX_NUM_LAYER_RECORDS &&
        layerNameIsValid(layerName)) {
        mTimeStatsTracker[layerId].uid = uid;
        mTimeStatsTracker[layerId].layerName = layerName;
        mTimeStatsTracker[layerId].gameMode = gameMode;
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

void TimeStats::setPresentTime(int32_t layerId, uint64_t frameNumber, nsecs_t presentTime,
                               Fps displayRefreshRate, std::optional<Fps> renderRate,
                               SetFrameRateVote frameRateVote, GameMode gameMode) {
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

    flushAvailableRecordsToStatsLocked(layerId, displayRefreshRate, renderRate, frameRateVote,
                                       gameMode);
}

void TimeStats::setPresentFence(int32_t layerId, uint64_t frameNumber,
                                const std::shared_ptr<FenceTime>& presentFence,
                                Fps displayRefreshRate, std::optional<Fps> renderRate,
                                SetFrameRateVote frameRateVote, GameMode gameMode) {
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

    flushAvailableRecordsToStatsLocked(layerId, displayRefreshRate, renderRate, frameRateVote,
                                       gameMode);
}

static const constexpr int32_t kValidJankyReason = JankType::DisplayHAL |
        JankType::SurfaceFlingerCpuDeadlineMissed | JankType::SurfaceFlingerGpuDeadlineMissed |
        JankType::AppDeadlineMissed | JankType::PredictionError |
        JankType::SurfaceFlingerScheduling;

template <class T>
static void updateJankPayload(T& t, int32_t reasons) {
    t.jankPayload.totalFrames++;

    if (reasons & kValidJankyReason) {
        t.jankPayload.totalJankyFrames++;
        if ((reasons & JankType::SurfaceFlingerCpuDeadlineMissed) != 0) {
            t.jankPayload.totalSFLongCpu++;
        }
        if ((reasons & JankType::SurfaceFlingerGpuDeadlineMissed) != 0) {
            t.jankPayload.totalSFLongGpu++;
        }
        if ((reasons & JankType::DisplayHAL) != 0) {
            t.jankPayload.totalSFUnattributed++;
        }
        if ((reasons & JankType::AppDeadlineMissed) != 0) {
            t.jankPayload.totalAppUnattributed++;
        }
        if ((reasons & JankType::PredictionError) != 0) {
            t.jankPayload.totalSFPredictionError++;
        }
        if ((reasons & JankType::SurfaceFlingerScheduling) != 0) {
            t.jankPayload.totalSFScheduling++;
        }
    }

    // We want to track BufferStuffing separately as it can provide info on latency issues
    if (reasons & JankType::BufferStuffing) {
        t.jankPayload.totalAppBufferStuffing++;
    }
}

void TimeStats::incrementJankyFrames(const JankyFramesInfo& info) {
    if (!mEnabled.load()) return;

    ATRACE_CALL();
    std::lock_guard<std::mutex> lock(mMutex);

    // Only update layer stats if we're already tracking the layer in TimeStats.
    // Otherwise, continue tracking the statistic but use a default layer name instead.
    // As an implementation detail, we do this because this method is expected to be
    // called from FrameTimeline, whose jank classification includes transaction jank
    // that occurs without a buffer. But, in general those layer names are not suitable as
    // aggregation keys: e.g., it's normal and expected for Window Manager to include the hash code
    // for an animation leash. So while we can show that jank in dumpsys, aggregating based on the
    // layer blows up the stats size, so as a workaround drop those stats. This assumes that
    // TimeStats will flush the first present fence for a layer *before* FrameTimeline does so that
    // the first jank record is not dropped.

    static const std::string kDefaultLayerName = "none";
    constexpr GameMode kDefaultGameMode = GameMode::Unsupported;

    const int32_t refreshRateBucket =
            clampToNearestBucket(info.refreshRate, REFRESH_RATE_BUCKET_WIDTH);
    const int32_t renderRateBucket =
            clampToNearestBucket(info.renderRate ? *info.renderRate : info.refreshRate,
                                 RENDER_RATE_BUCKET_WIDTH);
    const TimeStatsHelper::TimelineStatsKey timelineKey = {refreshRateBucket, renderRateBucket};

    if (!mTimeStats.stats.count(timelineKey)) {
        mTimeStats.stats[timelineKey].key = timelineKey;
    }

    TimeStatsHelper::TimelineStats& timelineStats = mTimeStats.stats[timelineKey];

    updateJankPayload<TimeStatsHelper::TimelineStats>(timelineStats, info.reasons);

    TimeStatsHelper::LayerStatsKey layerKey = {info.uid, info.layerName, info.gameMode};
    if (!timelineStats.stats.count(layerKey)) {
        layerKey = {info.uid, kDefaultLayerName, kDefaultGameMode};
        timelineStats.stats[layerKey].displayRefreshRateBucket = refreshRateBucket;
        timelineStats.stats[layerKey].renderRateBucket = renderRateBucket;
        timelineStats.stats[layerKey].uid = info.uid;
        timelineStats.stats[layerKey].layerName = kDefaultLayerName;
        timelineStats.stats[layerKey].gameMode = kDefaultGameMode;
    }

    TimeStatsHelper::TimeStatsLayer& timeStatsLayer = timelineStats.stats[layerKey];
    updateJankPayload<TimeStatsHelper::TimeStatsLayer>(timeStatsLayer, info.reasons);

    if (info.reasons & kValidJankyReason) {
        // TimeStats Histograms only retain positive values, so we don't need to check if these
        // deadlines were really missed if we know that the frame had jank, since deadlines
        // that were met will be dropped.
        timelineStats.displayDeadlineDeltas.insert(toMs(info.displayDeadlineDelta));
        timelineStats.displayPresentDeltas.insert(toMs(info.displayPresentJitter));
        timeStatsLayer.deltas["appDeadlineDeltas"].insert(toMs(info.appDeadlineDelta));
    }
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
            mTimeStats.displayOnTimeLegacy += elapsedTime;
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
    if (mTimeStats.refreshRateStatsLegacy.count(fps)) {
        mTimeStats.refreshRateStatsLegacy[fps] += duration;
    } else {
        mTimeStats.refreshRateStatsLegacy.insert({fps, duration});
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
            mTimeStats.presentToPresentLegacy.insert(presentToPresentMs);
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
        mTimeStats.renderEngineTimingLegacy.insert(renderEngineMs);

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
    mTimeStats.statsStartLegacy = static_cast<int64_t>(std::time(0));
    mPowerTime.prevTime = systemTime();
    ALOGD("Enabled");
}

void TimeStats::disable() {
    if (!mEnabled.load()) return;

    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    flushPowerTimeLocked();
    mEnabled.store(false);
    mTimeStats.statsEndLegacy = static_cast<int64_t>(std::time(0));
    ALOGD("Disabled");
}

void TimeStats::clearAll() {
    std::lock_guard<std::mutex> lock(mMutex);
    mTimeStats.stats.clear();
    clearGlobalLocked();
    clearLayersLocked();
}

void TimeStats::clearGlobalLocked() {
    ATRACE_CALL();

    mTimeStats.statsStartLegacy = (mEnabled.load() ? static_cast<int64_t>(std::time(0)) : 0);
    mTimeStats.statsEndLegacy = 0;
    mTimeStats.totalFramesLegacy = 0;
    mTimeStats.missedFramesLegacy = 0;
    mTimeStats.clientCompositionFramesLegacy = 0;
    mTimeStats.clientCompositionReusedFramesLegacy = 0;
    mTimeStats.compositionStrategyChangesLegacy = 0;
    mTimeStats.compositionStrategyPredictedLegacy = 0;
    mTimeStats.compositionStrategyPredictionSucceededLegacy = 0;
    mTimeStats.refreshRateSwitchesLegacy = 0;
    mTimeStats.displayEventConnectionsCountLegacy = 0;
    mTimeStats.displayOnTimeLegacy = 0;
    mTimeStats.presentToPresentLegacy.hist.clear();
    mTimeStats.frameDurationLegacy.hist.clear();
    mTimeStats.renderEngineTimingLegacy.hist.clear();
    mTimeStats.refreshRateStatsLegacy.clear();
    mPowerTime.prevTime = systemTime();
    for (auto& globalRecord : mTimeStats.stats) {
        globalRecord.second.clearGlobals();
    }
    mGlobalRecord.prevPresentTime = 0;
    mGlobalRecord.presentFences.clear();
    ALOGD("Cleared global stats");
}

void TimeStats::clearLayersLocked() {
    ATRACE_CALL();

    mTimeStatsTracker.clear();

    for (auto& globalRecord : mTimeStats.stats) {
        globalRecord.second.stats.clear();
    }
    ALOGD("Cleared layer stats");
}

bool TimeStats::isEnabled() {
    return mEnabled.load();
}

void TimeStats::dump(bool asProto, std::optional<uint32_t> maxLayers, std::string& result) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mMutex);
    if (mTimeStats.statsStartLegacy == 0) {
        return;
    }

    mTimeStats.statsEndLegacy = static_cast<int64_t>(std::time(0));

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
