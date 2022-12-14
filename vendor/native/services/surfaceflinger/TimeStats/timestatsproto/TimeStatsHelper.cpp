/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include "timestatsproto/TimeStatsHelper.h"

#include <android-base/stringprintf.h>
#include <ftl/enum.h>

#include <array>
#include <cinttypes>

#define HISTOGRAM_SIZE 85

using android::base::StringAppendF;
using android::base::StringPrintf;

namespace android {
namespace surfaceflinger {

// Time buckets for histogram, the calculated time deltas will be lower bounded
// to the buckets in this array.
static const std::array<int32_t, HISTOGRAM_SIZE> histogramConfig =
        {0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,
         17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,
         34,  36,  38,  40,  42,  44,  46,  48,  50,  54,  58,  62,  66,  70,  74,  78,  82,
         86,  90,  94,  98,  102, 106, 110, 114, 118, 122, 126, 130, 134, 138, 142, 146, 150,
         200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000};

void TimeStatsHelper::Histogram::insert(int32_t delta) {
    if (delta < 0) return;
    // std::lower_bound won't work on out of range values
    if (delta > histogramConfig[HISTOGRAM_SIZE - 1]) {
        hist[histogramConfig[HISTOGRAM_SIZE - 1]]++;
        return;
    }
    auto iter = std::lower_bound(histogramConfig.begin(), histogramConfig.end(), delta);
    hist[*iter]++;
}

int64_t TimeStatsHelper::Histogram::totalTime() const {
    int64_t ret = 0;
    for (const auto& ele : hist) {
        ret += ele.first * ele.second;
    }
    return ret;
}

float TimeStatsHelper::Histogram::averageTime() const {
    int64_t ret = 0;
    int64_t count = 0;
    for (const auto& ele : hist) {
        count += ele.second;
        ret += ele.first * ele.second;
    }
    return static_cast<float>(ret) / count;
}

std::string TimeStatsHelper::Histogram::toString() const {
    std::string result;
    for (int32_t i = 0; i < HISTOGRAM_SIZE; ++i) {
        int32_t bucket = histogramConfig[i];
        int32_t count = (hist.count(bucket) == 0) ? 0 : hist.at(bucket);
        StringAppendF(&result, "%dms=%d ", bucket, count);
    }
    result.back() = '\n';
    return result;
}

std::string TimeStatsHelper::JankPayload::toString() const {
    std::string result;
    StringAppendF(&result, "totalTimelineFrames = %d\n", totalFrames);
    StringAppendF(&result, "jankyFrames = %d\n", totalJankyFrames);
    StringAppendF(&result, "sfLongCpuJankyFrames = %d\n", totalSFLongCpu);
    StringAppendF(&result, "sfLongGpuJankyFrames = %d\n", totalSFLongGpu);
    StringAppendF(&result, "sfUnattributedJankyFrames = %d\n", totalSFUnattributed);
    StringAppendF(&result, "appUnattributedJankyFrames = %d\n", totalAppUnattributed);
    StringAppendF(&result, "sfSchedulingJankyFrames = %d\n", totalSFScheduling);
    StringAppendF(&result, "sfPredictionErrorJankyFrames = %d\n", totalSFPredictionError);
    StringAppendF(&result, "appBufferStuffingJankyFrames = %d\n", totalAppBufferStuffing);
    return result;
}

std::string TimeStatsHelper::SetFrameRateVote::toString() const {
    std::string result;
    StringAppendF(&result, "frameRate = %.2f\n", frameRate);
    StringAppendF(&result, "frameRateCompatibility = %s\n",
                  ftl::enum_string(frameRateCompatibility).c_str());
    StringAppendF(&result, "seamlessness = %s\n", ftl::enum_string(seamlessness).c_str());
    return result;
}

std::string TimeStatsHelper::TimeStatsLayer::toString() const {
    std::string result = "\n";
    StringAppendF(&result, "displayRefreshRate = %d fps\n", displayRefreshRateBucket);
    StringAppendF(&result, "renderRate = %d fps\n", renderRateBucket);
    StringAppendF(&result, "uid = %d\n", uid);
    StringAppendF(&result, "layerName = %s\n", layerName.c_str());
    StringAppendF(&result, "packageName = %s\n", packageName.c_str());
    StringAppendF(&result, "gameMode = %s\n", ftl::enum_string(gameMode).c_str());
    StringAppendF(&result, "totalFrames = %d\n", totalFrames);
    StringAppendF(&result, "droppedFrames = %d\n", droppedFrames);
    StringAppendF(&result, "lateAcquireFrames = %d\n", lateAcquireFrames);
    StringAppendF(&result, "badDesiredPresentFrames = %d\n", badDesiredPresentFrames);
    result.append("Jank payload for this layer:\n");
    result.append(jankPayload.toString());
    result.append("SetFrateRate vote for this layer:\n");
    result.append(setFrameRateVote.toString());
    const auto iter = deltas.find("present2present");
    if (iter != deltas.end()) {
        const float averageTime = iter->second.averageTime();
        const float averageFPS = averageTime < 1.0f ? 0.0f : 1000.0f / averageTime;
        StringAppendF(&result, "averageFPS = %.3f\n", averageFPS);
    }
    for (const auto& ele : deltas) {
        StringAppendF(&result, "%s histogram is as below:\n", ele.first.c_str());
        result.append(ele.second.toString());
    }

    return result;
}

std::string TimeStatsHelper::TimeStatsGlobal::toString(std::optional<uint32_t> maxLayers) const {
    std::string result = "SurfaceFlinger TimeStats:\n";
    result.append("Legacy stats are as follows:\n");
    StringAppendF(&result, "statsStart = %" PRId64 "\n", statsStartLegacy);
    StringAppendF(&result, "statsEnd = %" PRId64 "\n", statsEndLegacy);
    StringAppendF(&result, "totalFrames = %d\n", totalFramesLegacy);
    StringAppendF(&result, "missedFrames = %d\n", missedFramesLegacy);
    StringAppendF(&result, "clientCompositionFrames = %d\n", clientCompositionFramesLegacy);
    StringAppendF(&result, "clientCompositionReusedFrames = %d\n",
                  clientCompositionReusedFramesLegacy);
    StringAppendF(&result, "refreshRateSwitches = %d\n", refreshRateSwitchesLegacy);
    StringAppendF(&result, "compositionStrategyChanges = %d\n", compositionStrategyChangesLegacy);
    StringAppendF(&result, "compositionStrategyPredicted = %d\n",
                  compositionStrategyPredictedLegacy);
    StringAppendF(&result, "compositionStrategyPredictionSucceeded = %d\n",
                  compositionStrategyPredictionSucceededLegacy);
    StringAppendF(&result, "compositionStrategyPredictionFailed = %d\n",
                  compositionStrategyPredictedLegacy -
                          compositionStrategyPredictionSucceededLegacy);

    StringAppendF(&result, "displayOnTime = %" PRId64 " ms\n", displayOnTimeLegacy);
    StringAppendF(&result, "displayConfigStats is as below:\n");
    for (const auto& [fps, duration] : refreshRateStatsLegacy) {
        StringAppendF(&result, "%dfps = %ldms\n", fps, ns2ms(duration));
    }
    result.back() = '\n';
    StringAppendF(&result, "totalP2PTime = %" PRId64 " ms\n", presentToPresentLegacy.totalTime());
    StringAppendF(&result, "presentToPresent histogram is as below:\n");
    result.append(presentToPresentLegacy.toString());
    const float averageFrameDuration = frameDurationLegacy.averageTime();
    StringAppendF(&result, "averageFrameDuration = %.3f ms\n",
                  std::isnan(averageFrameDuration) ? 0.0f : averageFrameDuration);
    StringAppendF(&result, "frameDuration histogram is as below:\n");
    result.append(frameDurationLegacy.toString());
    const float averageRenderEngineTiming = renderEngineTimingLegacy.averageTime();
    StringAppendF(&result, "averageRenderEngineTiming = %.3f ms\n",
                  std::isnan(averageRenderEngineTiming) ? 0.0f : averageRenderEngineTiming);
    StringAppendF(&result, "renderEngineTiming histogram is as below:\n");
    result.append(renderEngineTimingLegacy.toString());

    result.append("\nGlobal aggregated jank payload (Timeline stats):");
    for (const auto& ele : stats) {
        result.append("\n");
        StringAppendF(&result, "displayRefreshRate = %d fps\n",
                      ele.second.key.displayRefreshRateBucket);
        StringAppendF(&result, "renderRate = %d fps\n", ele.second.key.renderRateBucket);
        result.append(ele.second.jankPayload.toString());
        StringAppendF(&result, "sfDeadlineMisses histogram is as below:\n");
        result.append(ele.second.displayDeadlineDeltas.toString());
        StringAppendF(&result, "sfPredictionErrors histogram is as below:\n");
        result.append(ele.second.displayPresentDeltas.toString());
    }

    const auto dumpStats = generateDumpStats(maxLayers);
    for (const auto& ele : dumpStats) {
        result.append(ele->toString());
    }

    return result;
}

SFTimeStatsLayerProto TimeStatsHelper::TimeStatsLayer::toProto() const {
    SFTimeStatsLayerProto layerProto;
    layerProto.set_layer_name(layerName);
    layerProto.set_package_name(packageName);
    layerProto.set_total_frames(totalFrames);
    layerProto.set_dropped_frames(droppedFrames);
    for (const auto& ele : deltas) {
        SFTimeStatsDeltaProto* deltaProto = layerProto.add_deltas();
        deltaProto->set_delta_name(ele.first);
        for (const auto& histEle : ele.second.hist) {
            SFTimeStatsHistogramBucketProto* histProto = deltaProto->add_histograms();
            histProto->set_time_millis(histEle.first);
            histProto->set_frame_count(histEle.second);
        }
    }
    return layerProto;
}

SFTimeStatsGlobalProto TimeStatsHelper::TimeStatsGlobal::toProto(
        std::optional<uint32_t> maxLayers) const {
    SFTimeStatsGlobalProto globalProto;
    globalProto.set_stats_start(statsStartLegacy);
    globalProto.set_stats_end(statsEndLegacy);
    globalProto.set_total_frames(totalFramesLegacy);
    globalProto.set_missed_frames(missedFramesLegacy);
    globalProto.set_client_composition_frames(clientCompositionFramesLegacy);
    globalProto.set_display_on_time(displayOnTimeLegacy);
    for (const auto& ele : refreshRateStatsLegacy) {
        SFTimeStatsDisplayConfigBucketProto* configBucketProto =
                globalProto.add_display_config_stats();
        SFTimeStatsDisplayConfigProto* configProto = configBucketProto->mutable_config();
        configProto->set_fps(ele.first);
        configBucketProto->set_duration_millis(ns2ms(ele.second));
    }
    for (const auto& histEle : presentToPresentLegacy.hist) {
        SFTimeStatsHistogramBucketProto* histProto = globalProto.add_present_to_present();
        histProto->set_time_millis(histEle.first);
        histProto->set_frame_count(histEle.second);
    }
    for (const auto& histEle : frameDurationLegacy.hist) {
        SFTimeStatsHistogramBucketProto* histProto = globalProto.add_frame_duration();
        histProto->set_time_millis(histEle.first);
        histProto->set_frame_count(histEle.second);
    }
    for (const auto& histEle : renderEngineTimingLegacy.hist) {
        SFTimeStatsHistogramBucketProto* histProto = globalProto.add_render_engine_timing();
        histProto->set_time_millis(histEle.first);
        histProto->set_frame_count(histEle.second);
    }
    const auto dumpStats = generateDumpStats(maxLayers);
    for (const auto& ele : dumpStats) {
        SFTimeStatsLayerProto* layerProto = globalProto.add_stats();
        layerProto->CopyFrom(ele->toProto());
    }
    return globalProto;
}

std::vector<TimeStatsHelper::TimeStatsLayer const*>
TimeStatsHelper::TimeStatsGlobal::generateDumpStats(std::optional<uint32_t> maxLayers) const {
    std::vector<TimeStatsLayer const*> dumpStats;

    int numLayers = 0;
    for (const auto& ele : stats) {
        numLayers += ele.second.stats.size();
    }

    dumpStats.reserve(numLayers);

    for (const auto& ele : stats) {
        for (const auto& layerEle : ele.second.stats) {
            dumpStats.push_back(&layerEle.second);
        }
    }

    std::sort(dumpStats.begin(), dumpStats.end(),
              [](TimeStatsHelper::TimeStatsLayer const* l,
                 TimeStatsHelper::TimeStatsLayer const* r) {
                  return l->totalFrames > r->totalFrames;
              });

    if (maxLayers && (*maxLayers < dumpStats.size())) {
        dumpStats.resize(*maxLayers);
    }
    return dumpStats;
}

} // namespace surfaceflinger
} // namespace android
