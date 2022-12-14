/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <gui/LayerMetadata.h>
#include <timestatsproto/TimeStatsProtoHeader.h>
#include <utils/Timers.h>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace android {
namespace surfaceflinger {

class TimeStatsHelper {
public:
    class Histogram {
    public:
        // Key is the delta time between timestamps
        // Value is the number of appearances of that delta
        std::unordered_map<int32_t, int32_t> hist;

        void insert(int32_t delta);
        int64_t totalTime() const;
        float averageTime() const;
        std::string toString() const;
    };

    struct JankPayload {
        // note that transactions are counted for these frames.
        int32_t totalFrames = 0;
        int32_t totalJankyFrames = 0;
        int32_t totalSFLongCpu = 0;
        int32_t totalSFLongGpu = 0;
        int32_t totalSFUnattributed = 0;
        int32_t totalAppUnattributed = 0;
        int32_t totalSFScheduling = 0;
        int32_t totalSFPredictionError = 0;
        int32_t totalAppBufferStuffing = 0;

        std::string toString() const;
    };

    struct SetFrameRateVote {
        float frameRate = 0;

        // Needs to be in sync with atoms.proto
        enum class FrameRateCompatibility {
            Undefined = 0,
            Default = 1,
            ExactOrMultiple = 2,

            ftl_last = ExactOrMultiple
        } frameRateCompatibility = FrameRateCompatibility::Undefined;

        // Needs to be in sync with atoms.proto
        enum class Seamlessness {
            Undefined = 0,
            ShouldBeSeamless = 1,
            NotRequired = 2,

            ftl_last = NotRequired
        } seamlessness = Seamlessness::Undefined;

        std::string toString() const;
    };

    class TimeStatsLayer {
    public:
        uid_t uid;
        std::string layerName;
        std::string packageName;
        int32_t displayRefreshRateBucket = 0;
        int32_t renderRateBucket = 0;
        GameMode gameMode = GameMode::Unsupported;
        int32_t totalFrames = 0;
        int32_t droppedFrames = 0;
        int32_t lateAcquireFrames = 0;
        int32_t badDesiredPresentFrames = 0;
        JankPayload jankPayload;
        SetFrameRateVote setFrameRateVote;
        std::unordered_map<std::string, Histogram> deltas;

        std::string toString() const;
        SFTimeStatsLayerProto toProto() const;
    };

    // Lifted from SkiaGLRenderEngine's LinearEffect class.
    // Which in turn was inspired by art/runtime/class_linker.cc
    // Also this is what boost:hash_combine does so this is a pretty good hash.
    static size_t HashCombine(size_t seed, size_t val) {
        return seed ^ (val + 0x9e3779b9 + (seed << 6) + (seed >> 2));
    }

    struct TimelineStatsKey {
        int32_t displayRefreshRateBucket = 0;
        int32_t renderRateBucket = 0;

        struct Hasher {
            size_t operator()(const TimelineStatsKey& key) const {
                size_t result = std::hash<int32_t>{}(key.displayRefreshRateBucket);
                return HashCombine(result, std::hash<int32_t>{}(key.renderRateBucket));
            }
        };

        bool operator==(const TimelineStatsKey& o) const {
            return displayRefreshRateBucket == o.displayRefreshRateBucket &&
                    renderRateBucket == o.renderRateBucket;
        }
    };

    struct LayerStatsKey {
        uid_t uid = 0;
        std::string layerName;
        GameMode gameMode = GameMode::Unsupported;

        struct Hasher {
            size_t operator()(const LayerStatsKey& key) const {
                size_t uidHash = std::hash<uid_t>{}(key.uid);
                size_t layerNameHash = std::hash<std::string>{}(key.layerName);
                using T = std::underlying_type_t<GameMode>;
                size_t gameModeHash = std::hash<T>{}(static_cast<T>(key.gameMode));
                return HashCombine(uidHash, HashCombine(layerNameHash, gameModeHash));
            }
        };

        bool operator==(const LayerStatsKey& o) const {
            return uid == o.uid && layerName == o.layerName && gameMode == o.gameMode;
        }
    };

    struct TimelineStats {
        TimelineStatsKey key;
        JankPayload jankPayload;
        Histogram displayDeadlineDeltas;
        Histogram displayPresentDeltas;
        std::unordered_map<LayerStatsKey, TimeStatsLayer, LayerStatsKey::Hasher> stats;

        void clearGlobals() {
            jankPayload = {};
            displayDeadlineDeltas = {};
            displayPresentDeltas = {};
        }
    };

    class TimeStatsGlobal {
    public:
        // Note: these are all legacy statistics, we're keeping these around because a variety of
        // systems and form-factors find these useful when comparing with older releases. However,
        // the current recommendation is that the new timeline-based metrics are used, and the old
        // ones are deprecated.
        int64_t statsStartLegacy = 0;
        int64_t statsEndLegacy = 0;
        int32_t totalFramesLegacy = 0;
        int32_t missedFramesLegacy = 0;
        int32_t clientCompositionFramesLegacy = 0;
        int32_t clientCompositionReusedFramesLegacy = 0;
        int32_t refreshRateSwitchesLegacy = 0;
        int32_t compositionStrategyChangesLegacy = 0;
        int32_t displayEventConnectionsCountLegacy = 0;
        int64_t displayOnTimeLegacy = 0;
        Histogram presentToPresentLegacy;
        Histogram frameDurationLegacy;
        Histogram renderEngineTimingLegacy;
        std::unordered_map<uint32_t, nsecs_t> refreshRateStatsLegacy;
        int32_t compositionStrategyPredictedLegacy = 0;
        int32_t compositionStrategyPredictionSucceededLegacy = 0;

        std::unordered_map<TimelineStatsKey, TimelineStats, TimelineStatsKey::Hasher> stats;

        std::string toString(std::optional<uint32_t> maxLayers) const;
        SFTimeStatsGlobalProto toProto(std::optional<uint32_t> maxLayers) const;

    private:
        std::vector<TimeStatsLayer const*> generateDumpStats(
                std::optional<uint32_t> maxLayers) const;
    };
};

} // namespace surfaceflinger
} // namespace android
