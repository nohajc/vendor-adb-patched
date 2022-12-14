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

#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <variant>

#include <android/hardware/graphics/composer/2.4/IComposerClient.h>
#include <gui/JankInfo.h>
#include <gui/LayerMetadata.h>
#include <timestatsproto/TimeStatsHelper.h>
#include <timestatsproto/TimeStatsProtoHeader.h>
#include <ui/FenceTime.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <scheduler/Fps.h>

using namespace android::surfaceflinger;

namespace android {

class TimeStats {
public:
    using SetFrameRateVote = TimeStatsHelper::SetFrameRateVote;

    virtual ~TimeStats() = default;

    // Process a pull request from statsd.
    virtual bool onPullAtom(const int atomId, std::string* pulledData) = 0;

    virtual void parseArgs(bool asProto, const Vector<String16>& args, std::string& result) = 0;
    virtual bool isEnabled() = 0;
    virtual std::string miniDump() = 0;

    virtual void incrementTotalFrames() = 0;
    virtual void incrementMissedFrames() = 0;
    // Increments the number of times the display refresh rate changed.
    virtual void incrementRefreshRateSwitches() = 0;
    // Records the most up-to-date count of display event connections.
    // The stored count will be the maximum ever recoded.
    virtual void recordDisplayEventConnectionCount(int32_t count) = 0;

    // Records the start and end times for a frame.
    // The start time is the same as the beginning of a SurfaceFlinger
    // invalidate message.
    // The end time corresponds to when SurfaceFlinger finishes submitting the
    // request to HWC to present a frame.
    virtual void recordFrameDuration(nsecs_t startTime, nsecs_t endTime) = 0;
    // Records the start time and end times for when RenderEngine begins work.
    // The start time corresponds to the beginning of RenderEngine::drawLayers.
    // The end time corresponds to when RenderEngine finishes rendering.
    virtual void recordRenderEngineDuration(nsecs_t startTime, nsecs_t endTime) = 0;
    // Same as above, but passes in a fence representing the end time.
    virtual void recordRenderEngineDuration(nsecs_t startTime,
                                            const std::shared_ptr<FenceTime>& readyFence) = 0;

    virtual void setPostTime(int32_t layerId, uint64_t frameNumber, const std::string& layerName,
                             uid_t uid, nsecs_t postTime, GameMode) = 0;
    virtual void setLatchTime(int32_t layerId, uint64_t frameNumber, nsecs_t latchTime) = 0;
    // Reasons why latching a particular buffer may be skipped
    enum class LatchSkipReason {
        // If the acquire fence did not fire on some devices we skip latching
        // the buffer until the fence fires.
        LateAcquire,
    };
    // Increments the counter of skipped latch buffers.
    virtual void incrementLatchSkipped(int32_t layerId, LatchSkipReason reason) = 0;
    // Increments the counter of bad desired present times for this layer.
    // Bad desired present times are "implausible" and cause SurfaceFlinger to
    // latch a buffer immediately to avoid stalling.
    virtual void incrementBadDesiredPresent(int32_t layerId) = 0;
    virtual void setDesiredTime(int32_t layerId, uint64_t frameNumber, nsecs_t desiredTime) = 0;
    virtual void setAcquireTime(int32_t layerId, uint64_t frameNumber, nsecs_t acquireTime) = 0;
    virtual void setAcquireFence(int32_t layerId, uint64_t frameNumber,
                                 const std::shared_ptr<FenceTime>& acquireFence) = 0;
    // SetPresent{Time, Fence} are not expected to be called in the critical
    // rendering path, as they flush prior fences if those fences have fired.
    virtual void setPresentTime(int32_t layerId, uint64_t frameNumber, nsecs_t presentTime,
                                Fps displayRefreshRate, std::optional<Fps> renderRate,
                                SetFrameRateVote frameRateVote, GameMode) = 0;
    virtual void setPresentFence(int32_t layerId, uint64_t frameNumber,
                                 const std::shared_ptr<FenceTime>& presentFence,
                                 Fps displayRefreshRate, std::optional<Fps> renderRate,
                                 SetFrameRateVote frameRateVote, GameMode) = 0;

    // Increments janky frames, blamed to the provided {refreshRate, renderRate, uid, layerName}
    // key, with JankMetadata as supplementary reasons for the jank. Because FrameTimeline is the
    // infrastructure responsible for computing jank in the system, this is expected to be called
    // from FrameTimeline, rather than directly from SurfaceFlinger or individual layers. If there
    // are no jank reasons, then total frames are incremented but jank is not, for accurate
    // accounting of janky frames.
    // displayDeadlineDelta, displayPresentJitter, and appDeadlineDelta are also provided in order
    // to provide contextual information about a janky frame. These values may only be uploaded if
    // there was an associated valid jank reason, and they must be positive. When these frame counts
    // are incremented, these are also aggregated into a global reporting packet to help with data
    // validation and assessing of overall device health.
    struct JankyFramesInfo {
        Fps refreshRate;
        std::optional<Fps> renderRate;
        uid_t uid = 0;
        std::string layerName;
        GameMode gameMode = GameMode::Unsupported;
        int32_t reasons = 0;
        nsecs_t displayDeadlineDelta = 0;
        nsecs_t displayPresentJitter = 0;
        nsecs_t appDeadlineDelta = 0;

        static bool isOptApproxEqual(std::optional<Fps> lhs, std::optional<Fps> rhs) {
            return (!lhs && !rhs) || (lhs && rhs && isApproxEqual(*lhs, *rhs));
        }

        bool operator==(const JankyFramesInfo& o) const {
            return isApproxEqual(refreshRate, o.refreshRate) &&
                    isOptApproxEqual(renderRate, o.renderRate) && uid == o.uid &&
                    layerName == o.layerName && gameMode == o.gameMode && reasons == o.reasons &&
                    displayDeadlineDelta == o.displayDeadlineDelta &&
                    displayPresentJitter == o.displayPresentJitter &&
                    appDeadlineDelta == o.appDeadlineDelta;
        }

        friend std::ostream& operator<<(std::ostream& os, const JankyFramesInfo& info) {
            os << "JankyFramesInfo {";
            os << "\n    .refreshRate = " << info.refreshRate;
            os << "\n    .renderRate = "
               << (info.renderRate ? to_string(*info.renderRate) : "nullopt");
            os << "\n    .uid = " << info.uid;
            os << "\n    .layerName = " << info.layerName;
            os << "\n    .reasons = " << info.reasons;
            os << "\n    .displayDeadlineDelta = " << info.displayDeadlineDelta;
            os << "\n    .displayPresentJitter = " << info.displayPresentJitter;
            os << "\n    .appDeadlineDelta = " << info.appDeadlineDelta;
            return os << "\n}";
        }
    };

    struct ClientCompositionRecord {
        // Frame had client composition or mixed composition
        bool hadClientComposition = false;
        // Composition changed between hw composition and mixed/client composition
        bool changed = false;
        // Frame reused the client composition result from a previous frame
        bool reused = false;
        // Composition strategy predicted for frame
        bool predicted = false;
        // Composition strategy prediction succeeded
        bool predictionSucceeded = false;

        // Whether there is data we want to record.
        bool hasInterestingData() const {
            return hadClientComposition || changed || reused || predicted;
        }
    };

    virtual void incrementJankyFrames(const JankyFramesInfo& info) = 0;
    // Clean up the layer record
    virtual void onDestroy(int32_t layerId) = 0;
    // If SF skips or rejects a buffer, remove the corresponding TimeRecord.
    virtual void removeTimeRecord(int32_t layerId, uint64_t frameNumber) = 0;

    virtual void setPowerMode(
            hardware::graphics::composer::V2_4::IComposerClient::PowerMode powerMode) = 0;
    // Source of truth is RefrehRateStats.
    virtual void recordRefreshRate(uint32_t fps, nsecs_t duration) = 0;
    virtual void setPresentFenceGlobal(const std::shared_ptr<FenceTime>& presentFence) = 0;
    virtual void pushCompositionStrategyState(const ClientCompositionRecord&) = 0;
};

namespace impl {

class TimeStats : public android::TimeStats {
    using PowerMode = android::hardware::graphics::composer::V2_4::IComposerClient::PowerMode;

    struct FrameTime {
        uint64_t frameNumber = 0;
        nsecs_t postTime = 0;
        nsecs_t latchTime = 0;
        nsecs_t acquireTime = 0;
        nsecs_t desiredTime = 0;
        nsecs_t presentTime = 0;
    };

    struct TimeRecord {
        bool ready = false;
        FrameTime frameTime;
        std::shared_ptr<FenceTime> acquireFence;
        std::shared_ptr<FenceTime> presentFence;
    };

    struct LayerRecord {
        uid_t uid;
        std::string layerName;
        GameMode gameMode = GameMode::Unsupported;
        // This is the index in timeRecords, at which the timestamps for that
        // specific frame are still not fully received. This is not waiting for
        // fences to signal, but rather waiting to receive those fences/timestamps.
        int32_t waitData = -1;
        uint32_t droppedFrames = 0;
        uint32_t lateAcquireFrames = 0;
        uint32_t badDesiredPresentFrames = 0;
        TimeRecord prevTimeRecord;
        std::deque<TimeRecord> timeRecords;
    };

    struct PowerTime {
        PowerMode powerMode = PowerMode::OFF;
        nsecs_t prevTime = 0;
    };

    struct RenderEngineDuration {
        nsecs_t startTime;
        std::variant<nsecs_t, std::shared_ptr<FenceTime>> endTime;
    };

    struct GlobalRecord {
        nsecs_t prevPresentTime = 0;
        std::deque<std::shared_ptr<FenceTime>> presentFences;
        std::deque<RenderEngineDuration> renderEngineDurations;
    };

public:
    TimeStats();
    // For testing only for injecting custom dependencies.
    TimeStats(std::optional<size_t> maxPulledLayers,
              std::optional<size_t> maxPulledHistogramBuckets);

    bool onPullAtom(const int atomId, std::string* pulledData) override;
    void parseArgs(bool asProto, const Vector<String16>& args, std::string& result) override;
    bool isEnabled() override;
    std::string miniDump() override;

    void incrementTotalFrames() override;
    void incrementMissedFrames() override;
    void incrementRefreshRateSwitches() override;
    void recordDisplayEventConnectionCount(int32_t count) override;

    void recordFrameDuration(nsecs_t startTime, nsecs_t endTime) override;
    void recordRenderEngineDuration(nsecs_t startTime, nsecs_t endTime) override;
    void recordRenderEngineDuration(nsecs_t startTime,
                                    const std::shared_ptr<FenceTime>& readyFence) override;

    void setPostTime(int32_t layerId, uint64_t frameNumber, const std::string& layerName, uid_t uid,
                     nsecs_t postTime, GameMode) override;
    void setLatchTime(int32_t layerId, uint64_t frameNumber, nsecs_t latchTime) override;
    void incrementLatchSkipped(int32_t layerId, LatchSkipReason reason) override;
    void incrementBadDesiredPresent(int32_t layerId) override;
    void setDesiredTime(int32_t layerId, uint64_t frameNumber, nsecs_t desiredTime) override;
    void setAcquireTime(int32_t layerId, uint64_t frameNumber, nsecs_t acquireTime) override;
    void setAcquireFence(int32_t layerId, uint64_t frameNumber,
                         const std::shared_ptr<FenceTime>& acquireFence) override;
    void setPresentTime(int32_t layerId, uint64_t frameNumber, nsecs_t presentTime,
                        Fps displayRefreshRate, std::optional<Fps> renderRate, SetFrameRateVote,
                        GameMode) override;
    void setPresentFence(int32_t layerId, uint64_t frameNumber,
                         const std::shared_ptr<FenceTime>& presentFence, Fps displayRefreshRate,
                         std::optional<Fps> renderRate, SetFrameRateVote, GameMode) override;

    void incrementJankyFrames(const JankyFramesInfo& info) override;
    // Clean up the layer record
    void onDestroy(int32_t layerId) override;
    // If SF skips or rejects a buffer, remove the corresponding TimeRecord.
    void removeTimeRecord(int32_t layerId, uint64_t frameNumber) override;

    void setPowerMode(
            hardware::graphics::composer::V2_4::IComposerClient::PowerMode powerMode) override;
    // Source of truth is RefrehRateStats.
    void recordRefreshRate(uint32_t fps, nsecs_t duration) override;
    void setPresentFenceGlobal(const std::shared_ptr<FenceTime>& presentFence) override;

    void pushCompositionStrategyState(const ClientCompositionRecord&) override;

    static const size_t MAX_NUM_TIME_RECORDS = 64;

private:
    bool populateGlobalAtom(std::string* pulledData);
    bool populateLayerAtom(std::string* pulledData);
    bool recordReadyLocked(int32_t layerId, TimeRecord* timeRecord);
    void flushAvailableRecordsToStatsLocked(int32_t layerId, Fps displayRefreshRate,
                                            std::optional<Fps> renderRate, SetFrameRateVote,
                                            GameMode);
    void flushPowerTimeLocked();
    void flushAvailableGlobalRecordsToStatsLocked();
    bool canAddNewAggregatedStats(uid_t uid, const std::string& layerName, GameMode);

    void enable();
    void disable();
    void clearAll();
    void clearGlobalLocked();
    void clearLayersLocked();
    void dump(bool asProto, std::optional<uint32_t> maxLayers, std::string& result);

    std::atomic<bool> mEnabled = false;
    std::mutex mMutex;
    TimeStatsHelper::TimeStatsGlobal mTimeStats;
    // Hashmap for LayerRecord with layerId as the hash key
    std::unordered_map<int32_t, LayerRecord> mTimeStatsTracker;
    PowerTime mPowerTime;
    GlobalRecord mGlobalRecord;

    static const size_t MAX_NUM_LAYER_RECORDS = 200;

    static const size_t REFRESH_RATE_BUCKET_WIDTH = 30;
    static const size_t RENDER_RATE_BUCKET_WIDTH = REFRESH_RATE_BUCKET_WIDTH;
    static const size_t MAX_NUM_LAYER_STATS = 200;
    static const size_t MAX_NUM_PULLED_LAYERS = MAX_NUM_LAYER_STATS;
    size_t mMaxPulledLayers = MAX_NUM_PULLED_LAYERS;
    size_t mMaxPulledHistogramBuckets = 6;
};

} // namespace impl

} // namespace android
