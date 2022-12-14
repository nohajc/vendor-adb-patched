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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <android/hardware/graphics/composer/2.4/IComposerClient.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

#include <stats_event.h>
#include <stats_pull_atom_callback.h>
#include <statslog.h>
#include <timestatsproto/TimeStatsHelper.h>
#include <timestatsproto/TimeStatsProtoHeader.h>
#include <ui/FenceTime.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <variant>

using namespace android::surfaceflinger;

namespace android {

class TimeStats {
public:
    virtual ~TimeStats() = default;

    // Called once boot has been finished to perform additional capabilities,
    // e.g. registration to statsd.
    virtual void onBootFinished() = 0;

    virtual void parseArgs(bool asProto, const Vector<String16>& args, std::string& result) = 0;
    virtual bool isEnabled() = 0;
    virtual std::string miniDump() = 0;

    virtual void incrementTotalFrames() = 0;
    virtual void incrementMissedFrames() = 0;
    virtual void incrementClientCompositionFrames() = 0;
    virtual void incrementClientCompositionReusedFrames() = 0;
    // Increments the number of times the display refresh rate changed.
    virtual void incrementRefreshRateSwitches() = 0;
    // Increments the number of changes in composition strategy
    // The intention is to reflect the number of changes between hwc and gpu
    // composition, where "gpu composition" may also include mixed composition.
    virtual void incrementCompositionStrategyChanges() = 0;
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
                             nsecs_t postTime) = 0;
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
    virtual void setPresentTime(int32_t layerId, uint64_t frameNumber, nsecs_t presentTime) = 0;
    virtual void setPresentFence(int32_t layerId, uint64_t frameNumber,
                                 const std::shared_ptr<FenceTime>& presentFence) = 0;
    // Clean up the layer record
    virtual void onDestroy(int32_t layerId) = 0;
    // If SF skips or rejects a buffer, remove the corresponding TimeRecord.
    virtual void removeTimeRecord(int32_t layerId, uint64_t frameNumber) = 0;

    virtual void setPowerMode(
            hardware::graphics::composer::V2_4::IComposerClient::PowerMode powerMode) = 0;
    // Source of truth is RefrehRateStats.
    virtual void recordRefreshRate(uint32_t fps, nsecs_t duration) = 0;
    virtual void setPresentFenceGlobal(const std::shared_ptr<FenceTime>& presentFence) = 0;
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
        std::string layerName;
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

    // Delegate to the statsd service and associated APIs.
    // Production code may use this class directly, whereas unit test may define
    // a subclass for ease of testing.
    class StatsEventDelegate {
    public:
        virtual ~StatsEventDelegate() = default;
        virtual AStatsEvent* addStatsEventToPullData(AStatsEventList* data) {
            return AStatsEventList_addStatsEvent(data);
        }
        virtual void setStatsPullAtomCallback(int32_t atom_tag,
                                              AStatsManager_PullAtomMetadata* metadata,
                                              AStatsManager_PullAtomCallback callback,
                                              void* cookie) {
            return AStatsManager_setPullAtomCallback(atom_tag, metadata, callback, cookie);
        }

        virtual void clearStatsPullAtomCallback(int32_t atom_tag) {
            return AStatsManager_clearPullAtomCallback(atom_tag);
        }

        virtual void statsEventSetAtomId(AStatsEvent* event, uint32_t atom_id) {
            return AStatsEvent_setAtomId(event, atom_id);
        }

        virtual void statsEventWriteInt32(AStatsEvent* event, int32_t field) {
            return AStatsEvent_writeInt32(event, field);
        }

        virtual void statsEventWriteInt64(AStatsEvent* event, int64_t field) {
            return AStatsEvent_writeInt64(event, field);
        }

        virtual void statsEventWriteString8(AStatsEvent* event, const char* field) {
            return AStatsEvent_writeString(event, field);
        }

        virtual void statsEventWriteByteArray(AStatsEvent* event, const uint8_t* buf,
                                              size_t numBytes) {
            return AStatsEvent_writeByteArray(event, buf, numBytes);
        }

        virtual void statsEventBuild(AStatsEvent* event) { return AStatsEvent_build(event); }
    };
    // For testing only for injecting custom dependencies.
    TimeStats(std::unique_ptr<StatsEventDelegate> statsDelegate,
              std::optional<size_t> maxPulledLayers,
              std::optional<size_t> maxPulledHistogramBuckets);

    ~TimeStats() override;

    void onBootFinished() override;
    void parseArgs(bool asProto, const Vector<String16>& args, std::string& result) override;
    bool isEnabled() override;
    std::string miniDump() override;

    void incrementTotalFrames() override;
    void incrementMissedFrames() override;
    void incrementClientCompositionFrames() override;
    void incrementClientCompositionReusedFrames() override;
    void incrementRefreshRateSwitches() override;
    void incrementCompositionStrategyChanges() override;
    void recordDisplayEventConnectionCount(int32_t count) override;

    void recordFrameDuration(nsecs_t startTime, nsecs_t endTime) override;
    void recordRenderEngineDuration(nsecs_t startTime, nsecs_t endTime) override;
    void recordRenderEngineDuration(nsecs_t startTime,
                                    const std::shared_ptr<FenceTime>& readyFence) override;

    void setPostTime(int32_t layerId, uint64_t frameNumber, const std::string& layerName,
                     nsecs_t postTime) override;
    void setLatchTime(int32_t layerId, uint64_t frameNumber, nsecs_t latchTime) override;
    void incrementLatchSkipped(int32_t layerId, LatchSkipReason reason) override;
    void incrementBadDesiredPresent(int32_t layerId) override;
    void setDesiredTime(int32_t layerId, uint64_t frameNumber, nsecs_t desiredTime) override;
    void setAcquireTime(int32_t layerId, uint64_t frameNumber, nsecs_t acquireTime) override;
    void setAcquireFence(int32_t layerId, uint64_t frameNumber,
                         const std::shared_ptr<FenceTime>& acquireFence) override;
    void setPresentTime(int32_t layerId, uint64_t frameNumber, nsecs_t presentTime) override;
    void setPresentFence(int32_t layerId, uint64_t frameNumber,
                         const std::shared_ptr<FenceTime>& presentFence) override;
    // Clean up the layer record
    void onDestroy(int32_t layerId) override;
    // If SF skips or rejects a buffer, remove the corresponding TimeRecord.
    void removeTimeRecord(int32_t layerId, uint64_t frameNumber) override;

    void setPowerMode(
            hardware::graphics::composer::V2_4::IComposerClient::PowerMode powerMode) override;
    // Source of truth is RefrehRateStats.
    void recordRefreshRate(uint32_t fps, nsecs_t duration) override;
    void setPresentFenceGlobal(const std::shared_ptr<FenceTime>& presentFence) override;

    static const size_t MAX_NUM_TIME_RECORDS = 64;

private:
    static AStatsManager_PullAtomCallbackReturn pullAtomCallback(int32_t atom_tag,
                                                                 AStatsEventList* data,
                                                                 void* cookie);
    AStatsManager_PullAtomCallbackReturn populateGlobalAtom(AStatsEventList* data);
    AStatsManager_PullAtomCallbackReturn populateLayerAtom(AStatsEventList* data);
    bool recordReadyLocked(int32_t layerId, TimeRecord* timeRecord);
    void flushAvailableRecordsToStatsLocked(int32_t layerId);
    void flushPowerTimeLocked();
    void flushAvailableGlobalRecordsToStatsLocked();

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
    static const size_t MAX_NUM_LAYER_STATS = 200;
    std::unique_ptr<StatsEventDelegate> mStatsDelegate = std::make_unique<StatsEventDelegate>();
    size_t mMaxPulledLayers = 8;
    size_t mMaxPulledHistogramBuckets = 6;
};

} // namespace impl

} // namespace android
