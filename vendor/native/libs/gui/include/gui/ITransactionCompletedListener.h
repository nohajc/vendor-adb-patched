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

#include "JankInfo.h"

#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <binder/SafeInterface.h>

#include <gui/FrameTimestamps.h>
#include <ui/Fence.h>
#include <utils/Timers.h>

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <variant>

namespace android {

class ITransactionCompletedListener;
class ListenerCallbacks;

class CallbackId : public Parcelable {
public:
    int64_t id;
    enum class Type : int32_t { ON_COMPLETE, ON_COMMIT } type;

    CallbackId() {}
    CallbackId(int64_t id, Type type) : id(id), type(type) {}
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    bool operator==(const CallbackId& rhs) const { return id == rhs.id && type == rhs.type; }
};

struct CallbackIdHash {
    std::size_t operator()(const CallbackId& key) const { return std::hash<int64_t>()(key.id); }
};

class ReleaseCallbackId : public Parcelable {
public:
    static const ReleaseCallbackId INVALID_ID;

    uint64_t bufferId;
    uint64_t framenumber;
    ReleaseCallbackId() {}
    ReleaseCallbackId(uint64_t bufferId, uint64_t framenumber)
          : bufferId(bufferId), framenumber(framenumber) {}
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    bool operator==(const ReleaseCallbackId& rhs) const {
        return bufferId == rhs.bufferId && framenumber == rhs.framenumber;
    }
    bool operator!=(const ReleaseCallbackId& rhs) const { return !operator==(rhs); }
    std::string to_string() const {
        if (*this == INVALID_ID) return "INVALID_ID";

        return "bufferId:" + std::to_string(bufferId) +
                " framenumber:" + std::to_string(framenumber);
    }
};

struct ReleaseBufferCallbackIdHash {
    std::size_t operator()(const ReleaseCallbackId& key) const {
        return std::hash<uint64_t>()(key.bufferId);
    }
};

class FrameEventHistoryStats : public Parcelable {
public:
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    FrameEventHistoryStats() = default;
    FrameEventHistoryStats(uint64_t fn, const sp<Fence>& gpuCompFence, CompositorTiming compTiming,
                           nsecs_t refreshTime, nsecs_t dequeueReadyTime)
          : frameNumber(fn),
            gpuCompositionDoneFence(gpuCompFence),
            compositorTiming(compTiming),
            refreshStartTime(refreshTime),
            dequeueReadyTime(dequeueReadyTime) {}

    uint64_t frameNumber;
    sp<Fence> gpuCompositionDoneFence;
    CompositorTiming compositorTiming;
    nsecs_t refreshStartTime;
    nsecs_t dequeueReadyTime;
};

/**
 * Jank information representing SurfaceFlinger's jank classification about frames for a specific
 * surface.
 */
class JankData : public Parcelable {
public:
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    JankData();
    JankData(int64_t frameVsyncId, int32_t jankType)
          : frameVsyncId(frameVsyncId), jankType(jankType) {}

    // Identifier for the frame submitted with Transaction.setFrameTimelineVsyncId
    int64_t frameVsyncId;

    // Bitmask of janks that occurred
    int32_t jankType;
};

class SurfaceStats : public Parcelable {
public:
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    SurfaceStats() = default;
    SurfaceStats(const sp<IBinder>& sc, std::variant<nsecs_t, sp<Fence>> acquireTimeOrFence,
                 const sp<Fence>& prevReleaseFence, uint32_t hint,
                 uint32_t currentMaxAcquiredBuffersCount, FrameEventHistoryStats frameEventStats,
                 std::vector<JankData> jankData, ReleaseCallbackId previousReleaseCallbackId)
          : surfaceControl(sc),
            acquireTimeOrFence(std::move(acquireTimeOrFence)),
            previousReleaseFence(prevReleaseFence),
            transformHint(hint),
            currentMaxAcquiredBufferCount(currentMaxAcquiredBuffersCount),
            eventStats(frameEventStats),
            jankData(std::move(jankData)),
            previousReleaseCallbackId(previousReleaseCallbackId) {}

    sp<IBinder> surfaceControl;
    std::variant<nsecs_t, sp<Fence>> acquireTimeOrFence = -1;
    sp<Fence> previousReleaseFence;
    uint32_t transformHint = 0;
    uint32_t currentMaxAcquiredBufferCount = 0;
    FrameEventHistoryStats eventStats;
    std::vector<JankData> jankData;
    ReleaseCallbackId previousReleaseCallbackId;
};

class TransactionStats : public Parcelable {
public:
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    TransactionStats() = default;
    TransactionStats(const std::vector<CallbackId>& ids) : callbackIds(ids) {}
    TransactionStats(const std::unordered_set<CallbackId, CallbackIdHash>& ids)
          : callbackIds(ids.begin(), ids.end()) {}
    TransactionStats(const std::vector<CallbackId>& ids, nsecs_t latch, const sp<Fence>& present,
                     const std::vector<SurfaceStats>& surfaces)
          : callbackIds(ids), latchTime(latch), presentFence(present), surfaceStats(surfaces) {}

    std::vector<CallbackId> callbackIds;
    nsecs_t latchTime = -1;
    sp<Fence> presentFence = nullptr;
    std::vector<SurfaceStats> surfaceStats;
};

class ListenerStats : public Parcelable {
public:
    status_t writeToParcel(Parcel* output) const override;
    status_t readFromParcel(const Parcel* input) override;

    static ListenerStats createEmpty(
            const sp<IBinder>& listener,
            const std::unordered_set<CallbackId, CallbackIdHash>& callbackIds);

    sp<IBinder> listener;
    std::vector<TransactionStats> transactionStats;
};

class ITransactionCompletedListener : public IInterface {
public:
    DECLARE_META_INTERFACE(TransactionCompletedListener)

    virtual void onTransactionCompleted(ListenerStats stats) = 0;

    virtual void onReleaseBuffer(ReleaseCallbackId callbackId, sp<Fence> releaseFence,
                                 uint32_t currentMaxAcquiredBufferCount) = 0;
    virtual void onTransactionQueueStalled() = 0;
};

class BnTransactionCompletedListener : public SafeBnInterface<ITransactionCompletedListener> {
public:
    BnTransactionCompletedListener()
          : SafeBnInterface<ITransactionCompletedListener>("BnTransactionCompletedListener") {}

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                        uint32_t flags = 0) override;
};

class ListenerCallbacks {
public:
    ListenerCallbacks(const sp<IBinder>& listener,
                      const std::unordered_set<CallbackId, CallbackIdHash>& callbacks)
          : transactionCompletedListener(listener),
            callbackIds(callbacks.begin(), callbacks.end()) {}

    ListenerCallbacks(const sp<IBinder>& listener, const std::vector<CallbackId>& ids)
          : transactionCompletedListener(listener), callbackIds(ids) {}

    bool operator==(const ListenerCallbacks& rhs) const {
        if (transactionCompletedListener != rhs.transactionCompletedListener) {
            return false;
        }
        if (callbackIds.empty()) {
            return rhs.callbackIds.empty();
        }
        return callbackIds.front().id == rhs.callbackIds.front().id;
    }

    // Returns a new ListenerCallbacks filtered by type
    ListenerCallbacks filter(CallbackId::Type type) const;

    sp<IBinder> transactionCompletedListener;
    std::vector<CallbackId> callbackIds;
};

struct IListenerHash {
    std::size_t operator()(const sp<IBinder>& strongPointer) const {
        return std::hash<IBinder*>{}(strongPointer.get());
    }
};

struct CallbackIdsHash {
    // CallbackId vectors have several properties that let us get away with this simple hash.
    // 1) CallbackIds are never 0 so if something has gone wrong and our CallbackId vector is
    // empty we can still hash 0.
    // 2) CallbackId vectors for the same listener either are identical or contain none of the
    // same members. It is sufficient to just check the first CallbackId in the vectors. If
    // they match, they are the same. If they do not match, they are not the same.
    std::size_t operator()(const std::vector<CallbackId>& callbackIds) const {
        return std::hash<int64_t>{}((callbackIds.empty()) ? 0 : callbackIds.front().id);
    }
};

struct ListenerCallbacksHash {
    std::size_t HashCombine(size_t value1, size_t value2) const {
        return value1 ^ (value2 + 0x9e3779b9 + (value1 << 6) + (value1 >> 2));
    }

    std::size_t operator()(const ListenerCallbacks& listenerCallbacks) const {
        struct IListenerHash listenerHasher;
        struct CallbackIdsHash callbackIdsHasher;

        std::size_t listenerHash = listenerHasher(listenerCallbacks.transactionCompletedListener);
        std::size_t callbackIdsHash = callbackIdsHasher(listenerCallbacks.callbackIds);

        return HashCombine(listenerHash, callbackIdsHash);
    }
};

} // namespace android
