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

#define LOG_TAG "ITransactionCompletedListener"
//#define LOG_NDEBUG 0

#include <gui/ISurfaceComposer.h>
#include <gui/ITransactionCompletedListener.h>
#include <gui/LayerState.h>
#include <private/gui/ParcelUtils.h>

namespace android {

namespace { // Anonymous

enum class Tag : uint32_t {
    ON_TRANSACTION_COMPLETED = IBinder::FIRST_CALL_TRANSACTION,
    ON_RELEASE_BUFFER,
    ON_TRANSACTION_QUEUE_STALLED,
    LAST = ON_RELEASE_BUFFER,
};

} // Anonymous namespace

status_t FrameEventHistoryStats::writeToParcel(Parcel* output) const {
    status_t err = output->writeUint64(frameNumber);
    if (err != NO_ERROR) return err;

    if (gpuCompositionDoneFence) {
        err = output->writeBool(true);
        if (err != NO_ERROR) return err;

        err = output->write(*gpuCompositionDoneFence);
    } else {
        err = output->writeBool(false);
    }
    if (err != NO_ERROR) return err;

    err = output->writeInt64(compositorTiming.deadline);
    if (err != NO_ERROR) return err;

    err = output->writeInt64(compositorTiming.interval);
    if (err != NO_ERROR) return err;

    err = output->writeInt64(compositorTiming.presentLatency);
    if (err != NO_ERROR) return err;

    err = output->writeInt64(refreshStartTime);
    if (err != NO_ERROR) return err;

    err = output->writeInt64(dequeueReadyTime);
    return err;
}

status_t FrameEventHistoryStats::readFromParcel(const Parcel* input) {
    status_t err = input->readUint64(&frameNumber);
    if (err != NO_ERROR) return err;

    bool hasFence = false;
    err = input->readBool(&hasFence);
    if (err != NO_ERROR) return err;

    if (hasFence) {
        gpuCompositionDoneFence = new Fence();
        err = input->read(*gpuCompositionDoneFence);
        if (err != NO_ERROR) return err;
    }

    err = input->readInt64(&(compositorTiming.deadline));
    if (err != NO_ERROR) return err;

    err = input->readInt64(&(compositorTiming.interval));
    if (err != NO_ERROR) return err;

    err = input->readInt64(&(compositorTiming.presentLatency));
    if (err != NO_ERROR) return err;

    err = input->readInt64(&refreshStartTime);
    if (err != NO_ERROR) return err;

    err = input->readInt64(&dequeueReadyTime);
    return err;
}

JankData::JankData()
      : frameVsyncId(FrameTimelineInfo::INVALID_VSYNC_ID), jankType(JankType::None) {}

status_t JankData::writeToParcel(Parcel* output) const {
    SAFE_PARCEL(output->writeInt64, frameVsyncId);
    SAFE_PARCEL(output->writeInt32, jankType);
    return NO_ERROR;
}

status_t JankData::readFromParcel(const Parcel* input) {
    SAFE_PARCEL(input->readInt64, &frameVsyncId);
    SAFE_PARCEL(input->readInt32, &jankType);
    return NO_ERROR;
}

status_t SurfaceStats::writeToParcel(Parcel* output) const {
    SAFE_PARCEL(output->writeStrongBinder, surfaceControl);
    if (const auto* acquireFence = std::get_if<sp<Fence>>(&acquireTimeOrFence)) {
        SAFE_PARCEL(output->writeBool, true);
        SAFE_PARCEL(output->write, **acquireFence);
    } else {
        SAFE_PARCEL(output->writeBool, false);
        SAFE_PARCEL(output->writeInt64, std::get<nsecs_t>(acquireTimeOrFence));
    }

    if (previousReleaseFence) {
        SAFE_PARCEL(output->writeBool, true);
        SAFE_PARCEL(output->write, *previousReleaseFence);
    } else {
        SAFE_PARCEL(output->writeBool, false);
    }
    SAFE_PARCEL(output->writeUint32, transformHint);
    SAFE_PARCEL(output->writeUint32, currentMaxAcquiredBufferCount);
    SAFE_PARCEL(output->writeParcelable, eventStats);
    SAFE_PARCEL(output->writeInt32, static_cast<int32_t>(jankData.size()));
    for (const auto& data : jankData) {
        SAFE_PARCEL(output->writeParcelable, data);
    }
    SAFE_PARCEL(output->writeParcelable, previousReleaseCallbackId);
    return NO_ERROR;
}

status_t SurfaceStats::readFromParcel(const Parcel* input) {
    SAFE_PARCEL(input->readStrongBinder, &surfaceControl);

    bool hasFence = false;
    SAFE_PARCEL(input->readBool, &hasFence);
    if (hasFence) {
        acquireTimeOrFence = sp<Fence>::make();
        SAFE_PARCEL(input->read, *std::get<sp<Fence>>(acquireTimeOrFence));
    } else {
        nsecs_t acquireTime;
        SAFE_PARCEL(input->readInt64, &acquireTime);
        acquireTimeOrFence = acquireTime;
    }

    SAFE_PARCEL(input->readBool, &hasFence);
    if (hasFence) {
        previousReleaseFence = new Fence();
        SAFE_PARCEL(input->read, *previousReleaseFence);
    }
    SAFE_PARCEL(input->readUint32, &transformHint);
    SAFE_PARCEL(input->readUint32, &currentMaxAcquiredBufferCount);
    SAFE_PARCEL(input->readParcelable, &eventStats);

    int32_t jankData_size = 0;
    SAFE_PARCEL_READ_SIZE(input->readInt32, &jankData_size, input->dataSize());
    for (int i = 0; i < jankData_size; i++) {
        JankData data;
        SAFE_PARCEL(input->readParcelable, &data);
        jankData.push_back(data);
    }
    SAFE_PARCEL(input->readParcelable, &previousReleaseCallbackId);
    return NO_ERROR;
}

status_t TransactionStats::writeToParcel(Parcel* output) const {
    status_t err = output->writeParcelableVector(callbackIds);
    if (err != NO_ERROR) {
        return err;
    }
    err = output->writeInt64(latchTime);
    if (err != NO_ERROR) {
        return err;
    }
    if (presentFence) {
        err = output->writeBool(true);
        if (err != NO_ERROR) {
            return err;
        }
        err = output->write(*presentFence);
    } else {
        err = output->writeBool(false);
    }
    if (err != NO_ERROR) {
        return err;
    }
    return output->writeParcelableVector(surfaceStats);
}

status_t TransactionStats::readFromParcel(const Parcel* input) {
    status_t err = input->readParcelableVector(&callbackIds);
    if (err != NO_ERROR) {
        return err;
    }
    err = input->readInt64(&latchTime);
    if (err != NO_ERROR) {
        return err;
    }
    bool hasFence = false;
    err = input->readBool(&hasFence);
    if (err != NO_ERROR) {
        return err;
    }
    if (hasFence) {
        presentFence = new Fence();
        err = input->read(*presentFence);
        if (err != NO_ERROR) {
            return err;
        }
    }
    return input->readParcelableVector(&surfaceStats);
}

status_t ListenerStats::writeToParcel(Parcel* output) const {
    status_t err = output->writeInt32(static_cast<int32_t>(transactionStats.size()));
    if (err != NO_ERROR) {
        return err;
    }
    for (const auto& stats : transactionStats) {
        err = output->writeParcelable(stats);
        if (err != NO_ERROR) {
            return err;
        }
    }
    return NO_ERROR;
}

status_t ListenerStats::readFromParcel(const Parcel* input) {
    int32_t transactionStats_size = input->readInt32();

    for (int i = 0; i < transactionStats_size; i++) {
        TransactionStats stats;
        status_t err = input->readParcelable(&stats);
        if (err != NO_ERROR) {
            return err;
        }
        transactionStats.push_back(stats);
    }
    return NO_ERROR;
}

ListenerStats ListenerStats::createEmpty(
        const sp<IBinder>& listener,
        const std::unordered_set<CallbackId, CallbackIdHash>& callbackIds) {
    ListenerStats listenerStats;
    listenerStats.listener = listener;
    listenerStats.transactionStats.emplace_back(callbackIds);

    return listenerStats;
}

class BpTransactionCompletedListener : public SafeBpInterface<ITransactionCompletedListener> {
public:
    explicit BpTransactionCompletedListener(const sp<IBinder>& impl)
          : SafeBpInterface<ITransactionCompletedListener>(impl, "BpTransactionCompletedListener") {
    }

    ~BpTransactionCompletedListener() override;

    void onTransactionCompleted(ListenerStats stats) override {
        callRemoteAsync<decltype(&ITransactionCompletedListener::
                                         onTransactionCompleted)>(Tag::ON_TRANSACTION_COMPLETED,
                                                                  stats);
    }

    void onReleaseBuffer(ReleaseCallbackId callbackId, sp<Fence> releaseFence,
                         uint32_t currentMaxAcquiredBufferCount) override {
        callRemoteAsync<decltype(
                &ITransactionCompletedListener::onReleaseBuffer)>(Tag::ON_RELEASE_BUFFER,
                                                                  callbackId, releaseFence,
                                                                  currentMaxAcquiredBufferCount);
    }

    void onTransactionQueueStalled() override {
        callRemoteAsync<decltype(&ITransactionCompletedListener::onTransactionQueueStalled)>(
            Tag::ON_TRANSACTION_QUEUE_STALLED);
    }
};

// Out-of-line virtual method definitions to trigger vtable emission in this translation unit (see
// clang warning -Wweak-vtables)
BpTransactionCompletedListener::~BpTransactionCompletedListener() = default;

IMPLEMENT_META_INTERFACE(TransactionCompletedListener, "android.gui.ITransactionComposerListener");

status_t BnTransactionCompletedListener::onTransact(uint32_t code, const Parcel& data,
                                                    Parcel* reply, uint32_t flags) {
    if (code < IBinder::FIRST_CALL_TRANSACTION || code > static_cast<uint32_t>(Tag::LAST)) {
        return BBinder::onTransact(code, data, reply, flags);
    }
    auto tag = static_cast<Tag>(code);
    switch (tag) {
        case Tag::ON_TRANSACTION_COMPLETED:
            return callLocalAsync(data, reply,
                                  &ITransactionCompletedListener::onTransactionCompleted);
        case Tag::ON_RELEASE_BUFFER:
            return callLocalAsync(data, reply, &ITransactionCompletedListener::onReleaseBuffer);
        case Tag::ON_TRANSACTION_QUEUE_STALLED:
            return callLocalAsync(data, reply,
                                  &ITransactionCompletedListener::onTransactionQueueStalled);
    }
}

ListenerCallbacks ListenerCallbacks::filter(CallbackId::Type type) const {
    std::vector<CallbackId> filteredCallbackIds;
    for (const auto& callbackId : callbackIds) {
        if (callbackId.type == type) {
            filteredCallbackIds.push_back(callbackId);
        }
    }
    return ListenerCallbacks(transactionCompletedListener, filteredCallbackIds);
}

status_t CallbackId::writeToParcel(Parcel* output) const {
    SAFE_PARCEL(output->writeInt64, id);
    SAFE_PARCEL(output->writeInt32, static_cast<int32_t>(type));
    return NO_ERROR;
}

status_t CallbackId::readFromParcel(const Parcel* input) {
    SAFE_PARCEL(input->readInt64, &id);
    int32_t typeAsInt;
    SAFE_PARCEL(input->readInt32, &typeAsInt);
    type = static_cast<CallbackId::Type>(typeAsInt);
    return NO_ERROR;
}

status_t ReleaseCallbackId::writeToParcel(Parcel* output) const {
    SAFE_PARCEL(output->writeUint64, bufferId);
    SAFE_PARCEL(output->writeUint64, framenumber);
    return NO_ERROR;
}

status_t ReleaseCallbackId::readFromParcel(const Parcel* input) {
    SAFE_PARCEL(input->readUint64, &bufferId);
    SAFE_PARCEL(input->readUint64, &framenumber);
    return NO_ERROR;
}

const ReleaseCallbackId ReleaseCallbackId::INVALID_ID = ReleaseCallbackId(0, 0);

}; // namespace android
