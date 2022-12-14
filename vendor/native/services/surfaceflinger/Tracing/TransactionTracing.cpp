/*
 * Copyright 2021 The Android Open Source Project
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
#define LOG_TAG "TransactionTracing"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <android-base/stringprintf.h>
#include <log/log.h>
#include <utils/SystemClock.h>
#include <utils/Trace.h>

#include "ClientCache.h"
#include "TransactionTracing.h"
#include "renderengine/ExternalTexture.h"

namespace android {

// Keeps the binder address as the layer id so we can avoid holding the tracing lock in the
// binder thread.
class FlatDataMapper : public TransactionProtoParser::FlingerDataMapper {
public:
    virtual int64_t getLayerId(const sp<IBinder>& layerHandle) const {
        if (layerHandle == nullptr) {
            return -1;
        }

        return reinterpret_cast<int64_t>(layerHandle->localBinder());
    }

    void getGraphicBufferPropertiesFromCache(client_cache_t cachedBuffer, uint64_t* outBufferId,
                                             uint32_t* outWidth, uint32_t* outHeight,
                                             int32_t* outPixelFormat,
                                             uint64_t* outUsage) const override {
        std::shared_ptr<renderengine::ExternalTexture> buffer =
                ClientCache::getInstance().get(cachedBuffer);
        if (!buffer || !buffer->getBuffer()) {
            *outBufferId = 0;
            *outWidth = 0;
            *outHeight = 0;
            *outPixelFormat = 0;
            *outUsage = 0;
            return;
        }

        *outBufferId = buffer->getId();
        *outWidth = buffer->getWidth();
        *outHeight = buffer->getHeight();
        *outPixelFormat = buffer->getPixelFormat();
        *outUsage = buffer->getUsage();
        return;
    }
};

class FlingerDataMapper : public FlatDataMapper {
    std::unordered_map<BBinder* /* layerHandle */, int32_t /* layerId */>& mLayerHandles;

public:
    FlingerDataMapper(std::unordered_map<BBinder* /* handle */, int32_t /* id */>& layerHandles)
          : mLayerHandles(layerHandles) {}

    int64_t getLayerId(const sp<IBinder>& layerHandle) const override {
        if (layerHandle == nullptr) {
            return -1;
        }
        return getLayerId(layerHandle->localBinder());
    }

    int64_t getLayerId(BBinder* localBinder) const {
        auto it = mLayerHandles.find(localBinder);
        if (it == mLayerHandles.end()) {
            ALOGW("Could not find layer handle %p", localBinder);
            return -1;
        }
        return it->second;
    }
};

TransactionTracing::TransactionTracing()
      : mProtoParser(std::make_unique<FlingerDataMapper>(mLayerHandles)),
        mLockfreeProtoParser(std::make_unique<FlatDataMapper>()) {
    std::scoped_lock lock(mTraceLock);

    mBuffer.setSize(mBufferSizeInBytes);
    mStartingTimestamp = systemTime();
    {
        std::scoped_lock lock(mMainThreadLock);
        mThread = std::thread(&TransactionTracing::loop, this);
    }
}

TransactionTracing::~TransactionTracing() {
    std::thread thread;
    {
        std::scoped_lock lock(mMainThreadLock);
        mDone = true;
        mTransactionsAvailableCv.notify_all();
        thread = std::move(mThread);
    }
    if (thread.joinable()) {
        thread.join();
    }

    writeToFile();
}

status_t TransactionTracing::writeToFile(std::string filename) {
    std::scoped_lock lock(mTraceLock);
    proto::TransactionTraceFile fileProto = createTraceFileProto();
    addStartingStateToProtoLocked(fileProto);
    return mBuffer.writeToFile(fileProto, filename);
}

void TransactionTracing::setBufferSize(size_t bufferSizeInBytes) {
    std::scoped_lock lock(mTraceLock);
    mBufferSizeInBytes = bufferSizeInBytes;
    mBuffer.setSize(mBufferSizeInBytes);
}

proto::TransactionTraceFile TransactionTracing::createTraceFileProto() const {
    proto::TransactionTraceFile proto;
    proto.set_magic_number(uint64_t(proto::TransactionTraceFile_MagicNumber_MAGIC_NUMBER_H) << 32 |
                           proto::TransactionTraceFile_MagicNumber_MAGIC_NUMBER_L);
    return proto;
}

void TransactionTracing::dump(std::string& result) const {
    std::scoped_lock lock(mTraceLock);
    base::StringAppendF(&result,
                        "  queued transactions=%zu created layers=%zu handles=%zu states=%zu\n",
                        mQueuedTransactions.size(), mCreatedLayers.size(), mLayerHandles.size(),
                        mStartingStates.size());
    mBuffer.dump(result);
}

void TransactionTracing::addQueuedTransaction(const TransactionState& transaction) {
    proto::TransactionState* state =
            new proto::TransactionState(mLockfreeProtoParser.toProto(transaction));
    mTransactionQueue.push(state);
}

void TransactionTracing::addCommittedTransactions(std::vector<TransactionState>& transactions,
                                                  int64_t vsyncId) {
    CommittedTransactions committedTransactions;
    committedTransactions.vsyncId = vsyncId;
    committedTransactions.timestamp = systemTime();
    committedTransactions.transactionIds.reserve(transactions.size());
    for (const auto& transaction : transactions) {
        committedTransactions.transactionIds.emplace_back(transaction.id);
    }

    mPendingTransactions.emplace_back(committedTransactions);
    tryPushToTracingThread();
}

void TransactionTracing::loop() {
    while (true) {
        std::vector<CommittedTransactions> committedTransactions;
        std::vector<int32_t> removedLayers;
        {
            std::unique_lock<std::mutex> lock(mMainThreadLock);
            base::ScopedLockAssertion assumeLocked(mMainThreadLock);
            mTransactionsAvailableCv.wait(lock, [&]() REQUIRES(mMainThreadLock) {
                return mDone || !mCommittedTransactions.empty();
            });
            if (mDone) {
                mCommittedTransactions.clear();
                mRemovedLayers.clear();
                break;
            }

            removedLayers = std::move(mRemovedLayers);
            mRemovedLayers.clear();
            committedTransactions = std::move(mCommittedTransactions);
            mCommittedTransactions.clear();
        } // unlock mMainThreadLock

        if (!committedTransactions.empty() || !removedLayers.empty()) {
            addEntry(committedTransactions, removedLayers);
        }
    }
}

void TransactionTracing::addEntry(const std::vector<CommittedTransactions>& committedTransactions,
                                  const std::vector<int32_t>& removedLayers) {
    ATRACE_CALL();
    std::scoped_lock lock(mTraceLock);
    std::vector<std::string> removedEntries;
    proto::TransactionTraceEntry entryProto;

    while (auto incomingTransaction = mTransactionQueue.pop()) {
        auto transaction = *incomingTransaction;
        int32_t layerCount = transaction.layer_changes_size();
        for (int i = 0; i < layerCount; i++) {
            auto layer = transaction.mutable_layer_changes(i);
            layer->set_layer_id(
                mProtoParser.mMapper->getLayerId(reinterpret_cast<BBinder*>(layer->layer_id())));
            if ((layer->what() & layer_state_t::eReparent) && layer->parent_id() != -1) {
                layer->set_parent_id(
                    mProtoParser.mMapper->getLayerId(reinterpret_cast<BBinder*>(
                        layer->parent_id())));
            }

            if ((layer->what() & layer_state_t::eRelativeLayerChanged) &&
                layer->relative_parent_id() != -1) {
                layer->set_relative_parent_id(
                    mProtoParser.mMapper->getLayerId(reinterpret_cast<BBinder*>(
                        layer->relative_parent_id())));
            }

            if (layer->has_window_info_handle() &&
                layer->window_info_handle().crop_layer_id() != -1) {
                auto input = layer->mutable_window_info_handle();
                input->set_crop_layer_id(
                        mProtoParser.mMapper->getLayerId(reinterpret_cast<BBinder*>(
                            input->crop_layer_id())));
            }
        }
        mQueuedTransactions[incomingTransaction->transaction_id()] = transaction;
        delete incomingTransaction;
    }
    for (const CommittedTransactions& entry : committedTransactions) {
        entryProto.set_elapsed_realtime_nanos(entry.timestamp);
        entryProto.set_vsync_id(entry.vsyncId);
        entryProto.mutable_added_layers()->Reserve(static_cast<int32_t>(mCreatedLayers.size()));
        for (auto& newLayer : mCreatedLayers) {
            entryProto.mutable_added_layers()->Add(std::move(newLayer));
        }
        entryProto.mutable_removed_layers()->Reserve(static_cast<int32_t>(removedLayers.size()));
        for (auto& removedLayer : removedLayers) {
            entryProto.mutable_removed_layers()->Add(removedLayer);
        }
        mCreatedLayers.clear();
        entryProto.mutable_transactions()->Reserve(
                static_cast<int32_t>(entry.transactionIds.size()));
        for (const uint64_t& id : entry.transactionIds) {
            auto it = mQueuedTransactions.find(id);
            if (it != mQueuedTransactions.end()) {
                entryProto.mutable_transactions()->Add(std::move(it->second));
                mQueuedTransactions.erase(it);
            } else {
                ALOGW("Could not find transaction id %" PRIu64, id);
            }
        }

        std::string serializedProto;
        entryProto.SerializeToString(&serializedProto);
        entryProto.Clear();
        std::vector<std::string> entries = mBuffer.emplace(std::move(serializedProto));
        removedEntries.reserve(removedEntries.size() + entries.size());
        removedEntries.insert(removedEntries.end(), std::make_move_iterator(entries.begin()),
                              std::make_move_iterator(entries.end()));

        entryProto.mutable_removed_layer_handles()->Reserve(
                static_cast<int32_t>(mRemovedLayerHandles.size()));
        for (auto& handle : mRemovedLayerHandles) {
            entryProto.mutable_removed_layer_handles()->Add(handle);
        }
        mRemovedLayerHandles.clear();
    }

    proto::TransactionTraceEntry removedEntryProto;
    for (const std::string& removedEntry : removedEntries) {
        removedEntryProto.ParseFromString(removedEntry);
        updateStartingStateLocked(removedEntryProto);
        removedEntryProto.Clear();
    }
    mTransactionsAddedToBufferCv.notify_one();
}

void TransactionTracing::flush(int64_t vsyncId) {
    while (!mPendingTransactions.empty() || !mPendingRemovedLayers.empty()) {
        tryPushToTracingThread();
    }
    std::unique_lock<std::mutex> lock(mTraceLock);
    base::ScopedLockAssertion assumeLocked(mTraceLock);
    mTransactionsAddedToBufferCv.wait(lock, [&]() REQUIRES(mTraceLock) {
        proto::TransactionTraceEntry entry;
        if (mBuffer.used() > 0) {
            entry.ParseFromString(mBuffer.back());
        }
        return mBuffer.used() > 0 && entry.vsync_id() >= vsyncId;
    });
}

void TransactionTracing::onLayerAdded(BBinder* layerHandle, int layerId, const std::string& name,
                                      uint32_t flags, int parentId) {
    std::scoped_lock lock(mTraceLock);
    TracingLayerCreationArgs args{layerId, name, flags, parentId, -1 /* mirrorFromId */};
    if (mLayerHandles.find(layerHandle) != mLayerHandles.end()) {
        ALOGW("Duplicate handles found. %p", layerHandle);
    }
    mLayerHandles[layerHandle] = layerId;
    mCreatedLayers.push_back(mProtoParser.toProto(args));
}

void TransactionTracing::onMirrorLayerAdded(BBinder* layerHandle, int layerId,
                                            const std::string& name, int mirrorFromId) {
    std::scoped_lock lock(mTraceLock);
    TracingLayerCreationArgs args{layerId, name, 0 /* flags */, -1 /* parentId */, mirrorFromId};
    if (mLayerHandles.find(layerHandle) != mLayerHandles.end()) {
        ALOGW("Duplicate handles found. %p", layerHandle);
    }
    mLayerHandles[layerHandle] = layerId;
    mCreatedLayers.emplace_back(mProtoParser.toProto(args));
}

void TransactionTracing::onLayerRemoved(int32_t layerId) {
    mPendingRemovedLayers.emplace_back(layerId);
    tryPushToTracingThread();
}

void TransactionTracing::onHandleRemoved(BBinder* layerHandle) {
    std::scoped_lock lock(mTraceLock);
    auto it = mLayerHandles.find(layerHandle);
    if (it == mLayerHandles.end()) {
        ALOGW("handle not found. %p", layerHandle);
        return;
    }

    mRemovedLayerHandles.push_back(it->second);
    mLayerHandles.erase(it);
}

void TransactionTracing::tryPushToTracingThread() {
    // Try to acquire the lock from main thread.
    if (mMainThreadLock.try_lock()) {
        // We got the lock! Collect any pending transactions and continue.
        mCommittedTransactions.insert(mCommittedTransactions.end(),
                                      std::make_move_iterator(mPendingTransactions.begin()),
                                      std::make_move_iterator(mPendingTransactions.end()));
        mPendingTransactions.clear();
        mRemovedLayers.insert(mRemovedLayers.end(), mPendingRemovedLayers.begin(),
                              mPendingRemovedLayers.end());
        mPendingRemovedLayers.clear();
        mTransactionsAvailableCv.notify_one();
        mMainThreadLock.unlock();
    } else {
        ALOGV("Couldn't get lock");
    }
}

void TransactionTracing::updateStartingStateLocked(
        const proto::TransactionTraceEntry& removedEntry) {
    mStartingTimestamp = removedEntry.elapsed_realtime_nanos();
    // Keep track of layer starting state so we can reconstruct the layer state as we purge
    // transactions from the buffer.
    for (const proto::LayerCreationArgs& addedLayer : removedEntry.added_layers()) {
        TracingLayerState& startingState = mStartingStates[addedLayer.layer_id()];
        startingState.layerId = addedLayer.layer_id();
        mProtoParser.fromProto(addedLayer, startingState.args);
    }

    // Merge layer states to starting transaction state.
    for (const proto::TransactionState& transaction : removedEntry.transactions()) {
        for (const proto::LayerState& layerState : transaction.layer_changes()) {
            auto it = mStartingStates.find((int32_t)layerState.layer_id());
            if (it == mStartingStates.end()) {
                ALOGW("Could not find layer id %d", (int32_t)layerState.layer_id());
                continue;
            }
            mProtoParser.mergeFromProto(layerState, it->second);
        }
    }

    // Clean up stale starting states since the layer has been removed and the buffer does not
    // contain any references to the layer.
    for (const int32_t removedLayerId : removedEntry.removed_layers()) {
        mStartingStates.erase(removedLayerId);
    }
}

void TransactionTracing::addStartingStateToProtoLocked(proto::TransactionTraceFile& proto) {
    if (mStartingStates.size() == 0) {
        return;
    }

    proto::TransactionTraceEntry* entryProto = proto.add_entry();
    entryProto->set_elapsed_realtime_nanos(mStartingTimestamp);
    entryProto->set_vsync_id(0);

    entryProto->mutable_added_layers()->Reserve(static_cast<int32_t>(mStartingStates.size()));
    for (auto& [layerId, state] : mStartingStates) {
        entryProto->mutable_added_layers()->Add(mProtoParser.toProto(state.args));
    }

    proto::TransactionState transactionProto = mProtoParser.toProto(mStartingStates);
    transactionProto.set_vsync_id(0);
    transactionProto.set_post_time(mStartingTimestamp);
    entryProto->mutable_transactions()->Add(std::move(transactionProto));
}

proto::TransactionTraceFile TransactionTracing::writeToProto() {
    std::scoped_lock<std::mutex> lock(mTraceLock);
    proto::TransactionTraceFile proto = createTraceFileProto();
    addStartingStateToProtoLocked(proto);
    mBuffer.writeToProto(proto);
    return proto;
}

} // namespace android
