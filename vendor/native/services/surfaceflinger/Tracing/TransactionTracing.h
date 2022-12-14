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

#pragma once

#include <android-base/thread_annotations.h>
#include <layerproto/TransactionProto.h>
#include <utils/Errors.h>
#include <utils/Timers.h>

#include <memory>
#include <mutex>
#include <thread>

#include "RingBuffer.h"
#include "LocklessStack.h"
#include "TransactionProtoParser.h"

using namespace android::surfaceflinger;

namespace android {

class SurfaceFlinger;
class TransactionTracingTest;

/*
 * Records all committed transactions into a ring bufffer.
 *
 * Transactions come in via the binder thread. They are serialized to proto
 * and stored in a map using the transaction id as key. Main thread will
 * pass the list of transaction ids that are committed every vsync and notify
 * the tracing thread. The tracing thread will then wake up and add the
 * committed transactions to the ring buffer.
 *
 * When generating SF dump state, we will flush the buffer to a file which
 * will then be included in the bugreport.
 *
 */
class TransactionTracing {
public:
    TransactionTracing();
    ~TransactionTracing();

    void addQueuedTransaction(const TransactionState&);
    void addCommittedTransactions(std::vector<TransactionState>& transactions, int64_t vsyncId);
    status_t writeToFile(std::string filename = FILE_NAME);
    void setBufferSize(size_t bufferSizeInBytes);
    void onLayerAdded(BBinder* layerHandle, int layerId, const std::string& name, uint32_t flags,
                      int parentId);
    void onMirrorLayerAdded(BBinder* layerHandle, int layerId, const std::string& name,
                            int mirrorFromId);
    void onLayerRemoved(int layerId);
    void onHandleRemoved(BBinder* layerHandle);
    void dump(std::string&) const;
    static constexpr auto CONTINUOUS_TRACING_BUFFER_SIZE = 512 * 1024;
    static constexpr auto ACTIVE_TRACING_BUFFER_SIZE = 100 * 1024 * 1024;

private:
    friend class TransactionTracingTest;

    static constexpr auto FILE_NAME = "/data/misc/wmtrace/transactions_trace.winscope";

    mutable std::mutex mTraceLock;
    RingBuffer<proto::TransactionTraceFile, proto::TransactionTraceEntry> mBuffer
            GUARDED_BY(mTraceLock);
    size_t mBufferSizeInBytes GUARDED_BY(mTraceLock) = CONTINUOUS_TRACING_BUFFER_SIZE;
    std::unordered_map<uint64_t, proto::TransactionState> mQueuedTransactions
            GUARDED_BY(mTraceLock);
    LocklessStack<proto::TransactionState> mTransactionQueue;
    nsecs_t mStartingTimestamp GUARDED_BY(mTraceLock);
    std::vector<proto::LayerCreationArgs> mCreatedLayers GUARDED_BY(mTraceLock);
    std::unordered_map<BBinder* /* layerHandle */, int32_t /* layerId */> mLayerHandles
            GUARDED_BY(mTraceLock);
    std::vector<int32_t /* layerId */> mRemovedLayerHandles GUARDED_BY(mTraceLock);
    std::map<int32_t /* layerId */, TracingLayerState> mStartingStates GUARDED_BY(mTraceLock);
    TransactionProtoParser mProtoParser GUARDED_BY(mTraceLock);
    // Parses the transaction to proto without holding any tracing locks so we can generate proto
    // in the binder thread without any contention.
    TransactionProtoParser mLockfreeProtoParser;

    // We do not want main thread to block so main thread will try to acquire mMainThreadLock,
    // otherwise will push data to temporary container.
    std::mutex mMainThreadLock;
    std::thread mThread GUARDED_BY(mMainThreadLock);
    bool mDone GUARDED_BY(mMainThreadLock) = false;
    std::condition_variable mTransactionsAvailableCv;
    std::condition_variable mTransactionsAddedToBufferCv;
    struct CommittedTransactions {
        std::vector<uint64_t> transactionIds;
        int64_t vsyncId;
        int64_t timestamp;
    };
    std::vector<CommittedTransactions> mCommittedTransactions GUARDED_BY(mMainThreadLock);
    std::vector<CommittedTransactions> mPendingTransactions; // only accessed by main thread

    std::vector<int32_t /* layerId */> mRemovedLayers GUARDED_BY(mMainThreadLock);
    std::vector<int32_t /* layerId */> mPendingRemovedLayers; // only accessed by main thread

    proto::TransactionTraceFile createTraceFileProto() const;
    void loop();
    void addEntry(const std::vector<CommittedTransactions>& committedTransactions,
                  const std::vector<int32_t>& removedLayers) EXCLUDES(mTraceLock);
    int32_t getLayerIdLocked(const sp<IBinder>& layerHandle) REQUIRES(mTraceLock);
    void tryPushToTracingThread() EXCLUDES(mMainThreadLock);
    void addStartingStateToProtoLocked(proto::TransactionTraceFile& proto) REQUIRES(mTraceLock);
    void updateStartingStateLocked(const proto::TransactionTraceEntry& entry) REQUIRES(mTraceLock);

    // TEST
    // Wait until all the committed transactions for the specified vsync id are added to the buffer.
    void flush(int64_t vsyncId) EXCLUDES(mMainThreadLock);
    // Return buffer contents as trace file proto
    proto::TransactionTraceFile writeToProto() EXCLUDES(mMainThreadLock);
};

} // namespace android
