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

#include <condition_variable>
#include <deque>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <android-base/thread_annotations.h>
#include <binder/IBinder.h>
#include <compositionengine/FenceResult.h>
#include <ftl/future.h>
#include <gui/ITransactionCompletedListener.h>
#include <ui/Fence.h>

namespace android {

class CallbackHandle : public RefBase {
public:
    CallbackHandle(const sp<IBinder>& transactionListener, const std::vector<CallbackId>& ids,
                   const sp<IBinder>& sc);

    sp<IBinder> listener;
    std::vector<CallbackId> callbackIds;
    wp<IBinder> surfaceControl;

    bool releasePreviousBuffer = false;
    std::string name;
    sp<Fence> previousReleaseFence;
    std::vector<ftl::SharedFuture<FenceResult>> previousReleaseFences;
    std::variant<nsecs_t, sp<Fence>> acquireTimeOrFence = -1;
    nsecs_t latchTime = -1;
    uint32_t transformHint = 0;
    uint32_t currentMaxAcquiredBufferCount = 0;
    std::shared_ptr<FenceTime> gpuCompositionDoneFence{FenceTime::NO_FENCE};
    CompositorTiming compositorTiming;
    nsecs_t refreshStartTime = 0;
    nsecs_t dequeueReadyTime = 0;
    uint64_t frameNumber = 0;
    ReleaseCallbackId previousReleaseCallbackId = ReleaseCallbackId::INVALID_ID;
};

class TransactionCallbackInvoker {
public:
    status_t addCallbackHandles(const std::deque<sp<CallbackHandle>>& handles,
                                const std::vector<JankData>& jankData);
    status_t addOnCommitCallbackHandles(const std::deque<sp<CallbackHandle>>& handles,
                                             std::deque<sp<CallbackHandle>>& outRemainingHandles);

    // Adds the Transaction CallbackHandle from a layer that does not need to be relatched and
    // presented this frame.
    status_t registerUnpresentedCallbackHandle(const sp<CallbackHandle>& handle);
    void addEmptyTransaction(const ListenerCallbacks& listenerCallbacks);

    void addPresentFence(const sp<Fence>& presentFence);

    void sendCallbacks(bool onCommitOnly);
    void clearCompletedTransactions() {
        mCompletedTransactions.clear();
    }

    status_t addCallbackHandle(const sp<CallbackHandle>& handle,
                               const std::vector<JankData>& jankData);


private:
    status_t findOrCreateTransactionStats(const sp<IBinder>& listener,
                                          const std::vector<CallbackId>& callbackIds,
                                          TransactionStats** outTransactionStats);

    std::unordered_map<sp<IBinder>, std::deque<TransactionStats>, IListenerHash>
        mCompletedTransactions;

    sp<Fence> mPresentFence;
};

} // namespace android
