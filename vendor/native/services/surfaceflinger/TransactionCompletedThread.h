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
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <android-base/thread_annotations.h>

#include <binder/IBinder.h>
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
    sp<Fence> previousReleaseFence;
    nsecs_t acquireTime = -1;
    nsecs_t latchTime = -1;
    uint32_t transformHint = 0;
    std::shared_ptr<FenceTime> gpuCompositionDoneFence{FenceTime::NO_FENCE};
    CompositorTiming compositorTiming;
    nsecs_t refreshStartTime = 0;
    nsecs_t dequeueReadyTime = 0;
    uint64_t frameNumber = 0;
};

class TransactionCompletedThread {
public:
    ~TransactionCompletedThread();

    void run();

    // Adds listener and callbackIds in case there are no SurfaceControls that are supposed
    // to be included in the callback. This functions should be call before attempting to register
    // any callback handles.
    status_t startRegistration(const ListenerCallbacks& listenerCallbacks);
    // Ends the registration. After this is called, no more CallbackHandles will be registered.
    // It is safe to send a callback if the Transaction doesn't have any Pending callback handles.
    status_t endRegistration(const ListenerCallbacks& listenerCallbacks);

    // Informs the TransactionCompletedThread that there is a Transaction with a CallbackHandle
    // that needs to be latched and presented this frame. This function should be called once the
    // layer has received the CallbackHandle so the TransactionCompletedThread knows not to send
    // a callback for that Listener/Transaction pair until that CallbackHandle has been latched and
    // presented.
    status_t registerPendingCallbackHandle(const sp<CallbackHandle>& handle);
    // Notifies the TransactionCompletedThread that a pending CallbackHandle has been presented.
    status_t finalizePendingCallbackHandles(const std::deque<sp<CallbackHandle>>& handles);

    // Adds the Transaction CallbackHandle from a layer that does not need to be relatched and
    // presented this frame.
    status_t registerUnpresentedCallbackHandle(const sp<CallbackHandle>& handle);

    void addPresentFence(const sp<Fence>& presentFence);

    void sendCallbacks();

private:
    void threadMain();

    bool isRegisteringTransaction(const sp<IBinder>& transactionListener,
                                  const std::vector<CallbackId>& callbackIds) REQUIRES(mMutex);

    status_t findTransactionStats(const sp<IBinder>& listener,
                                  const std::vector<CallbackId>& callbackIds,
                                  TransactionStats** outTransactionStats) REQUIRES(mMutex);

    status_t addCallbackHandle(const sp<CallbackHandle>& handle) REQUIRES(mMutex);

    class ThreadDeathRecipient : public IBinder::DeathRecipient {
    public:
        // This function is a no-op. isBinderAlive needs a linked DeathRecipient to work.
        // Death recipients needs a binderDied function.
        //
        // (isBinderAlive checks if BpBinder's mAlive is 0. mAlive is only set to 0 in sendObituary.
        // sendObituary is only called if linkToDeath was called with a DeathRecipient.)
        void binderDied(const wp<IBinder>& /*who*/) override {}
    };
    sp<ThreadDeathRecipient> mDeathRecipient;

    // Protects the creation and destruction of mThread
    std::mutex mThreadMutex;

    std::thread mThread GUARDED_BY(mThreadMutex);

    std::mutex mMutex;
    std::condition_variable_any mConditionVariable;

    std::unordered_set<ListenerCallbacks, ListenerCallbacksHash> mRegisteringTransactions
            GUARDED_BY(mMutex);

    std::unordered_map<
            sp<IBinder>,
            std::unordered_map<std::vector<CallbackId>, uint32_t /*count*/, CallbackIdsHash>,
            IListenerHash>
            mPendingTransactions GUARDED_BY(mMutex);

    std::unordered_map<sp<IBinder>, std::deque<TransactionStats>, IListenerHash>
            mCompletedTransactions GUARDED_BY(mMutex);

    bool mRunning GUARDED_BY(mMutex) = false;
    bool mKeepRunning GUARDED_BY(mMutex) = true;

    sp<Fence> mPresentFence GUARDED_BY(mMutex);
};

} // namespace android
