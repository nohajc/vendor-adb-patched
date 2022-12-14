/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_GUI_BLAST_BUFFER_QUEUE_H
#define ANDROID_GUI_BLAST_BUFFER_QUEUE_H

#include <gui/IGraphicBufferProducer.h>
#include <gui/BufferItemConsumer.h>
#include <gui/BufferItem.h>
#include <gui/SurfaceComposerClient.h>

#include <utils/Condition.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>

#include <system/window.h>
#include <thread>

namespace android {

class BufferItemConsumer;

class BLASTBufferItemConsumer : public BufferItemConsumer {
public:
    BLASTBufferItemConsumer(const sp<IGraphicBufferConsumer>& consumer, uint64_t consumerUsage,
                            int bufferCount, bool controlledByApp)
          : BufferItemConsumer(consumer, consumerUsage, bufferCount, controlledByApp),
            mCurrentlyConnected(false),
            mPreviouslyConnected(false) {}

    void onDisconnect() override;
    void addAndGetFrameTimestamps(const NewFrameEventsEntry* newTimestamps,
                                  FrameEventHistoryDelta* outDelta) override
            REQUIRES(mFrameEventHistoryMutex);
    void updateFrameTimestamps(uint64_t frameNumber, nsecs_t refreshStartTime,
                               const sp<Fence>& gpuCompositionDoneFence,
                               const sp<Fence>& presentFence, const sp<Fence>& prevReleaseFence,
                               CompositorTiming compositorTiming, nsecs_t latchTime,
                               nsecs_t dequeueReadyTime) REQUIRES(mFrameEventHistoryMutex);
    void getConnectionEvents(uint64_t frameNumber, bool* needsDisconnect);

private:
    uint64_t mCurrentFrameNumber = 0;

    Mutex mFrameEventHistoryMutex;
    ConsumerFrameEventHistory mFrameEventHistory GUARDED_BY(mFrameEventHistoryMutex);
    std::queue<uint64_t> mDisconnectEvents GUARDED_BY(mFrameEventHistoryMutex);
    bool mCurrentlyConnected GUARDED_BY(mFrameEventHistoryMutex);
    bool mPreviouslyConnected GUARDED_BY(mFrameEventHistoryMutex);
};

class BLASTBufferQueue
    : public ConsumerBase::FrameAvailableListener, public BufferItemConsumer::BufferFreedListener
{
public:
    BLASTBufferQueue(const sp<SurfaceControl>& surface, int width, int height,
                     bool enableTripleBuffering = true);

    sp<IGraphicBufferProducer> getIGraphicBufferProducer() const {
        return mProducer;
    }

    void onBufferFreed(const wp<GraphicBuffer>&/* graphicBuffer*/) override { /* TODO */ }
    void onFrameReplaced(const BufferItem& item) override {onFrameAvailable(item);}
    void onFrameAvailable(const BufferItem& item) override;

    void transactionCallback(nsecs_t latchTime, const sp<Fence>& presentFence,
            const std::vector<SurfaceControlStats>& stats);
    void setNextTransaction(SurfaceComposerClient::Transaction *t);

    void update(const sp<SurfaceControl>& surface, int width, int height);

    virtual ~BLASTBufferQueue() = default;

private:
    friend class BLASTBufferQueueHelper;

    // can't be copied
    BLASTBufferQueue& operator = (const BLASTBufferQueue& rhs);
    BLASTBufferQueue(const BLASTBufferQueue& rhs);

    void processNextBufferLocked(bool useNextTransaction) REQUIRES(mMutex);
    Rect computeCrop(const BufferItem& item);

    sp<SurfaceControl> mSurfaceControl;

    std::mutex mMutex;
    std::condition_variable mCallbackCV;

    // BufferQueue internally allows 1 more than
    // the max to be acquired
    static const int MAX_ACQUIRED_BUFFERS = 1;

    int32_t mNumFrameAvailable GUARDED_BY(mMutex);
    int32_t mNumAcquired GUARDED_BY(mMutex);

    struct PendingReleaseItem {
        BufferItem item;
        sp<Fence> releaseFence;
    };

    std::queue<const BufferItem> mSubmitted GUARDED_BY(mMutex);
    PendingReleaseItem mPendingReleaseItem GUARDED_BY(mMutex);

    int mWidth GUARDED_BY(mMutex);
    int mHeight GUARDED_BY(mMutex);

    uint32_t mTransformHint GUARDED_BY(mMutex);

    sp<IGraphicBufferConsumer> mConsumer;
    sp<IGraphicBufferProducer> mProducer;
    sp<BLASTBufferItemConsumer> mBufferItemConsumer;

    SurfaceComposerClient::Transaction* mNextTransaction GUARDED_BY(mMutex);
};

} // namespace android

#endif  // ANDROID_GUI_SURFACE_H
