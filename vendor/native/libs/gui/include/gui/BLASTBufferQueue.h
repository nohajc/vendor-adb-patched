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
#include <queue>

namespace android {

class BLASTBufferQueue;
class BufferItemConsumer;

class BLASTBufferItemConsumer : public BufferItemConsumer {
public:
    BLASTBufferItemConsumer(const sp<IGraphicBufferConsumer>& consumer, uint64_t consumerUsage,
                            int bufferCount, bool controlledByApp, wp<BLASTBufferQueue> bbq)
          : BufferItemConsumer(consumer, consumerUsage, bufferCount, controlledByApp),
            mBLASTBufferQueue(std::move(bbq)),
            mCurrentlyConnected(false),
            mPreviouslyConnected(false) {}

    void onDisconnect() override;
    void addAndGetFrameTimestamps(const NewFrameEventsEntry* newTimestamps,
                                  FrameEventHistoryDelta* outDelta) override REQUIRES(mMutex);
    void updateFrameTimestamps(uint64_t frameNumber, nsecs_t refreshStartTime,
                               const sp<Fence>& gpuCompositionDoneFence,
                               const sp<Fence>& presentFence, const sp<Fence>& prevReleaseFence,
                               CompositorTiming compositorTiming, nsecs_t latchTime,
                               nsecs_t dequeueReadyTime) REQUIRES(mMutex);
    void getConnectionEvents(uint64_t frameNumber, bool* needsDisconnect);

    void resizeFrameEventHistory(size_t newSize);

protected:
    void onSidebandStreamChanged() override REQUIRES(mMutex);

private:
    const wp<BLASTBufferQueue> mBLASTBufferQueue;

    uint64_t mCurrentFrameNumber = 0;

    Mutex mMutex;
    ConsumerFrameEventHistory mFrameEventHistory GUARDED_BY(mMutex);
    std::queue<uint64_t> mDisconnectEvents GUARDED_BY(mMutex);
    bool mCurrentlyConnected GUARDED_BY(mMutex);
    bool mPreviouslyConnected GUARDED_BY(mMutex);
};

class BLASTBufferQueue
    : public ConsumerBase::FrameAvailableListener, public BufferItemConsumer::BufferFreedListener
{
public:
    BLASTBufferQueue(const std::string& name, bool updateDestinationFrame = true);
    BLASTBufferQueue(const std::string& name, const sp<SurfaceControl>& surface, int width,
                     int height, int32_t format);

    sp<IGraphicBufferProducer> getIGraphicBufferProducer() const {
        return mProducer;
    }
    sp<Surface> getSurface(bool includeSurfaceControlHandle);
    bool isSameSurfaceControl(const sp<SurfaceControl>& surfaceControl) const;

    void onBufferFreed(const wp<GraphicBuffer>&/* graphicBuffer*/) override { /* TODO */ }
    void onFrameReplaced(const BufferItem& item) override;
    void onFrameAvailable(const BufferItem& item) override;
    void onFrameDequeued(const uint64_t) override;
    void onFrameCancelled(const uint64_t) override;

    void transactionCommittedCallback(nsecs_t latchTime, const sp<Fence>& presentFence,
                                      const std::vector<SurfaceControlStats>& stats);
    virtual void transactionCallback(nsecs_t latchTime, const sp<Fence>& presentFence,
                                     const std::vector<SurfaceControlStats>& stats);
    void releaseBufferCallback(const ReleaseCallbackId& id, const sp<Fence>& releaseFence,
                               std::optional<uint32_t> currentMaxAcquiredBufferCount);
    void releaseBufferCallbackLocked(const ReleaseCallbackId& id, const sp<Fence>& releaseFence,
                                     std::optional<uint32_t> currentMaxAcquiredBufferCount,
                                     bool fakeRelease);
    void syncNextTransaction(std::function<void(SurfaceComposerClient::Transaction*)> callback,
                             bool acquireSingleBuffer = true);
    void stopContinuousSyncTransaction();

    void mergeWithNextTransaction(SurfaceComposerClient::Transaction* t, uint64_t frameNumber);
    void applyPendingTransactions(uint64_t frameNumber);
    SurfaceComposerClient::Transaction* gatherPendingTransactions(uint64_t frameNumber);

    void update(const sp<SurfaceControl>& surface, uint32_t width, uint32_t height, int32_t format);

    status_t setFrameRate(float frameRate, int8_t compatibility, bool shouldBeSeamless);
    status_t setFrameTimelineInfo(uint64_t frameNumber, const FrameTimelineInfo& info);

    void setSidebandStream(const sp<NativeHandle>& stream);

    uint32_t getLastTransformHint() const;
    uint64_t getLastAcquiredFrameNum();
    void abandon();

    /**
     * Set a callback to be invoked when we are hung. The boolean parameter
     * indicates whether the hang is due to an unfired fence.
     * TODO: The boolean is always true atm, unfired fence is
     * the only case we detect.
     */
    void setTransactionHangCallback(std::function<void(bool)> callback);

    virtual ~BLASTBufferQueue();

private:
    friend class BLASTBufferQueueHelper;
    friend class BBQBufferQueueProducer;

    // can't be copied
    BLASTBufferQueue& operator = (const BLASTBufferQueue& rhs);
    BLASTBufferQueue(const BLASTBufferQueue& rhs);
    void createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
                           sp<IGraphicBufferConsumer>* outConsumer);

    void resizeFrameEventHistory(size_t newSize);

    status_t acquireNextBufferLocked(
            const std::optional<SurfaceComposerClient::Transaction*> transaction) REQUIRES(mMutex);
    Rect computeCrop(const BufferItem& item) REQUIRES(mMutex);
    // Return true if we need to reject the buffer based on the scaling mode and the buffer size.
    bool rejectBuffer(const BufferItem& item) REQUIRES(mMutex);
    static PixelFormat convertBufferFormat(PixelFormat& format);
    void mergePendingTransactions(SurfaceComposerClient::Transaction* t, uint64_t frameNumber)
            REQUIRES(mMutex);

    void flushShadowQueue() REQUIRES(mMutex);
    void acquireAndReleaseBuffer() REQUIRES(mMutex);
    void releaseBuffer(const ReleaseCallbackId& callbackId, const sp<Fence>& releaseFence)
            REQUIRES(mMutex);

    std::string mName;
    // Represents the queued buffer count from buffer queue,
    // pre-BLAST. This is mNumFrameAvailable (buffers that queued to blast) +
    // mNumAcquired (buffers that queued to SF)  mPendingRelease.size() (buffers that are held by
    // blast). This counter is read by android studio profiler.
    std::string mQueuedBufferTrace;
    sp<SurfaceControl> mSurfaceControl;

    mutable std::mutex mMutex;
    std::condition_variable mCallbackCV;

    // BufferQueue internally allows 1 more than
    // the max to be acquired
    int32_t mMaxAcquiredBuffers = 1;

    int32_t mNumFrameAvailable GUARDED_BY(mMutex) = 0;
    int32_t mNumAcquired GUARDED_BY(mMutex) = 0;

    // Keep a reference to the submitted buffers so we can release when surfaceflinger drops the
    // buffer or the buffer has been presented and a new buffer is ready to be presented.
    std::unordered_map<ReleaseCallbackId, BufferItem, ReleaseBufferCallbackIdHash> mSubmitted
            GUARDED_BY(mMutex);

    // Keep a queue of the released buffers instead of immediately releasing
    // the buffers back to the buffer queue. This would be controlled by SF
    // setting the max acquired buffer count.
    struct ReleasedBuffer {
        ReleaseCallbackId callbackId;
        sp<Fence> releaseFence;
        bool operator==(const ReleasedBuffer& rhs) const {
            // Only compare Id so if we somehow got two callbacks
            // with different fences we don't decrement mNumAcquired
            // too far.
            return rhs.callbackId == callbackId;
        }
    };
    std::deque<ReleasedBuffer> mPendingRelease GUARDED_BY(mMutex);

    ui::Size mSize GUARDED_BY(mMutex);
    ui::Size mRequestedSize GUARDED_BY(mMutex);
    int32_t mFormat GUARDED_BY(mMutex);

    struct BufferInfo {
        bool hasBuffer = false;
        uint32_t width;
        uint32_t height;
        uint32_t transform;
        // This is used to check if we should update the blast layer size immediately or wait until
        // we get the next buffer. This will support scenarios where the layer can change sizes
        // and the buffer will scale to fit the new size.
        uint32_t scalingMode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
        Rect crop;

        void update(bool hasBuffer, uint32_t width, uint32_t height, uint32_t transform,
                    uint32_t scalingMode, const Rect& crop) {
            this->hasBuffer = hasBuffer;
            this->width = width;
            this->height = height;
            this->transform = transform;
            this->scalingMode = scalingMode;
            if (!crop.isEmpty()) {
                this->crop = crop;
            } else {
                this->crop = Rect(width, height);
            }
        }
    };

    // Last acquired buffer's info. This is used to calculate the correct scale when size change is
    // requested. We need to use the old buffer's info to determine what scale we need to apply to
    // ensure the correct size.
    BufferInfo mLastBufferInfo GUARDED_BY(mMutex);
    void setMatrix(SurfaceComposerClient::Transaction* t, const BufferInfo& bufferInfo)
            REQUIRES(mMutex);

    uint32_t mTransformHint GUARDED_BY(mMutex);

    sp<IGraphicBufferConsumer> mConsumer;
    sp<IGraphicBufferProducer> mProducer;
    sp<BLASTBufferItemConsumer> mBufferItemConsumer;

    std::function<void(SurfaceComposerClient::Transaction*)> mTransactionReadyCallback
            GUARDED_BY(mMutex);
    SurfaceComposerClient::Transaction* mSyncTransaction GUARDED_BY(mMutex);
    std::vector<std::tuple<uint64_t /* framenumber */, SurfaceComposerClient::Transaction>>
            mPendingTransactions GUARDED_BY(mMutex);

    std::queue<std::pair<uint64_t, FrameTimelineInfo>> mPendingFrameTimelines GUARDED_BY(mMutex);

    // Tracks the last acquired frame number
    uint64_t mLastAcquiredFrameNumber GUARDED_BY(mMutex) = 0;

    // Queues up transactions using this token in SurfaceFlinger. This prevents queued up
    // transactions from other parts of the client from blocking this transaction.
    const sp<IBinder> mApplyToken GUARDED_BY(mMutex) = new BBinder();

    // Guards access to mDequeueTimestamps since we cannot hold to mMutex in onFrameDequeued or
    // we will deadlock.
    std::mutex mTimestampMutex;
    // Tracks buffer dequeue times by the client. This info is sent to SurfaceFlinger which uses
    // it for debugging purposes.
    std::unordered_map<uint64_t /* bufferId */, nsecs_t> mDequeueTimestamps
            GUARDED_BY(mTimestampMutex);

    // Keep track of SurfaceControls that have submitted a transaction and BBQ is waiting on a
    // callback for them.
    std::queue<sp<SurfaceControl>> mSurfaceControlsWithPendingCallback GUARDED_BY(mMutex);

    uint32_t mCurrentMaxAcquiredBufferCount;

    // Flag to determine if syncTransaction should only acquire a single buffer and then clear or
    // continue to acquire buffers until explicitly cleared
    bool mAcquireSingleBuffer GUARDED_BY(mMutex) = true;

    // True if BBQ will update the destination frame used to scale the buffer to the requested size.
    // If false, the caller is responsible for updating the destination frame on the BBQ
    // surfacecontol. This is useful if the caller wants to synchronize the buffer scale with
    // additional scales in the hierarchy.
    bool mUpdateDestinationFrame GUARDED_BY(mMutex) = true;

    // We send all transactions on our apply token over one-way binder calls to avoid blocking
    // client threads. All of our transactions remain in order, since they are one-way binder calls
    // from a single process, to a single interface. However once we give up a Transaction for sync
    // we can start to have ordering issues. When we return from sync to normal frame production,
    // we wait on the commit callback of sync frames ensuring ordering, however we don't want to
    // wait on the commit callback for every normal frame (since even emitting them has a
    // performance cost) this means we need a method to ensure frames are in order when switching
    // from one-way application on our apply token, to application on some other apply token. We
    // make use of setBufferHasBarrier to declare this ordering. This boolean simply tracks when we
    // need to set this flag, notably only in the case where we are transitioning from a previous
    // transaction applied by us (one way, may not yet have reached server) and an upcoming
    // transaction that will be applied by some sync consumer.
    bool mAppliedLastTransaction = false;
    uint64_t mLastAppliedFrameNumber = 0;

    std::function<void(bool)> mTransactionHangCallback;

    std::unordered_set<uint64_t> mSyncedFrameNumbers GUARDED_BY(mMutex);
};

} // namespace android

#endif  // ANDROID_GUI_SURFACE_H
