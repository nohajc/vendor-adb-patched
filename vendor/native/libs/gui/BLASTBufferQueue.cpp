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

#undef LOG_TAG
#define LOG_TAG "BLASTBufferQueue"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0

#include <gui/BLASTBufferQueue.h>
#include <gui/BufferItemConsumer.h>
#include <gui/BufferQueueConsumer.h>
#include <gui/BufferQueueCore.h>
#include <gui/BufferQueueProducer.h>
#include <gui/GLConsumer.h>
#include <gui/IProducerListener.h>
#include <gui/Surface.h>
#include <utils/Singleton.h>
#include <utils/Trace.h>

#include <private/gui/ComposerService.h>

#include <chrono>

using namespace std::chrono_literals;

namespace {
inline const char* boolToString(bool b) {
    return b ? "true" : "false";
}
} // namespace

namespace android {

// Macros to include adapter info in log messages
#define BQA_LOGD(x, ...) \
    ALOGD("[%s](f:%u,a:%u) " x, mName.c_str(), mNumFrameAvailable, mNumAcquired, ##__VA_ARGS__)
#define BQA_LOGV(x, ...) \
    ALOGV("[%s](f:%u,a:%u) " x, mName.c_str(), mNumFrameAvailable, mNumAcquired, ##__VA_ARGS__)
// enable logs for a single layer
//#define BQA_LOGV(x, ...) \
//    ALOGV_IF((strstr(mName.c_str(), "SurfaceView") != nullptr), "[%s](f:%u,a:%u) " x, \
//              mName.c_str(), mNumFrameAvailable, mNumAcquired, ##__VA_ARGS__)
#define BQA_LOGE(x, ...) \
    ALOGE("[%s](f:%u,a:%u) " x, mName.c_str(), mNumFrameAvailable, mNumAcquired, ##__VA_ARGS__)

void BLASTBufferItemConsumer::onDisconnect() {
    Mutex::Autolock lock(mMutex);
    mPreviouslyConnected = mCurrentlyConnected;
    mCurrentlyConnected = false;
    if (mPreviouslyConnected) {
        mDisconnectEvents.push(mCurrentFrameNumber);
    }
    mFrameEventHistory.onDisconnect();
}

void BLASTBufferItemConsumer::addAndGetFrameTimestamps(const NewFrameEventsEntry* newTimestamps,
                                                       FrameEventHistoryDelta* outDelta) {
    Mutex::Autolock lock(mMutex);
    if (newTimestamps) {
        // BufferQueueProducer only adds a new timestamp on
        // queueBuffer
        mCurrentFrameNumber = newTimestamps->frameNumber;
        mFrameEventHistory.addQueue(*newTimestamps);
    }
    if (outDelta) {
        // frame event histories will be processed
        // only after the producer connects and requests
        // deltas for the first time.  Forward this intent
        // to SF-side to turn event processing back on
        mPreviouslyConnected = mCurrentlyConnected;
        mCurrentlyConnected = true;
        mFrameEventHistory.getAndResetDelta(outDelta);
    }
}

void BLASTBufferItemConsumer::updateFrameTimestamps(uint64_t frameNumber, nsecs_t refreshStartTime,
                                                    const sp<Fence>& glDoneFence,
                                                    const sp<Fence>& presentFence,
                                                    const sp<Fence>& prevReleaseFence,
                                                    CompositorTiming compositorTiming,
                                                    nsecs_t latchTime, nsecs_t dequeueReadyTime) {
    Mutex::Autolock lock(mMutex);

    // if the producer is not connected, don't bother updating,
    // the next producer that connects won't access this frame event
    if (!mCurrentlyConnected) return;
    std::shared_ptr<FenceTime> glDoneFenceTime = std::make_shared<FenceTime>(glDoneFence);
    std::shared_ptr<FenceTime> presentFenceTime = std::make_shared<FenceTime>(presentFence);
    std::shared_ptr<FenceTime> releaseFenceTime = std::make_shared<FenceTime>(prevReleaseFence);

    mFrameEventHistory.addLatch(frameNumber, latchTime);
    mFrameEventHistory.addRelease(frameNumber, dequeueReadyTime, std::move(releaseFenceTime));
    mFrameEventHistory.addPreComposition(frameNumber, refreshStartTime);
    mFrameEventHistory.addPostComposition(frameNumber, glDoneFenceTime, presentFenceTime,
                                          compositorTiming);
}

void BLASTBufferItemConsumer::getConnectionEvents(uint64_t frameNumber, bool* needsDisconnect) {
    bool disconnect = false;
    Mutex::Autolock lock(mMutex);
    while (!mDisconnectEvents.empty() && mDisconnectEvents.front() <= frameNumber) {
        disconnect = true;
        mDisconnectEvents.pop();
    }
    if (needsDisconnect != nullptr) *needsDisconnect = disconnect;
}

void BLASTBufferItemConsumer::onSidebandStreamChanged() {
    sp<BLASTBufferQueue> bbq = mBLASTBufferQueue.promote();
    if (bbq != nullptr) {
        sp<NativeHandle> stream = getSidebandStream();
        bbq->setSidebandStream(stream);
    }
}

BLASTBufferQueue::BLASTBufferQueue(const std::string& name)
      : mSurfaceControl(nullptr),
        mSize(1, 1),
        mRequestedSize(mSize),
        mFormat(PIXEL_FORMAT_RGBA_8888),
        mNextTransaction(nullptr) {
    createBufferQueue(&mProducer, &mConsumer);
    // since the adapter is in the client process, set dequeue timeout
    // explicitly so that dequeueBuffer will block
    mProducer->setDequeueTimeout(std::numeric_limits<int64_t>::max());

    // safe default, most producers are expected to override this
    mProducer->setMaxDequeuedBufferCount(2);
    mBufferItemConsumer = new BLASTBufferItemConsumer(mConsumer,
                                                      GraphicBuffer::USAGE_HW_COMPOSER |
                                                              GraphicBuffer::USAGE_HW_TEXTURE,
                                                      1, false, this);
    static int32_t id = 0;
    mName = name + "#" + std::to_string(id);
    auto consumerName = mName + "(BLAST Consumer)" + std::to_string(id);
    mQueuedBufferTrace = "QueuedBuffer - " + mName + "BLAST#" + std::to_string(id);
    id++;
    mBufferItemConsumer->setName(String8(consumerName.c_str()));
    mBufferItemConsumer->setFrameAvailableListener(this);
    mBufferItemConsumer->setBufferFreedListener(this);

    ComposerService::getComposerService()->getMaxAcquiredBufferCount(&mMaxAcquiredBuffers);
    mBufferItemConsumer->setMaxAcquiredBufferCount(mMaxAcquiredBuffers);
    mNumAcquired = 0;
    mNumFrameAvailable = 0;
    BQA_LOGV("BLASTBufferQueue created");
}

BLASTBufferQueue::BLASTBufferQueue(const std::string& name, const sp<SurfaceControl>& surface,
                                   int width, int height, int32_t format)
      : BLASTBufferQueue(name) {
    update(surface, width, height, format);
}

BLASTBufferQueue::~BLASTBufferQueue() {
    if (mPendingTransactions.empty()) {
        return;
    }
    BQA_LOGE("Applying pending transactions on dtor %d",
             static_cast<uint32_t>(mPendingTransactions.size()));
    SurfaceComposerClient::Transaction t;
    for (auto& [targetFrameNumber, transaction] : mPendingTransactions) {
        t.merge(std::move(transaction));
    }
    t.apply();
}

void BLASTBufferQueue::update(const sp<SurfaceControl>& surface, uint32_t width, uint32_t height,
                              int32_t format, SurfaceComposerClient::Transaction* outTransaction) {
    std::unique_lock _lock{mMutex};
    if (mFormat != format) {
        mFormat = format;
        mBufferItemConsumer->setDefaultBufferFormat(convertBufferFormat(format));
    }

    SurfaceComposerClient::Transaction t;
    const bool setBackpressureFlag = !SurfaceControl::isSameSurface(mSurfaceControl, surface);
    bool applyTransaction = false;

    // Always update the native object even though they might have the same layer handle, so we can
    // get the updated transform hint from WM.
    mSurfaceControl = surface;
    if (mSurfaceControl != nullptr) {
        if (setBackpressureFlag) {
            t.setFlags(mSurfaceControl, layer_state_t::eEnableBackpressure,
                       layer_state_t::eEnableBackpressure);
            applyTransaction = true;
        }
        mTransformHint = mSurfaceControl->getTransformHint();
        mBufferItemConsumer->setTransformHint(mTransformHint);
    }
    BQA_LOGV("update width=%d height=%d format=%d mTransformHint=%d", width, height, format,
             mTransformHint);

    ui::Size newSize(width, height);
    if (mRequestedSize != newSize) {
        mRequestedSize.set(newSize);
        mBufferItemConsumer->setDefaultBufferSize(mRequestedSize.width, mRequestedSize.height);
        if (mLastBufferInfo.scalingMode != NATIVE_WINDOW_SCALING_MODE_FREEZE) {
            // If the buffer supports scaling, update the frame immediately since the client may
            // want to scale the existing buffer to the new size.
            mSize = mRequestedSize;
            SurfaceComposerClient::Transaction* destFrameTransaction =
                    (outTransaction) ? outTransaction : &t;
            if (mSurfaceControl != nullptr) {
                destFrameTransaction->setDestinationFrame(mSurfaceControl,
                                                          Rect(0, 0, newSize.getWidth(),
                                                               newSize.getHeight()));
            }
            applyTransaction = true;
        }
    }
    if (applyTransaction) {
        t.setApplyToken(mApplyToken).apply();
    }
}

static std::optional<SurfaceControlStats> findMatchingStat(
        const std::vector<SurfaceControlStats>& stats, const sp<SurfaceControl>& sc) {
    for (auto stat : stats) {
        if (SurfaceControl::isSameSurface(sc, stat.surfaceControl)) {
            return stat;
        }
    }
    return std::nullopt;
}

static void transactionCommittedCallbackThunk(void* context, nsecs_t latchTime,
                                              const sp<Fence>& presentFence,
                                              const std::vector<SurfaceControlStats>& stats) {
    if (context == nullptr) {
        return;
    }
    sp<BLASTBufferQueue> bq = static_cast<BLASTBufferQueue*>(context);
    bq->transactionCommittedCallback(latchTime, presentFence, stats);
}

void BLASTBufferQueue::transactionCommittedCallback(nsecs_t /*latchTime*/,
                                                    const sp<Fence>& /*presentFence*/,
                                                    const std::vector<SurfaceControlStats>& stats) {
    {
        std::unique_lock _lock{mMutex};
        ATRACE_CALL();
        BQA_LOGV("transactionCommittedCallback");
        if (!mSurfaceControlsWithPendingCallback.empty()) {
            sp<SurfaceControl> pendingSC = mSurfaceControlsWithPendingCallback.front();
            std::optional<SurfaceControlStats> stat = findMatchingStat(stats, pendingSC);
            if (stat) {
                uint64_t currFrameNumber = stat->frameEventStats.frameNumber;

                // We need to check if we were waiting for a transaction callback in order to
                // process any pending buffers and unblock. It's possible to get transaction
                // callbacks for previous requests so we need to ensure the frame from this
                // transaction callback matches the last acquired buffer. Since acquireNextBuffer
                // will stop processing buffers when mWaitForTransactionCallback is set, we know
                // that mLastAcquiredFrameNumber is the frame we're waiting on.
                // We also want to check if mNextTransaction is null because it's possible another
                // sync request came in while waiting, but it hasn't started processing yet. In that
                // case, we don't actually want to flush the frames in between since they will get
                // processed and merged with the sync transaction and released earlier than if they
                // were sent to SF
                if (mWaitForTransactionCallback && mNextTransaction == nullptr &&
                    currFrameNumber >= mLastAcquiredFrameNumber) {
                    mWaitForTransactionCallback = false;
                    flushShadowQueueLocked();
                }
            } else {
                BQA_LOGE("Failed to find matching SurfaceControl in transactionCommittedCallback");
            }
        } else {
            BQA_LOGE("No matching SurfaceControls found: mSurfaceControlsWithPendingCallback was "
                     "empty.");
        }

        decStrong((void*)transactionCommittedCallbackThunk);
    }
}

static void transactionCallbackThunk(void* context, nsecs_t latchTime,
                                     const sp<Fence>& presentFence,
                                     const std::vector<SurfaceControlStats>& stats) {
    if (context == nullptr) {
        return;
    }
    sp<BLASTBufferQueue> bq = static_cast<BLASTBufferQueue*>(context);
    bq->transactionCallback(latchTime, presentFence, stats);
}

void BLASTBufferQueue::transactionCallback(nsecs_t /*latchTime*/, const sp<Fence>& /*presentFence*/,
                                           const std::vector<SurfaceControlStats>& stats) {
    std::function<void(int64_t)> transactionCompleteCallback = nullptr;
    uint64_t currFrameNumber = 0;

    {
        std::unique_lock _lock{mMutex};
        ATRACE_CALL();
        BQA_LOGV("transactionCallback");

        if (!mSurfaceControlsWithPendingCallback.empty()) {
            sp<SurfaceControl> pendingSC = mSurfaceControlsWithPendingCallback.front();
            mSurfaceControlsWithPendingCallback.pop();
            std::optional<SurfaceControlStats> statsOptional = findMatchingStat(stats, pendingSC);
            if (statsOptional) {
                SurfaceControlStats stat = *statsOptional;
                mTransformHint = stat.transformHint;
                mBufferItemConsumer->setTransformHint(mTransformHint);
                BQA_LOGV("updated mTransformHint=%d", mTransformHint);
                // Update frametime stamps if the frame was latched and presented, indicated by a
                // valid latch time.
                if (stat.latchTime > 0) {
                    mBufferItemConsumer
                            ->updateFrameTimestamps(stat.frameEventStats.frameNumber,
                                                    stat.frameEventStats.refreshStartTime,
                                                    stat.frameEventStats.gpuCompositionDoneFence,
                                                    stat.presentFence, stat.previousReleaseFence,
                                                    stat.frameEventStats.compositorTiming,
                                                    stat.latchTime,
                                                    stat.frameEventStats.dequeueReadyTime);
                }
                currFrameNumber = stat.frameEventStats.frameNumber;

                if (mTransactionCompleteCallback &&
                    currFrameNumber >= mTransactionCompleteFrameNumber) {
                    if (currFrameNumber > mTransactionCompleteFrameNumber) {
                        BQA_LOGE("transactionCallback received for a newer framenumber=%" PRIu64
                                 " than expected=%" PRIu64,
                                 currFrameNumber, mTransactionCompleteFrameNumber);
                    }
                    transactionCompleteCallback = std::move(mTransactionCompleteCallback);
                    mTransactionCompleteFrameNumber = 0;
                }
                std::vector<ReleaseCallbackId> staleReleases;
                for (const auto& [key, value]: mSubmitted) {
                    if (currFrameNumber > key.framenumber) {
                        staleReleases.push_back(key);
                    }
                }
                for (const auto& staleRelease : staleReleases) {
                    releaseBufferCallbackLocked(staleRelease, stat.previousReleaseFence ? stat.previousReleaseFence : Fence::NO_FENCE,
                                                stat.transformHint, stat.currentMaxAcquiredBufferCount);
                }
            } else {
                BQA_LOGE("Failed to find matching SurfaceControl in transactionCallback");
            }
        } else {
            BQA_LOGE("No matching SurfaceControls found: mSurfaceControlsWithPendingCallback was "
                     "empty.");
        }


        decStrong((void*)transactionCallbackThunk);
    }

    if (transactionCompleteCallback) {
        transactionCompleteCallback(currFrameNumber);
    }
}

// Unlike transactionCallbackThunk the release buffer callback does not extend the life of the
// BBQ. This is because if the BBQ is destroyed, then the buffers will be released by the client.
// So we pass in a weak pointer to the BBQ and if it still alive, then we release the buffer.
// Otherwise, this is a no-op.
static void releaseBufferCallbackThunk(wp<BLASTBufferQueue> context, const ReleaseCallbackId& id,
                                       const sp<Fence>& releaseFence, uint32_t transformHint,
                                       uint32_t currentMaxAcquiredBufferCount) {
    sp<BLASTBufferQueue> blastBufferQueue = context.promote();
    if (blastBufferQueue) {
        blastBufferQueue->releaseBufferCallback(id, releaseFence, transformHint,
                                                currentMaxAcquiredBufferCount);
    } else {
        ALOGV("releaseBufferCallbackThunk %s blastBufferQueue is dead", id.to_string().c_str());
    }
}

void BLASTBufferQueue::flushShadowQueueLocked() {
    BQA_LOGV("flushShadowQueueLocked");
    int numFramesToFlush = mNumFrameAvailable;
    while (numFramesToFlush > 0) {
        acquireNextBufferLocked(std::nullopt);
        numFramesToFlush--;
    }
}

void BLASTBufferQueue::flushShadowQueue() {
    std::unique_lock _lock{mMutex};
    flushShadowQueueLocked();
}

void BLASTBufferQueue::releaseBufferCallback(const ReleaseCallbackId& id,
                                             const sp<Fence>& releaseFence, uint32_t transformHint,
                                             uint32_t currentMaxAcquiredBufferCount) {
    std::unique_lock _lock{mMutex};
    releaseBufferCallbackLocked(id, releaseFence, transformHint, currentMaxAcquiredBufferCount);
}

void BLASTBufferQueue::releaseBufferCallbackLocked(const ReleaseCallbackId& id,
                                                   const sp<Fence>& releaseFence, uint32_t transformHint,
                                                   uint32_t currentMaxAcquiredBufferCount) {
    ATRACE_CALL();
    BQA_LOGV("releaseBufferCallback %s", id.to_string().c_str());

    if (mSurfaceControl != nullptr) {
        mTransformHint = transformHint;
        mSurfaceControl->setTransformHint(transformHint);
        mBufferItemConsumer->setTransformHint(mTransformHint);
        BQA_LOGV("updated mTransformHint=%d", mTransformHint);
    }

    // Calculate how many buffers we need to hold before we release them back
    // to the buffer queue. This will prevent higher latency when we are running
    // on a lower refresh rate than the max supported. We only do that for EGL
    // clients as others don't care about latency
    const bool isEGL = [&] {
        const auto it = mSubmitted.find(id);
        return it != mSubmitted.end() && it->second.mApi == NATIVE_WINDOW_API_EGL;
    }();

    const auto numPendingBuffersToHold =
            isEGL ? std::max(0u, mMaxAcquiredBuffers - currentMaxAcquiredBufferCount) : 0;
    auto rb = ReleasedBuffer{id, releaseFence};
    if (std::find(mPendingRelease.begin(), mPendingRelease.end(), rb) == mPendingRelease.end()) {
        mPendingRelease.emplace_back(rb);
    }

    // Release all buffers that are beyond the ones that we need to hold
    while (mPendingRelease.size() > numPendingBuffersToHold) {
        const auto releaseBuffer = mPendingRelease.front();
        mPendingRelease.pop_front();
        auto it = mSubmitted.find(releaseBuffer.callbackId);
        if (it == mSubmitted.end()) {
            BQA_LOGE("ERROR: releaseBufferCallback without corresponding submitted buffer %s",
                     releaseBuffer.callbackId.to_string().c_str());
            return;
        }
        mNumAcquired--;
        BQA_LOGV("released %s", id.to_string().c_str());
        mBufferItemConsumer->releaseBuffer(it->second, releaseBuffer.releaseFence);
        mSubmitted.erase(it);
        // Don't process the transactions here if mWaitForTransactionCallback is set. Instead, let
        // onFrameAvailable handle processing them since it will merge with the nextTransaction.
        if (!mWaitForTransactionCallback) {
            acquireNextBufferLocked(std::nullopt);
        }
    }

    ATRACE_INT("PendingRelease", mPendingRelease.size());
    ATRACE_INT(mQueuedBufferTrace.c_str(),
               mNumFrameAvailable + mNumAcquired - mPendingRelease.size());
    mCallbackCV.notify_all();
}

void BLASTBufferQueue::acquireNextBufferLocked(
        const std::optional<SurfaceComposerClient::Transaction*> transaction) {
    ATRACE_CALL();
    // If the next transaction is set, we want to guarantee the our acquire will not fail, so don't
    // include the extra buffer when checking if we can acquire the next buffer.
    const bool includeExtraAcquire = !transaction;
    const bool maxAcquired = maxBuffersAcquired(includeExtraAcquire);
    if (mNumFrameAvailable == 0 || maxAcquired) {
        BQA_LOGV("Can't process next buffer maxBuffersAcquired=%s", boolToString(maxAcquired));
        return;
    }

    if (mSurfaceControl == nullptr) {
        BQA_LOGE("ERROR : surface control is null");
        return;
    }

    SurfaceComposerClient::Transaction localTransaction;
    bool applyTransaction = true;
    SurfaceComposerClient::Transaction* t = &localTransaction;
    if (transaction) {
        t = *transaction;
        applyTransaction = false;
    }

    BufferItem bufferItem;

    status_t status =
            mBufferItemConsumer->acquireBuffer(&bufferItem, 0 /* expectedPresent */, false);
    if (status == BufferQueue::NO_BUFFER_AVAILABLE) {
        BQA_LOGV("Failed to acquire a buffer, err=NO_BUFFER_AVAILABLE");
        return;
    } else if (status != OK) {
        BQA_LOGE("Failed to acquire a buffer, err=%s", statusToString(status).c_str());
        return;
    }
    auto buffer = bufferItem.mGraphicBuffer;
    mNumFrameAvailable--;

    if (buffer == nullptr) {
        mBufferItemConsumer->releaseBuffer(bufferItem, Fence::NO_FENCE);
        BQA_LOGE("Buffer was empty");
        return;
    }

    if (rejectBuffer(bufferItem)) {
        BQA_LOGE("rejecting buffer:active_size=%dx%d, requested_size=%dx%d "
                 "buffer{size=%dx%d transform=%d}",
                 mSize.width, mSize.height, mRequestedSize.width, mRequestedSize.height,
                 buffer->getWidth(), buffer->getHeight(), bufferItem.mTransform);
        mBufferItemConsumer->releaseBuffer(bufferItem, Fence::NO_FENCE);
        acquireNextBufferLocked(transaction);
        return;
    }

    mNumAcquired++;
    mLastAcquiredFrameNumber = bufferItem.mFrameNumber;
    ReleaseCallbackId releaseCallbackId(buffer->getId(), mLastAcquiredFrameNumber);
    mSubmitted[releaseCallbackId] = bufferItem;

    bool needsDisconnect = false;
    mBufferItemConsumer->getConnectionEvents(bufferItem.mFrameNumber, &needsDisconnect);

    // if producer disconnected before, notify SurfaceFlinger
    if (needsDisconnect) {
        t->notifyProducerDisconnect(mSurfaceControl);
    }

    // Ensure BLASTBufferQueue stays alive until we receive the transaction complete callback.
    incStrong((void*)transactionCallbackThunk);

    const bool updateDestinationFrame = mRequestedSize != mSize;
    mSize = mRequestedSize;
    Rect crop = computeCrop(bufferItem);
    mLastBufferInfo.update(true /* hasBuffer */, bufferItem.mGraphicBuffer->getWidth(),
                           bufferItem.mGraphicBuffer->getHeight(), bufferItem.mTransform,
                           bufferItem.mScalingMode, crop);

    auto releaseBufferCallback =
            std::bind(releaseBufferCallbackThunk, wp<BLASTBufferQueue>(this) /* callbackContext */,
                      std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
                      std::placeholders::_4);
    t->setBuffer(mSurfaceControl, buffer, releaseCallbackId, releaseBufferCallback);
    t->setDataspace(mSurfaceControl, static_cast<ui::Dataspace>(bufferItem.mDataSpace));
    t->setHdrMetadata(mSurfaceControl, bufferItem.mHdrMetadata);
    t->setSurfaceDamageRegion(mSurfaceControl, bufferItem.mSurfaceDamage);
    t->setAcquireFence(mSurfaceControl,
                       bufferItem.mFence ? new Fence(bufferItem.mFence->dup()) : Fence::NO_FENCE);
    t->addTransactionCompletedCallback(transactionCallbackThunk, static_cast<void*>(this));

    mSurfaceControlsWithPendingCallback.push(mSurfaceControl);

    if (updateDestinationFrame) {
        t->setDestinationFrame(mSurfaceControl, Rect(0, 0, mSize.getWidth(), mSize.getHeight()));
    }
    t->setBufferCrop(mSurfaceControl, crop);
    t->setTransform(mSurfaceControl, bufferItem.mTransform);
    t->setTransformToDisplayInverse(mSurfaceControl, bufferItem.mTransformToDisplayInverse);
    if (!bufferItem.mIsAutoTimestamp) {
        t->setDesiredPresentTime(bufferItem.mTimestamp);
    }
    t->setFrameNumber(mSurfaceControl, bufferItem.mFrameNumber);

    if (!mNextFrameTimelineInfoQueue.empty()) {
        t->setFrameTimelineInfo(mNextFrameTimelineInfoQueue.front());
        mNextFrameTimelineInfoQueue.pop();
    }

    if (mAutoRefresh != bufferItem.mAutoRefresh) {
        t->setAutoRefresh(mSurfaceControl, bufferItem.mAutoRefresh);
        mAutoRefresh = bufferItem.mAutoRefresh;
    }
    {
        std::unique_lock _lock{mTimestampMutex};
        auto dequeueTime = mDequeueTimestamps.find(buffer->getId());
        if (dequeueTime != mDequeueTimestamps.end()) {
            Parcel p;
            p.writeInt64(dequeueTime->second);
            t->setMetadata(mSurfaceControl, METADATA_DEQUEUE_TIME, p);
            mDequeueTimestamps.erase(dequeueTime);
        }
    }

    auto mergeTransaction =
            [&t, currentFrameNumber = bufferItem.mFrameNumber](
                    std::tuple<uint64_t, SurfaceComposerClient::Transaction> pendingTransaction) {
                auto& [targetFrameNumber, transaction] = pendingTransaction;
                if (currentFrameNumber < targetFrameNumber) {
                    return false;
                }
                t->merge(std::move(transaction));
                return true;
            };

    mPendingTransactions.erase(std::remove_if(mPendingTransactions.begin(),
                                              mPendingTransactions.end(), mergeTransaction),
                               mPendingTransactions.end());

    if (applyTransaction) {
        t->setApplyToken(mApplyToken).apply();
    }

    BQA_LOGV("acquireNextBufferLocked size=%dx%d mFrameNumber=%" PRIu64
             " applyTransaction=%s mTimestamp=%" PRId64 "%s mPendingTransactions.size=%d"
             " graphicBufferId=%" PRIu64 "%s transform=%d",
             mSize.width, mSize.height, bufferItem.mFrameNumber, boolToString(applyTransaction),
             bufferItem.mTimestamp, bufferItem.mIsAutoTimestamp ? "(auto)" : "",
             static_cast<uint32_t>(mPendingTransactions.size()), bufferItem.mGraphicBuffer->getId(),
             bufferItem.mAutoRefresh ? " mAutoRefresh" : "", bufferItem.mTransform);
}

Rect BLASTBufferQueue::computeCrop(const BufferItem& item) {
    if (item.mScalingMode == NATIVE_WINDOW_SCALING_MODE_SCALE_CROP) {
        return GLConsumer::scaleDownCrop(item.mCrop, mSize.width, mSize.height);
    }
    return item.mCrop;
}

void BLASTBufferQueue::acquireAndReleaseBuffer() {
    BufferItem bufferItem;
    status_t status =
            mBufferItemConsumer->acquireBuffer(&bufferItem, 0 /* expectedPresent */, false);
    if (status != OK) {
        BQA_LOGE("Failed to acquire a buffer in acquireAndReleaseBuffer, err=%s",
                 statusToString(status).c_str());
        return;
    }
    mNumFrameAvailable--;
    mBufferItemConsumer->releaseBuffer(bufferItem, bufferItem.mFence);
}

void BLASTBufferQueue::onFrameAvailable(const BufferItem& item) {
    ATRACE_CALL();
    std::unique_lock _lock{mMutex};

    const bool nextTransactionSet = mNextTransaction != nullptr;
    BQA_LOGV("onFrameAvailable-start nextTransactionSet=%s", boolToString(nextTransactionSet));
    if (nextTransactionSet) {
        if (mWaitForTransactionCallback) {
            // We are waiting on a previous sync's transaction callback so allow another sync
            // transaction to proceed.
            //
            // We need to first flush out the transactions that were in between the two syncs.
            // We do this by merging them into mNextTransaction so any buffer merging will get
            // a release callback invoked. The release callback will be async so we need to wait
            // on max acquired to make sure we have the capacity to acquire another buffer.
            if (maxBuffersAcquired(false /* includeExtraAcquire */)) {
                BQA_LOGD("waiting to flush shadow queue...");
                mCallbackCV.wait(_lock);
            }
            while (mNumFrameAvailable > 0) {
                // flush out the shadow queue
                acquireAndReleaseBuffer();
            }
        }

        while (maxBuffersAcquired(false /* includeExtraAcquire */)) {
            BQA_LOGD("waiting for free buffer.");
            mCallbackCV.wait(_lock);
        }
    }

    // add to shadow queue
    mNumFrameAvailable++;
    if (mWaitForTransactionCallback && mNumFrameAvailable == 2) {
        acquireAndReleaseBuffer();
    }
    ATRACE_INT(mQueuedBufferTrace.c_str(),
               mNumFrameAvailable + mNumAcquired - mPendingRelease.size());

    BQA_LOGV("onFrameAvailable framenumber=%" PRIu64 " nextTransactionSet=%s", item.mFrameNumber,
             boolToString(nextTransactionSet));

    if (nextTransactionSet) {
        acquireNextBufferLocked(std::move(mNextTransaction));

        // Only need a commit callback when syncing to ensure the buffer that's synced has been sent
        // to SF
        incStrong((void*)transactionCommittedCallbackThunk);
        mNextTransaction->addTransactionCommittedCallback(transactionCommittedCallbackThunk,
                                                          static_cast<void*>(this));

        mNextTransaction = nullptr;
        mWaitForTransactionCallback = true;
    } else if (!mWaitForTransactionCallback) {
        acquireNextBufferLocked(std::nullopt);
    }
}

void BLASTBufferQueue::onFrameReplaced(const BufferItem& item) {
    BQA_LOGV("onFrameReplaced framenumber=%" PRIu64, item.mFrameNumber);
    // Do nothing since we are not storing unacquired buffer items locally.
}

void BLASTBufferQueue::onFrameDequeued(const uint64_t bufferId) {
    std::unique_lock _lock{mTimestampMutex};
    mDequeueTimestamps[bufferId] = systemTime();
};

void BLASTBufferQueue::onFrameCancelled(const uint64_t bufferId) {
    std::unique_lock _lock{mTimestampMutex};
    mDequeueTimestamps.erase(bufferId);
};

void BLASTBufferQueue::setNextTransaction(SurfaceComposerClient::Transaction* t) {
    std::lock_guard _lock{mMutex};
    mNextTransaction = t;
}

bool BLASTBufferQueue::rejectBuffer(const BufferItem& item) {
    if (item.mScalingMode != NATIVE_WINDOW_SCALING_MODE_FREEZE) {
        // Only reject buffers if scaling mode is freeze.
        return false;
    }

    uint32_t bufWidth = item.mGraphicBuffer->getWidth();
    uint32_t bufHeight = item.mGraphicBuffer->getHeight();

    // Take the buffer's orientation into account
    if (item.mTransform & ui::Transform::ROT_90) {
        std::swap(bufWidth, bufHeight);
    }
    ui::Size bufferSize(bufWidth, bufHeight);
    if (mRequestedSize != mSize && mRequestedSize == bufferSize) {
        return false;
    }

    // reject buffers if the buffer size doesn't match.
    return mSize != bufferSize;
}

void BLASTBufferQueue::setTransactionCompleteCallback(
        uint64_t frameNumber, std::function<void(int64_t)>&& transactionCompleteCallback) {
    std::lock_guard _lock{mMutex};
    if (transactionCompleteCallback == nullptr) {
        mTransactionCompleteCallback = nullptr;
    } else {
        mTransactionCompleteCallback = std::move(transactionCompleteCallback);
        mTransactionCompleteFrameNumber = frameNumber;
    }
}

// Check if we have acquired the maximum number of buffers.
// Consumer can acquire an additional buffer if that buffer is not droppable. Set
// includeExtraAcquire is true to include this buffer to the count. Since this depends on the state
// of the buffer, the next acquire may return with NO_BUFFER_AVAILABLE.
bool BLASTBufferQueue::maxBuffersAcquired(bool includeExtraAcquire) const {
    int maxAcquiredBuffers = mMaxAcquiredBuffers + (includeExtraAcquire ? 2 : 1);
    return mNumAcquired == maxAcquiredBuffers;
}

class BBQSurface : public Surface {
private:
    std::mutex mMutex;
    sp<BLASTBufferQueue> mBbq;
    bool mDestroyed = false;

public:
    BBQSurface(const sp<IGraphicBufferProducer>& igbp, bool controlledByApp,
               const sp<IBinder>& scHandle, const sp<BLASTBufferQueue>& bbq)
          : Surface(igbp, controlledByApp, scHandle), mBbq(bbq) {}

    void allocateBuffers() override {
        uint32_t reqWidth = mReqWidth ? mReqWidth : mUserWidth;
        uint32_t reqHeight = mReqHeight ? mReqHeight : mUserHeight;
        auto gbp = getIGraphicBufferProducer();
        std::thread ([reqWidth, reqHeight, gbp=getIGraphicBufferProducer(),
                      reqFormat=mReqFormat, reqUsage=mReqUsage] () {
            gbp->allocateBuffers(reqWidth, reqHeight,
                                 reqFormat, reqUsage);

        }).detach();
    }

    status_t setFrameRate(float frameRate, int8_t compatibility,
                          int8_t changeFrameRateStrategy) override {
        std::unique_lock _lock{mMutex};
        if (mDestroyed) {
            return DEAD_OBJECT;
        }
        if (!ValidateFrameRate(frameRate, compatibility, changeFrameRateStrategy,
                               "BBQSurface::setFrameRate")) {
            return BAD_VALUE;
        }
        return mBbq->setFrameRate(frameRate, compatibility, changeFrameRateStrategy);
    }

    status_t setFrameTimelineInfo(const FrameTimelineInfo& frameTimelineInfo) override {
        std::unique_lock _lock{mMutex};
        if (mDestroyed) {
            return DEAD_OBJECT;
        }
        return mBbq->setFrameTimelineInfo(frameTimelineInfo);
    }

    void destroy() override {
        Surface::destroy();

        std::unique_lock _lock{mMutex};
        mDestroyed = true;
        mBbq = nullptr;
    }
};

// TODO: Can we coalesce this with frame updates? Need to confirm
// no timing issues.
status_t BLASTBufferQueue::setFrameRate(float frameRate, int8_t compatibility,
                                        bool shouldBeSeamless) {
    std::unique_lock _lock{mMutex};
    SurfaceComposerClient::Transaction t;

    return t.setFrameRate(mSurfaceControl, frameRate, compatibility, shouldBeSeamless).apply();
}

status_t BLASTBufferQueue::setFrameTimelineInfo(const FrameTimelineInfo& frameTimelineInfo) {
    std::unique_lock _lock{mMutex};
    mNextFrameTimelineInfoQueue.push(frameTimelineInfo);
    return OK;
}

void BLASTBufferQueue::setSidebandStream(const sp<NativeHandle>& stream) {
    std::unique_lock _lock{mMutex};
    SurfaceComposerClient::Transaction t;

    t.setSidebandStream(mSurfaceControl, stream).apply();
}

sp<Surface> BLASTBufferQueue::getSurface(bool includeSurfaceControlHandle) {
    std::unique_lock _lock{mMutex};
    sp<IBinder> scHandle = nullptr;
    if (includeSurfaceControlHandle && mSurfaceControl) {
        scHandle = mSurfaceControl->getHandle();
    }
    return new BBQSurface(mProducer, true, scHandle, this);
}

void BLASTBufferQueue::mergeWithNextTransaction(SurfaceComposerClient::Transaction* t,
                                                uint64_t frameNumber) {
    std::lock_guard _lock{mMutex};
    if (mLastAcquiredFrameNumber >= frameNumber) {
        // Apply the transaction since we have already acquired the desired frame.
        t->apply();
    } else {
        mPendingTransactions.emplace_back(frameNumber, *t);
        // Clear the transaction so it can't be applied elsewhere.
        t->clear();
    }
}

// Maintains a single worker thread per process that services a list of runnables.
class AsyncWorker : public Singleton<AsyncWorker> {
private:
    std::thread mThread;
    bool mDone = false;
    std::deque<std::function<void()>> mRunnables;
    std::mutex mMutex;
    std::condition_variable mCv;
    void run() {
        std::unique_lock<std::mutex> lock(mMutex);
        while (!mDone) {
            while (!mRunnables.empty()) {
                std::deque<std::function<void()>> runnables = std::move(mRunnables);
                mRunnables.clear();
                lock.unlock();
                // Run outside the lock since the runnable might trigger another
                // post to the async worker.
                execute(runnables);
                lock.lock();
            }
            mCv.wait(lock);
        }
    }

    void execute(std::deque<std::function<void()>>& runnables) {
        while (!runnables.empty()) {
            std::function<void()> runnable = runnables.front();
            runnables.pop_front();
            runnable();
        }
    }

public:
    AsyncWorker() : Singleton<AsyncWorker>() { mThread = std::thread(&AsyncWorker::run, this); }

    ~AsyncWorker() {
        mDone = true;
        mCv.notify_all();
        if (mThread.joinable()) {
            mThread.join();
        }
    }

    void post(std::function<void()> runnable) {
        std::unique_lock<std::mutex> lock(mMutex);
        mRunnables.emplace_back(std::move(runnable));
        mCv.notify_one();
    }
};
ANDROID_SINGLETON_STATIC_INSTANCE(AsyncWorker);

// Asynchronously calls ProducerListener functions so we can emulate one way binder calls.
class AsyncProducerListener : public BnProducerListener {
private:
    const sp<IProducerListener> mListener;

public:
    AsyncProducerListener(const sp<IProducerListener>& listener) : mListener(listener) {}

    void onBufferReleased() override {
        AsyncWorker::getInstance().post([listener = mListener]() { listener->onBufferReleased(); });
    }

    void onBuffersDiscarded(const std::vector<int32_t>& slots) override {
        AsyncWorker::getInstance().post(
                [listener = mListener, slots = slots]() { listener->onBuffersDiscarded(slots); });
    }
};

// Extends the BufferQueueProducer to create a wrapper around the listener so the listener calls
// can be non-blocking when the producer is in the client process.
class BBQBufferQueueProducer : public BufferQueueProducer {
public:
    BBQBufferQueueProducer(const sp<BufferQueueCore>& core)
          : BufferQueueProducer(core, false /* consumerIsSurfaceFlinger*/) {}

    status_t connect(const sp<IProducerListener>& listener, int api, bool producerControlledByApp,
                     QueueBufferOutput* output) override {
        if (!listener) {
            return BufferQueueProducer::connect(listener, api, producerControlledByApp, output);
        }

        return BufferQueueProducer::connect(new AsyncProducerListener(listener), api,
                                            producerControlledByApp, output);
    }

    int query(int what, int* value) override {
        if (what == NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER) {
            *value = 1;
            return NO_ERROR;
        }
        return BufferQueueProducer::query(what, value);
    }
};

// Similar to BufferQueue::createBufferQueue but creates an adapter specific bufferqueue producer.
// This BQP allows invoking client specified ProducerListeners and invoke them asynchronously,
// emulating one way binder call behavior. Without this, if the listener calls back into the queue,
// we can deadlock.
void BLASTBufferQueue::createBufferQueue(sp<IGraphicBufferProducer>* outProducer,
                                         sp<IGraphicBufferConsumer>* outConsumer) {
    LOG_ALWAYS_FATAL_IF(outProducer == nullptr, "BLASTBufferQueue: outProducer must not be NULL");
    LOG_ALWAYS_FATAL_IF(outConsumer == nullptr, "BLASTBufferQueue: outConsumer must not be NULL");

    sp<BufferQueueCore> core(new BufferQueueCore());
    LOG_ALWAYS_FATAL_IF(core == nullptr, "BLASTBufferQueue: failed to create BufferQueueCore");

    sp<IGraphicBufferProducer> producer(new BBQBufferQueueProducer(core));
    LOG_ALWAYS_FATAL_IF(producer == nullptr,
                        "BLASTBufferQueue: failed to create BBQBufferQueueProducer");

    sp<BufferQueueConsumer> consumer(new BufferQueueConsumer(core));
    consumer->setAllowExtraAcquire(true);
    LOG_ALWAYS_FATAL_IF(consumer == nullptr,
                        "BLASTBufferQueue: failed to create BufferQueueConsumer");

    *outProducer = producer;
    *outConsumer = consumer;
}

PixelFormat BLASTBufferQueue::convertBufferFormat(PixelFormat& format) {
    PixelFormat convertedFormat = format;
    switch (format) {
        case PIXEL_FORMAT_TRANSPARENT:
        case PIXEL_FORMAT_TRANSLUCENT:
            convertedFormat = PIXEL_FORMAT_RGBA_8888;
            break;
        case PIXEL_FORMAT_OPAQUE:
            convertedFormat = PIXEL_FORMAT_RGBX_8888;
            break;
    }
    return convertedFormat;
}

uint32_t BLASTBufferQueue::getLastTransformHint() const {
    if (mSurfaceControl != nullptr) {
        return mSurfaceControl->getTransformHint();
    } else {
        return 0;
    }
}

uint64_t BLASTBufferQueue::getLastAcquiredFrameNum() {
    std::unique_lock _lock{mMutex};
    return mLastAcquiredFrameNumber;
}

} // namespace android
