/*
 * Copyright (C) 2018 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "BufferQueueLayer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#include "BufferQueueLayer.h"

#include <compositionengine/LayerFECompositionState.h>
#include <gui/BufferQueueConsumer.h>
#include <system/window.h>

#include "LayerRejecter.h"
#include "SurfaceInterceptor.h"

#include "FrameTracer/FrameTracer.h"
#include "Scheduler/LayerHistory.h"
#include "TimeStats/TimeStats.h"

namespace android {
using PresentState = frametimeline::SurfaceFrame::PresentState;

BufferQueueLayer::BufferQueueLayer(const LayerCreationArgs& args) : BufferLayer(args) {}

BufferQueueLayer::~BufferQueueLayer() {
    mContentsChangedListener->abandon();
    mConsumer->abandon();
}

// -----------------------------------------------------------------------
// Interface implementation for Layer
// -----------------------------------------------------------------------

void BufferQueueLayer::onLayerDisplayed(ftl::SharedFuture<FenceResult> futureFenceResult) {
    const sp<Fence> releaseFence = futureFenceResult.get().value_or(Fence::NO_FENCE);
    mConsumer->setReleaseFence(releaseFence);

    // Prevent tracing the same release multiple times.
    if (mPreviousFrameNumber != mPreviousReleasedFrameNumber) {
        mFlinger->mFrameTracer->traceFence(getSequence(), mPreviousBufferId, mPreviousFrameNumber,
                                           std::make_shared<FenceTime>(releaseFence),
                                           FrameTracer::FrameEvent::RELEASE_FENCE);
        mPreviousReleasedFrameNumber = mPreviousFrameNumber;
    }
}

void BufferQueueLayer::setTransformHint(ui::Transform::RotationFlags displayTransformHint) {
    BufferLayer::setTransformHint(displayTransformHint);
    mConsumer->setTransformHint(mTransformHint);
}

void BufferQueueLayer::releasePendingBuffer(nsecs_t) {
    if (!mConsumer->releasePendingBuffer()) {
        return;
    }
}

void BufferQueueLayer::setDefaultBufferSize(uint32_t w, uint32_t h) {
    mConsumer->setDefaultBufferSize(w, h);
}

int32_t BufferQueueLayer::getQueuedFrameCount() const {
    return mQueuedFrames;
}

bool BufferQueueLayer::isBufferDue(nsecs_t expectedPresentTime) const {
    Mutex::Autolock lock(mQueueItemLock);

    const int64_t addedTime = mQueueItems[0].item.mTimestamp;

    // Ignore timestamps more than a second in the future
    const bool isPlausible = addedTime < (expectedPresentTime + s2ns(1));
    ALOGW_IF(!isPlausible,
             "[%s] Timestamp %" PRId64 " seems implausible "
             "relative to expectedPresent %" PRId64,
             getDebugName(), addedTime, expectedPresentTime);

    if (!isPlausible) {
        mFlinger->mTimeStats->incrementBadDesiredPresent(getSequence());
    }

    const bool isDue = addedTime < expectedPresentTime;
    return isDue || !isPlausible;
}

// -----------------------------------------------------------------------
// Interface implementation for BufferLayer
// -----------------------------------------------------------------------

bool BufferQueueLayer::fenceHasSignaled() const {
    Mutex::Autolock lock(mQueueItemLock);

    if (SurfaceFlinger::enableLatchUnsignaledConfig != LatchUnsignaledConfig::Disabled) {
        return true;
    }

    if (!hasFrameUpdate()) {
        return true;
    }

    if (mQueueItems[0].item.mIsDroppable) {
        // Even though this buffer's fence may not have signaled yet, it could
        // be replaced by another buffer before it has a chance to, which means
        // that it's possible to get into a situation where a buffer is never
        // able to be latched. To avoid this, grab this buffer anyway.
        return true;
    }
    const bool fenceSignaled =
            mQueueItems[0].item.mFenceTime->getSignalTime() != Fence::SIGNAL_TIME_PENDING;
    if (!fenceSignaled) {
        mFlinger->mTimeStats->incrementLatchSkipped(getSequence(),
                                                    TimeStats::LatchSkipReason::LateAcquire);
    }

    return fenceSignaled;
}

bool BufferQueueLayer::framePresentTimeIsCurrent(nsecs_t expectedPresentTime) const {
    Mutex::Autolock lock(mQueueItemLock);

    if (!hasFrameUpdate() || isRemovedFromCurrentState()) {
        return true;
    }

    return mQueueItems[0].item.mTimestamp <= expectedPresentTime;
}

bool BufferQueueLayer::latchSidebandStream(bool& recomputeVisibleRegions) {
    // We need to update the sideband stream if the layer has both a buffer and a sideband stream.
    editCompositionState()->sidebandStreamHasFrame = hasFrameUpdate() && mSidebandStream.get();

    bool sidebandStreamChanged = true;
    if (mSidebandStreamChanged.compare_exchange_strong(sidebandStreamChanged, false)) {
        // mSidebandStreamChanged was changed to false
        mSidebandStream = mConsumer->getSidebandStream();
        auto* layerCompositionState = editCompositionState();
        layerCompositionState->sidebandStream = mSidebandStream;
        if (layerCompositionState->sidebandStream != nullptr) {
            setTransactionFlags(eTransactionNeeded);
            mFlinger->setTransactionFlags(eTraversalNeeded);
        }
        recomputeVisibleRegions = true;

        return true;
    }
    return false;
}

bool BufferQueueLayer::hasFrameUpdate() const {
    return mQueuedFrames > 0;
}

status_t BufferQueueLayer::updateTexImage(bool& recomputeVisibleRegions, nsecs_t latchTime,
                                          nsecs_t expectedPresentTime) {
    // This boolean is used to make sure that SurfaceFlinger's shadow copy
    // of the buffer queue isn't modified when the buffer queue is returning
    // BufferItem's that weren't actually queued. This can happen in shared
    // buffer mode.
    bool queuedBuffer = false;
    const int32_t layerId = getSequence();
    LayerRejecter r(mDrawingState, getDrawingState(), recomputeVisibleRegions,
                    getProducerStickyTransform() != 0, mName,
                    getTransformToDisplayInverse());

    if (isRemovedFromCurrentState()) {
        expectedPresentTime = 0;
    }

    // updateTexImage() below might drop the some buffers at the head of the queue if there is a
    // buffer behind them which is timely to be presented. However this buffer may not be signaled
    // yet. The code below makes sure that this wouldn't happen by setting maxFrameNumber to the
    // last buffer that was signaled.
    uint64_t lastSignaledFrameNumber = mLastFrameNumberReceived;
    {
        Mutex::Autolock lock(mQueueItemLock);
        for (size_t i = 0; i < mQueueItems.size(); i++) {
            bool fenceSignaled =
                    mQueueItems[i].item.mFenceTime->getSignalTime() != Fence::SIGNAL_TIME_PENDING;
            if (!fenceSignaled) {
                break;
            }
            lastSignaledFrameNumber = mQueueItems[i].item.mFrameNumber;
        }
    }
    const uint64_t maxFrameNumberToAcquire =
            std::min(mLastFrameNumberReceived.load(), lastSignaledFrameNumber);

    bool autoRefresh;
    status_t updateResult = mConsumer->updateTexImage(&r, expectedPresentTime, &autoRefresh,
                                                      &queuedBuffer, maxFrameNumberToAcquire);
    mDrawingState.autoRefresh = autoRefresh;
    if (updateResult == BufferQueue::PRESENT_LATER) {
        // Producer doesn't want buffer to be displayed yet.  Signal a
        // layer update so we check again at the next opportunity.
        mFlinger->onLayerUpdate();
        return BAD_VALUE;
    } else if (updateResult == BufferLayerConsumer::BUFFER_REJECTED) {
        // If the buffer has been rejected, remove it from the shadow queue
        // and return early
        if (queuedBuffer) {
            Mutex::Autolock lock(mQueueItemLock);
            if (mQueuedFrames > 0) {
                mConsumer->mergeSurfaceDamage(mQueueItems[0].item.mSurfaceDamage);
                mFlinger->mTimeStats->removeTimeRecord(layerId, mQueueItems[0].item.mFrameNumber);
                if (mQueueItems[0].surfaceFrame) {
                    addSurfaceFrameDroppedForBuffer(mQueueItems[0].surfaceFrame);
                }
                mQueueItems.erase(mQueueItems.begin());
                mQueuedFrames--;
            }
        }
        return BAD_VALUE;
    } else if (updateResult != NO_ERROR || mUpdateTexImageFailed) {
        // This can occur if something goes wrong when trying to create the
        // EGLImage for this buffer. If this happens, the buffer has already
        // been released, so we need to clean up the queue and bug out
        // early.
        if (queuedBuffer) {
            Mutex::Autolock lock(mQueueItemLock);
            for (auto& [item, surfaceFrame] : mQueueItems) {
                if (surfaceFrame) {
                    addSurfaceFrameDroppedForBuffer(surfaceFrame);
                }
            }
            mQueueItems.clear();
            mQueuedFrames = 0;
            mFlinger->mTimeStats->onDestroy(layerId);
            mFlinger->mFrameTracer->onDestroy(layerId);
        }

        // Once we have hit this state, the shadow queue may no longer
        // correctly reflect the incoming BufferQueue's contents, so even if
        // updateTexImage starts working, the only safe course of action is
        // to continue to ignore updates.
        mUpdateTexImageFailed = true;

        return BAD_VALUE;
    }

    bool more_frames_pending = false;
    if (queuedBuffer) {
        // Autolock scope
        auto currentFrameNumber = mConsumer->getFrameNumber();

        Mutex::Autolock lock(mQueueItemLock);

        // Remove any stale buffers that have been dropped during
        // updateTexImage
        while (mQueuedFrames > 0 && mQueueItems[0].item.mFrameNumber != currentFrameNumber) {
            mConsumer->mergeSurfaceDamage(mQueueItems[0].item.mSurfaceDamage);
            mFlinger->mTimeStats->removeTimeRecord(layerId, mQueueItems[0].item.mFrameNumber);
            if (mQueueItems[0].surfaceFrame) {
                addSurfaceFrameDroppedForBuffer(mQueueItems[0].surfaceFrame);
            }
            mQueueItems.erase(mQueueItems.begin());
            mQueuedFrames--;
        }

        uint64_t bufferID = mQueueItems[0].item.mGraphicBuffer->getId();
        mFlinger->mTimeStats->setLatchTime(layerId, currentFrameNumber, latchTime);
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferID, currentFrameNumber, latchTime,
                                               FrameTracer::FrameEvent::LATCH);

        if (mQueueItems[0].surfaceFrame) {
            addSurfaceFramePresentedForBuffer(mQueueItems[0].surfaceFrame,
                                              mQueueItems[0].item.mFenceTime->getSignalTime(),
                                              latchTime);
        }
        mQueueItems.erase(mQueueItems.begin());
        more_frames_pending = (mQueuedFrames.fetch_sub(1) > 1);
    }

    // Decrement the queued-frames count.  Signal another event if we
    // have more frames pending.
    if ((queuedBuffer && more_frames_pending) || mDrawingState.autoRefresh) {
        mFlinger->onLayerUpdate();
    }

    return NO_ERROR;
}

status_t BufferQueueLayer::updateActiveBuffer() {
    // update the active buffer
    mPreviousBufferId = getCurrentBufferId();
    mBufferInfo.mBuffer =
            mConsumer->getCurrentBuffer(&mBufferInfo.mBufferSlot, &mBufferInfo.mFence);

    if (mBufferInfo.mBuffer == nullptr) {
        // this can only happen if the very first buffer was rejected.
        return BAD_VALUE;
    }
    return NO_ERROR;
}

status_t BufferQueueLayer::updateFrameNumber() {
    mPreviousFrameNumber = mCurrentFrameNumber;
    mCurrentFrameNumber = mConsumer->getFrameNumber();
    return NO_ERROR;
}

void BufferQueueLayer::setFrameTimelineInfoForBuffer(const FrameTimelineInfo& frameTimelineInfo) {
    mFrameTimelineInfo = frameTimelineInfo;
}

// -----------------------------------------------------------------------
// Interface implementation for BufferLayerConsumer::ContentsChangedListener
// -----------------------------------------------------------------------

void BufferQueueLayer::onFrameDequeued(const uint64_t bufferId) {
    const int32_t layerId = getSequence();
    mFlinger->mFrameTracer->traceNewLayer(layerId, getName().c_str());
    mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, FrameTracer::UNSPECIFIED_FRAME_NUMBER,
                                           systemTime(), FrameTracer::FrameEvent::DEQUEUE);
}

void BufferQueueLayer::onFrameDetached(const uint64_t bufferId) {
    const int32_t layerId = getSequence();
    mFlinger->mFrameTracer->traceNewLayer(layerId, getName().c_str());
    mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, FrameTracer::UNSPECIFIED_FRAME_NUMBER,
                                           systemTime(), FrameTracer::FrameEvent::DETACH);
}

void BufferQueueLayer::onFrameCancelled(const uint64_t bufferId) {
    const int32_t layerId = getSequence();
    mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, FrameTracer::UNSPECIFIED_FRAME_NUMBER,
                                           systemTime(), FrameTracer::FrameEvent::CANCEL);
}

void BufferQueueLayer::onFrameAvailable(const BufferItem& item) {
    const int32_t layerId = getSequence();
    const uint64_t bufferId = item.mGraphicBuffer->getId();
    mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, item.mFrameNumber, systemTime(),
                                           FrameTracer::FrameEvent::QUEUE);
    mFlinger->mFrameTracer->traceFence(layerId, bufferId, item.mFrameNumber,
                                       std::make_shared<FenceTime>(item.mFence),
                                       FrameTracer::FrameEvent::ACQUIRE_FENCE);

    ATRACE_CALL();
    // Add this buffer from our internal queue tracker
    { // Autolock scope
        const nsecs_t presentTime = item.mIsAutoTimestamp ? 0 : item.mTimestamp;

        using LayerUpdateType = scheduler::LayerHistory::LayerUpdateType;
        mFlinger->mScheduler->recordLayerHistory(this, presentTime, LayerUpdateType::Buffer);

        Mutex::Autolock lock(mQueueItemLock);
        // Reset the frame number tracker when we receive the first buffer after
        // a frame number reset
        if (item.mFrameNumber == 1) {
            mLastFrameNumberReceived = 0;
        }

        // Ensure that callbacks are handled in order
        while (item.mFrameNumber != mLastFrameNumberReceived + 1) {
            status_t result = mQueueItemCondition.waitRelative(mQueueItemLock, ms2ns(500));
            if (result != NO_ERROR) {
                ALOGE("[%s] Timed out waiting on callback", getDebugName());
                break;
            }
        }

        auto surfaceFrame = createSurfaceFrameForBuffer(mFrameTimelineInfo, systemTime(), mName);

        mQueueItems.push_back({item, surfaceFrame});
        mQueuedFrames++;

        // Wake up any pending callbacks
        mLastFrameNumberReceived = item.mFrameNumber;
        mQueueItemCondition.broadcast();
    }

    mFlinger->mInterceptor->saveBufferUpdate(layerId, item.mGraphicBuffer->getWidth(),
                                             item.mGraphicBuffer->getHeight(), item.mFrameNumber);

    mFlinger->onLayerUpdate();
    mConsumer->onBufferAvailable(item);
}

void BufferQueueLayer::onFrameReplaced(const BufferItem& item) {
    ATRACE_CALL();
    { // Autolock scope
        Mutex::Autolock lock(mQueueItemLock);

        // Ensure that callbacks are handled in order
        while (item.mFrameNumber != mLastFrameNumberReceived + 1) {
            status_t result = mQueueItemCondition.waitRelative(mQueueItemLock, ms2ns(500));
            if (result != NO_ERROR) {
                ALOGE("[%s] Timed out waiting on callback", getDebugName());
                break;
            }
        }

        if (!hasFrameUpdate()) {
            ALOGE("Can't replace a frame on an empty queue");
            return;
        }

        auto surfaceFrame = createSurfaceFrameForBuffer(mFrameTimelineInfo, systemTime(), mName);
        mQueueItems[mQueueItems.size() - 1].item = item;
        mQueueItems[mQueueItems.size() - 1].surfaceFrame = std::move(surfaceFrame);

        // Wake up any pending callbacks
        mLastFrameNumberReceived = item.mFrameNumber;
        mQueueItemCondition.broadcast();
    }

    const int32_t layerId = getSequence();
    const uint64_t bufferId = item.mGraphicBuffer->getId();
    mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, item.mFrameNumber, systemTime(),
                                           FrameTracer::FrameEvent::QUEUE);
    mFlinger->mFrameTracer->traceFence(layerId, bufferId, item.mFrameNumber,
                                       std::make_shared<FenceTime>(item.mFence),
                                       FrameTracer::FrameEvent::ACQUIRE_FENCE);
    mConsumer->onBufferAvailable(item);
}

void BufferQueueLayer::onSidebandStreamChanged() {
    bool sidebandStreamChanged = false;
    if (mSidebandStreamChanged.compare_exchange_strong(sidebandStreamChanged, true)) {
        // mSidebandStreamChanged was changed to true
        mFlinger->onLayerUpdate();
    }
}

// -----------------------------------------------------------------------

void BufferQueueLayer::onFirstRef() {
    BufferLayer::onFirstRef();

    // Creates a custom BufferQueue for SurfaceFlingerConsumer to use
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    mFlinger->getFactory().createBufferQueue(&producer, &consumer, true);
    mProducer = mFlinger->getFactory().createMonitoredProducer(producer, mFlinger, this);
    mConsumer =
            mFlinger->getFactory().createBufferLayerConsumer(consumer, mFlinger->getRenderEngine(),
                                                             mTextureName, this);
    mConsumer->setConsumerUsageBits(getEffectiveUsage(0));

    mContentsChangedListener = new ContentsChangedListener(this);
    mConsumer->setContentsChangedListener(mContentsChangedListener);
    mConsumer->setName(String8(mName.data(), mName.size()));

    mProducer->setMaxDequeuedBufferCount(2);
}

status_t BufferQueueLayer::setDefaultBufferProperties(uint32_t w, uint32_t h, PixelFormat format) {
    // never allow a surface larger than what our underlying GL implementation
    // can handle.
    if (mFlinger->exceedsMaxRenderTargetSize(w, h)) {
        ALOGE("dimensions too large %" PRIu32 " x %" PRIu32, w, h);
        return BAD_VALUE;
    }

    setDefaultBufferSize(w, h);
    mConsumer->setDefaultBufferFormat(format);
    mConsumer->setConsumerUsageBits(getEffectiveUsage(0));

    return NO_ERROR;
}

sp<IGraphicBufferProducer> BufferQueueLayer::getProducer() const {
    return mProducer;
}

uint32_t BufferQueueLayer::getProducerStickyTransform() const {
    int producerStickyTransform = 0;
    int ret = mProducer->query(NATIVE_WINDOW_STICKY_TRANSFORM, &producerStickyTransform);
    if (ret != OK) {
        ALOGW("%s: Error %s (%d) while querying window sticky transform.", __FUNCTION__,
              strerror(-ret), ret);
        return 0;
    }
    return static_cast<uint32_t>(producerStickyTransform);
}

void BufferQueueLayer::gatherBufferInfo() {
    BufferLayer::gatherBufferInfo();

    mBufferInfo.mDesiredPresentTime = mConsumer->getTimestamp();
    mBufferInfo.mFenceTime = mConsumer->getCurrentFenceTime();
    mBufferInfo.mFence = mConsumer->getCurrentFence();
    mBufferInfo.mTransform = mConsumer->getCurrentTransform();
    mBufferInfo.mDataspace = translateDataspace(mConsumer->getCurrentDataSpace());
    mBufferInfo.mCrop = mConsumer->getCurrentCrop();
    mBufferInfo.mScaleMode = mConsumer->getCurrentScalingMode();
    mBufferInfo.mSurfaceDamage = mConsumer->getSurfaceDamage();
    mBufferInfo.mHdrMetadata = mConsumer->getCurrentHdrMetadata();
    mBufferInfo.mApi = mConsumer->getCurrentApi();
    mBufferInfo.mTransformToDisplayInverse = mConsumer->getTransformToDisplayInverse();
}

sp<Layer> BufferQueueLayer::createClone() {
    LayerCreationArgs args(mFlinger.get(), nullptr, mName + " (Mirror)", 0, LayerMetadata());
    args.textureName = mTextureName;
    sp<BufferQueueLayer> layer = mFlinger->getFactory().createBufferQueueLayer(args);
    layer->setInitialValuesForClone(this);

    return layer;
}

// -----------------------------------------------------------------------
// Interface implementation for BufferLayerConsumer::ContentsChangedListener
// -----------------------------------------------------------------------

void BufferQueueLayer::ContentsChangedListener::onFrameAvailable(const BufferItem& item) {
    Mutex::Autolock lock(mMutex);
    if (mBufferQueueLayer != nullptr) {
        mBufferQueueLayer->onFrameAvailable(item);
    }
}

void BufferQueueLayer::ContentsChangedListener::onFrameReplaced(const BufferItem& item) {
    Mutex::Autolock lock(mMutex);
    if (mBufferQueueLayer != nullptr) {
        mBufferQueueLayer->onFrameReplaced(item);
    }
}

void BufferQueueLayer::ContentsChangedListener::onSidebandStreamChanged() {
    Mutex::Autolock lock(mMutex);
    if (mBufferQueueLayer != nullptr) {
        mBufferQueueLayer->onSidebandStreamChanged();
    }
}

void BufferQueueLayer::ContentsChangedListener::onFrameDequeued(const uint64_t bufferId) {
    Mutex::Autolock lock(mMutex);
    if (mBufferQueueLayer != nullptr) {
        mBufferQueueLayer->onFrameDequeued(bufferId);
    }
}

void BufferQueueLayer::ContentsChangedListener::onFrameDetached(const uint64_t bufferId) {
    Mutex::Autolock lock(mMutex);
    if (mBufferQueueLayer != nullptr) {
        mBufferQueueLayer->onFrameDetached(bufferId);
    }
}

void BufferQueueLayer::ContentsChangedListener::onFrameCancelled(const uint64_t bufferId) {
    Mutex::Autolock lock(mMutex);
    if (mBufferQueueLayer != nullptr) {
        mBufferQueueLayer->onFrameCancelled(bufferId);
    }
}

void BufferQueueLayer::ContentsChangedListener::abandon() {
    Mutex::Autolock lock(mMutex);
    mBufferQueueLayer = nullptr;
}

// -----------------------------------------------------------------------

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
