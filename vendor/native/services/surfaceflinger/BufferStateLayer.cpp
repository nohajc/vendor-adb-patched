/*
 * Copyright (C) 2017 The Android Open Source Project
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
#pragma clang diagnostic ignored "-Wextra"

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "BufferStateLayer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "BufferStateLayer.h"

#include <limits>

#include <FrameTimeline/FrameTimeline.h>
#include <compositionengine/LayerFECompositionState.h>
#include <gui/BufferQueue.h>
#include <private/gui/SyncFeatures.h>
#include <renderengine/Image.h>
#include "TunnelModeEnabledReporter.h"

#include "EffectLayer.h"
#include "FrameTracer/FrameTracer.h"
#include "TimeStats/TimeStats.h"

namespace android {

using PresentState = frametimeline::SurfaceFrame::PresentState;
namespace {
void callReleaseBufferCallback(const sp<ITransactionCompletedListener>& listener,
                               const sp<GraphicBuffer>& buffer, uint64_t framenumber,
                               const sp<Fence>& releaseFence, uint32_t transformHint,
                               uint32_t currentMaxAcquiredBufferCount) {
    if (!listener) {
        return;
    }
    listener->onReleaseBuffer({buffer->getId(), framenumber},
                              releaseFence ? releaseFence : Fence::NO_FENCE, transformHint,
                              currentMaxAcquiredBufferCount);
}
} // namespace

BufferStateLayer::BufferStateLayer(const LayerCreationArgs& args)
      : BufferLayer(args), mHwcSlotGenerator(new HwcSlotGenerator()) {
    mDrawingState.dataspace = ui::Dataspace::V0_SRGB;
}

BufferStateLayer::~BufferStateLayer() {
    // The original layer and the clone layer share the same texture and buffer. Therefore, only
    // one of the layers, in this case the original layer, needs to handle the deletion. The
    // original layer and the clone should be removed at the same time so there shouldn't be any
    // issue with the clone layer trying to use the texture.
    if (mBufferInfo.mBuffer != nullptr) {
        callReleaseBufferCallback(mDrawingState.releaseBufferListener,
                                  mBufferInfo.mBuffer->getBuffer(), mBufferInfo.mFrameNumber,
                                  mBufferInfo.mFence, mTransformHint,
                                  mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(
                                          mOwnerUid));
    }
}

status_t BufferStateLayer::addReleaseFence(const sp<CallbackHandle>& ch,
                                           const sp<Fence>& fence) {
    if (ch == nullptr) {
        return OK;
    }
    ch->previousReleaseCallbackId = mPreviousReleaseCallbackId;
    if (!ch->previousReleaseFence.get()) {
        ch->previousReleaseFence = fence;
        return OK;
    }

    // Below logic is lifted from ConsumerBase.cpp:
    // Check status of fences first because merging is expensive.
    // Merging an invalid fence with any other fence results in an
    // invalid fence.
    auto currentStatus = ch->previousReleaseFence->getStatus();
    if (currentStatus == Fence::Status::Invalid) {
        ALOGE("Existing fence has invalid state, layer: %s", mName.c_str());
        return BAD_VALUE;
    }

    auto incomingStatus = fence->getStatus();
    if (incomingStatus == Fence::Status::Invalid) {
        ALOGE("New fence has invalid state, layer: %s", mName.c_str());
        ch->previousReleaseFence = fence;
        return BAD_VALUE;
    }

    // If both fences are signaled or both are unsignaled, we need to merge
    // them to get an accurate timestamp.
    if (currentStatus == incomingStatus) {
        char fenceName[32] = {};
        snprintf(fenceName, 32, "%.28s", mName.c_str());
        sp<Fence> mergedFence = Fence::merge(
                fenceName, ch->previousReleaseFence, fence);
        if (!mergedFence.get()) {
            ALOGE("failed to merge release fences, layer: %s", mName.c_str());
            // synchronization is broken, the best we can do is hope fences
            // signal in order so the new fence will act like a union
            ch->previousReleaseFence = fence;
            return BAD_VALUE;
        }
        ch->previousReleaseFence = mergedFence;
    } else if (incomingStatus == Fence::Status::Unsignaled) {
        // If one fence has signaled and the other hasn't, the unsignaled
        // fence will approximately correspond with the correct timestamp.
        // There's a small race if both fences signal at about the same time
        // and their statuses are retrieved with unfortunate timing. However,
        // by this point, they will have both signaled and only the timestamp
        // will be slightly off; any dependencies after this point will
        // already have been met.
        ch->previousReleaseFence = fence;
    }
    // else if (currentStatus == Fence::Status::Unsignaled) is a no-op.

    return OK;
}

// -----------------------------------------------------------------------
// Interface implementation for Layer
// -----------------------------------------------------------------------
void BufferStateLayer::onLayerDisplayed(const sp<Fence>& releaseFence) {
    if (!releaseFence->isValid()) {
        return;
    }
    // The previous release fence notifies the client that SurfaceFlinger is done with the previous
    // buffer that was presented on this layer. The first transaction that came in this frame that
    // replaced the previous buffer on this layer needs this release fence, because the fence will
    // let the client know when that previous buffer is removed from the screen.
    //
    // Every other transaction on this layer does not need a release fence because no other
    // Transactions that were set on this layer this frame are going to have their preceeding buffer
    // removed from the display this frame.
    //
    // For example, if we have 3 transactions this frame. The first transaction doesn't contain a
    // buffer so it doesn't need a previous release fence because the layer still needs the previous
    // buffer. The second transaction contains a buffer so it needs a previous release fence because
    // the previous buffer will be released this frame. The third transaction also contains a
    // buffer. It replaces the buffer in the second transaction. The buffer in the second
    // transaction will now no longer be presented so it is released immediately and the third
    // transaction doesn't need a previous release fence.
    sp<CallbackHandle> ch;
    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->releasePreviousBuffer &&
            mDrawingState.releaseBufferEndpoint == handle->listener) {
            ch = handle;
            break;
        }
    }
    auto status = addReleaseFence(ch, releaseFence);
    if (status != OK) {
        ALOGE("Failed to add release fence for layer %s", getName().c_str());
    }

    mPreviousReleaseFence = releaseFence;

    // Prevent tracing the same release multiple times.
    if (mPreviousFrameNumber != mPreviousReleasedFrameNumber) {
        mPreviousReleasedFrameNumber = mPreviousFrameNumber;
    }
}

void BufferStateLayer::onSurfaceFrameCreated(
        const std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame) {
    while (mPendingJankClassifications.size() >= kPendingClassificationMaxSurfaceFrames) {
        // Too many SurfaceFrames pending classification. The front of the deque is probably not
        // tracked by FrameTimeline and will never be presented. This will only result in a memory
        // leak.
        ALOGW("Removing the front of pending jank deque from layer - %s to prevent memory leak",
              mName.c_str());
        std::string miniDump = mPendingJankClassifications.front()->miniDump();
        ALOGD("Head SurfaceFrame mini dump\n%s", miniDump.c_str());
        mPendingJankClassifications.pop_front();
    }
    mPendingJankClassifications.emplace_back(surfaceFrame);
}

void BufferStateLayer::releasePendingBuffer(nsecs_t dequeueReadyTime) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->transformHint = mTransformHint;
        handle->dequeueReadyTime = dequeueReadyTime;
        handle->currentMaxAcquiredBufferCount =
                mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(mOwnerUid);
    }

    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->releasePreviousBuffer &&
            mDrawingState.releaseBufferEndpoint == handle->listener) {
            handle->previousReleaseCallbackId = mPreviousReleaseCallbackId;
            break;
        }
    }

    std::vector<JankData> jankData;
    jankData.reserve(mPendingJankClassifications.size());
    while (!mPendingJankClassifications.empty()
            && mPendingJankClassifications.front()->getJankType()) {
        std::shared_ptr<frametimeline::SurfaceFrame> surfaceFrame =
                mPendingJankClassifications.front();
        mPendingJankClassifications.pop_front();
        jankData.emplace_back(
                JankData(surfaceFrame->getToken(), surfaceFrame->getJankType().value()));
    }

    mFlinger->getTransactionCallbackInvoker().finalizePendingCallbackHandles(
            mDrawingState.callbackHandles, jankData);

    mDrawingState.callbackHandles = {};

    const sp<Fence>& releaseFence(mPreviousReleaseFence);
    std::shared_ptr<FenceTime> releaseFenceTime = std::make_shared<FenceTime>(releaseFence);
    {
        Mutex::Autolock lock(mFrameEventHistoryMutex);
        if (mPreviousFrameNumber != 0) {
            mFrameEventHistory.addRelease(mPreviousFrameNumber, dequeueReadyTime,
                                          std::move(releaseFenceTime));
        }
    }
}

void BufferStateLayer::finalizeFrameEventHistory(const std::shared_ptr<FenceTime>& glDoneFence,
                                                 const CompositorTiming& compositorTiming) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->gpuCompositionDoneFence = glDoneFence;
        handle->compositorTiming = compositorTiming;
    }
}

bool BufferStateLayer::willPresentCurrentTransaction() const {
    // Returns true if the most recent Transaction applied to CurrentState will be presented.
    return (getSidebandStreamChanged() || getAutoRefresh() ||
            (mDrawingState.modified &&
             (mDrawingState.buffer != nullptr || mDrawingState.bgColorLayer != nullptr)));
}

Rect BufferStateLayer::getCrop(const Layer::State& s) const {
    return s.crop;
}

bool BufferStateLayer::setTransform(uint32_t transform) {
    if (mDrawingState.bufferTransform == transform) return false;
    mDrawingState.bufferTransform = transform;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setTransformToDisplayInverse(bool transformToDisplayInverse) {
    if (mDrawingState.transformToDisplayInverse == transformToDisplayInverse) return false;
    mDrawingState.sequence++;
    mDrawingState.transformToDisplayInverse = transformToDisplayInverse;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setCrop(const Rect& crop) {
    if (mDrawingState.crop == crop) return false;
    mDrawingState.sequence++;
    mDrawingState.crop = crop;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setBufferCrop(const Rect& bufferCrop) {
    if (mDrawingState.bufferCrop == bufferCrop) return false;

    mDrawingState.sequence++;
    mDrawingState.bufferCrop = bufferCrop;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setDestinationFrame(const Rect& destinationFrame) {
    if (mDrawingState.destinationFrame == destinationFrame) return false;

    mDrawingState.sequence++;
    mDrawingState.destinationFrame = destinationFrame;

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

static bool assignTransform(ui::Transform* dst, ui::Transform& from) {
    if (*dst == from) {
        return false;
    }
    *dst = from;
    return true;
}

// Translate destination frame into scale and position. If a destination frame is not set, use the
// provided scale and position
bool BufferStateLayer::updateGeometry() {
    if (mDrawingState.destinationFrame.isEmpty()) {
        // If destination frame is not set, use the requested transform set via
        // BufferStateLayer::setPosition and BufferStateLayer::setMatrix.
        return assignTransform(&mDrawingState.transform, mRequestedTransform);
    }

    Rect destRect = mDrawingState.destinationFrame;
    int32_t destW = destRect.width();
    int32_t destH = destRect.height();
    if (destRect.left < 0) {
        destRect.left = 0;
        destRect.right = destW;
    }
    if (destRect.top < 0) {
        destRect.top = 0;
        destRect.bottom = destH;
    }

    if (!mDrawingState.buffer) {
        ui::Transform t;
        t.set(destRect.left, destRect.top);
        return assignTransform(&mDrawingState.transform, t);
    }

    uint32_t bufferWidth = mDrawingState.buffer->getBuffer()->getWidth();
    uint32_t bufferHeight = mDrawingState.buffer->getBuffer()->getHeight();
    // Undo any transformations on the buffer.
    if (mDrawingState.bufferTransform & ui::Transform::ROT_90) {
        std::swap(bufferWidth, bufferHeight);
    }
    uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
    if (mDrawingState.transformToDisplayInverse) {
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufferWidth, bufferHeight);
        }
    }

    float sx = destW / static_cast<float>(bufferWidth);
    float sy = destH / static_cast<float>(bufferHeight);
    ui::Transform t;
    t.set(sx, 0, 0, sy);
    t.set(destRect.left, destRect.top);
    return assignTransform(&mDrawingState.transform, t);
}

bool BufferStateLayer::setMatrix(const layer_state_t::matrix22_t& matrix,
                                 bool allowNonRectPreservingTransforms) {
    if (mRequestedTransform.dsdx() == matrix.dsdx && mRequestedTransform.dtdy() == matrix.dtdy &&
        mRequestedTransform.dtdx() == matrix.dtdx && mRequestedTransform.dsdy() == matrix.dsdy) {
        return false;
    }

    ui::Transform t;
    t.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);

    if (!allowNonRectPreservingTransforms && !t.preserveRects()) {
        ALOGW("Attempt to set rotation matrix without permission ACCESS_SURFACE_FLINGER nor "
              "ROTATE_SURFACE_FLINGER ignored");
        return false;
    }

    mRequestedTransform.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);

    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    return true;
}

bool BufferStateLayer::setPosition(float x, float y) {
    if (mRequestedTransform.tx() == x && mRequestedTransform.ty() == y) {
        return false;
    }

    mRequestedTransform.set(x, y);

    mDrawingState.sequence++;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    return true;
}

bool BufferStateLayer::addFrameEvent(const sp<Fence>& acquireFence, nsecs_t postedTime,
                                     nsecs_t desiredPresentTime) {
    Mutex::Autolock lock(mFrameEventHistoryMutex);
    mAcquireTimeline.updateSignalTimes();
    std::shared_ptr<FenceTime> acquireFenceTime =
            std::make_shared<FenceTime>((acquireFence ? acquireFence : Fence::NO_FENCE));
    NewFrameEventsEntry newTimestamps = {mDrawingState.frameNumber, postedTime, desiredPresentTime,
                                         acquireFenceTime};
    mFrameEventHistory.setProducerWantsEvents();
    mFrameEventHistory.addQueue(newTimestamps);
    return true;
}

bool BufferStateLayer::setBuffer(const std::shared_ptr<renderengine::ExternalTexture>& buffer,
                                 const sp<Fence>& acquireFence, nsecs_t postTime,
                                 nsecs_t desiredPresentTime, bool isAutoTimestamp,
                                 const client_cache_t& clientCacheId, uint64_t frameNumber,
                                 std::optional<nsecs_t> dequeueTime, const FrameTimelineInfo& info,
                                 const sp<ITransactionCompletedListener>& releaseBufferListener,
                                 const sp<IBinder>& releaseBufferEndpoint) {
    ATRACE_CALL();

    if (mDrawingState.buffer) {
        mReleasePreviousBuffer = true;
        if (mDrawingState.buffer != mBufferInfo.mBuffer ||
            mDrawingState.frameNumber != mBufferInfo.mFrameNumber) {
            // If mDrawingState has a buffer, and we are about to update again
            // before swapping to drawing state, then the first buffer will be
            // dropped and we should decrement the pending buffer count and
            // call any release buffer callbacks if set.
            callReleaseBufferCallback(mDrawingState.releaseBufferListener,
                                      mDrawingState.buffer->getBuffer(), mDrawingState.frameNumber,
                                      mDrawingState.acquireFence, mTransformHint,
                                      mFlinger->getMaxAcquiredBufferCountForCurrentRefreshRate(
                                              mOwnerUid));
            decrementPendingBufferCount();
            if (mDrawingState.bufferSurfaceFrameTX != nullptr &&
                mDrawingState.bufferSurfaceFrameTX->getPresentState() != PresentState::Presented) {
              addSurfaceFrameDroppedForBuffer(mDrawingState.bufferSurfaceFrameTX);
              mDrawingState.bufferSurfaceFrameTX.reset();
            }
        }
    }

    mDrawingState.frameNumber = frameNumber;
    mDrawingState.releaseBufferListener = releaseBufferListener;
    mDrawingState.buffer = buffer;
    mDrawingState.clientCacheId = clientCacheId;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->setPostTime(layerId, mDrawingState.frameNumber, getName().c_str(),
                                      mOwnerUid, postTime, getGameMode());
    mDrawingState.desiredPresentTime = desiredPresentTime;
    mDrawingState.isAutoTimestamp = isAutoTimestamp;

    const nsecs_t presentTime = [&] {
        if (!isAutoTimestamp) return desiredPresentTime;

        const auto prediction =
                mFlinger->mFrameTimeline->getTokenManager()->getPredictionsForToken(info.vsyncId);
        if (prediction.has_value()) return prediction->presentTime;

        return static_cast<nsecs_t>(0);
    }();
    mFlinger->mScheduler->recordLayerHistory(this, presentTime,
                                             LayerHistory::LayerUpdateType::Buffer);

    addFrameEvent(acquireFence, postTime, isAutoTimestamp ? 0 : desiredPresentTime);

    setFrameTimelineVsyncForBufferTransaction(info, postTime);

    if (buffer && dequeueTime && *dequeueTime != 0) {
        const uint64_t bufferId = buffer->getBuffer()->getId();
        mFlinger->mFrameTracer->traceNewLayer(layerId, getName().c_str());
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, *dequeueTime,
                                               FrameTracer::FrameEvent::DEQUEUE);
        mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, postTime,
                                               FrameTracer::FrameEvent::QUEUE);
    }

    mDrawingState.width = mDrawingState.buffer->getBuffer()->getWidth();
    mDrawingState.height = mDrawingState.buffer->getBuffer()->getHeight();
    mDrawingState.releaseBufferEndpoint = releaseBufferEndpoint;

    return true;
}

bool BufferStateLayer::setAcquireFence(const sp<Fence>& fence) {
    mDrawingState.acquireFence = fence;
    mDrawingState.acquireFenceTime = std::make_unique<FenceTime>(fence);

    // The acquire fences of BufferStateLayers have already signaled before they are set
    mCallbackHandleAcquireTime = mDrawingState.acquireFenceTime->getSignalTime();

    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setDataspace(ui::Dataspace dataspace) {
    if (mDrawingState.dataspace == dataspace) return false;
    mDrawingState.dataspace = dataspace;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setHdrMetadata(const HdrMetadata& hdrMetadata) {
    if (mDrawingState.hdrMetadata == hdrMetadata) return false;
    mDrawingState.hdrMetadata = hdrMetadata;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setSurfaceDamageRegion(const Region& surfaceDamage) {
    mDrawingState.surfaceDamageRegion = surfaceDamage;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setApi(int32_t api) {
    if (mDrawingState.api == api) return false;
    mDrawingState.api = api;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setSidebandStream(const sp<NativeHandle>& sidebandStream) {
    if (mDrawingState.sidebandStream == sidebandStream) return false;

    if (mDrawingState.sidebandStream != nullptr && sidebandStream == nullptr) {
        mFlinger->mTunnelModeEnabledReporter->decrementTunnelModeCount();
    } else if (sidebandStream != nullptr) {
        mFlinger->mTunnelModeEnabledReporter->incrementTunnelModeCount();
    }

    mDrawingState.sidebandStream = sidebandStream;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    if (!mSidebandStreamChanged.exchange(true)) {
        // mSidebandStreamChanged was false
        mFlinger->signalLayerUpdate();
    }
    return true;
}

bool BufferStateLayer::setTransactionCompletedListeners(
        const std::vector<sp<CallbackHandle>>& handles) {
    // If there is no handle, we will not send a callback so reset mReleasePreviousBuffer and return
    if (handles.empty()) {
        mReleasePreviousBuffer = false;
        return false;
    }

    const bool willPresent = willPresentCurrentTransaction();

    for (const auto& handle : handles) {
        // If this transaction set a buffer on this layer, release its previous buffer
        handle->releasePreviousBuffer = mReleasePreviousBuffer;

        // If this layer will be presented in this frame
        if (willPresent) {
            // If this transaction set an acquire fence on this layer, set its acquire time
            handle->acquireTime = mCallbackHandleAcquireTime;
            handle->frameNumber = mDrawingState.frameNumber;

            // Notify the transaction completed thread that there is a pending latched callback
            // handle
            mFlinger->getTransactionCallbackInvoker().registerPendingCallbackHandle(handle);

            // Store so latched time and release fence can be set
            mDrawingState.callbackHandles.push_back(handle);

        } else { // If this layer will NOT need to be relatched and presented this frame
            // Notify the transaction completed thread this handle is done
            mFlinger->getTransactionCallbackInvoker().registerUnpresentedCallbackHandle(handle);
        }
    }

    mReleasePreviousBuffer = false;
    mCallbackHandleAcquireTime = -1;

    return willPresent;
}

bool BufferStateLayer::setTransparentRegionHint(const Region& transparent) {
    mDrawingState.sequence++;
    mDrawingState.transparentRegionHint = transparent;
    mDrawingState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

Rect BufferStateLayer::getBufferSize(const State& s) const {
    // for buffer state layers we use the display frame size as the buffer size.

    if (mBufferInfo.mBuffer == nullptr) {
        return Rect::INVALID_RECT;
    }

    uint32_t bufWidth = mBufferInfo.mBuffer->getBuffer()->getWidth();
    uint32_t bufHeight = mBufferInfo.mBuffer->getBuffer()->getHeight();

    // Undo any transformations on the buffer and return the result.
    if (mBufferInfo.mTransform & ui::Transform::ROT_90) {
        std::swap(bufWidth, bufHeight);
    }

    if (getTransformToDisplayInverse()) {
        uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufWidth, bufHeight);
        }
    }

    return Rect(0, 0, bufWidth, bufHeight);
}

FloatRect BufferStateLayer::computeSourceBounds(const FloatRect& parentBounds) const {
    if (mBufferInfo.mBuffer == nullptr) {
        return parentBounds;
    }

    return getBufferSize(getDrawingState()).toFloatRect();
}

// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Interface implementation for BufferLayer
// -----------------------------------------------------------------------
bool BufferStateLayer::fenceHasSignaled() const {
    if (SurfaceFlinger::enableLatchUnsignaled) {
        return true;
    }

    const bool fenceSignaled =
            getDrawingState().acquireFence->getStatus() == Fence::Status::Signaled;
    if (!fenceSignaled) {
        mFlinger->mTimeStats->incrementLatchSkipped(getSequence(),
                                                    TimeStats::LatchSkipReason::LateAcquire);
    }

    return fenceSignaled;
}

bool BufferStateLayer::framePresentTimeIsCurrent(nsecs_t expectedPresentTime) const {
    if (!hasFrameUpdate() || isRemovedFromCurrentState()) {
        return true;
    }

    return mDrawingState.isAutoTimestamp || mDrawingState.desiredPresentTime <= expectedPresentTime;
}

bool BufferStateLayer::onPreComposition(nsecs_t refreshStartTime) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->refreshStartTime = refreshStartTime;
    }
    return BufferLayer::onPreComposition(refreshStartTime);
}

uint64_t BufferStateLayer::getFrameNumber(nsecs_t /*expectedPresentTime*/) const {
    return mDrawingState.frameNumber;
}

/**
 * This is the frameNumber used for deferred transaction signalling. We need to use this because
 * of cases where we defer a transaction for a surface to itself. In the BLAST world this
 * may not make a huge amount of sense (Why not just merge the Buffer transaction with the
 * deferred transaction?) but this is an important legacy use case, for example moving
 * a window at the same time it draws makes use of this kind of technique. So anyway
 * imagine we have something like this:
 *
 * Transaction { // containing
 *     Buffer -> frameNumber = 2
 *     DeferTransactionUntil -> frameNumber = 2
 *     Random other stuff
 *  }
 * Now imagine mFrameNumber returned mDrawingState.frameNumber (or mCurrentFrameNumber).
 * Prior to doTransaction SurfaceFlinger will call notifyAvailableFrames, but because we
 * haven't swapped mDrawingState to mDrawingState yet we will think the sync point
 * is not ready. So we will return false from applyPendingState and not swap
 * current state to drawing state. But because we don't swap current state
 * to drawing state the number will never update and we will be stuck. This way
 * we can see we need to return the frame number for the buffer we are about
 * to apply.
 */
uint64_t BufferStateLayer::getHeadFrameNumber(nsecs_t /* expectedPresentTime */) const {
    return mDrawingState.frameNumber;
}

void BufferStateLayer::setAutoRefresh(bool autoRefresh) {
    if (!mAutoRefresh.exchange(autoRefresh)) {
        mFlinger->signalLayerUpdate();
    }
}

bool BufferStateLayer::latchSidebandStream(bool& recomputeVisibleRegions) {
    // We need to update the sideband stream if the layer has both a buffer and a sideband stream.
    const bool updateSidebandStream = hasFrameUpdate() && mSidebandStream.get();

    if (mSidebandStreamChanged.exchange(false) || updateSidebandStream) {
        const State& s(getDrawingState());
        // mSidebandStreamChanged was true
        mSidebandStream = s.sidebandStream;
        editCompositionState()->sidebandStream = mSidebandStream;
        if (mSidebandStream != nullptr) {
            setTransactionFlags(eTransactionNeeded);
            mFlinger->setTransactionFlags(eTraversalNeeded);
        }
        recomputeVisibleRegions = true;

        return true;
    }
    return false;
}

bool BufferStateLayer::hasFrameUpdate() const {
    const State& c(getDrawingState());
    return (mDrawingStateModified || mDrawingState.modified) && (c.buffer != nullptr || c.bgColorLayer != nullptr);
}

status_t BufferStateLayer::updateTexImage(bool& /*recomputeVisibleRegions*/, nsecs_t latchTime,
                                          nsecs_t /*expectedPresentTime*/) {
    const State& s(getDrawingState());

    if (!s.buffer) {
        if (s.bgColorLayer) {
            for (auto& handle : mDrawingState.callbackHandles) {
                handle->latchTime = latchTime;
            }
        }
        return NO_ERROR;
    }

    for (auto& handle : mDrawingState.callbackHandles) {
        if (handle->frameNumber == mDrawingState.frameNumber) {
            handle->latchTime = latchTime;
        }
    }

    const int32_t layerId = getSequence();
    const uint64_t bufferId = mDrawingState.buffer->getBuffer()->getId();
    const uint64_t frameNumber = mDrawingState.frameNumber;
    const auto acquireFence = std::make_shared<FenceTime>(mDrawingState.acquireFence);
    mFlinger->mTimeStats->setAcquireFence(layerId, frameNumber, acquireFence);
    mFlinger->mTimeStats->setLatchTime(layerId, frameNumber, latchTime);

    mFlinger->mFrameTracer->traceFence(layerId, bufferId, frameNumber, acquireFence,
                                       FrameTracer::FrameEvent::ACQUIRE_FENCE);
    mFlinger->mFrameTracer->traceTimestamp(layerId, bufferId, frameNumber, latchTime,
                                           FrameTracer::FrameEvent::LATCH);

    auto& bufferSurfaceFrame = mDrawingState.bufferSurfaceFrameTX;
    if (bufferSurfaceFrame != nullptr &&
        bufferSurfaceFrame->getPresentState() != PresentState::Presented) {
        // Update only if the bufferSurfaceFrame wasn't already presented. A Presented
        // bufferSurfaceFrame could be seen here if a pending state was applied successfully and we
        // are processing the next state.
        addSurfaceFramePresentedForBuffer(bufferSurfaceFrame,
                                          mDrawingState.acquireFenceTime->getSignalTime(),
                                          latchTime);
        mDrawingState.bufferSurfaceFrameTX.reset();
    }

    std::deque<sp<CallbackHandle>> remainingHandles;
    mFlinger->getTransactionCallbackInvoker()
            .finalizeOnCommitCallbackHandles(mDrawingState.callbackHandles, remainingHandles);
    mDrawingState.callbackHandles = remainingHandles;

    mDrawingStateModified = false;

    return NO_ERROR;
}

status_t BufferStateLayer::updateActiveBuffer() {
    const State& s(getDrawingState());

    if (s.buffer == nullptr) {
        return BAD_VALUE;
    }

    if (!mBufferInfo.mBuffer || s.buffer->getBuffer() != mBufferInfo.mBuffer->getBuffer()) {
        decrementPendingBufferCount();
    }

    mPreviousReleaseCallbackId = {getCurrentBufferId(), mBufferInfo.mFrameNumber};
    mBufferInfo.mBuffer = s.buffer;
    mBufferInfo.mFence = s.acquireFence;
    mBufferInfo.mFrameNumber = s.frameNumber;

    return NO_ERROR;
}

status_t BufferStateLayer::updateFrameNumber(nsecs_t latchTime) {
    // TODO(marissaw): support frame history events
    mPreviousFrameNumber = mCurrentFrameNumber;
    mCurrentFrameNumber = mDrawingState.frameNumber;
    {
        Mutex::Autolock lock(mFrameEventHistoryMutex);
        mFrameEventHistory.addLatch(mCurrentFrameNumber, latchTime);
    }
    return NO_ERROR;
}

void BufferStateLayer::HwcSlotGenerator::bufferErased(const client_cache_t& clientCacheId) {
    std::lock_guard lock(mMutex);
    if (!clientCacheId.isValid()) {
        ALOGE("invalid process, failed to erase buffer");
        return;
    }
    eraseBufferLocked(clientCacheId);
}

uint32_t BufferStateLayer::HwcSlotGenerator::getHwcCacheSlot(const client_cache_t& clientCacheId) {
    std::lock_guard<std::mutex> lock(mMutex);
    auto itr = mCachedBuffers.find(clientCacheId);
    if (itr == mCachedBuffers.end()) {
        return addCachedBuffer(clientCacheId);
    }
    auto& [hwcCacheSlot, counter] = itr->second;
    counter = mCounter++;
    return hwcCacheSlot;
}

uint32_t BufferStateLayer::HwcSlotGenerator::addCachedBuffer(const client_cache_t& clientCacheId)
        REQUIRES(mMutex) {
    if (!clientCacheId.isValid()) {
        ALOGE("invalid process, returning invalid slot");
        return BufferQueue::INVALID_BUFFER_SLOT;
    }

    ClientCache::getInstance().registerErasedRecipient(clientCacheId, wp<ErasedRecipient>(this));

    uint32_t hwcCacheSlot = getFreeHwcCacheSlot();
    mCachedBuffers[clientCacheId] = {hwcCacheSlot, mCounter++};
    return hwcCacheSlot;
}

uint32_t BufferStateLayer::HwcSlotGenerator::getFreeHwcCacheSlot() REQUIRES(mMutex) {
    if (mFreeHwcCacheSlots.empty()) {
        evictLeastRecentlyUsed();
    }

    uint32_t hwcCacheSlot = mFreeHwcCacheSlots.top();
    mFreeHwcCacheSlots.pop();
    return hwcCacheSlot;
}

void BufferStateLayer::HwcSlotGenerator::evictLeastRecentlyUsed() REQUIRES(mMutex) {
    uint64_t minCounter = UINT_MAX;
    client_cache_t minClientCacheId = {};
    for (const auto& [clientCacheId, slotCounter] : mCachedBuffers) {
        const auto& [hwcCacheSlot, counter] = slotCounter;
        if (counter < minCounter) {
            minCounter = counter;
            minClientCacheId = clientCacheId;
        }
    }
    eraseBufferLocked(minClientCacheId);

    ClientCache::getInstance().unregisterErasedRecipient(minClientCacheId, this);
}

void BufferStateLayer::HwcSlotGenerator::eraseBufferLocked(const client_cache_t& clientCacheId)
        REQUIRES(mMutex) {
    auto itr = mCachedBuffers.find(clientCacheId);
    if (itr == mCachedBuffers.end()) {
        return;
    }
    auto& [hwcCacheSlot, counter] = itr->second;

    // TODO send to hwc cache and resources

    mFreeHwcCacheSlots.push(hwcCacheSlot);
    mCachedBuffers.erase(clientCacheId);
}

void BufferStateLayer::gatherBufferInfo() {
    BufferLayer::gatherBufferInfo();

    const State& s(getDrawingState());
    mBufferInfo.mDesiredPresentTime = s.desiredPresentTime;
    mBufferInfo.mFenceTime = std::make_shared<FenceTime>(s.acquireFence);
    mBufferInfo.mFence = s.acquireFence;
    mBufferInfo.mTransform = s.bufferTransform;
    auto lastDataspace = mBufferInfo.mDataspace;
    mBufferInfo.mDataspace = translateDataspace(s.dataspace);
    if (lastDataspace != mBufferInfo.mDataspace) {
        mFlinger->mSomeDataspaceChanged = true;
    }
    mBufferInfo.mCrop = computeBufferCrop(s);
    mBufferInfo.mScaleMode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
    mBufferInfo.mSurfaceDamage = s.surfaceDamageRegion;
    mBufferInfo.mHdrMetadata = s.hdrMetadata;
    mBufferInfo.mApi = s.api;
    mBufferInfo.mTransformToDisplayInverse = s.transformToDisplayInverse;
    mBufferInfo.mBufferSlot = mHwcSlotGenerator->getHwcCacheSlot(s.clientCacheId);
}

uint32_t BufferStateLayer::getEffectiveScalingMode() const {
   return NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
}

Rect BufferStateLayer::computeBufferCrop(const State& s) {
    if (s.buffer && !s.bufferCrop.isEmpty()) {
        Rect bufferCrop;
        s.buffer->getBuffer()->getBounds().intersect(s.bufferCrop, &bufferCrop);
        return bufferCrop;
    } else if (s.buffer) {
        return s.buffer->getBuffer()->getBounds();
    } else {
        return s.bufferCrop;
    }
}

sp<Layer> BufferStateLayer::createClone() {
    LayerCreationArgs args(mFlinger.get(), nullptr, mName + " (Mirror)", 0, 0, 0, LayerMetadata());
    args.textureName = mTextureName;
    sp<BufferStateLayer> layer = mFlinger->getFactory().createBufferStateLayer(args);
    layer->mHwcSlotGenerator = mHwcSlotGenerator;
    layer->setInitialValuesForClone(this);
    return layer;
}

bool BufferStateLayer::bufferNeedsFiltering() const {
    const State& s(getDrawingState());
    if (!s.buffer) {
        return false;
    }

    uint32_t bufferWidth = s.buffer->getBuffer()->width;
    uint32_t bufferHeight = s.buffer->getBuffer()->height;

    // Undo any transformations on the buffer and return the result.
    if (s.bufferTransform & ui::Transform::ROT_90) {
        std::swap(bufferWidth, bufferHeight);
    }

    if (s.transformToDisplayInverse) {
        uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufferWidth, bufferHeight);
        }
    }

    const Rect layerSize{getBounds()};
    return layerSize.width() != bufferWidth || layerSize.height() != bufferHeight;
}

void BufferStateLayer::decrementPendingBufferCount() {
    int32_t pendingBuffers = --mPendingBufferTransactions;
    tracePendingBufferCount(pendingBuffers);
}

void BufferStateLayer::tracePendingBufferCount(int32_t pendingBuffers) {
    ATRACE_INT(mBlastTransactionName.c_str(), pendingBuffers);
}


/*
 * We don't want to send the layer's transform to input, but rather the
 * parent's transform. This is because BufferStateLayer's transform is
 * information about how the buffer is placed on screen. The parent's
 * transform makes more sense to send since it's information about how the
 * layer is placed on screen. This transform is used by input to determine
 * how to go from screen space back to window space.
 */
ui::Transform BufferStateLayer::getInputTransform() const {
    sp<Layer> parent = mDrawingParent.promote();
    if (parent == nullptr) {
        return ui::Transform();
    }

    return parent->getTransform();
}

/**
 * Similar to getInputTransform, we need to update the bounds to include the transform.
 * This is because bounds for BSL doesn't include buffer transform, where the input assumes
 * that's already included.
 */
Rect BufferStateLayer::getInputBounds() const {
    Rect bufferBounds = getCroppedBufferSize(getDrawingState());
    if (mDrawingState.transform.getType() == ui::Transform::IDENTITY || !bufferBounds.isValid()) {
        return bufferBounds;
    }
    return mDrawingState.transform.transform(bufferBounds);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
