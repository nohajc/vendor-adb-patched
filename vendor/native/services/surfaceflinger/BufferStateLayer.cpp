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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "BufferStateLayer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "BufferStateLayer.h"

#include <limits>

#include <compositionengine/LayerFECompositionState.h>
#include <gui/BufferQueue.h>
#include <private/gui/SyncFeatures.h>
#include <renderengine/Image.h>

#include "EffectLayer.h"
#include "TimeStats/TimeStats.h"

namespace android {

// clang-format off
const std::array<float, 16> BufferStateLayer::IDENTITY_MATRIX{
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1
};
// clang-format on

BufferStateLayer::BufferStateLayer(const LayerCreationArgs& args)
      : BufferLayer(args), mHwcSlotGenerator(new HwcSlotGenerator()) {
    mOverrideScalingMode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
    mCurrentState.dataspace = ui::Dataspace::V0_SRGB;
}

BufferStateLayer::~BufferStateLayer() {
    // The original layer and the clone layer share the same texture and buffer. Therefore, only
    // one of the layers, in this case the original layer, needs to handle the deletion. The
    // original layer and the clone should be removed at the same time so there shouldn't be any
    // issue with the clone layer trying to use the texture.
    if (mBufferInfo.mBuffer != nullptr && !isClone()) {
        // Ensure that mBuffer is uncached from RenderEngine here, as
        // RenderEngine may have been using the buffer as an external texture
        // after the client uncached the buffer.
        auto& engine(mFlinger->getRenderEngine());
        engine.unbindExternalTextureBuffer(mBufferInfo.mBuffer->getId());
    }
}

status_t BufferStateLayer::addReleaseFence(const sp<CallbackHandle>& ch,
                                           const sp<Fence>& fence) {
    if (ch == nullptr) {
        return OK;
    }
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
        if (handle->releasePreviousBuffer) {
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

void BufferStateLayer::releasePendingBuffer(nsecs_t dequeueReadyTime) {
    for (const auto& handle : mDrawingState.callbackHandles) {
        handle->transformHint = mTransformHint;
        handle->dequeueReadyTime = dequeueReadyTime;
    }

    mFlinger->getTransactionCompletedThread().finalizePendingCallbackHandles(
            mDrawingState.callbackHandles);

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

bool BufferStateLayer::shouldPresentNow(nsecs_t /*expectedPresentTime*/) const {
    if (getSidebandStreamChanged() || getAutoRefresh()) {
        return true;
    }

    return hasFrameUpdate();
}

bool BufferStateLayer::willPresentCurrentTransaction() const {
    // Returns true if the most recent Transaction applied to CurrentState will be presented.
    return (getSidebandStreamChanged() || getAutoRefresh() ||
            (mCurrentState.modified &&
             (mCurrentState.buffer != nullptr || mCurrentState.bgColorLayer != nullptr))) &&
        !mLayerDetached;
}

/* TODO: vhau uncomment once deferred transaction migration complete in
 * WindowManager
void BufferStateLayer::pushPendingState() {
    if (!mCurrentState.modified) {
        return;
    }
    mPendingStates.push_back(mCurrentState);
    ATRACE_INT(mTransactionName.c_str(), mPendingStates.size());
}
*/

bool BufferStateLayer::applyPendingStates(Layer::State* stateToCommit) {
    mCurrentStateModified = mCurrentState.modified;
    bool stateUpdateAvailable = Layer::applyPendingStates(stateToCommit);
    mCurrentStateModified = stateUpdateAvailable && mCurrentStateModified;
    mCurrentState.modified = false;
    return stateUpdateAvailable;
}

// Crop that applies to the window
Rect BufferStateLayer::getCrop(const Layer::State& /*s*/) const {
    return Rect::INVALID_RECT;
}

bool BufferStateLayer::setTransform(uint32_t transform) {
    if (mCurrentState.transform == transform) return false;
    mCurrentState.transform = transform;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setTransformToDisplayInverse(bool transformToDisplayInverse) {
    if (mCurrentState.transformToDisplayInverse == transformToDisplayInverse) return false;
    mCurrentState.sequence++;
    mCurrentState.transformToDisplayInverse = transformToDisplayInverse;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setCrop(const Rect& crop) {
    Rect c = crop;
    if (c.left < 0) {
        c.left = 0;
    }
    if (c.top < 0) {
        c.top = 0;
    }
    // If the width and/or height are < 0, make it [0, 0, -1, -1] so the equality comparision below
    // treats all invalid rectangles the same.
    if (!c.isValid()) {
        c.makeInvalid();
    }

    if (mCurrentState.crop == c) return false;
    mCurrentState.crop = c;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setFrame(const Rect& frame) {
    int x = frame.left;
    int y = frame.top;
    int w = frame.getWidth();
    int h = frame.getHeight();

    if (x < 0) {
        x = 0;
        w = frame.right;
    }

    if (y < 0) {
        y = 0;
        h = frame.bottom;
    }

    if (mCurrentState.active.transform.tx() == x && mCurrentState.active.transform.ty() == y &&
        mCurrentState.active.w == w && mCurrentState.active.h == h) {
        return false;
    }

    if (!frame.isValid()) {
        x = y = w = h = 0;
    }
    mCurrentState.active.transform.set(x, y);
    mCurrentState.active.w = w;
    mCurrentState.active.h = h;

    mCurrentState.sequence++;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::addFrameEvent(const sp<Fence>& acquireFence, nsecs_t postedTime,
                                     nsecs_t desiredPresentTime) {
    Mutex::Autolock lock(mFrameEventHistoryMutex);
    mAcquireTimeline.updateSignalTimes();
    std::shared_ptr<FenceTime> acquireFenceTime =
            std::make_shared<FenceTime>((acquireFence ? acquireFence : Fence::NO_FENCE));
    NewFrameEventsEntry newTimestamps = {mCurrentState.frameNumber, postedTime, desiredPresentTime,
                                         acquireFenceTime};
    mFrameEventHistory.setProducerWantsEvents();
    mFrameEventHistory.addQueue(newTimestamps);
    return true;
}

bool BufferStateLayer::setBuffer(const sp<GraphicBuffer>& buffer, const sp<Fence>& acquireFence,
                                 nsecs_t postTime, nsecs_t desiredPresentTime,
                                 const client_cache_t& clientCacheId) {
    if (mCurrentState.buffer) {
        mReleasePreviousBuffer = true;
    }

    mCurrentState.frameNumber++;

    mCurrentState.buffer = buffer;
    mCurrentState.clientCacheId = clientCacheId;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);

    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->setPostTime(layerId, mCurrentState.frameNumber, getName().c_str(),
                                      postTime);
    desiredPresentTime = desiredPresentTime <= 0 ? 0 : desiredPresentTime;
    mCurrentState.desiredPresentTime = desiredPresentTime;

    mFlinger->mScheduler->recordLayerHistory(this, desiredPresentTime,
                                             LayerHistory::LayerUpdateType::Buffer);

    addFrameEvent(acquireFence, postTime, desiredPresentTime);
    return true;
}

bool BufferStateLayer::setAcquireFence(const sp<Fence>& fence) {
    // The acquire fences of BufferStateLayers have already signaled before they are set
    mCallbackHandleAcquireTime = fence->getSignalTime();

    mCurrentState.acquireFence = fence;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setDataspace(ui::Dataspace dataspace) {
    if (mCurrentState.dataspace == dataspace) return false;
    mCurrentState.dataspace = dataspace;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setHdrMetadata(const HdrMetadata& hdrMetadata) {
    if (mCurrentState.hdrMetadata == hdrMetadata) return false;
    mCurrentState.hdrMetadata = hdrMetadata;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setSurfaceDamageRegion(const Region& surfaceDamage) {
    mCurrentState.surfaceDamageRegion = surfaceDamage;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setApi(int32_t api) {
    if (mCurrentState.api == api) return false;
    mCurrentState.api = api;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

bool BufferStateLayer::setSidebandStream(const sp<NativeHandle>& sidebandStream) {
    if (mCurrentState.sidebandStream == sidebandStream) return false;
    mCurrentState.sidebandStream = sidebandStream;
    mCurrentState.modified = true;
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

            // Notify the transaction completed thread that there is a pending latched callback
            // handle
            mFlinger->getTransactionCompletedThread().registerPendingCallbackHandle(handle);

            // Store so latched time and release fence can be set
            mCurrentState.callbackHandles.push_back(handle);

        } else { // If this layer will NOT need to be relatched and presented this frame
            // Notify the transaction completed thread this handle is done
            mFlinger->getTransactionCompletedThread().registerUnpresentedCallbackHandle(handle);
        }
    }

    mReleasePreviousBuffer = false;
    mCallbackHandleAcquireTime = -1;

    return willPresent;
}

void BufferStateLayer::forceSendCallbacks() {
    mFlinger->getTransactionCompletedThread().finalizePendingCallbackHandles(
            mCurrentState.callbackHandles);
}

bool BufferStateLayer::setTransparentRegionHint(const Region& transparent) {
    mCurrentState.transparentRegionHint = transparent;
    mCurrentState.modified = true;
    setTransactionFlags(eTransactionNeeded);
    return true;
}

Rect BufferStateLayer::getBufferSize(const State& s) const {
    // for buffer state layers we use the display frame size as the buffer size.
    if (getActiveWidth(s) < UINT32_MAX && getActiveHeight(s) < UINT32_MAX) {
        return Rect(getActiveWidth(s), getActiveHeight(s));
    }

    // if the display frame is not defined, use the parent bounds as the buffer size.
    const auto& p = mDrawingParent.promote();
    if (p != nullptr) {
        Rect parentBounds = Rect(p->getBounds(Region()));
        if (!parentBounds.isEmpty()) {
            return parentBounds;
        }
    }

    return Rect::INVALID_RECT;
}

FloatRect BufferStateLayer::computeSourceBounds(const FloatRect& parentBounds) const {
    const State& s(getDrawingState());
    // for buffer state layers we use the display frame size as the buffer size.
    if (getActiveWidth(s) < UINT32_MAX && getActiveHeight(s) < UINT32_MAX) {
        return FloatRect(0, 0, getActiveWidth(s), getActiveHeight(s));
    }

    // if the display frame is not defined, use the parent bounds as the buffer size.
    return parentBounds;
}

// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Interface implementation for BufferLayer
// -----------------------------------------------------------------------
bool BufferStateLayer::fenceHasSignaled() const {
    if (latchUnsignaledBuffers()) {
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

    return mCurrentState.desiredPresentTime <= expectedPresentTime;
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
 * Now imagine getHeadFrameNumber returned mDrawingState.mFrameNumber (or mCurrentFrameNumber).
 * Prior to doTransaction SurfaceFlinger will call notifyAvailableFrames, but because we
 * haven't swapped mCurrentState to mDrawingState yet we will think the sync point
 * is not ready. So we will return false from applyPendingState and not swap
 * current state to drawing state. But because we don't swap current state
 * to drawing state the number will never update and we will be stuck. This way
 * we can see we need to return the frame number for the buffer we are about
 * to apply.
 */
uint64_t BufferStateLayer::getHeadFrameNumber(nsecs_t /* expectedPresentTime */) const {
    return mCurrentState.frameNumber;
}

bool BufferStateLayer::getAutoRefresh() const {
    // TODO(marissaw): support shared buffer mode
    return false;
}

bool BufferStateLayer::getSidebandStreamChanged() const {
    return mSidebandStreamChanged.load();
}

bool BufferStateLayer::latchSidebandStream(bool& recomputeVisibleRegions) {
    if (mSidebandStreamChanged.exchange(false)) {
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
    const State& c(getCurrentState());
    return mCurrentStateModified && (c.buffer != nullptr || c.bgColorLayer != nullptr);
}

status_t BufferStateLayer::bindTextureImage() {
    const State& s(getDrawingState());
    auto& engine(mFlinger->getRenderEngine());

    return engine.bindExternalTextureBuffer(mTextureName, s.buffer, s.acquireFence);
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

    const int32_t layerId = getSequence();

    // Reject if the layer is invalid
    uint32_t bufferWidth = s.buffer->width;
    uint32_t bufferHeight = s.buffer->height;

    if (s.transform & ui::Transform::ROT_90) {
        std::swap(bufferWidth, bufferHeight);
    }

    if (s.transformToDisplayInverse) {
        uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufferWidth, bufferHeight);
        }
    }

    if (getEffectiveScalingMode() == NATIVE_WINDOW_SCALING_MODE_FREEZE &&
        (s.active.w != bufferWidth || s.active.h != bufferHeight)) {
        ALOGE("[%s] rejecting buffer: "
              "bufferWidth=%d, bufferHeight=%d, front.active.{w=%d, h=%d}",
              getDebugName(), bufferWidth, bufferHeight, s.active.w, s.active.h);
        mFlinger->mTimeStats->removeTimeRecord(layerId, mDrawingState.frameNumber);
        return BAD_VALUE;
    }

    for (auto& handle : mDrawingState.callbackHandles) {
        handle->latchTime = latchTime;
        handle->frameNumber = mDrawingState.frameNumber;
    }

    if (!SyncFeatures::getInstance().useNativeFenceSync()) {
        // Bind the new buffer to the GL texture.
        //
        // Older devices require the "implicit" synchronization provided
        // by glEGLImageTargetTexture2DOES, which this method calls.  Newer
        // devices will either call this in Layer::onDraw, or (if it's not
        // a GL-composited layer) not at all.
        status_t err = bindTextureImage();
        if (err != NO_ERROR) {
            mFlinger->mTimeStats->onDestroy(layerId);
            return BAD_VALUE;
        }
    }

    mFlinger->mTimeStats->setAcquireFence(layerId, mDrawingState.frameNumber,
                                          std::make_shared<FenceTime>(mDrawingState.acquireFence));
    mFlinger->mTimeStats->setLatchTime(layerId, mDrawingState.frameNumber, latchTime);

    mCurrentStateModified = false;

    return NO_ERROR;
}

status_t BufferStateLayer::updateActiveBuffer() {
    const State& s(getDrawingState());

    if (s.buffer == nullptr) {
        return BAD_VALUE;
    }

    mPreviousBufferId = getCurrentBufferId();
    mBufferInfo.mBuffer = s.buffer;
    mBufferInfo.mFence = s.acquireFence;

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
    mBufferInfo.mTransform = s.transform;
    mBufferInfo.mDataspace = translateDataspace(s.dataspace);
    mBufferInfo.mCrop = computeCrop(s);
    mBufferInfo.mScaleMode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
    mBufferInfo.mSurfaceDamage = s.surfaceDamageRegion;
    mBufferInfo.mHdrMetadata = s.hdrMetadata;
    mBufferInfo.mApi = s.api;
    mBufferInfo.mTransformToDisplayInverse = s.transformToDisplayInverse;
    mBufferInfo.mBufferSlot = mHwcSlotGenerator->getHwcCacheSlot(s.clientCacheId);
}

Rect BufferStateLayer::computeCrop(const State& s) {
    if (s.crop.isEmpty() && s.buffer) {
        return s.buffer->getBounds();
    } else if (s.buffer) {
        Rect crop = s.crop;
        crop.left = std::max(crop.left, 0);
        crop.top = std::max(crop.top, 0);
        uint32_t bufferWidth = s.buffer->getWidth();
        uint32_t bufferHeight = s.buffer->getHeight();
        if (bufferHeight <= std::numeric_limits<int32_t>::max() &&
            bufferWidth <= std::numeric_limits<int32_t>::max()) {
            crop.right = std::min(crop.right, static_cast<int32_t>(bufferWidth));
            crop.bottom = std::min(crop.bottom, static_cast<int32_t>(bufferHeight));
        }
        if (!crop.isValid()) {
            // Crop rect is out of bounds, return whole buffer
            return s.buffer->getBounds();
        }
        return crop;
    }
    return s.crop;
}

sp<Layer> BufferStateLayer::createClone() {
    LayerCreationArgs args(mFlinger.get(), nullptr, mName + " (Mirror)", 0, 0, 0, LayerMetadata());
    args.textureName = mTextureName;
    sp<BufferStateLayer> layer = mFlinger->getFactory().createBufferStateLayer(args);
    layer->mHwcSlotGenerator = mHwcSlotGenerator;
    layer->setInitialValuesForClone(this);
    return layer;
}

Layer::RoundedCornerState BufferStateLayer::getRoundedCornerState() const {
    const auto& p = mDrawingParent.promote();
    if (p != nullptr) {
        RoundedCornerState parentState = p->getRoundedCornerState();
        if (parentState.radius > 0) {
            ui::Transform t = getActiveTransform(getDrawingState());
            t = t.inverse();
            parentState.cropRect = t.transform(parentState.cropRect);
            // The rounded corners shader only accepts 1 corner radius for performance reasons,
            // but a transform matrix can define horizontal and vertical scales.
            // Let's take the average between both of them and pass into the shader, practically we
            // never do this type of transformation on windows anyway.
            parentState.radius *= (t[0][0] + t[1][1]) / 2.0f;
            return parentState;
        }
    }
    const float radius = getDrawingState().cornerRadius;
    const State& s(getDrawingState());
    if (radius <= 0 || (getActiveWidth(s) == UINT32_MAX && getActiveHeight(s) == UINT32_MAX))
        return RoundedCornerState();
    return RoundedCornerState(FloatRect(static_cast<float>(s.active.transform.tx()),
                                        static_cast<float>(s.active.transform.ty()),
                                        static_cast<float>(s.active.transform.tx() + s.active.w),
                                        static_cast<float>(s.active.transform.ty() + s.active.h)),
                              radius);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
