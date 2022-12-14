/*
 **
 ** Copyright 2012 The Android Open Source Project
 **
 ** Licensed under the Apache License Version 2.0(the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing software
 ** distributed under the License is distributed on an "AS IS" BASIS
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "FramebufferSurface"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <utils/String8.h>
#include <log/log.h>

#include <hardware/hardware.h>
#include <gui/BufferItem.h>
#include <gui/BufferQueue.h>
#include <gui/Surface.h>

#include <ui/DebugUtils.h>
#include <ui/GraphicBuffer.h>
#include <ui/Rect.h>

#include "FramebufferSurface.h"
#include "HWComposer.h"
#include "../SurfaceFlinger.h"

// ----------------------------------------------------------------------------
namespace android {
// ----------------------------------------------------------------------------

using ui::Dataspace;

/*
 * This implements the (main) framebuffer management. This class is used
 * mostly by SurfaceFlinger, but also by command line GL application.
 *
 */

FramebufferSurface::FramebufferSurface(HWComposer& hwc, DisplayId displayId,
                                       const sp<IGraphicBufferConsumer>& consumer,
                                       uint32_t maxWidth, uint32_t maxHeight)
      : ConsumerBase(consumer),
        mDisplayId(displayId),
        mMaxWidth(maxWidth),
        mMaxHeight(maxHeight),
        mCurrentBufferSlot(-1),
        mCurrentBuffer(),
        mCurrentFence(Fence::NO_FENCE),
        mHwc(hwc),
        mHasPendingRelease(false),
        mPreviousBufferSlot(BufferQueue::INVALID_BUFFER_SLOT),
        mPreviousBuffer() {
    ALOGV("Creating for display %s", to_string(displayId).c_str());

    mName = "FramebufferSurface";
    mConsumer->setConsumerName(mName);
    mConsumer->setConsumerUsageBits(GRALLOC_USAGE_HW_FB |
                                       GRALLOC_USAGE_HW_RENDER |
                                       GRALLOC_USAGE_HW_COMPOSER);
    const auto& activeConfig = mHwc.getActiveConfig(displayId);
    ui::Size limitedSize =
            limitFramebufferSize(activeConfig->getWidth(), activeConfig->getHeight());
    mConsumer->setDefaultBufferSize(limitedSize.width, limitedSize.height);
    mConsumer->setMaxAcquiredBufferCount(
            SurfaceFlinger::maxFrameBufferAcquiredBuffers - 1);
}

void FramebufferSurface::resizeBuffers(uint32_t width, uint32_t height) {
    ui::Size limitedSize = limitFramebufferSize(width, height);
    mConsumer->setDefaultBufferSize(limitedSize.width, limitedSize.height);
}

status_t FramebufferSurface::beginFrame(bool /*mustRecompose*/) {
    return NO_ERROR;
}

status_t FramebufferSurface::prepareFrame(CompositionType /*compositionType*/) {
    return NO_ERROR;
}

status_t FramebufferSurface::advanceFrame() {
    uint32_t slot = 0;
    sp<GraphicBuffer> buf;
    sp<Fence> acquireFence(Fence::NO_FENCE);
    Dataspace dataspace = Dataspace::UNKNOWN;
    status_t result = nextBuffer(slot, buf, acquireFence, dataspace);
    mDataSpace = dataspace;
    if (result != NO_ERROR) {
        ALOGE("error latching next FramebufferSurface buffer: %s (%d)",
                strerror(-result), result);
    }
    return result;
}

status_t FramebufferSurface::nextBuffer(uint32_t& outSlot,
        sp<GraphicBuffer>& outBuffer, sp<Fence>& outFence,
        Dataspace& outDataspace) {
    Mutex::Autolock lock(mMutex);

    BufferItem item;
    status_t err = acquireBufferLocked(&item, 0);
    if (err == BufferQueue::NO_BUFFER_AVAILABLE) {
        mHwcBufferCache.getHwcBuffer(mCurrentBufferSlot, mCurrentBuffer, &outSlot, &outBuffer);
        return NO_ERROR;
    } else if (err != NO_ERROR) {
        ALOGE("error acquiring buffer: %s (%d)", strerror(-err), err);
        return err;
    }

    // If the BufferQueue has freed and reallocated a buffer in mCurrentSlot
    // then we may have acquired the slot we already own.  If we had released
    // our current buffer before we call acquireBuffer then that release call
    // would have returned STALE_BUFFER_SLOT, and we would have called
    // freeBufferLocked on that slot.  Because the buffer slot has already
    // been overwritten with the new buffer all we have to do is skip the
    // releaseBuffer call and we should be in the same state we'd be in if we
    // had released the old buffer first.
    if (mCurrentBufferSlot != BufferQueue::INVALID_BUFFER_SLOT &&
        item.mSlot != mCurrentBufferSlot) {
        mHasPendingRelease = true;
        mPreviousBufferSlot = mCurrentBufferSlot;
        mPreviousBuffer = mCurrentBuffer;
    }
    mCurrentBufferSlot = item.mSlot;
    mCurrentBuffer = mSlots[mCurrentBufferSlot].mGraphicBuffer;
    mCurrentFence = item.mFence;

    outFence = item.mFence;
    mHwcBufferCache.getHwcBuffer(mCurrentBufferSlot, mCurrentBuffer, &outSlot, &outBuffer);
    outDataspace = static_cast<Dataspace>(item.mDataSpace);
    status_t result = mHwc.setClientTarget(mDisplayId, outSlot, outFence, outBuffer, outDataspace);
    if (result != NO_ERROR) {
        ALOGE("error posting framebuffer: %d", result);
        return result;
    }

    return NO_ERROR;
}

void FramebufferSurface::freeBufferLocked(int slotIndex) {
    ConsumerBase::freeBufferLocked(slotIndex);
    if (slotIndex == mCurrentBufferSlot) {
        mCurrentBufferSlot = BufferQueue::INVALID_BUFFER_SLOT;
    }
}

void FramebufferSurface::onFrameCommitted() {
    if (mHasPendingRelease) {
        sp<Fence> fence = mHwc.getPresentFence(mDisplayId);
        if (fence->isValid()) {
            status_t result = addReleaseFence(mPreviousBufferSlot,
                    mPreviousBuffer, fence);
            ALOGE_IF(result != NO_ERROR, "onFrameCommitted: failed to add the"
                    " fence: %s (%d)", strerror(-result), result);
        }
        status_t result = releaseBufferLocked(mPreviousBufferSlot, mPreviousBuffer);
        ALOGE_IF(result != NO_ERROR, "onFrameCommitted: error releasing buffer:"
                " %s (%d)", strerror(-result), result);

        mPreviousBuffer.clear();
        mHasPendingRelease = false;
    }
}

ui::Size FramebufferSurface::limitFramebufferSize(uint32_t width, uint32_t height) {
    ui::Size framebufferSize(width, height);
    bool wasLimited = true;
    if (width > mMaxWidth && mMaxWidth != 0) {
        float aspectRatio = float(width) / float(height);
        framebufferSize.height = mMaxWidth / aspectRatio;
        framebufferSize.width = mMaxWidth;
        wasLimited = true;
    }
    if (height > mMaxHeight && mMaxHeight != 0) {
        float aspectRatio = float(width) / float(height);
        framebufferSize.height = mMaxHeight;
        framebufferSize.width = mMaxHeight * aspectRatio;
        wasLimited = true;
    }
    ALOGI_IF(wasLimited, "framebuffer size has been limited to [%dx%d] from [%dx%d]",
             framebufferSize.width, framebufferSize.height, width, height);
    return framebufferSize;
}

void FramebufferSurface::dumpAsString(String8& result) const {
    Mutex::Autolock lock(mMutex);
    result.appendFormat("  FramebufferSurface: dataspace: %s(%d)\n",
                        dataspaceDetails(static_cast<android_dataspace>(mDataSpace)).c_str(),
                        mDataSpace);
    ConsumerBase::dumpLocked(result, "   ");
}

void FramebufferSurface::dumpLocked(String8& result, const char* prefix) const
{
    ConsumerBase::dumpLocked(result, prefix);
}

const sp<Fence>& FramebufferSurface::getClientTargetAcquireFence() const {
    return mCurrentFence;
}

// ----------------------------------------------------------------------------
}; // namespace android
// ----------------------------------------------------------------------------

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
