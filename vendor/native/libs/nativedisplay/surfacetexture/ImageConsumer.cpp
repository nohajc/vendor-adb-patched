/*
 * Copyright 2019 The Android Open Source Project
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

#include <gui/BufferQueue.h>
#include <surfacetexture/ImageConsumer.h>
#include <surfacetexture/SurfaceTexture.h>

// Macro for including the SurfaceTexture name in log messages
#define IMG_LOGE(x, ...) ALOGE("[%s] " x, st.mName.string(), ##__VA_ARGS__)

namespace android {

void ImageConsumer::onReleaseBufferLocked(int buf) {
    mImageSlots[buf].eglFence() = EGL_NO_SYNC_KHR;
}

sp<GraphicBuffer> ImageConsumer::dequeueBuffer(int* outSlotid, android_dataspace* outDataspace,
                                               bool* outQueueEmpty, SurfaceTexture& st,
                                               SurfaceTexture_createReleaseFence createFence,
                                               SurfaceTexture_fenceWait fenceWait,
                                               void* fencePassThroughHandle) {
    BufferItem item;
    status_t err;
    err = st.acquireBufferLocked(&item, 0);
    if (err != OK) {
        if (err != BufferQueue::NO_BUFFER_AVAILABLE) {
            IMG_LOGE("Error acquiring buffer: %s (%d)", strerror(err), err);
        } else {
            int slot = st.mCurrentTexture;
            if (slot != BufferItem::INVALID_BUFFER_SLOT) {
                *outQueueEmpty = true;
                *outDataspace = st.mCurrentDataSpace;
                *outSlotid = slot;
                return st.mSlots[slot].mGraphicBuffer;
            }
        }
        return nullptr;
    }

    int slot = item.mSlot;
    if (item.mFence->isValid()) {
        // Wait on the producer fence for the buffer to be ready.
        err = fenceWait(item.mFence->get(), fencePassThroughHandle);
        if (err != OK) {
            st.releaseBufferLocked(slot, st.mSlots[slot].mGraphicBuffer, EGL_NO_DISPLAY,
                                   EGL_NO_SYNC_KHR);
            return nullptr;
        }
    }

    // Release old buffer.
    if (st.mCurrentTexture != BufferItem::INVALID_BUFFER_SLOT) {
        // If needed, set the released slot's fence to guard against a producer
        // accessing the buffer before the outstanding accesses have completed.
        int releaseFenceId = -1;
        EGLDisplay display = EGL_NO_DISPLAY;
        err = createFence(st.mUseFenceSync, &mImageSlots[slot].eglFence(), &display,
                          &releaseFenceId, fencePassThroughHandle);
        if (OK != err) {
            st.releaseBufferLocked(slot, st.mSlots[slot].mGraphicBuffer, EGL_NO_DISPLAY,
                                   EGL_NO_SYNC_KHR);
            return nullptr;
        }

        if (releaseFenceId != -1) {
            sp<Fence> releaseFence(new Fence(releaseFenceId));
            status_t err = st.addReleaseFenceLocked(st.mCurrentTexture,
                                                    st.mSlots[st.mCurrentTexture].mGraphicBuffer,
                                                    releaseFence);
            if (err != OK) {
                IMG_LOGE("dequeueImage: error adding release fence: %s (%d)", strerror(-err), err);
                st.releaseBufferLocked(slot, st.mSlots[slot].mGraphicBuffer, EGL_NO_DISPLAY,
                                       EGL_NO_SYNC_KHR);
                return nullptr;
            }
        }

        // Finally release the old buffer.
        status_t status =
                st.releaseBufferLocked(st.mCurrentTexture,
                                       st.mSlots[st.mCurrentTexture].mGraphicBuffer, display,
                                       mImageSlots[st.mCurrentTexture].eglFence());
        if (status < NO_ERROR) {
            IMG_LOGE("dequeueImage: failed to release buffer: %s (%d)", strerror(-status), status);
            err = status;
            // Keep going, with error raised.
        }
    }

    // Update the state.
    st.mCurrentTexture = slot;
    st.mCurrentCrop = item.mCrop;
    st.mCurrentTransform = item.mTransform;
    st.mCurrentScalingMode = item.mScalingMode;
    st.mCurrentTimestamp = item.mTimestamp;
    st.mCurrentDataSpace = item.mDataSpace;
    st.mCurrentFence = item.mFence;
    st.mCurrentFenceTime = item.mFenceTime;
    st.mCurrentFrameNumber = item.mFrameNumber;
    st.computeCurrentTransformMatrixLocked();

    *outQueueEmpty = false;
    *outDataspace = item.mDataSpace;
    *outSlotid = slot;
    return st.mSlots[slot].mGraphicBuffer;
}

} /* namespace android */
