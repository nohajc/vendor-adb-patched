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

#pragma once

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <cutils/compiler.h>
#include <gui/BufferItem.h>
#include <gui/BufferQueueDefs.h>
#include <system/graphics.h>

namespace android {

class SurfaceTexture;
class DequeueBufferCallbacks;

/*
 * ImageConsumer implements the parts of SurfaceTexture that deal with
 * images consumed by HWUI view system.
 */
class ImageConsumer {
public:
    typedef status_t (*SurfaceTexture_createReleaseFence)(bool useFenceSync, EGLSyncKHR* eglFence,
                                                          EGLDisplay* display, int* releaseFence,
                                                          void* fencePassThroughHandle);

    typedef status_t (*SurfaceTexture_fenceWait)(int fence, void* fencePassThroughHandle);

    sp<GraphicBuffer> dequeueBuffer(int* outSlotid, android_dataspace* outDataspace,
                                    HdrMetadata* outHdrMetadata, bool* outQueueEmpty,
                                    SurfaceTexture& cb,
                                    SurfaceTexture_createReleaseFence createFence,
                                    SurfaceTexture_fenceWait fenceWait,
                                    void* fencePassThroughHandle);

    /**
     * onReleaseBufferLocked amends the ConsumerBase method to update the
     * mImageSlots array in addition to the ConsumerBase.
     */
    void onReleaseBufferLocked(int slot);

private:
    /**
     * ImageSlot contains the information and object references that
     * ImageConsumer maintains about a BufferQueue buffer slot.
     */
    class ImageSlot {
    public:
        ImageSlot() : mEglFence(EGL_NO_SYNC_KHR) {}

        inline EGLSyncKHR& eglFence() { return mEglFence; }

    private:
        /**
         * mEglFence is the EGL sync object that must signal before the buffer
         * associated with this buffer slot may be dequeued.
         */
        EGLSyncKHR mEglFence;
    };

    /**
     * ImageConsumer stores the SkImages that have been allocated by the BufferQueue
     * for each buffer slot.  It is initialized to null pointers, and gets
     * filled in with the result of BufferQueue::acquire when the
     * client dequeues a buffer from a
     * slot that has not yet been used. The buffer allocated to a slot will also
     * be replaced if the requested buffer usage or geometry differs from that
     * of the buffer allocated to a slot.
     */
    ImageSlot mImageSlots[BufferQueueDefs::NUM_BUFFER_SLOTS];
};

} /* namespace android */
