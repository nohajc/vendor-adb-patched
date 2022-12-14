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

#pragma once

#include "BufferLayer.h"

#include <utils/String8.h>

namespace android {

/*
 * A new BufferQueue and a new BufferLayerConsumer are created when the
 * BufferLayer is first referenced.
 *
 * This also implements onFrameAvailable(), which notifies SurfaceFlinger
 * that new data has arrived.
 */
class BufferQueueLayer : public BufferLayer {
public:
    // Only call while mStateLock is held
    explicit BufferQueueLayer(const LayerCreationArgs&);
    ~BufferQueueLayer() override;

    // -----------------------------------------------------------------------
    // Interface implementation for Layer
    // -----------------------------------------------------------------------
public:
    const char* getType() const override { return "BufferQueueLayer"; }

    void onLayerDisplayed(const sp<Fence>& releaseFence) override;

    std::vector<OccupancyTracker::Segment> getOccupancyHistory(bool forceFlush) override;

    // If a buffer was replaced this frame, release the former buffer
    void releasePendingBuffer(nsecs_t dequeueReadyTime) override;

    void setDefaultBufferSize(uint32_t w, uint32_t h) override;

    int32_t getQueuedFrameCount() const override;

    bool shouldPresentNow(nsecs_t expectedPresentTime) const override;

    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Interface implementation for BufferLayer
    // -----------------------------------------------------------------------
public:
    bool fenceHasSignaled() const override;
    bool framePresentTimeIsCurrent(nsecs_t expectedPresentTime) const override;

private:
    uint64_t getFrameNumber(nsecs_t expectedPresentTime) const override;

    bool getAutoRefresh() const override;
    bool getSidebandStreamChanged() const override;

    bool latchSidebandStream(bool& recomputeVisibleRegions) override;
    void setTransformHint(ui::Transform::RotationFlags displayTransformHint) override;

    bool hasFrameUpdate() const override;

    status_t bindTextureImage() override;
    status_t updateTexImage(bool& recomputeVisibleRegions, nsecs_t latchTime,
                            nsecs_t expectedPresentTime) override;

    status_t updateActiveBuffer() override;
    status_t updateFrameNumber(nsecs_t latchTime) override;

    sp<Layer> createClone() override;

    void onFrameAvailable(const BufferItem& item);
    void onFrameReplaced(const BufferItem& item);
    void onSidebandStreamChanged();
    void onFrameDequeued(const uint64_t bufferId);
    void onFrameDetached(const uint64_t bufferId);
    void onFrameCancelled(const uint64_t bufferId);

protected:
    void gatherBufferInfo() override;

    // -----------------------------------------------------------------------
    // Interface implementation for BufferLayerConsumer::ContentsChangedListener
    // -----------------------------------------------------------------------
    class ContentsChangedListener : public BufferLayerConsumer::ContentsChangedListener {
    public:
        ContentsChangedListener(BufferQueueLayer* bufferQueueLayer)
              : mBufferQueueLayer(bufferQueueLayer) {}
        void abandon();

    protected:
        void onFrameAvailable(const BufferItem& item) override;
        void onFrameReplaced(const BufferItem& item) override;
        void onSidebandStreamChanged() override;
        void onFrameDequeued(const uint64_t bufferId) override;
        void onFrameDetached(const uint64_t bufferId) override;
        void onFrameCancelled(const uint64_t bufferId) override;

    private:
        BufferQueueLayer* mBufferQueueLayer = nullptr;
        Mutex mMutex;
    };
    // -----------------------------------------------------------------------

public:
    status_t setDefaultBufferProperties(uint32_t w, uint32_t h, PixelFormat format);

    sp<IGraphicBufferProducer> getProducer() const;

private:
    // Temporary - Used only for LEGACY camera mode.
    uint32_t getProducerStickyTransform() const;

    void onFirstRef() override;

    sp<BufferLayerConsumer> mConsumer;
    sp<IGraphicBufferProducer> mProducer;

    bool mUpdateTexImageFailed{false};

    uint64_t mPreviousBufferId = 0;
    uint64_t mPreviousReleasedFrameNumber = 0;

    // Local copy of the queued contents of the incoming BufferQueue
    mutable Mutex mQueueItemLock;
    Condition mQueueItemCondition;
    Vector<BufferItem> mQueueItems;
    std::atomic<uint64_t> mLastFrameNumberReceived{0};

    bool mAutoRefresh{false};

    // thread-safe
    std::atomic<int32_t> mQueuedFrames{0};
    std::atomic<bool> mSidebandStreamChanged{false};

    sp<ContentsChangedListener> mContentsChangedListener;
};

} // namespace android
