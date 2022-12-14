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

namespace frametimeline {
class SurfaceFrame;
}

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

    // Implements Layer.
    const char* getType() const override { return "BufferQueueLayer"; }

    void onLayerDisplayed(const sp<Fence>& releaseFence) override;

    std::vector<OccupancyTracker::Segment> getOccupancyHistory(bool forceFlush) override;

    // If a buffer was replaced this frame, release the former buffer
    void releasePendingBuffer(nsecs_t dequeueReadyTime) override;

    void setDefaultBufferSize(uint32_t w, uint32_t h) override;

    int32_t getQueuedFrameCount() const override;

    // Returns true if the next buffer should be presented at the expected present time
    bool isBufferDue(nsecs_t expectedPresentTime) const override;

    // Implements BufferLayer.
    bool fenceHasSignaled() const override;
    bool framePresentTimeIsCurrent(nsecs_t expectedPresentTime) const override;

    status_t setDefaultBufferProperties(uint32_t w, uint32_t h, PixelFormat format);
    sp<IGraphicBufferProducer> getProducer() const;

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

private:
    uint64_t getFrameNumber(nsecs_t expectedPresentTime) const override;

    bool latchSidebandStream(bool& recomputeVisibleRegions) override;
    void setTransformHint(ui::Transform::RotationFlags displayTransformHint) override;

    bool hasFrameUpdate() const override;

    status_t updateTexImage(bool& recomputeVisibleRegions, nsecs_t latchTime,
                            nsecs_t expectedPresentTime) override;

    status_t updateActiveBuffer() override;
    status_t updateFrameNumber(nsecs_t latchTime) override;
    void setFrameTimelineInfoForBuffer(const FrameTimelineInfo& frameTimelineInfo) override;

    sp<Layer> createClone() override;

    void onFirstRef() override;

    void onFrameAvailable(const BufferItem& item);
    void onFrameReplaced(const BufferItem& item);
    void onSidebandStreamChanged();
    void onFrameDequeued(const uint64_t bufferId);
    void onFrameDetached(const uint64_t bufferId);
    void onFrameCancelled(const uint64_t bufferId);

    // Temporary - Used only for LEGACY camera mode.
    uint32_t getProducerStickyTransform() const;

    sp<BufferLayerConsumer> mConsumer;
    sp<IGraphicBufferProducer> mProducer;

    bool mUpdateTexImageFailed{false};

    uint64_t mPreviousBufferId = 0;
    uint64_t mPreviousReleasedFrameNumber = 0;

    // Local copy of the queued contents of the incoming BufferQueue
    mutable Mutex mQueueItemLock;
    Condition mQueueItemCondition;

    struct BufferData {
        BufferData(BufferItem item, std::shared_ptr<frametimeline::SurfaceFrame> surfaceFrame)
              : item(item), surfaceFrame(surfaceFrame) {}
        BufferItem item;
        std::shared_ptr<frametimeline::SurfaceFrame> surfaceFrame;
    };
    std::vector<BufferData> mQueueItems;
    std::atomic<uint64_t> mLastFrameNumberReceived{0};

    // thread-safe
    std::atomic<int32_t> mQueuedFrames{0};

    sp<ContentsChangedListener> mContentsChangedListener;

    // The last vsync info received on this layer. This will be used when we get
    // a buffer to correlate the buffer with the vsync id. Can only be accessed
    // with the SF state lock held.
    FrameTimelineInfo mFrameTimelineInfo;
};

} // namespace android
