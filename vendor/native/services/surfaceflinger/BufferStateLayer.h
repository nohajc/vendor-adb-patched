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
#include "Layer.h"

#include <renderengine/Image.h>
#include <renderengine/RenderEngine.h>
#include <system/window.h>
#include <utils/String8.h>

#include <stack>

namespace android {

class SlotGenerationTest;

class BufferStateLayer : public BufferLayer {
public:
    explicit BufferStateLayer(const LayerCreationArgs&);

    ~BufferStateLayer() override;

    // Implements Layer.
    const char* getType() const override { return "BufferStateLayer"; }

    void onLayerDisplayed(ftl::SharedFuture<FenceResult>) override;

    void releasePendingBuffer(nsecs_t dequeueReadyTime) override;

    void finalizeFrameEventHistory(const std::shared_ptr<FenceTime>& glDoneFence,
                                   const CompositorTiming& compositorTiming) override;

    bool isBufferDue(nsecs_t /*expectedPresentTime*/) const override { return true; }

    Region getActiveTransparentRegion(const Layer::State& s) const override {
        return s.transparentRegionHint;
    }
    Rect getCrop(const Layer::State& s) const;

    bool setTransform(uint32_t transform) override;
    bool setTransformToDisplayInverse(bool transformToDisplayInverse) override;
    bool setCrop(const Rect& crop) override;
    bool setBuffer(std::shared_ptr<renderengine::ExternalTexture>& /* buffer */,
                   const BufferData& bufferData, nsecs_t postTime, nsecs_t desiredPresentTime,
                   bool isAutoTimestamp, std::optional<nsecs_t> dequeueTime,
                   const FrameTimelineInfo& info) override;
    bool setDataspace(ui::Dataspace dataspace) override;
    bool setHdrMetadata(const HdrMetadata& hdrMetadata) override;
    bool setSurfaceDamageRegion(const Region& surfaceDamage) override;
    bool setApi(int32_t api) override;
    bool setSidebandStream(const sp<NativeHandle>& sidebandStream) override;
    bool setTransactionCompletedListeners(const std::vector<sp<CallbackHandle>>& handles) override;
    bool setPosition(float /*x*/, float /*y*/) override;
    bool setMatrix(const layer_state_t::matrix22_t& /*matrix*/);

    // Override to ignore legacy layer state properties that are not used by BufferStateLayer
    bool setSize(uint32_t /*w*/, uint32_t /*h*/) override { return false; }
    bool setTransparentRegionHint(const Region& transparent) override;

    Rect getBufferSize(const State& s) const override;
    FloatRect computeSourceBounds(const FloatRect& parentBounds) const override;
    void setAutoRefresh(bool autoRefresh) override;

    bool setBufferCrop(const Rect& bufferCrop) override;
    bool setDestinationFrame(const Rect& destinationFrame) override;
    bool updateGeometry() override;

    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Interface implementation for BufferLayer
    // -----------------------------------------------------------------------
    bool fenceHasSignaled() const override;
    bool framePresentTimeIsCurrent(nsecs_t expectedPresentTime) const override;
    bool onPreComposition(nsecs_t refreshStartTime) override;
    uint32_t getEffectiveScalingMode() const override;

    // See mPendingBufferTransactions
    void decrementPendingBufferCount();
    std::atomic<int32_t>* getPendingBufferCounter() override { return &mPendingBufferTransactions; }
    std::string getPendingBufferCounterName() override { return mBlastTransactionName; }

    bool shouldPresentNow(nsecs_t /*expectedPresentTime*/) const override { return true; }

protected:
    void gatherBufferInfo() override;
    void onSurfaceFrameCreated(const std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame);
    ui::Transform getInputTransform() const override;
    Rect getInputBounds() const override;

private:
    friend class SlotGenerationTest;
    friend class TransactionFrameTracerTest;
    friend class TransactionSurfaceFrameTest;

    inline void tracePendingBufferCount(int32_t pendingBuffers);

    bool updateFrameEventHistory(const sp<Fence>& acquireFence, nsecs_t postedTime,
                                 nsecs_t requestedPresentTime);

    bool latchSidebandStream(bool& recomputeVisibleRegions) override;

    bool hasFrameUpdate() const override;

    status_t updateTexImage(bool& recomputeVisibleRegions, nsecs_t latchTime,
                            nsecs_t expectedPresentTime) override;

    status_t updateActiveBuffer() override;
    status_t updateFrameNumber() override;

    sp<Layer> createClone() override;

    // Crop that applies to the buffer
    Rect computeBufferCrop(const State& s);

    bool willPresentCurrentTransaction() const;

    bool bufferNeedsFiltering() const override;

    bool simpleBufferUpdate(const layer_state_t& s) const override;

    ReleaseCallbackId mPreviousReleaseCallbackId = ReleaseCallbackId::INVALID_ID;
    uint64_t mPreviousReleasedFrameNumber = 0;

    uint64_t mPreviousBarrierFrameNumber = 0;

    bool mReleasePreviousBuffer = false;

    // Stores the last set acquire fence signal time used to populate the callback handle's acquire
    // time.
    std::variant<nsecs_t, sp<Fence>> mCallbackHandleAcquireTimeOrFence = -1;

    std::deque<std::shared_ptr<android::frametimeline::SurfaceFrame>> mPendingJankClassifications;
    // An upper bound on the number of SurfaceFrames in the pending classifications deque.
    static constexpr int kPendingClassificationMaxSurfaceFrames = 25;

    const std::string mBlastTransactionName{"BufferTX - " + mName};
    // This integer is incremented everytime a buffer arrives at the server for this layer,
    // and decremented when a buffer is dropped or latched. When changed the integer is exported
    // to systrace with ATRACE_INT and mBlastTransactionName. This way when debugging perf it is
    // possible to see when a buffer arrived at the server, and in which frame it latched.
    //
    // You can understand the trace this way:
    //     - If the integer increases, a buffer arrived at the server.
    //     - If the integer decreases in latchBuffer, that buffer was latched
    //     - If the integer decreases in setBuffer or doTransaction, a buffer was dropped
    std::atomic<int32_t> mPendingBufferTransactions{0};

    // Contains requested position and matrix updates. This will be applied if the client does
    // not specify a destination frame.
    ui::Transform mRequestedTransform;

    // TODO(marissaw): support sticky transform for LEGACY camera mode

    class HwcSlotGenerator : public ClientCache::ErasedRecipient {
    public:
        HwcSlotGenerator() {
            for (int i = 0; i < BufferQueue::NUM_BUFFER_SLOTS; i++) {
                mFreeHwcCacheSlots.push(i);
            }
        }

        void bufferErased(const client_cache_t& clientCacheId);

        int getHwcCacheSlot(const client_cache_t& clientCacheId);

    private:
        friend class SlotGenerationTest;
        int addCachedBuffer(const client_cache_t& clientCacheId) REQUIRES(mMutex);
        int getFreeHwcCacheSlot() REQUIRES(mMutex);
        void evictLeastRecentlyUsed() REQUIRES(mMutex);
        void eraseBufferLocked(const client_cache_t& clientCacheId) REQUIRES(mMutex);

        struct CachedBufferHash {
            std::size_t operator()(const client_cache_t& clientCacheId) const {
                return std::hash<uint64_t>{}(clientCacheId.id);
            }
        };

        std::mutex mMutex;

        std::unordered_map<client_cache_t, std::pair<int /*HwcCacheSlot*/, uint64_t /*counter*/>,
                           CachedBufferHash>
                mCachedBuffers GUARDED_BY(mMutex);
        std::stack<int /*HwcCacheSlot*/> mFreeHwcCacheSlots GUARDED_BY(mMutex);

        // The cache increments this counter value when a slot is updated or used.
        // Used to track the least recently-used buffer
        uint64_t mCounter = 0;
    };

    sp<HwcSlotGenerator> mHwcSlotGenerator;
};

} // namespace android
