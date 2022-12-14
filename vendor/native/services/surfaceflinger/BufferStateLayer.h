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

    // -----------------------------------------------------------------------
    // Interface implementation for Layer
    // -----------------------------------------------------------------------
    const char* getType() const override { return "BufferStateLayer"; }

    void onLayerDisplayed(const sp<Fence>& releaseFence) override;
    void releasePendingBuffer(nsecs_t dequeueReadyTime) override;

    void finalizeFrameEventHistory(const std::shared_ptr<FenceTime>& glDoneFence,
                                   const CompositorTiming& compositorTiming) override;

    bool shouldPresentNow(nsecs_t expectedPresentTime) const override;

    uint32_t doTransactionResize(uint32_t flags, Layer::State* /*stateToCommit*/) override {
        return flags;
    }
    /*TODO:vhau return to using BufferStateLayer override once WM
     * has removed deferred transactions!
    void pushPendingState() override;*/
    bool applyPendingStates(Layer::State* stateToCommit) override;

    uint32_t getActiveWidth(const Layer::State& s) const override { return s.active.w; }
    uint32_t getActiveHeight(const Layer::State& s) const override { return s.active.h; }
    ui::Transform getActiveTransform(const Layer::State& s) const override {
        return s.active.transform;
    }
    Region getActiveTransparentRegion(const Layer::State& s) const override {
        return s.transparentRegionHint;
    }
    Rect getCrop(const Layer::State& s) const;

    bool setTransform(uint32_t transform) override;
    bool setTransformToDisplayInverse(bool transformToDisplayInverse) override;
    bool setCrop(const Rect& crop) override;
    bool setFrame(const Rect& frame) override;
    bool setBuffer(const sp<GraphicBuffer>& buffer, const sp<Fence>& acquireFence, nsecs_t postTime,
                   nsecs_t desiredPresentTime, const client_cache_t& clientCacheId) override;
    bool setAcquireFence(const sp<Fence>& fence) override;
    bool setDataspace(ui::Dataspace dataspace) override;
    bool setHdrMetadata(const HdrMetadata& hdrMetadata) override;
    bool setSurfaceDamageRegion(const Region& surfaceDamage) override;
    bool setApi(int32_t api) override;
    bool setSidebandStream(const sp<NativeHandle>& sidebandStream) override;
    bool setTransactionCompletedListeners(const std::vector<sp<CallbackHandle>>& handles) override;
    void forceSendCallbacks() override;
    bool addFrameEvent(const sp<Fence>& acquireFence, nsecs_t postedTime,
                       nsecs_t requestedPresentTime) override;

    // Override to ignore legacy layer state properties that are not used by BufferStateLayer
    bool setSize(uint32_t /*w*/, uint32_t /*h*/) override { return false; }
    bool setPosition(float /*x*/, float /*y*/) override { return false; }
    bool setTransparentRegionHint(const Region& transparent) override;
    bool setMatrix(const layer_state_t::matrix22_t& /*matrix*/,
                   bool /*allowNonRectPreservingTransforms*/) override {
        return false;
    }
    bool setCrop_legacy(const Rect& /*crop*/) override { return false; }
    bool setOverrideScalingMode(int32_t /*overrideScalingMode*/) override { return false; }
    void deferTransactionUntil_legacy(const sp<IBinder>& /*barrierHandle*/,
                                      uint64_t /*frameNumber*/) override {}
    void deferTransactionUntil_legacy(const sp<Layer>& /*barrierLayer*/,
                                      uint64_t /*frameNumber*/) override {}

    Rect getBufferSize(const State& s) const override;
    FloatRect computeSourceBounds(const FloatRect& parentBounds) const override;
    Layer::RoundedCornerState getRoundedCornerState() const override;

    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Interface implementation for BufferLayer
    // -----------------------------------------------------------------------
    bool fenceHasSignaled() const override;
    bool framePresentTimeIsCurrent(nsecs_t expectedPresentTime) const override;
    bool onPreComposition(nsecs_t refreshStartTime) override;

protected:
    void gatherBufferInfo() override;
    uint64_t getHeadFrameNumber(nsecs_t expectedPresentTime) const;

private:
    bool updateFrameEventHistory(const sp<Fence>& acquireFence, nsecs_t postedTime,
                                 nsecs_t requestedPresentTime);

    status_t addReleaseFence(const sp<CallbackHandle>& ch, const sp<Fence>& releaseFence);

    uint64_t getFrameNumber(nsecs_t expectedPresentTime) const override;

    bool getAutoRefresh() const override;
    bool getSidebandStreamChanged() const override;

    bool latchSidebandStream(bool& recomputeVisibleRegions) override;

    bool hasFrameUpdate() const override;

    status_t bindTextureImage() override;
    status_t updateTexImage(bool& recomputeVisibleRegions, nsecs_t latchTime,
                            nsecs_t expectedPresentTime) override;

    status_t updateActiveBuffer() override;
    status_t updateFrameNumber(nsecs_t latchTime) override;

    sp<Layer> createClone() override;

    // Crop that applies to the buffer
    Rect computeCrop(const State& s);

private:
    friend class SlotGenerationTest;
    bool willPresentCurrentTransaction() const;

    static const std::array<float, 16> IDENTITY_MATRIX;

    std::unique_ptr<renderengine::Image> mTextureImage;

    std::atomic<bool> mSidebandStreamChanged{false};

    mutable uint64_t mFrameNumber{0};
    uint64_t mFrameCounter{0};

    sp<Fence> mPreviousReleaseFence;
    uint64_t mPreviousBufferId = 0;
    uint64_t mPreviousReleasedFrameNumber = 0;

    mutable bool mCurrentStateModified = false;
    bool mReleasePreviousBuffer = false;
    nsecs_t mCallbackHandleAcquireTime = -1;

    // TODO(marissaw): support sticky transform for LEGACY camera mode

    class HwcSlotGenerator : public ClientCache::ErasedRecipient {
    public:
        HwcSlotGenerator() {
            for (uint32_t i = 0; i < BufferQueue::NUM_BUFFER_SLOTS; i++) {
                mFreeHwcCacheSlots.push(i);
            }
        }

        void bufferErased(const client_cache_t& clientCacheId);

        uint32_t getHwcCacheSlot(const client_cache_t& clientCacheId);

    private:
        friend class SlotGenerationTest;
        uint32_t addCachedBuffer(const client_cache_t& clientCacheId) REQUIRES(mMutex);
        uint32_t getFreeHwcCacheSlot() REQUIRES(mMutex);
        void evictLeastRecentlyUsed() REQUIRES(mMutex);
        void eraseBufferLocked(const client_cache_t& clientCacheId) REQUIRES(mMutex);

        struct CachedBufferHash {
            std::size_t operator()(const client_cache_t& clientCacheId) const {
                return std::hash<uint64_t>{}(clientCacheId.id);
            }
        };

        std::mutex mMutex;

        std::unordered_map<client_cache_t,
                           std::pair<uint32_t /*HwcCacheSlot*/, uint32_t /*counter*/>,
                           CachedBufferHash>
                mCachedBuffers GUARDED_BY(mMutex);
        std::stack<uint32_t /*HwcCacheSlot*/> mFreeHwcCacheSlots GUARDED_BY(mMutex);

        // The cache increments this counter value when a slot is updated or used.
        // Used to track the least recently-used buffer
        uint64_t mCounter = 0;
    };

    sp<HwcSlotGenerator> mHwcSlotGenerator;
};

} // namespace android
