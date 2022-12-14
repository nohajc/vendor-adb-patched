/*
 * Copyright 2021 The Android Open Source Project
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

#include <compositionengine/Output.h>
#include <compositionengine/ProjectionSpace.h>
#include <compositionengine/impl/planner/LayerState.h>
#include <compositionengine/impl/planner/TexturePool.h>
#include <renderengine/RenderEngine.h>

#include <chrono>

namespace android {

namespace compositionengine::impl::planner {

std::string durationString(std::chrono::milliseconds duration);

class LayerState;

class CachedSet {
public:
    class Layer {
    public:
        Layer(const LayerState*, std::chrono::steady_clock::time_point lastUpdate);

        const LayerState* getState() const { return mState; }
        const std::string& getName() const { return mState->getName(); }
        int32_t getBackgroundBlurRadius() const { return mState->getBackgroundBlurRadius(); }
        Rect getDisplayFrame() const { return mState->getDisplayFrame(); }
        const Region& getVisibleRegion() const { return mState->getVisibleRegion(); }
        const sp<GraphicBuffer>& getBuffer() const {
            return mState->getOutputLayer()->getLayerFE().getCompositionState()->buffer;
        }
        int64_t getFramesSinceBufferUpdate() const { return mState->getFramesSinceBufferUpdate(); }
        NonBufferHash getHash() const { return mHash; }
        std::chrono::steady_clock::time_point getLastUpdate() const { return mLastUpdate; }

    private:
        const LayerState* mState;
        NonBufferHash mHash;
        std::chrono::steady_clock::time_point mLastUpdate;
    };

    CachedSet(const LayerState*, std::chrono::steady_clock::time_point lastUpdate);
    CachedSet(Layer layer);

    void addLayer(const LayerState*, std::chrono::steady_clock::time_point lastUpdate);

    std::chrono::steady_clock::time_point getLastUpdate() const { return mLastUpdate; }
    size_t getLayerCount() const { return mLayers.size(); }
    const Layer& getFirstLayer() const { return mLayers[0]; }
    const Rect& getBounds() const { return mBounds; }
    Rect getTextureBounds() const {
        return mTexture ? mTexture->get()->getBuffer()->getBounds() : Rect::INVALID_RECT;
    }
    const Region& getVisibleRegion() const { return mVisibleRegion; }
    size_t getAge() const { return mAge; }
    std::shared_ptr<renderengine::ExternalTexture> getBuffer() const {
        return mTexture ? mTexture->get() : nullptr;
    }
    const sp<Fence>& getDrawFence() const { return mDrawFence; }
    const ProjectionSpace& getOutputSpace() const { return mOutputSpace; }
    ui::Dataspace getOutputDataspace() const { return mOutputDataspace; }
    const std::vector<Layer>& getConstituentLayers() const { return mLayers; }

    NonBufferHash getNonBufferHash() const;

    size_t getComponentDisplayCost() const;
    size_t getCreationCost() const;
    size_t getDisplayCost() const;

    bool hasBufferUpdate() const;
    bool hasRenderedBuffer() const { return mTexture != nullptr; }
    bool hasReadyBuffer() const;

    // Decomposes this CachedSet into a vector of its layers as individual CachedSets
    std::vector<CachedSet> decompose() const;

    void updateAge(std::chrono::steady_clock::time_point now);

    void setLastUpdate(std::chrono::steady_clock::time_point now) { mLastUpdate = now; }
    void append(const CachedSet& other) {
        mTexture.reset();
        mOutputDataspace = ui::Dataspace::UNKNOWN;
        mDrawFence = nullptr;
        mBlurLayer = nullptr;
        mHolePunchLayer = nullptr;
        mSkipCount = 0;

        mLayers.insert(mLayers.end(), other.mLayers.cbegin(), other.mLayers.cend());
        Region boundingRegion;
        boundingRegion.orSelf(mBounds);
        boundingRegion.orSelf(other.mBounds);
        mBounds = boundingRegion.getBounds();
        mVisibleRegion.orSelf(other.mVisibleRegion);
    }
    void incrementAge() { ++mAge; }
    void incrementSkipCount() { mSkipCount++; }
    size_t getSkipCount() { return mSkipCount; }

    // Renders the cached set with the supplied output composition state.
    void render(renderengine::RenderEngine& re, TexturePool& texturePool,
                const OutputCompositionState& outputState, bool deviceHandlesColorTransform);

    void dump(std::string& result) const;

    // Whether this represents a single layer with a buffer and rounded corners.
    // If it is, we may be able to draw it by placing it behind another
    // CachedSet and punching a hole.
    bool requiresHolePunch() const;

    // True if any constituent layer is configured to blur any layers behind.
    bool hasBlurBehind() const;

    // Add a layer that will be drawn behind this one. ::render() will render a
    // hole in this CachedSet's buffer, allowing the supplied layer to peek
    // through. Must be called before ::render().
    // Will do nothing if this CachedSet is not opaque where the hole punch
    // layer is displayed.
    // If isFirstLayer is true, this CachedSet can be considered opaque because
    // nothing (besides the hole punch layer) will be drawn behind it.
    void addHolePunchLayerIfFeasible(const CachedSet&, bool isFirstLayer);

    void addBackgroundBlurLayer(const CachedSet&);

    // Retrieve the layer that will be drawn behind this one.
    compositionengine::OutputLayer* getHolePunchLayer() const;

    compositionengine::OutputLayer* getBlurLayer() const;

    bool hasUnsupportedDataspace() const;

    bool hasProtectedLayers() const;

    bool hasSolidColorLayers() const;

private:
    const NonBufferHash mFingerprint;
    std::chrono::steady_clock::time_point mLastUpdate = std::chrono::steady_clock::now();
    std::vector<Layer> mLayers;

    // Unowned.
    const LayerState* mHolePunchLayer = nullptr;
    const LayerState* mBlurLayer = nullptr;
    Rect mBounds = Rect::EMPTY_RECT;
    Region mVisibleRegion;
    size_t mAge = 0;
    size_t mSkipCount = 0;

    // TODO(b/190411067): This is a shared pointer only because CachedSets are copied into different
    // containers in the Flattener. Logically this should have unique ownership otherwise.
    std::shared_ptr<TexturePool::AutoTexture> mTexture;
    sp<Fence> mDrawFence;
    ProjectionSpace mOutputSpace;
    ui::Dataspace mOutputDataspace;
    ui::Transform::RotationFlags mOrientation = ui::Transform::ROT_0;

    static const bool sDebugHighlighLayers;
};

} // namespace compositionengine::impl::planner
} // namespace android
