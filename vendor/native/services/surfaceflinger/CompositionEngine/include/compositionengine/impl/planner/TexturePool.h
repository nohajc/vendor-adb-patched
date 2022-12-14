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
#include <renderengine/RenderEngine.h>

#include <renderengine/ExternalTexture.h>
#include <chrono>
#include "android-base/macros.h"

namespace android::compositionengine::impl::planner {

// A pool of textures that only manages textures of a single size.
// While it is possible to define a texture pool supporting variable-sized textures to save on
// memory, it is a simpler implementation to only manage screen-sized textures. The texture pool is
// unbounded - there are a minimum number of textures preallocated. Under heavy system load, new
// textures may be allocated, but only a maximum number of retained once those textures are no
// longer necessary.
class TexturePool {
public:
    // RAII class helping with managing textures from the texture pool
    // Textures once they're no longer used should be returned to the pool instead of outright
    // deleted.
    class AutoTexture {
    public:
        AutoTexture(TexturePool& texturePool,
                    std::shared_ptr<renderengine::ExternalTexture> texture, const sp<Fence>& fence)
              : mTexturePool(texturePool), mTexture(texture), mFence(fence) {}

        ~AutoTexture() { mTexturePool.returnTexture(std::move(mTexture), mFence); }

        sp<Fence> getReadyFence() { return mFence; }

        void setReadyFence(const sp<Fence>& fence) { mFence = fence; }

        // Disable copying and assigning
        AutoTexture(const AutoTexture&) = delete;
        AutoTexture& operator=(const AutoTexture&) = delete;

        // Gets a pointer to the underlying external texture
        const std::shared_ptr<renderengine::ExternalTexture>& get() const { return mTexture; }

    private:
        TexturePool& mTexturePool;
        std::shared_ptr<renderengine::ExternalTexture> mTexture;
        sp<Fence> mFence;
    };

    TexturePool(renderengine::RenderEngine& renderEngine)
          : mRenderEngine(renderEngine), mEnabled(false) {}

    virtual ~TexturePool() = default;

    // Sets the display size for the texture pool.
    // This will trigger a reallocation for all remaining textures in the pool.
    // setDisplaySize must be called for the texture pool to be used.
    void setDisplaySize(ui::Size size);

    // Borrows a new texture from the pool.
    // If the pool is currently starved of textures, then a new texture is generated.
    // When the AutoTexture object is destroyed, the scratch texture is automatically returned
    // to the pool.
    std::shared_ptr<AutoTexture> borrowTexture();

    // Enables or disables the pool. When the pool is disabled, no buffers will
    // be held by the pool. This is useful when the active display changes.
    void setEnabled(bool enable);

    void dump(std::string& out) const;

protected:
    // Proteted visibility so that they can be used for testing
    const static constexpr size_t kMinPoolSize = 3;
    const static constexpr size_t kMaxPoolSize = 4;

    struct Entry {
        std::shared_ptr<renderengine::ExternalTexture> texture;
        sp<Fence> fence;
    };

    std::deque<Entry> mPool;

private:
    std::shared_ptr<renderengine::ExternalTexture> genTexture();
    // Returns a previously borrowed texture to the pool.
    void returnTexture(std::shared_ptr<renderengine::ExternalTexture>&& texture,
                       const sp<Fence>& fence);
    void allocatePool();
    renderengine::RenderEngine& mRenderEngine;
    ui::Size mSize;
    bool mEnabled;
};

} // namespace android::compositionengine::impl::planner
