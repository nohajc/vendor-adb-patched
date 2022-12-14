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

// #define LOG_NDEBUG 0

#undef LOG_TAG
#define LOG_TAG "Planner"

#include <compositionengine/impl/planner/TexturePool.h>
#include <renderengine/impl/ExternalTexture.h>
#include <utils/Log.h>

namespace android::compositionengine::impl::planner {

void TexturePool::allocatePool() {
    mPool.clear();
    if (mEnabled && mSize.isValid()) {
        mPool.resize(kMinPoolSize);
        std::generate_n(mPool.begin(), kMinPoolSize, [&]() {
            return Entry{genTexture(), nullptr};
        });
    }
}

void TexturePool::setDisplaySize(ui::Size size) {
    if (mSize == size) {
        return;
    }
    mSize = size;
    allocatePool();
}

std::shared_ptr<TexturePool::AutoTexture> TexturePool::borrowTexture() {
    if (mPool.empty()) {
        return std::make_shared<AutoTexture>(*this, genTexture(), nullptr);
    }

    const auto entry = mPool.front();
    mPool.pop_front();
    return std::make_shared<AutoTexture>(*this, entry.texture, entry.fence);
}

void TexturePool::returnTexture(std::shared_ptr<renderengine::ExternalTexture>&& texture,
                                const sp<Fence>& fence) {
    // Drop the texture on the floor if the pool is not enabled
    if (!mEnabled) {
        return;
    }

    // Or the texture on the floor if the pool is no longer tracking textures of the same size.
    if (static_cast<int32_t>(texture->getBuffer()->getWidth()) != mSize.getWidth() ||
        static_cast<int32_t>(texture->getBuffer()->getHeight()) != mSize.getHeight()) {
        ALOGV("Deallocating texture from Planner's pool - display size changed (previous: (%dx%d), "
              "current: (%dx%d))",
              texture->getBuffer()->getWidth(), texture->getBuffer()->getHeight(), mSize.getWidth(),
              mSize.getHeight());
        return;
    }

    // Also ensure the pool does not grow beyond a maximum size.
    if (mPool.size() == kMaxPoolSize) {
        ALOGD("Deallocating texture from Planner's pool - max size [%" PRIu64 "] reached",
              static_cast<uint64_t>(kMaxPoolSize));
        return;
    }

    mPool.push_back({std::move(texture), fence});
}

std::shared_ptr<renderengine::ExternalTexture> TexturePool::genTexture() {
    LOG_ALWAYS_FATAL_IF(!mSize.isValid(), "Attempted to generate texture with invalid size");
    return std::make_shared<
            renderengine::impl::
                    ExternalTexture>(sp<GraphicBuffer>::
                                             make(static_cast<uint32_t>(mSize.getWidth()),
                                                  static_cast<uint32_t>(mSize.getHeight()),
                                                  HAL_PIXEL_FORMAT_RGBA_8888, 1U,
                                                  static_cast<uint64_t>(
                                                          GraphicBuffer::USAGE_HW_RENDER |
                                                          GraphicBuffer::USAGE_HW_COMPOSER |
                                                          GraphicBuffer::USAGE_HW_TEXTURE),
                                                  "Planner"),
                                     mRenderEngine,
                                     renderengine::impl::ExternalTexture::Usage::READABLE |
                                             renderengine::impl::ExternalTexture::Usage::WRITEABLE);
}

void TexturePool::setEnabled(bool enabled) {
    mEnabled = enabled;
    allocatePool();
}

void TexturePool::dump(std::string& out) const {
    base::StringAppendF(&out,
                        "TexturePool (%s) has %zu buffers of size [%" PRId32 ", %" PRId32 "]\n",
                        mEnabled ? "enabled" : "disabled", mPool.size(), mSize.width, mSize.height);
}

} // namespace android::compositionengine::impl::planner