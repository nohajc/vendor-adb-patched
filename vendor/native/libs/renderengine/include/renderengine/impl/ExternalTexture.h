/*
 * Copyright 2022 The Android Open Source Project
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

#include <android-base/macros.h>
#include <renderengine/ExternalTexture.h>
#include <ui/GraphicBuffer.h>

namespace android::renderengine::impl {

class RenderEngine;

class ExternalTexture : public android::renderengine::ExternalTexture {
public:
    // Usage specifies the rendering intent for the buffer.
    enum Usage : uint32_t {
        // When a buffer is not READABLE but is WRITEABLE, then GLESRenderEngine will use that as a
        // hint to load the buffer into a separate cache
        READABLE = 1 << 0,

        // The buffer needs to be mapped as a 2D texture if set, otherwise must be mapped as an
        // external texture
        WRITEABLE = 1 << 1,
    };

    // Creates an ExternalTexture for the provided buffer and RenderEngine instance, with the given
    // usage hint of type Usage.
    ExternalTexture(const sp<GraphicBuffer>& buffer,
                    android::renderengine::RenderEngine& renderEngine, uint32_t usage);
    ~ExternalTexture();
    const sp<GraphicBuffer>& getBuffer() const override { return mBuffer; };
    uint32_t getWidth() const override { return getBuffer()->getWidth(); }
    uint32_t getHeight() const override { return getBuffer()->getHeight(); }
    uint64_t getId() const override { return getBuffer()->getId(); }
    PixelFormat getPixelFormat() const override { return getBuffer()->getPixelFormat(); }
    uint64_t getUsage() const override { return getBuffer()->getUsage(); }
    bool hasSameBuffer(const renderengine::ExternalTexture& other) const override {
        return getBuffer() == other.getBuffer();
    }

private:
    sp<GraphicBuffer> mBuffer;
    android::renderengine::RenderEngine& mRenderEngine;
};

} // namespace android::renderengine::impl
