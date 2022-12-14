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

#include <android-base/macros.h>
#include <ui/GraphicBuffer.h>

namespace android::renderengine {

class RenderEngine;

/**
 * Manages GPU image resources on behalf of clients using RenderEngine.
 *
 * Clients of RenderEngine are required to wrap their GraphicBuffer objects as an ExternalTexture,
 * which is then mapped into GPU resources required by RenderEngine. When a client no longer needs
 * to use the GraphicBuffer as input into RenderEngine::drawLayers, then the client should delete
 * their ExternalTexture so that resources may be freed.
 */
class ExternalTexture {
public:
    ExternalTexture() = default;
    virtual ~ExternalTexture() = default;

    virtual bool hasSameBuffer(const ExternalTexture& other) const = 0;
    virtual uint32_t getWidth() const = 0;
    virtual uint32_t getHeight() const = 0;
    virtual uint64_t getId() const = 0;
    virtual PixelFormat getPixelFormat() const = 0;
    virtual uint64_t getUsage() const = 0;

    // Retrieves the buffer that is bound to this texture.
    virtual const sp<GraphicBuffer>& getBuffer() const = 0;

    Rect getBounds() const {
        return {0, 0, static_cast<int32_t>(getWidth()), static_cast<int32_t>(getHeight())};
    }
    DISALLOW_COPY_AND_ASSIGN(ExternalTexture);
};

} // namespace android::renderengine
