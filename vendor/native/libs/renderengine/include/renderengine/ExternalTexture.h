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
    ExternalTexture(const sp<GraphicBuffer>& buffer, RenderEngine& renderEngine, uint32_t usage);

    ~ExternalTexture();

    // Retrieves the buffer that is bound to this texture.
    const sp<GraphicBuffer>& getBuffer() const { return mBuffer; }

private:
    sp<GraphicBuffer> mBuffer;
    RenderEngine& mRenderEngine;
    DISALLOW_COPY_AND_ASSIGN(ExternalTexture);
};

} // namespace android::renderengine
