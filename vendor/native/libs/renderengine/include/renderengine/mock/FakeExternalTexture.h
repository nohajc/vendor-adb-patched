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

#include <renderengine/ExternalTexture.h>

namespace android {
namespace renderengine {
namespace mock {

class FakeExternalTexture : public renderengine::ExternalTexture {
    const sp<GraphicBuffer> mNullBuffer = nullptr;
    uint32_t mWidth;
    uint32_t mHeight;
    uint64_t mId;
    PixelFormat mPixelFormat;
    uint64_t mUsage;

public:
    FakeExternalTexture(uint32_t width, uint32_t height, uint64_t id, PixelFormat pixelFormat,
                        uint64_t usage)
          : mWidth(width), mHeight(height), mId(id), mPixelFormat(pixelFormat), mUsage(usage) {}
    const sp<GraphicBuffer>& getBuffer() const { return mNullBuffer; }
    bool hasSameBuffer(const renderengine::ExternalTexture& other) const override {
        return getId() == other.getId();
    }
    uint32_t getWidth() const override { return mWidth; }
    uint32_t getHeight() const override { return mHeight; }
    uint64_t getId() const override { return mId; }
    PixelFormat getPixelFormat() const override { return mPixelFormat; }
    uint64_t getUsage() const override { return mUsage; }
    ~FakeExternalTexture() = default;
};

} // namespace mock
} // namespace renderengine
} // namespace android
