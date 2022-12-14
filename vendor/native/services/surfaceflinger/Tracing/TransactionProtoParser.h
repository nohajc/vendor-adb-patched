/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <layerproto/TransactionProto.h>
#include <utils/RefBase.h>

#include "TransactionState.h"

namespace android::surfaceflinger {

struct TracingLayerCreationArgs {
    int32_t layerId;
    std::string name;
    uint32_t flags = 0;
    int32_t parentId = -1;
    int32_t mirrorFromId = -1;
};

struct TracingLayerState : layer_state_t {
    uint64_t bufferId;
    uint32_t bufferHeight;
    uint32_t bufferWidth;
    int32_t pixelFormat;
    uint64_t bufferUsage;
    bool hasSidebandStream;
    int32_t parentId;
    int32_t relativeParentId;
    int32_t inputCropId;
    TracingLayerCreationArgs args;
};

// Class which exposes buffer properties from BufferData without holding on to the actual buffer
// handle.
class BufferDataStub : public BufferData {
public:
    BufferDataStub(uint64_t bufferId, uint32_t width, uint32_t height, int32_t pixelFormat,
                   uint64_t outUsage)
          : mBufferId(bufferId),
            mWidth(width),
            mHeight(height),
            mPixelFormat(pixelFormat),
            mOutUsage(outUsage) {}
    bool hasBuffer() const override { return mBufferId != 0; }
    bool hasSameBuffer(const BufferData& other) const override {
        return getId() == other.getId() && frameNumber == other.frameNumber;
    }
    uint32_t getWidth() const override { return mWidth; }
    uint32_t getHeight() const override { return mHeight; }
    uint64_t getId() const override { return mBufferId; }
    PixelFormat getPixelFormat() const override { return mPixelFormat; }
    uint64_t getUsage() const override { return mOutUsage; }

private:
    uint64_t mBufferId;
    uint32_t mWidth;
    uint32_t mHeight;
    int32_t mPixelFormat;
    uint64_t mOutUsage;
};

class TransactionProtoParser {
public:
    // Utility class to map handles to ids and buffers to buffer properties without pulling
    // in SurfaceFlinger dependencies.
    class FlingerDataMapper {
    public:
        virtual ~FlingerDataMapper() = default;
        virtual sp<IBinder> getLayerHandle(int32_t /* layerId */) const { return nullptr; }
        virtual int64_t getLayerId(const sp<IBinder>& /* layerHandle */) const { return -1; }
        virtual int64_t getLayerId(BBinder* /* layerHandle */) const { return -1; }
        virtual sp<IBinder> getDisplayHandle(int32_t /* displayId */) const { return nullptr; }
        virtual int32_t getDisplayId(const sp<IBinder>& /* displayHandle */) const { return -1; }
        virtual std::shared_ptr<BufferData> getGraphicData(uint64_t bufferId, uint32_t width,
                                                           uint32_t height, int32_t pixelFormat,
                                                           uint64_t usage) const {
            return std::make_shared<BufferDataStub>(bufferId, width, height, pixelFormat, usage);
        }
        virtual void getGraphicBufferPropertiesFromCache(client_cache_t /* cachedBuffer */,
                                                         uint64_t* /* outBufferId */,
                                                         uint32_t* /* outWidth */,
                                                         uint32_t* /* outHeight */,
                                                         int32_t* /* outPixelFormat */,
                                                         uint64_t* /* outUsage */) const {}
    };

    TransactionProtoParser(std::unique_ptr<FlingerDataMapper> provider)
          : mMapper(std::move(provider)) {}

    proto::TransactionState toProto(const TransactionState&);
    proto::TransactionState toProto(const std::map<int32_t /* layerId */, TracingLayerState>&);
    proto::LayerCreationArgs toProto(const TracingLayerCreationArgs& args);

    TransactionState fromProto(const proto::TransactionState&);
    void mergeFromProto(const proto::LayerState&, TracingLayerState& outState);
    void fromProto(const proto::LayerCreationArgs&, TracingLayerCreationArgs& outArgs);
    std::unique_ptr<FlingerDataMapper> mMapper;

private:
    proto::LayerState toProto(const layer_state_t&);
    proto::DisplayState toProto(const DisplayState&);
    void fromProto(const proto::LayerState&, layer_state_t& out);
    DisplayState fromProto(const proto::DisplayState&);

};

} // namespace android::surfaceflinger
