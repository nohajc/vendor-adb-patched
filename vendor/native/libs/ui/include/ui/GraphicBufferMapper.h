/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef ANDROID_UI_BUFFER_MAPPER_H
#define ANDROID_UI_BUFFER_MAPPER_H

#include <stdint.h>
#include <sys/types.h>

#include <memory>

#include <ui/GraphicTypes.h>
#include <ui/PixelFormat.h>
#include <ui/Rect.h>
#include <utils/Singleton.h>

// Needed by code that still uses the GRALLOC_USAGE_* constants.
// when/if we get rid of gralloc, we should provide aliases or fix call sites.
#include <hardware/gralloc.h>


namespace android {

// ---------------------------------------------------------------------------

class GrallocMapper;

class GraphicBufferMapper : public Singleton<GraphicBufferMapper>
{
public:
    enum Version {
        GRALLOC_2,
        GRALLOC_3,
        GRALLOC_4,
    };
    static void preloadHal();
    static inline GraphicBufferMapper& get() { return getInstance(); }

    void dumpBuffer(buffer_handle_t bufferHandle, std::string& result, bool less = true) const;
    static void dumpBufferToSystemLog(buffer_handle_t bufferHandle, bool less = true);

    // The imported outHandle must be freed with freeBuffer when no longer
    // needed. rawHandle is owned by the caller.
    status_t importBuffer(buffer_handle_t rawHandle,
            uint32_t width, uint32_t height, uint32_t layerCount,
            PixelFormat format, uint64_t usage, uint32_t stride,
            buffer_handle_t* outHandle);

    status_t freeBuffer(buffer_handle_t handle);

    void getTransportSize(buffer_handle_t handle,
            uint32_t* outTransportNumFds, uint32_t* outTransportNumInts);

    status_t lock(buffer_handle_t handle, uint32_t usage, const Rect& bounds, void** vaddr,
                  int32_t* outBytesPerPixel = nullptr, int32_t* outBytesPerStride = nullptr);

    status_t lockYCbCr(buffer_handle_t handle,
            uint32_t usage, const Rect& bounds, android_ycbcr *ycbcr);

    status_t unlock(buffer_handle_t handle);

    status_t lockAsync(buffer_handle_t handle, uint32_t usage, const Rect& bounds, void** vaddr,
                       int fenceFd, int32_t* outBytesPerPixel = nullptr,
                       int32_t* outBytesPerStride = nullptr);

    status_t lockAsync(buffer_handle_t handle, uint64_t producerUsage, uint64_t consumerUsage,
                       const Rect& bounds, void** vaddr, int fenceFd,
                       int32_t* outBytesPerPixel = nullptr, int32_t* outBytesPerStride = nullptr);

    status_t lockAsyncYCbCr(buffer_handle_t handle,
            uint32_t usage, const Rect& bounds, android_ycbcr *ycbcr,
            int fenceFd);

    status_t unlockAsync(buffer_handle_t handle, int *fenceFd);

    status_t isSupported(uint32_t width, uint32_t height, android::PixelFormat format,
                         uint32_t layerCount, uint64_t usage, bool* outSupported);

    /**
     * Gets the gralloc metadata associated with the buffer.
     *
     * These functions are supported by gralloc 4.0+.
     */
    status_t getBufferId(buffer_handle_t bufferHandle, uint64_t* outBufferId);
    status_t getName(buffer_handle_t bufferHandle, std::string* outName);
    status_t getWidth(buffer_handle_t bufferHandle, uint64_t* outWidth);
    status_t getHeight(buffer_handle_t bufferHandle, uint64_t* outHeight);
    status_t getLayerCount(buffer_handle_t bufferHandle, uint64_t* outLayerCount);
    status_t getPixelFormatRequested(buffer_handle_t bufferHandle,
                                     ui::PixelFormat* outPixelFormatRequested);
    status_t getPixelFormatFourCC(buffer_handle_t bufferHandle, uint32_t* outPixelFormatFourCC);
    status_t getPixelFormatModifier(buffer_handle_t bufferHandle, uint64_t* outPixelFormatModifier);
    status_t getUsage(buffer_handle_t bufferHandle, uint64_t* outUsage);
    status_t getAllocationSize(buffer_handle_t bufferHandle, uint64_t* outAllocationSize);
    status_t getProtectedContent(buffer_handle_t bufferHandle, uint64_t* outProtectedContent);
    status_t getCompression(
            buffer_handle_t bufferHandle,
            aidl::android::hardware::graphics::common::ExtendableType* outCompression);
    status_t getCompression(buffer_handle_t bufferHandle, ui::Compression* outCompression);
    status_t getInterlaced(
            buffer_handle_t bufferHandle,
            aidl::android::hardware::graphics::common::ExtendableType* outInterlaced);
    status_t getInterlaced(buffer_handle_t bufferHandle, ui::Interlaced* outInterlaced);
    status_t getChromaSiting(
            buffer_handle_t bufferHandle,
            aidl::android::hardware::graphics::common::ExtendableType* outChromaSiting);
    status_t getChromaSiting(buffer_handle_t bufferHandle, ui::ChromaSiting* outChromaSiting);
    status_t getPlaneLayouts(buffer_handle_t bufferHandle,
                             std::vector<ui::PlaneLayout>* outPlaneLayouts);
    status_t getDataspace(buffer_handle_t bufferHandle, ui::Dataspace* outDataspace);
    status_t getBlendMode(buffer_handle_t bufferHandle, ui::BlendMode* outBlendMode);
    status_t getSmpte2086(buffer_handle_t bufferHandle, std::optional<ui::Smpte2086>* outSmpte2086);
    status_t getCta861_3(buffer_handle_t bufferHandle, std::optional<ui::Cta861_3>* outCta861_3);
    status_t getSmpte2094_40(buffer_handle_t bufferHandle,
                             std::optional<std::vector<uint8_t>>* outSmpte2094_40);

    /**
     * Gets the default metadata for a gralloc buffer allocated with the given parameters.
     *
     * These functions are supported by gralloc 4.0+.
     */
    status_t getDefaultPixelFormatFourCC(uint32_t width, uint32_t height, PixelFormat format,
                                         uint32_t layerCount, uint64_t usage,
                                         uint32_t* outPixelFormatFourCC);
    status_t getDefaultPixelFormatModifier(uint32_t width, uint32_t height, PixelFormat format,
                                           uint32_t layerCount, uint64_t usage,
                                           uint64_t* outPixelFormatModifier);
    status_t getDefaultAllocationSize(uint32_t width, uint32_t height, PixelFormat format,
                                      uint32_t layerCount, uint64_t usage,
                                      uint64_t* outAllocationSize);
    status_t getDefaultProtectedContent(uint32_t width, uint32_t height, PixelFormat format,
                                        uint32_t layerCount, uint64_t usage,
                                        uint64_t* outProtectedContent);
    status_t getDefaultCompression(
            uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount,
            uint64_t usage,
            aidl::android::hardware::graphics::common::ExtendableType* outCompression);
    status_t getDefaultCompression(uint32_t width, uint32_t height, PixelFormat format,
                                   uint32_t layerCount, uint64_t usage,
                                   ui::Compression* outCompression);
    status_t getDefaultInterlaced(
            uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount,
            uint64_t usage,
            aidl::android::hardware::graphics::common::ExtendableType* outInterlaced);
    status_t getDefaultInterlaced(uint32_t width, uint32_t height, PixelFormat format,
                                  uint32_t layerCount, uint64_t usage,
                                  ui::Interlaced* outInterlaced);
    status_t getDefaultChromaSiting(
            uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount,
            uint64_t usage,
            aidl::android::hardware::graphics::common::ExtendableType* outChromaSiting);
    status_t getDefaultChromaSiting(uint32_t width, uint32_t height, PixelFormat format,
                                    uint32_t layerCount, uint64_t usage,
                                    ui::ChromaSiting* outChromaSiting);
    status_t getDefaultPlaneLayouts(uint32_t width, uint32_t height, PixelFormat format,
                                    uint32_t layerCount, uint64_t usage,
                                    std::vector<ui::PlaneLayout>* outPlaneLayouts);

    const GrallocMapper& getGrallocMapper() const {
        return reinterpret_cast<const GrallocMapper&>(*mMapper);
    }

    Version getMapperVersion() const { return mMapperVersion; }

private:
    friend class Singleton<GraphicBufferMapper>;

    GraphicBufferMapper();

    std::unique_ptr<const GrallocMapper> mMapper;

    Version mMapperVersion;
};

// ---------------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_UI_BUFFER_MAPPER_H

