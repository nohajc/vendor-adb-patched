/*
 * Copyright 2019 The Android Open Source Project
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

#ifndef ANDROID_UI_GRALLOC4_H
#define ANDROID_UI_GRALLOC4_H

#include <android/hardware/graphics/allocator/4.0/IAllocator.h>
#include <android/hardware/graphics/common/1.1/types.h>
#include <android/hardware/graphics/mapper/4.0/IMapper.h>
#include <gralloctypes/Gralloc4.h>
#include <ui/Gralloc.h>
#include <ui/GraphicTypes.h>
#include <ui/Rect.h>
#include <utils/StrongPointer.h>

#include <string>

namespace android {

class Gralloc4Mapper : public GrallocMapper {
public:
    static void preload();

    Gralloc4Mapper();

    bool isLoaded() const override;

    std::string dumpBuffer(buffer_handle_t bufferHandle, bool less = true) const override;
    std::string dumpBuffers(bool less = true) const;

    status_t createDescriptor(void* bufferDescriptorInfo, void* outBufferDescriptor) const override;

    status_t importBuffer(const hardware::hidl_handle& rawHandle,
                          buffer_handle_t* outBufferHandle) const override;

    void freeBuffer(buffer_handle_t bufferHandle) const override;

    status_t validateBufferSize(buffer_handle_t bufferHandle, uint32_t width, uint32_t height,
                                PixelFormat format, uint32_t layerCount, uint64_t usage,
                                uint32_t stride) const override;

    void getTransportSize(buffer_handle_t bufferHandle, uint32_t* outNumFds,
                          uint32_t* outNumInts) const override;

    status_t lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect& bounds,
                  int acquireFence, void** outData, int32_t* outBytesPerPixel,
                  int32_t* outBytesPerStride) const override;

    status_t lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect& bounds,
                  int acquireFence, android_ycbcr* ycbcr) const override;

    int unlock(buffer_handle_t bufferHandle) const override;

    status_t isSupported(uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount,
                         uint64_t usage, bool* outSupported) const override;

    status_t getBufferId(buffer_handle_t bufferHandle, uint64_t* outBufferId) const override;
    status_t getName(buffer_handle_t bufferHandle, std::string* outName) const override;
    status_t getWidth(buffer_handle_t bufferHandle, uint64_t* outWidth) const override;
    status_t getHeight(buffer_handle_t bufferHandle, uint64_t* outHeight) const override;
    status_t getLayerCount(buffer_handle_t bufferHandle, uint64_t* outLayerCount) const override;
    status_t getPixelFormatRequested(buffer_handle_t bufferHandle,
                                     ui::PixelFormat* outPixelFormatRequested) const override;
    status_t getPixelFormatFourCC(buffer_handle_t bufferHandle,
                                  uint32_t* outPixelFormatFourCC) const override;
    status_t getPixelFormatModifier(buffer_handle_t bufferHandle,
                                    uint64_t* outPixelFormatModifier) const override;
    status_t getUsage(buffer_handle_t bufferHandle, uint64_t* outUsage) const override;
    status_t getAllocationSize(buffer_handle_t bufferHandle,
                               uint64_t* outAllocationSize) const override;
    status_t getProtectedContent(buffer_handle_t bufferHandle,
                                 uint64_t* outProtectedContent) const override;
    status_t getCompression(buffer_handle_t bufferHandle,
                            aidl::android::hardware::graphics::common::ExtendableType*
                                    outCompression) const override;
    status_t getCompression(buffer_handle_t bufferHandle,
                            ui::Compression* outCompression) const override;
    status_t getInterlaced(buffer_handle_t bufferHandle,
                           aidl::android::hardware::graphics::common::ExtendableType* outInterlaced)
            const override;
    status_t getInterlaced(buffer_handle_t bufferHandle,
                           ui::Interlaced* outInterlaced) const override;
    status_t getChromaSiting(buffer_handle_t bufferHandle,
                             aidl::android::hardware::graphics::common::ExtendableType*
                                     outChromaSiting) const override;
    status_t getChromaSiting(buffer_handle_t bufferHandle,
                             ui::ChromaSiting* outChromaSiting) const override;
    status_t getPlaneLayouts(buffer_handle_t bufferHandle,
                             std::vector<ui::PlaneLayout>* outPlaneLayouts) const override;
    status_t getDataspace(buffer_handle_t bufferHandle, ui::Dataspace* outDataspace) const override;
    status_t getBlendMode(buffer_handle_t bufferHandle, ui::BlendMode* outBlendMode) const override;
    status_t getSmpte2086(buffer_handle_t bufferHandle,
                          std::optional<ui::Smpte2086>* outSmpte2086) const override;
    status_t getCta861_3(buffer_handle_t bufferHandle,
                         std::optional<ui::Cta861_3>* outCta861_3) const override;
    status_t getSmpte2094_40(buffer_handle_t bufferHandle,
                             std::optional<std::vector<uint8_t>>* outSmpte2094_40) const override;

    status_t getDefaultPixelFormatFourCC(uint32_t width, uint32_t height, PixelFormat format,
                                         uint32_t layerCount, uint64_t usage,
                                         uint32_t* outPixelFormatFourCC) const override;
    status_t getDefaultPixelFormatModifier(uint32_t width, uint32_t height, PixelFormat format,
                                           uint32_t layerCount, uint64_t usage,
                                           uint64_t* outPixelFormatModifier) const override;
    status_t getDefaultAllocationSize(uint32_t width, uint32_t height, PixelFormat format,
                                      uint32_t layerCount, uint64_t usage,
                                      uint64_t* outAllocationSize) const override;
    status_t getDefaultProtectedContent(uint32_t width, uint32_t height, PixelFormat format,
                                        uint32_t layerCount, uint64_t usage,
                                        uint64_t* outProtectedContent) const override;
    status_t getDefaultCompression(uint32_t width, uint32_t height, PixelFormat format,
                                   uint32_t layerCount, uint64_t usage,
                                   aidl::android::hardware::graphics::common::ExtendableType*
                                           outCompression) const override;
    status_t getDefaultCompression(uint32_t width, uint32_t height, PixelFormat format,
                                   uint32_t layerCount, uint64_t usage,
                                   ui::Compression* outCompression) const override;
    status_t getDefaultInterlaced(uint32_t width, uint32_t height, PixelFormat format,
                                  uint32_t layerCount, uint64_t usage,
                                  aidl::android::hardware::graphics::common::ExtendableType*
                                          outInterlaced) const override;
    status_t getDefaultInterlaced(uint32_t width, uint32_t height, PixelFormat format,
                                  uint32_t layerCount, uint64_t usage,
                                  ui::Interlaced* outInterlaced) const override;
    status_t getDefaultChromaSiting(uint32_t width, uint32_t height, PixelFormat format,
                                    uint32_t layerCount, uint64_t usage,
                                    aidl::android::hardware::graphics::common::ExtendableType*
                                            outChromaSiting) const override;
    status_t getDefaultChromaSiting(uint32_t width, uint32_t height, PixelFormat format,
                                    uint32_t layerCount, uint64_t usage,
                                    ui::ChromaSiting* outChromaSiting) const override;
    status_t getDefaultPlaneLayouts(uint32_t width, uint32_t height, PixelFormat format,
                                    uint32_t layerCount, uint64_t usage,
                                    std::vector<ui::PlaneLayout>* outPlaneLayouts) const override;

    std::vector<android::hardware::graphics::mapper::V4_0::IMapper::MetadataTypeDescription>
    listSupportedMetadataTypes() const;

private:
    friend class GraphicBufferAllocator;

    // Determines whether the passed info is compatible with the mapper.
    status_t validateBufferDescriptorInfo(
            hardware::graphics::mapper::V4_0::IMapper::BufferDescriptorInfo* descriptorInfo) const;

    template <class T>
    using DecodeFunction = status_t (*)(const hardware::hidl_vec<uint8_t>& input, T* output);

    template <class T>
    status_t get(
            buffer_handle_t bufferHandle,
            const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
            DecodeFunction<T> decodeFunction, T* outMetadata) const;

    template <class T>
    status_t getDefault(
            uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount,
            uint64_t usage,
            const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
            DecodeFunction<T> decodeFunction, T* outMetadata) const;

    template <class T>
    status_t metadataDumpHelper(
            const android::hardware::graphics::mapper::V4_0::IMapper::BufferDump& bufferDump,
            aidl::android::hardware::graphics::common::StandardMetadataType metadataType,
            DecodeFunction<T> decodeFunction, T* outT) const;
    status_t bufferDumpHelper(
            const android::hardware::graphics::mapper::V4_0::IMapper::BufferDump& bufferDump,
            std::ostringstream* outDump, uint64_t* outAllocationSize, bool less) const;

    sp<hardware::graphics::mapper::V4_0::IMapper> mMapper;
};

class Gralloc4Allocator : public GrallocAllocator {
public:
    // An allocator relies on a mapper, and that mapper must be alive at all
    // time.
    Gralloc4Allocator(const Gralloc4Mapper& mapper);

    bool isLoaded() const override;

    std::string dumpDebugInfo(bool less = true) const override;

    status_t allocate(std::string requestorName, uint32_t width, uint32_t height,
                      PixelFormat format, uint32_t layerCount, uint64_t usage, uint32_t bufferCount,
                      uint32_t* outStride, buffer_handle_t* outBufferHandles,
                      bool importBuffers = true) const override;

private:
    const Gralloc4Mapper& mMapper;
    sp<hardware::graphics::allocator::V4_0::IAllocator> mAllocator;
};

} // namespace android

#endif // ANDROID_UI_GRALLOC4_H
