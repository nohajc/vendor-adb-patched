/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_UI_GRALLOC_H
#define ANDROID_UI_GRALLOC_H

#include <gralloctypes/Gralloc4.h>
#include <hidl/HidlSupport.h>
#include <ui/GraphicTypes.h>
#include <ui/PixelFormat.h>
#include <ui/Rect.h>
#include <utils/StrongPointer.h>

#include <string>

namespace android {

// A wrapper to IMapper
class GrallocMapper {
public:
    virtual ~GrallocMapper();

    virtual bool isLoaded() const = 0;

    virtual std::string dumpBuffer(buffer_handle_t /*bufferHandle*/, bool /*less*/) const {
        return "";
    }

    virtual status_t createDescriptor(void* bufferDescriptorInfo,
                                      void* outBufferDescriptor) const = 0;

    // Import a buffer that is from another HAL, another process, or is
    // cloned.
    //
    // The returned handle must be freed with freeBuffer.
    virtual status_t importBuffer(const hardware::hidl_handle& rawHandle,
                                  buffer_handle_t* outBufferHandle) const = 0;

    virtual void freeBuffer(buffer_handle_t bufferHandle) const = 0;

    virtual status_t validateBufferSize(buffer_handle_t bufferHandle, uint32_t width,
                                        uint32_t height, android::PixelFormat format,
                                        uint32_t layerCount, uint64_t usage,
                                        uint32_t stride) const = 0;

    virtual void getTransportSize(buffer_handle_t bufferHandle, uint32_t* outNumFds,
                                  uint32_t* outNumInts) const = 0;

    // The ownership of acquireFence is always transferred to the callee, even
    // on errors.
    virtual status_t lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect& bounds,
                          int acquireFence, void** outData, int32_t* outBytesPerPixel,
                          int32_t* outBytesPerStride) const = 0;

    // The ownership of acquireFence is always transferred to the callee, even
    // on errors.
    virtual status_t lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect& bounds,
                          int acquireFence, android_ycbcr* ycbcr) const = 0;

    // unlock returns a fence sync object (or -1) and the fence sync object is
    // owned by the caller
    virtual int unlock(buffer_handle_t bufferHandle) const = 0;

    // isSupported queries whether or not a buffer with the given width, height,
    // format, layer count, and usage can be allocated on the device.  If
    // *outSupported is set to true, a buffer with the given specifications may be successfully
    // allocated if resources are available.  If false, a buffer with the given specifications will
    // never successfully allocate on this device. Note that this function is not guaranteed to be
    // supported on all devices, in which case a status_t of INVALID_OPERATION will be returned.
    virtual status_t isSupported(uint32_t /*width*/, uint32_t /*height*/,
                                 android::PixelFormat /*format*/, uint32_t /*layerCount*/,
                                 uint64_t /*usage*/, bool* /*outSupported*/) const {
        return INVALID_OPERATION;
    }

    virtual status_t getBufferId(buffer_handle_t /*bufferHandle*/,
                                 uint64_t* /*outBufferId*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getName(buffer_handle_t /*bufferHandle*/, std::string* /*outName*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getWidth(buffer_handle_t /*bufferHandle*/, uint64_t* /*outWidth*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getHeight(buffer_handle_t /*bufferHandle*/, uint64_t* /*outHeight*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getLayerCount(buffer_handle_t /*bufferHandle*/,
                                   uint64_t* /*outLayerCount*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getPixelFormatRequested(buffer_handle_t /*bufferHandle*/,
                                             ui::PixelFormat* /*outPixelFormatRequested*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getPixelFormatFourCC(buffer_handle_t /*bufferHandle*/,
                                          uint32_t* /*outPixelFormatFourCC*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getPixelFormatModifier(buffer_handle_t /*bufferHandle*/,
                                            uint64_t* /*outPixelFormatModifier*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getUsage(buffer_handle_t /*bufferHandle*/, uint64_t* /*outUsage*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getAllocationSize(buffer_handle_t /*bufferHandle*/,
                                       uint64_t* /*outAllocationSize*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getProtectedContent(buffer_handle_t /*bufferHandle*/,
                                         uint64_t* /*outProtectedContent*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getCompression(
            buffer_handle_t /*bufferHandle*/,
            aidl::android::hardware::graphics::common::ExtendableType* /*outCompression*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getCompression(buffer_handle_t /*bufferHandle*/,
                                    ui::Compression* /*outCompression*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getInterlaced(
            buffer_handle_t /*bufferHandle*/,
            aidl::android::hardware::graphics::common::ExtendableType* /*outInterlaced*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getInterlaced(buffer_handle_t /*bufferHandle*/,
                                   ui::Interlaced* /*outInterlaced*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getChromaSiting(
            buffer_handle_t /*bufferHandle*/,
            aidl::android::hardware::graphics::common::ExtendableType* /*outChromaSiting*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getChromaSiting(buffer_handle_t /*bufferHandle*/,
                                     ui::ChromaSiting* /*outChromaSiting*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getPlaneLayouts(buffer_handle_t /*bufferHandle*/,
                                     std::vector<ui::PlaneLayout>* /*outPlaneLayouts*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDataspace(buffer_handle_t /*bufferHandle*/,
                                  ui::Dataspace* /*outDataspace*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getBlendMode(buffer_handle_t /*bufferHandle*/,
                                  ui::BlendMode* /*outBlendMode*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getSmpte2086(buffer_handle_t /*bufferHandle*/,
                                  std::optional<ui::Smpte2086>* /*outSmpte2086*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getCta861_3(buffer_handle_t /*bufferHandle*/,
                                 std::optional<ui::Cta861_3>* /*outCta861_3*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getSmpte2094_40(
            buffer_handle_t /*bufferHandle*/,
            std::optional<std::vector<uint8_t>>* /*outSmpte2094_40*/) const {
        return INVALID_OPERATION;
    }

    virtual status_t getDefaultPixelFormatFourCC(uint32_t /*width*/, uint32_t /*height*/,
                                                 PixelFormat /*format*/, uint32_t /*layerCount*/,
                                                 uint64_t /*usage*/,
                                                 uint32_t* /*outPixelFormatFourCC*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultPixelFormatModifier(uint32_t /*width*/, uint32_t /*height*/,
                                                   PixelFormat /*format*/, uint32_t /*layerCount*/,
                                                   uint64_t /*usage*/,
                                                   uint64_t* /*outPixelFormatModifier*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultAllocationSize(uint32_t /*width*/, uint32_t /*height*/,
                                              PixelFormat /*format*/, uint32_t /*layerCount*/,
                                              uint64_t /*usage*/,
                                              uint64_t* /*outAllocationSize*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultProtectedContent(uint32_t /*width*/, uint32_t /*height*/,
                                                PixelFormat /*format*/, uint32_t /*layerCount*/,
                                                uint64_t /*usage*/,
                                                uint64_t* /*outProtectedContent*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultCompression(
            uint32_t /*width*/, uint32_t /*height*/, PixelFormat /*format*/,
            uint32_t /*layerCount*/, uint64_t /*usage*/,
            aidl::android::hardware::graphics::common::ExtendableType* /*outCompression*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultCompression(uint32_t /*width*/, uint32_t /*height*/,
                                           PixelFormat /*format*/, uint32_t /*layerCount*/,
                                           uint64_t /*usage*/,
                                           ui::Compression* /*outCompression*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultInterlaced(
            uint32_t /*width*/, uint32_t /*height*/, PixelFormat /*format*/,
            uint32_t /*layerCount*/, uint64_t /*usage*/,
            aidl::android::hardware::graphics::common::ExtendableType* /*outInterlaced*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultInterlaced(uint32_t /*width*/, uint32_t /*height*/,
                                          PixelFormat /*format*/, uint32_t /*layerCount*/,
                                          uint64_t /*usage*/,
                                          ui::Interlaced* /*outInterlaced*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultChromaSiting(
            uint32_t /*width*/, uint32_t /*height*/, PixelFormat /*format*/,
            uint32_t /*layerCount*/, uint64_t /*usage*/,
            aidl::android::hardware::graphics::common::ExtendableType* /*outChromaSiting*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultChromaSiting(uint32_t /*width*/, uint32_t /*height*/,
                                            PixelFormat /*format*/, uint32_t /*layerCount*/,
                                            uint64_t /*usage*/,
                                            ui::ChromaSiting* /*outChromaSiting*/) const {
        return INVALID_OPERATION;
    }
    virtual status_t getDefaultPlaneLayouts(
            uint32_t /*width*/, uint32_t /*height*/, PixelFormat /*format*/,
            uint32_t /*layerCount*/, uint64_t /*usage*/,
            std::vector<ui::PlaneLayout>* /*outPlaneLayouts*/) const {
        return INVALID_OPERATION;
    }

    virtual std::vector<android::hardware::graphics::mapper::V4_0::IMapper::MetadataTypeDescription>
    listSupportedMetadataTypes() const {
        return {};
    }
};

// A wrapper to IAllocator
class GrallocAllocator {
public:
    virtual ~GrallocAllocator();

    virtual bool isLoaded() const = 0;

    virtual std::string dumpDebugInfo(bool less = true) const = 0;

    /*
     * The returned buffers are already imported and must not be imported
     * again.  outBufferHandles must point to a space that can contain at
     * least "bufferCount" buffer_handle_t.
     */
    virtual status_t allocate(std::string requestorName, uint32_t width, uint32_t height,
                              PixelFormat format, uint32_t layerCount, uint64_t usage,
                              uint32_t bufferCount, uint32_t* outStride,
                              buffer_handle_t* outBufferHandles,
                              bool importBuffers = true) const = 0;
};

} // namespace android

#endif // ANDROID_UI_GRALLOC_H
