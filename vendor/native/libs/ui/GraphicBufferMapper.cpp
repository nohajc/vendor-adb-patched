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

#define LOG_TAG "GraphicBufferMapper"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0

#include <ui/GraphicBufferMapper.h>

#include <grallocusage/GrallocUsageConversion.h>

// We would eliminate the non-conforming zero-length array, but we can't since
// this is effectively included from the Linux kernel
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#include <sync/sync.h>
#pragma clang diagnostic pop

#include <utils/Log.h>
#include <utils/Trace.h>

#include <ui/Gralloc.h>
#include <ui/Gralloc2.h>
#include <ui/Gralloc3.h>
#include <ui/Gralloc4.h>
#include <ui/GraphicBuffer.h>

#include <system/graphics.h>

namespace android {
// ---------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE( GraphicBufferMapper )

void GraphicBufferMapper::preloadHal() {
    Gralloc2Mapper::preload();
    Gralloc3Mapper::preload();
    Gralloc4Mapper::preload();
}

GraphicBufferMapper::GraphicBufferMapper() {
    mMapper = std::make_unique<const Gralloc4Mapper>();
    if (mMapper->isLoaded()) {
        mMapperVersion = Version::GRALLOC_4;
        return;
    }
    mMapper = std::make_unique<const Gralloc3Mapper>();
    if (mMapper->isLoaded()) {
        mMapperVersion = Version::GRALLOC_3;
        return;
    }
    mMapper = std::make_unique<const Gralloc2Mapper>();
    if (mMapper->isLoaded()) {
        mMapperVersion = Version::GRALLOC_2;
        return;
    }

    LOG_ALWAYS_FATAL("gralloc-mapper is missing");
}

void GraphicBufferMapper::dumpBuffer(buffer_handle_t bufferHandle, std::string& result,
                                     bool less) const {
    result.append(mMapper->dumpBuffer(bufferHandle, less));
}

void GraphicBufferMapper::dumpBufferToSystemLog(buffer_handle_t bufferHandle, bool less) {
    std::string s;
    GraphicBufferMapper::getInstance().dumpBuffer(bufferHandle, s, less);
    ALOGD("%s", s.c_str());
}

status_t GraphicBufferMapper::importBuffer(buffer_handle_t rawHandle,
        uint32_t width, uint32_t height, uint32_t layerCount,
        PixelFormat format, uint64_t usage, uint32_t stride,
        buffer_handle_t* outHandle)
{
    ATRACE_CALL();

    buffer_handle_t bufferHandle;
    status_t error = mMapper->importBuffer(hardware::hidl_handle(rawHandle), &bufferHandle);
    if (error != NO_ERROR) {
        ALOGW("importBuffer(%p) failed: %d", rawHandle, error);
        return error;
    }

    error = mMapper->validateBufferSize(bufferHandle, width, height, format, layerCount, usage,
                                        stride);
    if (error != NO_ERROR) {
        ALOGE("validateBufferSize(%p) failed: %d", rawHandle, error);
        freeBuffer(bufferHandle);
        return static_cast<status_t>(error);
    }

    *outHandle = bufferHandle;

    return NO_ERROR;
}

void GraphicBufferMapper::getTransportSize(buffer_handle_t handle,
            uint32_t* outTransportNumFds, uint32_t* outTransportNumInts)
{
    mMapper->getTransportSize(handle, outTransportNumFds, outTransportNumInts);
}

status_t GraphicBufferMapper::freeBuffer(buffer_handle_t handle)
{
    ATRACE_CALL();

    mMapper->freeBuffer(handle);

    return NO_ERROR;
}

status_t GraphicBufferMapper::lock(buffer_handle_t handle, uint32_t usage, const Rect& bounds,
                                   void** vaddr, int32_t* outBytesPerPixel,
                                   int32_t* outBytesPerStride) {
    return lockAsync(handle, usage, bounds, vaddr, -1, outBytesPerPixel, outBytesPerStride);
}

status_t GraphicBufferMapper::lockYCbCr(buffer_handle_t handle, uint32_t usage,
        const Rect& bounds, android_ycbcr *ycbcr)
{
    return lockAsyncYCbCr(handle, usage, bounds, ycbcr, -1);
}

status_t GraphicBufferMapper::unlock(buffer_handle_t handle)
{
    int32_t fenceFd = -1;
    status_t error = unlockAsync(handle, &fenceFd);
    if (error == NO_ERROR && fenceFd >= 0) {
        sync_wait(fenceFd, -1);
        close(fenceFd);
    }
    return error;
}

status_t GraphicBufferMapper::lockAsync(buffer_handle_t handle, uint32_t usage, const Rect& bounds,
                                        void** vaddr, int fenceFd, int32_t* outBytesPerPixel,
                                        int32_t* outBytesPerStride) {
    return lockAsync(handle, usage, usage, bounds, vaddr, fenceFd, outBytesPerPixel,
                     outBytesPerStride);
}

status_t GraphicBufferMapper::lockAsync(buffer_handle_t handle, uint64_t producerUsage,
                                        uint64_t consumerUsage, const Rect& bounds, void** vaddr,
                                        int fenceFd, int32_t* outBytesPerPixel,
                                        int32_t* outBytesPerStride) {
    ATRACE_CALL();

    const uint64_t usage = static_cast<uint64_t>(
            android_convertGralloc1To0Usage(producerUsage, consumerUsage));
    return mMapper->lock(handle, usage, bounds, fenceFd, vaddr, outBytesPerPixel,
                         outBytesPerStride);
}

status_t GraphicBufferMapper::lockAsyncYCbCr(buffer_handle_t handle,
        uint32_t usage, const Rect& bounds, android_ycbcr *ycbcr, int fenceFd)
{
    ATRACE_CALL();

    return mMapper->lock(handle, usage, bounds, fenceFd, ycbcr);
}

status_t GraphicBufferMapper::unlockAsync(buffer_handle_t handle, int *fenceFd)
{
    ATRACE_CALL();

    *fenceFd = mMapper->unlock(handle);

    return NO_ERROR;
}

status_t GraphicBufferMapper::isSupported(uint32_t width, uint32_t height,
                                          android::PixelFormat format, uint32_t layerCount,
                                          uint64_t usage, bool* outSupported) {
    return mMapper->isSupported(width, height, format, layerCount, usage, outSupported);
}

status_t GraphicBufferMapper::getBufferId(buffer_handle_t bufferHandle, uint64_t* outBufferId) {
    return mMapper->getBufferId(bufferHandle, outBufferId);
}

status_t GraphicBufferMapper::getName(buffer_handle_t bufferHandle, std::string* outName) {
    return mMapper->getName(bufferHandle, outName);
}

status_t GraphicBufferMapper::getWidth(buffer_handle_t bufferHandle, uint64_t* outWidth) {
    return mMapper->getWidth(bufferHandle, outWidth);
}

status_t GraphicBufferMapper::getHeight(buffer_handle_t bufferHandle, uint64_t* outHeight) {
    return mMapper->getHeight(bufferHandle, outHeight);
}

status_t GraphicBufferMapper::getLayerCount(buffer_handle_t bufferHandle, uint64_t* outLayerCount) {
    return mMapper->getLayerCount(bufferHandle, outLayerCount);
}

status_t GraphicBufferMapper::getPixelFormatRequested(buffer_handle_t bufferHandle,
                                                      ui::PixelFormat* outPixelFormatRequested) {
    return mMapper->getPixelFormatRequested(bufferHandle, outPixelFormatRequested);
}

status_t GraphicBufferMapper::getPixelFormatFourCC(buffer_handle_t bufferHandle,
                                                   uint32_t* outPixelFormatFourCC) {
    return mMapper->getPixelFormatFourCC(bufferHandle, outPixelFormatFourCC);
}

status_t GraphicBufferMapper::getPixelFormatModifier(buffer_handle_t bufferHandle,
                                                     uint64_t* outPixelFormatModifier) {
    return mMapper->getPixelFormatModifier(bufferHandle, outPixelFormatModifier);
}

status_t GraphicBufferMapper::getUsage(buffer_handle_t bufferHandle, uint64_t* outUsage) {
    return mMapper->getUsage(bufferHandle, outUsage);
}

status_t GraphicBufferMapper::getAllocationSize(buffer_handle_t bufferHandle,
                                                uint64_t* outAllocationSize) {
    return mMapper->getAllocationSize(bufferHandle, outAllocationSize);
}

status_t GraphicBufferMapper::getProtectedContent(buffer_handle_t bufferHandle,
                                                  uint64_t* outProtectedContent) {
    return mMapper->getProtectedContent(bufferHandle, outProtectedContent);
}

status_t GraphicBufferMapper::getCompression(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType* outCompression) {
    return mMapper->getCompression(bufferHandle, outCompression);
}

status_t GraphicBufferMapper::getCompression(buffer_handle_t bufferHandle,
                                             ui::Compression* outCompression) {
    return mMapper->getCompression(bufferHandle, outCompression);
}

status_t GraphicBufferMapper::getInterlaced(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType* outInterlaced) {
    return mMapper->getInterlaced(bufferHandle, outInterlaced);
}

status_t GraphicBufferMapper::getInterlaced(buffer_handle_t bufferHandle,
                                            ui::Interlaced* outInterlaced) {
    return mMapper->getInterlaced(bufferHandle, outInterlaced);
}

status_t GraphicBufferMapper::getChromaSiting(
        buffer_handle_t bufferHandle,
        aidl::android::hardware::graphics::common::ExtendableType* outChromaSiting) {
    return mMapper->getChromaSiting(bufferHandle, outChromaSiting);
}

status_t GraphicBufferMapper::getChromaSiting(buffer_handle_t bufferHandle,
                                              ui::ChromaSiting* outChromaSiting) {
    return mMapper->getChromaSiting(bufferHandle, outChromaSiting);
}

status_t GraphicBufferMapper::getPlaneLayouts(buffer_handle_t bufferHandle,
                                              std::vector<ui::PlaneLayout>* outPlaneLayouts) {
    return mMapper->getPlaneLayouts(bufferHandle, outPlaneLayouts);
}

status_t GraphicBufferMapper::getDataspace(buffer_handle_t bufferHandle,
                                           ui::Dataspace* outDataspace) {
    return mMapper->getDataspace(bufferHandle, outDataspace);
}

status_t GraphicBufferMapper::getBlendMode(buffer_handle_t bufferHandle,
                                           ui::BlendMode* outBlendMode) {
    return mMapper->getBlendMode(bufferHandle, outBlendMode);
}

status_t GraphicBufferMapper::getSmpte2086(buffer_handle_t bufferHandle,
                                           std::optional<ui::Smpte2086>* outSmpte2086) {
    return mMapper->getSmpte2086(bufferHandle, outSmpte2086);
}

status_t GraphicBufferMapper::getCta861_3(buffer_handle_t bufferHandle,
                                          std::optional<ui::Cta861_3>* outCta861_3) {
    return mMapper->getCta861_3(bufferHandle, outCta861_3);
}

status_t GraphicBufferMapper::getSmpte2094_40(
        buffer_handle_t bufferHandle, std::optional<std::vector<uint8_t>>* outSmpte2094_40) {
    return mMapper->getSmpte2094_40(bufferHandle, outSmpte2094_40);
}

status_t GraphicBufferMapper::getDefaultPixelFormatFourCC(uint32_t width, uint32_t height,
                                                          PixelFormat format, uint32_t layerCount,
                                                          uint64_t usage,
                                                          uint32_t* outPixelFormatFourCC) {
    return mMapper->getDefaultPixelFormatFourCC(width, height, format, layerCount, usage,
                                                outPixelFormatFourCC);
}

status_t GraphicBufferMapper::getDefaultPixelFormatModifier(uint32_t width, uint32_t height,
                                                            PixelFormat format, uint32_t layerCount,
                                                            uint64_t usage,
                                                            uint64_t* outPixelFormatModifier) {
    return mMapper->getDefaultPixelFormatModifier(width, height, format, layerCount, usage,
                                                  outPixelFormatModifier);
}

status_t GraphicBufferMapper::getDefaultAllocationSize(uint32_t width, uint32_t height,
                                                       PixelFormat format, uint32_t layerCount,
                                                       uint64_t usage,
                                                       uint64_t* outAllocationSize) {
    return mMapper->getDefaultAllocationSize(width, height, format, layerCount, usage,
                                             outAllocationSize);
}

status_t GraphicBufferMapper::getDefaultProtectedContent(uint32_t width, uint32_t height,
                                                         PixelFormat format, uint32_t layerCount,
                                                         uint64_t usage,
                                                         uint64_t* outProtectedContent) {
    return mMapper->getDefaultProtectedContent(width, height, format, layerCount, usage,
                                               outProtectedContent);
}

status_t GraphicBufferMapper::getDefaultCompression(
        uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount, uint64_t usage,
        aidl::android::hardware::graphics::common::ExtendableType* outCompression) {
    return mMapper->getDefaultCompression(width, height, format, layerCount, usage, outCompression);
}

status_t GraphicBufferMapper::getDefaultCompression(uint32_t width, uint32_t height,
                                                    PixelFormat format, uint32_t layerCount,
                                                    uint64_t usage,
                                                    ui::Compression* outCompression) {
    return mMapper->getDefaultCompression(width, height, format, layerCount, usage, outCompression);
}

status_t GraphicBufferMapper::getDefaultInterlaced(
        uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount, uint64_t usage,
        aidl::android::hardware::graphics::common::ExtendableType* outInterlaced) {
    return mMapper->getDefaultInterlaced(width, height, format, layerCount, usage, outInterlaced);
}

status_t GraphicBufferMapper::getDefaultInterlaced(uint32_t width, uint32_t height,
                                                   PixelFormat format, uint32_t layerCount,
                                                   uint64_t usage, ui::Interlaced* outInterlaced) {
    return mMapper->getDefaultInterlaced(width, height, format, layerCount, usage, outInterlaced);
}

status_t GraphicBufferMapper::getDefaultChromaSiting(
        uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount, uint64_t usage,
        aidl::android::hardware::graphics::common::ExtendableType* outChromaSiting) {
    return mMapper->getDefaultChromaSiting(width, height, format, layerCount, usage,
                                           outChromaSiting);
}

status_t GraphicBufferMapper::getDefaultChromaSiting(uint32_t width, uint32_t height,
                                                     PixelFormat format, uint32_t layerCount,
                                                     uint64_t usage,
                                                     ui::ChromaSiting* outChromaSiting) {
    return mMapper->getDefaultChromaSiting(width, height, format, layerCount, usage,
                                           outChromaSiting);
}

status_t GraphicBufferMapper::getDefaultPlaneLayouts(
        uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount, uint64_t usage,
        std::vector<ui::PlaneLayout>* outPlaneLayouts) {
    return mMapper->getDefaultPlaneLayouts(width, height, format, layerCount, usage,
                                           outPlaneLayouts);
}

// ---------------------------------------------------------------------------
}; // namespace android
