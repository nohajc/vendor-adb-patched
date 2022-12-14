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

#define LOG_TAG "Gralloc4"

#include <aidl/android/hardware/graphics/allocator/AllocationError.h>
#include <aidl/android/hardware/graphics/allocator/AllocationResult.h>
#include <aidl/android/hardware/graphics/common/BufferUsage.h>
#include <aidlcommonsupport/NativeHandle.h>
#include <android/binder_enums.h>
#include <android/binder_manager.h>
#include <cutils/android_filesystem_config.h>
#include <cutils/multiuser.h>
#include <gralloctypes/Gralloc4.h>
#include <hidl/ServiceManagement.h>
#include <hwbinder/IPCThreadState.h>
#include <ui/Gralloc4.h>

#include <inttypes.h>
#include <log/log.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#include <sync/sync.h>
#pragma clang diagnostic pop

using aidl::android::hardware::graphics::allocator::AllocationError;
using aidl::android::hardware::graphics::allocator::AllocationResult;
using aidl::android::hardware::graphics::common::ExtendableType;
using aidl::android::hardware::graphics::common::PlaneLayoutComponentType;
using aidl::android::hardware::graphics::common::StandardMetadataType;
using android::hardware::hidl_vec;
using android::hardware::graphics::allocator::V4_0::IAllocator;
using android::hardware::graphics::common::V1_2::BufferUsage;
using android::hardware::graphics::common::V1_2::PixelFormat;
using android::hardware::graphics::mapper::V4_0::BufferDescriptor;
using android::hardware::graphics::mapper::V4_0::Error;
using android::hardware::graphics::mapper::V4_0::IMapper;
using AidlIAllocator = ::aidl::android::hardware::graphics::allocator::IAllocator;
using AidlBufferUsage = ::aidl::android::hardware::graphics::common::BufferUsage;
using AidlDataspace = ::aidl::android::hardware::graphics::common::Dataspace;
using AidlNativeHandle = ::aidl::android::hardware::common::NativeHandle;
using BufferDump = android::hardware::graphics::mapper::V4_0::IMapper::BufferDump;
using MetadataDump = android::hardware::graphics::mapper::V4_0::IMapper::MetadataDump;
using MetadataType = android::hardware::graphics::mapper::V4_0::IMapper::MetadataType;
using MetadataTypeDescription =
        android::hardware::graphics::mapper::V4_0::IMapper::MetadataTypeDescription;

namespace android {

namespace {

static constexpr Error kTransactionError = Error::NO_RESOURCES;
static const auto kAidlAllocatorServiceName = AidlIAllocator::descriptor + std::string("/default");

// TODO(b/72323293, b/72703005): Remove these invalid bits from callers
static constexpr uint64_t kRemovedUsageBits = static_cast<uint64_t>((1 << 10) | (1 << 13));

uint64_t getValidUsageBits() {
    static const uint64_t validUsageBits = []() -> uint64_t {
        uint64_t bits = 0;
        for (const auto bit :
             hardware::hidl_enum_range<hardware::graphics::common::V1_2::BufferUsage>()) {
            bits = bits | bit;
        }
        return bits;
    }();
    return validUsageBits | kRemovedUsageBits;
}

uint64_t getValidUsageBits41() {
    static const uint64_t validUsageBits = []() -> uint64_t {
        uint64_t bits = 0;
        for (const auto bit : ndk::enum_range<AidlBufferUsage>{}) {
            bits |= static_cast<int64_t>(bit);
        }
        return bits;
    }();
    return validUsageBits;
}

static inline IMapper::Rect sGralloc4Rect(const Rect& rect) {
    IMapper::Rect outRect{};
    outRect.left = rect.left;
    outRect.top = rect.top;
    outRect.width = rect.width();
    outRect.height = rect.height();
    return outRect;
}

// See if gralloc "4.1" is available.
static bool hasIAllocatorAidl() {
    // Avoid re-querying repeatedly for this information;
    static bool sHasIAllocatorAidl = []() -> bool {
        if (__builtin_available(android 31, *)) {
            return AServiceManager_isDeclared(kAidlAllocatorServiceName.c_str());
        }
        return false;
    }();
    return sHasIAllocatorAidl;
}

// Determines whether the passed info is compatible with the mapper.
static status_t validateBufferDescriptorInfo(IMapper::BufferDescriptorInfo* descriptorInfo) {
    uint64_t validUsageBits = getValidUsageBits();
    if (hasIAllocatorAidl()) {
        validUsageBits |= getValidUsageBits41();
    }

    if (descriptorInfo->usage & ~validUsageBits) {
        ALOGE("buffer descriptor contains invalid usage bits 0x%" PRIx64,
              descriptorInfo->usage & ~validUsageBits);
        return BAD_VALUE;
    }

    // Combinations that are only allowed with gralloc 4.1.
    // Previous grallocs must be protected from this.
    if (!hasIAllocatorAidl() &&
            descriptorInfo->format != hardware::graphics::common::V1_2::PixelFormat::BLOB &&
            descriptorInfo->usage & BufferUsage::GPU_DATA_BUFFER) {
        ALOGE("non-BLOB pixel format with GPU_DATA_BUFFER usage is not supported prior to gralloc 4.1");
        return BAD_VALUE;
    }

    return NO_ERROR;
}

static inline status_t sBufferDescriptorInfo(std::string name, uint32_t width, uint32_t height,
                                             PixelFormat format, uint32_t layerCount,
                                             uint64_t usage,
                                             IMapper::BufferDescriptorInfo* outDescriptorInfo) {
    outDescriptorInfo->name = name;
    outDescriptorInfo->width = width;
    outDescriptorInfo->height = height;
    outDescriptorInfo->layerCount = layerCount;
    outDescriptorInfo->format = static_cast<hardware::graphics::common::V1_2::PixelFormat>(format);
    outDescriptorInfo->usage = usage;
    outDescriptorInfo->reservedSize = 0;

    return validateBufferDescriptorInfo(outDescriptorInfo);
}

} // anonymous namespace

void Gralloc4Mapper::preload() {
    android::hardware::preloadPassthroughService<IMapper>();
}

Gralloc4Mapper::Gralloc4Mapper() {
    mMapper = IMapper::getService();
    if (mMapper == nullptr) {
        ALOGI("mapper 4.x is not supported");
        return;
    }
    if (mMapper->isRemote()) {
        LOG_ALWAYS_FATAL("gralloc-mapper must be in passthrough mode");
    }
}

bool Gralloc4Mapper::isLoaded() const {
    return mMapper != nullptr;
}

status_t Gralloc4Mapper::createDescriptor(void* bufferDescriptorInfo,
                                          void* outBufferDescriptor) const {
    IMapper::BufferDescriptorInfo* descriptorInfo =
            static_cast<IMapper::BufferDescriptorInfo*>(bufferDescriptorInfo);
    BufferDescriptor* outDescriptor = static_cast<BufferDescriptor*>(outBufferDescriptor);

    status_t status = validateBufferDescriptorInfo(descriptorInfo);
    if (status != NO_ERROR) {
        return status;
    }

    Error error;
    auto hidl_cb = [&](const auto& tmpError, const auto& tmpDescriptor) {
        error = tmpError;
        if (error != Error::NONE) {
            return;
        }
        *outDescriptor = tmpDescriptor;
    };

    hardware::Return<void> ret = mMapper->createDescriptor(*descriptorInfo, hidl_cb);

    return static_cast<status_t>((ret.isOk()) ? error : kTransactionError);
}

status_t Gralloc4Mapper::importBuffer(const hardware::hidl_handle& rawHandle,
                                      buffer_handle_t* outBufferHandle) const {
    Error error;
    auto ret = mMapper->importBuffer(rawHandle, [&](const auto& tmpError, const auto& tmpBuffer) {
        error = tmpError;
        if (error != Error::NONE) {
            return;
        }
        *outBufferHandle = static_cast<buffer_handle_t>(tmpBuffer);
    });

    return static_cast<status_t>((ret.isOk()) ? error : kTransactionError);
}

void Gralloc4Mapper::freeBuffer(buffer_handle_t bufferHandle) const {
    auto buffer = const_cast<native_handle_t*>(bufferHandle);
    auto ret = mMapper->freeBuffer(buffer);

    auto error = (ret.isOk()) ? static_cast<Error>(ret) : kTransactionError;
    ALOGE_IF(error != Error::NONE, "freeBuffer(%p) failed with %d", buffer, error);
}

status_t Gralloc4Mapper::validateBufferSize(buffer_handle_t bufferHandle, uint32_t width,
                                            uint32_t height, PixelFormat format,
                                            uint32_t layerCount, uint64_t usage,
                                            uint32_t stride) const {
    IMapper::BufferDescriptorInfo descriptorInfo;
    if (auto error = sBufferDescriptorInfo("validateBufferSize", width, height, format, layerCount,
                                           usage, &descriptorInfo) != OK) {
        return error;
    }

    auto buffer = const_cast<native_handle_t*>(bufferHandle);
    auto ret = mMapper->validateBufferSize(buffer, descriptorInfo, stride);

    return static_cast<status_t>((ret.isOk()) ? static_cast<Error>(ret) : kTransactionError);
}

void Gralloc4Mapper::getTransportSize(buffer_handle_t bufferHandle, uint32_t* outNumFds,
                                      uint32_t* outNumInts) const {
    *outNumFds = uint32_t(bufferHandle->numFds);
    *outNumInts = uint32_t(bufferHandle->numInts);

    Error error;
    auto buffer = const_cast<native_handle_t*>(bufferHandle);
    auto ret = mMapper->getTransportSize(buffer,
                                         [&](const auto& tmpError, const auto& tmpNumFds,
                                             const auto& tmpNumInts) {
                                             error = tmpError;
                                             if (error != Error::NONE) {
                                                 return;
                                             }
                                             *outNumFds = tmpNumFds;
                                             *outNumInts = tmpNumInts;
                                         });

    error = (ret.isOk()) ? error : kTransactionError;

    ALOGE_IF(error != Error::NONE, "getTransportSize(%p) failed with %d", buffer, error);
}

status_t Gralloc4Mapper::lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect& bounds,
                              int acquireFence, void** outData, int32_t* outBytesPerPixel,
                              int32_t* outBytesPerStride) const {
    std::vector<ui::PlaneLayout> planeLayouts;
    status_t err = getPlaneLayouts(bufferHandle, &planeLayouts);

    if (err == NO_ERROR && !planeLayouts.empty()) {
        if (outBytesPerPixel) {
            int32_t bitsPerPixel = planeLayouts.front().sampleIncrementInBits;
            for (const auto& planeLayout : planeLayouts) {
                if (bitsPerPixel != planeLayout.sampleIncrementInBits) {
                    bitsPerPixel = -1;
                }
            }
            if (bitsPerPixel >= 0 && bitsPerPixel % 8 == 0) {
                *outBytesPerPixel = bitsPerPixel / 8;
            } else {
                *outBytesPerPixel = -1;
            }
        }
        if (outBytesPerStride) {
            int32_t bytesPerStride = planeLayouts.front().strideInBytes;
            for (const auto& planeLayout : planeLayouts) {
                if (bytesPerStride != planeLayout.strideInBytes) {
                    bytesPerStride = -1;
                }
            }
            if (bytesPerStride >= 0) {
                *outBytesPerStride = bytesPerStride;
            } else {
                *outBytesPerStride = -1;
            }
        }
    }

    auto buffer = const_cast<native_handle_t*>(bufferHandle);

    IMapper::Rect accessRegion = sGralloc4Rect(bounds);

    // put acquireFence in a hidl_handle
    hardware::hidl_handle acquireFenceHandle;
    NATIVE_HANDLE_DECLARE_STORAGE(acquireFenceStorage, 1, 0);
    if (acquireFence >= 0) {
        auto h = native_handle_init(acquireFenceStorage, 1, 0);
        h->data[0] = acquireFence;
        acquireFenceHandle = h;
    }

    Error error;
    auto ret = mMapper->lock(buffer, usage, accessRegion, acquireFenceHandle,
                             [&](const auto& tmpError, const auto& tmpData) {
                                 error = tmpError;
                                 if (error != Error::NONE) {
                                     return;
                                 }
                                 *outData = tmpData;
                             });

    // we own acquireFence even on errors
    if (acquireFence >= 0) {
        close(acquireFence);
    }

    error = (ret.isOk()) ? error : kTransactionError;

    ALOGW_IF(error != Error::NONE, "lock(%p, ...) failed: %d", bufferHandle, error);

    return static_cast<status_t>(error);
}

status_t Gralloc4Mapper::lock(buffer_handle_t bufferHandle, uint64_t usage, const Rect& bounds,
                              int acquireFence, android_ycbcr* outYcbcr) const {
    if (!outYcbcr) {
        return BAD_VALUE;
    }

    std::vector<ui::PlaneLayout> planeLayouts;
    status_t error = getPlaneLayouts(bufferHandle, &planeLayouts);
    if (error != NO_ERROR) {
        return error;
    }

    void* data = nullptr;
    error = lock(bufferHandle, usage, bounds, acquireFence, &data, nullptr, nullptr);
    if (error != NO_ERROR) {
        return error;
    }

    android_ycbcr ycbcr;

    ycbcr.y = nullptr;
    ycbcr.cb = nullptr;
    ycbcr.cr = nullptr;
    ycbcr.ystride = 0;
    ycbcr.cstride = 0;
    ycbcr.chroma_step = 0;

    for (const auto& planeLayout : planeLayouts) {
        for (const auto& planeLayoutComponent : planeLayout.components) {
            if (!gralloc4::isStandardPlaneLayoutComponentType(planeLayoutComponent.type)) {
                continue;
            }

            uint8_t* tmpData = static_cast<uint8_t*>(data) + planeLayout.offsetInBytes;

            // Note that `offsetInBits` may not be a multiple of 8 for packed formats (e.g. P010)
            // but we still want to point to the start of the first byte.
            tmpData += (planeLayoutComponent.offsetInBits / 8);

            uint64_t sampleIncrementInBytes;

            auto type = static_cast<PlaneLayoutComponentType>(planeLayoutComponent.type.value);
            switch (type) {
                case PlaneLayoutComponentType::Y:
                    if ((ycbcr.y != nullptr) || (planeLayout.sampleIncrementInBits % 8 != 0)) {
                        unlock(bufferHandle);
                        return BAD_VALUE;
                    }
                    ycbcr.y = tmpData;
                    ycbcr.ystride = planeLayout.strideInBytes;
                    break;

                case PlaneLayoutComponentType::CB:
                case PlaneLayoutComponentType::CR:
                    if (planeLayout.sampleIncrementInBits % 8 != 0) {
                        unlock(bufferHandle);
                        return BAD_VALUE;
                    }

                    sampleIncrementInBytes = planeLayout.sampleIncrementInBits / 8;
                    if ((sampleIncrementInBytes != 1) && (sampleIncrementInBytes != 2) &&
                        (sampleIncrementInBytes != 4)) {
                        unlock(bufferHandle);
                        return BAD_VALUE;
                    }

                    if (ycbcr.cstride == 0 && ycbcr.chroma_step == 0) {
                        ycbcr.cstride = planeLayout.strideInBytes;
                        ycbcr.chroma_step = sampleIncrementInBytes;
                    } else {
                        if ((static_cast<int64_t>(ycbcr.cstride) != planeLayout.strideInBytes) ||
                            (ycbcr.chroma_step != sampleIncrementInBytes)) {
                            unlock(bufferHandle);
                            return BAD_VALUE;
                        }
                    }

                    if (type == PlaneLayoutComponentType::CB) {
                        if (ycbcr.cb != nullptr) {
                            unlock(bufferHandle);
                            return BAD_VALUE;
                        }
                        ycbcr.cb = tmpData;
                    } else {
                        if (ycbcr.cr != nullptr) {
                            unlock(bufferHandle);
                            return BAD_VALUE;
                        }
                        ycbcr.cr = tmpData;
                    }
                    break;
                default:
                    break;
            };
        }
    }

    *outYcbcr = ycbcr;
    return static_cast<status_t>(Error::NONE);
}

int Gralloc4Mapper::unlock(buffer_handle_t bufferHandle) const {
    auto buffer = const_cast<native_handle_t*>(bufferHandle);

    int releaseFence = -1;
    Error error;
    auto ret = mMapper->unlock(buffer, [&](const auto& tmpError, const auto& tmpReleaseFence) {
        error = tmpError;
        if (error != Error::NONE) {
            return;
        }

        auto fenceHandle = tmpReleaseFence.getNativeHandle();
        if (fenceHandle && fenceHandle->numFds == 1) {
            int fd = dup(fenceHandle->data[0]);
            if (fd >= 0) {
                releaseFence = fd;
            } else {
                ALOGW("failed to dup unlock release fence");
                sync_wait(fenceHandle->data[0], -1);
            }
        }
    });

    if (!ret.isOk()) {
        error = kTransactionError;
    }

    if (error != Error::NONE) {
        ALOGE("unlock(%p) failed with %d", buffer, error);
    }

    return releaseFence;
}

status_t Gralloc4Mapper::isSupported(uint32_t width, uint32_t height, PixelFormat format,
                                     uint32_t layerCount, uint64_t usage,
                                     bool* outSupported) const {
    IMapper::BufferDescriptorInfo descriptorInfo;
    if (auto error = sBufferDescriptorInfo("isSupported", width, height, format, layerCount, usage,
                                           &descriptorInfo) != OK) {
        // Usage isn't known to the HAL or otherwise failed validation.
        *outSupported = false;
        return OK;
    }

    Error error;
    auto ret = mMapper->isSupported(descriptorInfo,
                                    [&](const auto& tmpError, const auto& tmpSupported) {
                                        error = tmpError;
                                        if (error != Error::NONE) {
                                            return;
                                        }
                                        if (outSupported) {
                                            *outSupported = tmpSupported;
                                        }
                                    });

    if (!ret.isOk()) {
        error = kTransactionError;
    }

    if (error != Error::NONE) {
        ALOGE("isSupported(%u, %u, %d, %u, ...) failed with %d", width, height, format, layerCount,
              error);
    }

    return static_cast<status_t>(error);
}

template <class T>
status_t Gralloc4Mapper::get(buffer_handle_t bufferHandle, const MetadataType& metadataType,
                             DecodeFunction<T> decodeFunction, T* outMetadata) const {
    if (!outMetadata) {
        return BAD_VALUE;
    }

    hidl_vec<uint8_t> vec;
    Error error;
    auto ret = mMapper->get(const_cast<native_handle_t*>(bufferHandle), metadataType,
                            [&](const auto& tmpError, const hidl_vec<uint8_t>& tmpVec) {
                                error = tmpError;
                                vec = tmpVec;
                            });

    if (!ret.isOk()) {
        error = kTransactionError;
    }

    if (error != Error::NONE) {
        ALOGE("get(%s, %" PRIu64 ", ...) failed with %d", metadataType.name.c_str(),
              metadataType.value, error);
        return static_cast<status_t>(error);
    }

    return decodeFunction(vec, outMetadata);
}

template <class T>
status_t Gralloc4Mapper::set(buffer_handle_t bufferHandle, const MetadataType& metadataType,
                             const T& metadata, EncodeFunction<T> encodeFunction) const {
    hidl_vec<uint8_t> encodedMetadata;
    if (const status_t status = encodeFunction(metadata, &encodedMetadata); status != OK) {
        ALOGE("Encoding metadata(%s) failed with %d", metadataType.name.c_str(), status);
        return status;
    }
    hidl_vec<uint8_t> vec;
    auto ret =
            mMapper->set(const_cast<native_handle_t*>(bufferHandle), metadataType, encodedMetadata);

    const Error error = ret.withDefault(kTransactionError);
    switch (error) {
        case Error::BAD_DESCRIPTOR:
        case Error::BAD_BUFFER:
        case Error::BAD_VALUE:
        case Error::NO_RESOURCES:
            ALOGE("set(%s, %" PRIu64 ", ...) failed with %d", metadataType.name.c_str(),
                  metadataType.value, error);
            break;
        // It is not an error to attempt to set metadata that a particular gralloc implementation
        // happens to not support.
        case Error::UNSUPPORTED:
        case Error::NONE:
            break;
    }

    return static_cast<status_t>(error);
}

status_t Gralloc4Mapper::getBufferId(buffer_handle_t bufferHandle, uint64_t* outBufferId) const {
    return get(bufferHandle, gralloc4::MetadataType_BufferId, gralloc4::decodeBufferId,
               outBufferId);
}

status_t Gralloc4Mapper::getName(buffer_handle_t bufferHandle, std::string* outName) const {
    return get(bufferHandle, gralloc4::MetadataType_Name, gralloc4::decodeName, outName);
}

status_t Gralloc4Mapper::getWidth(buffer_handle_t bufferHandle, uint64_t* outWidth) const {
    return get(bufferHandle, gralloc4::MetadataType_Width, gralloc4::decodeWidth, outWidth);
}

status_t Gralloc4Mapper::getHeight(buffer_handle_t bufferHandle, uint64_t* outHeight) const {
    return get(bufferHandle, gralloc4::MetadataType_Height, gralloc4::decodeHeight, outHeight);
}

status_t Gralloc4Mapper::getLayerCount(buffer_handle_t bufferHandle,
                                       uint64_t* outLayerCount) const {
    return get(bufferHandle, gralloc4::MetadataType_LayerCount, gralloc4::decodeLayerCount,
               outLayerCount);
}

status_t Gralloc4Mapper::getPixelFormatRequested(buffer_handle_t bufferHandle,
                                                 ui::PixelFormat* outPixelFormatRequested) const {
    return get(bufferHandle, gralloc4::MetadataType_PixelFormatRequested,
               gralloc4::decodePixelFormatRequested, outPixelFormatRequested);
}

status_t Gralloc4Mapper::getPixelFormatFourCC(buffer_handle_t bufferHandle,
                                              uint32_t* outPixelFormatFourCC) const {
    return get(bufferHandle, gralloc4::MetadataType_PixelFormatFourCC,
               gralloc4::decodePixelFormatFourCC, outPixelFormatFourCC);
}

status_t Gralloc4Mapper::getPixelFormatModifier(buffer_handle_t bufferHandle,
                                                uint64_t* outPixelFormatModifier) const {
    return get(bufferHandle, gralloc4::MetadataType_PixelFormatModifier,
               gralloc4::decodePixelFormatModifier, outPixelFormatModifier);
}

status_t Gralloc4Mapper::getUsage(buffer_handle_t bufferHandle, uint64_t* outUsage) const {
    return get(bufferHandle, gralloc4::MetadataType_Usage, gralloc4::decodeUsage, outUsage);
}

status_t Gralloc4Mapper::getAllocationSize(buffer_handle_t bufferHandle,
                                           uint64_t* outAllocationSize) const {
    return get(bufferHandle, gralloc4::MetadataType_AllocationSize, gralloc4::decodeAllocationSize,
               outAllocationSize);
}

status_t Gralloc4Mapper::getProtectedContent(buffer_handle_t bufferHandle,
                                             uint64_t* outProtectedContent) const {
    return get(bufferHandle, gralloc4::MetadataType_ProtectedContent,
               gralloc4::decodeProtectedContent, outProtectedContent);
}

status_t Gralloc4Mapper::getCompression(buffer_handle_t bufferHandle,
                                        ExtendableType* outCompression) const {
    return get(bufferHandle, gralloc4::MetadataType_Compression, gralloc4::decodeCompression,
               outCompression);
}

status_t Gralloc4Mapper::getCompression(buffer_handle_t bufferHandle,
                                        ui::Compression* outCompression) const {
    if (!outCompression) {
        return BAD_VALUE;
    }
    ExtendableType compression;
    status_t error = getCompression(bufferHandle, &compression);
    if (error) {
        return error;
    }
    if (!gralloc4::isStandardCompression(compression)) {
        return BAD_TYPE;
    }
    *outCompression = gralloc4::getStandardCompressionValue(compression);
    return NO_ERROR;
}

status_t Gralloc4Mapper::getInterlaced(buffer_handle_t bufferHandle,
                                       ExtendableType* outInterlaced) const {
    return get(bufferHandle, gralloc4::MetadataType_Interlaced, gralloc4::decodeInterlaced,
               outInterlaced);
}

status_t Gralloc4Mapper::getInterlaced(buffer_handle_t bufferHandle,
                                       ui::Interlaced* outInterlaced) const {
    if (!outInterlaced) {
        return BAD_VALUE;
    }
    ExtendableType interlaced;
    status_t error = getInterlaced(bufferHandle, &interlaced);
    if (error) {
        return error;
    }
    if (!gralloc4::isStandardInterlaced(interlaced)) {
        return BAD_TYPE;
    }
    *outInterlaced = gralloc4::getStandardInterlacedValue(interlaced);
    return NO_ERROR;
}

status_t Gralloc4Mapper::getChromaSiting(buffer_handle_t bufferHandle,
                                         ExtendableType* outChromaSiting) const {
    return get(bufferHandle, gralloc4::MetadataType_ChromaSiting, gralloc4::decodeChromaSiting,
               outChromaSiting);
}

status_t Gralloc4Mapper::getChromaSiting(buffer_handle_t bufferHandle,
                                         ui::ChromaSiting* outChromaSiting) const {
    if (!outChromaSiting) {
        return BAD_VALUE;
    }
    ExtendableType chromaSiting;
    status_t error = getChromaSiting(bufferHandle, &chromaSiting);
    if (error) {
        return error;
    }
    if (!gralloc4::isStandardChromaSiting(chromaSiting)) {
        return BAD_TYPE;
    }
    *outChromaSiting = gralloc4::getStandardChromaSitingValue(chromaSiting);
    return NO_ERROR;
}

status_t Gralloc4Mapper::getPlaneLayouts(buffer_handle_t bufferHandle,
                                         std::vector<ui::PlaneLayout>* outPlaneLayouts) const {
    return get(bufferHandle, gralloc4::MetadataType_PlaneLayouts, gralloc4::decodePlaneLayouts,
               outPlaneLayouts);
}

status_t Gralloc4Mapper::getDataspace(buffer_handle_t bufferHandle,
                                      ui::Dataspace* outDataspace) const {
    if (!outDataspace) {
        return BAD_VALUE;
    }
    AidlDataspace dataspace;
    status_t error = get(bufferHandle, gralloc4::MetadataType_Dataspace, gralloc4::decodeDataspace,
                         &dataspace);
    if (error) {
        return error;
    }

    // Gralloc4 uses stable AIDL dataspace but the rest of the system still uses HIDL dataspace
    *outDataspace = static_cast<ui::Dataspace>(dataspace);
    return NO_ERROR;
}

status_t Gralloc4Mapper::setDataspace(buffer_handle_t bufferHandle, ui::Dataspace dataspace) const {
    return set(bufferHandle, gralloc4::MetadataType_Dataspace,
               static_cast<aidl::android::hardware::graphics::common::Dataspace>(dataspace),
               gralloc4::encodeDataspace);
}

status_t Gralloc4Mapper::getBlendMode(buffer_handle_t bufferHandle,
                                      ui::BlendMode* outBlendMode) const {
    return get(bufferHandle, gralloc4::MetadataType_BlendMode, gralloc4::decodeBlendMode,
               outBlendMode);
}

status_t Gralloc4Mapper::getSmpte2086(buffer_handle_t bufferHandle,
                                      std::optional<ui::Smpte2086>* outSmpte2086) const {
    return get(bufferHandle, gralloc4::MetadataType_Smpte2086, gralloc4::decodeSmpte2086,
               outSmpte2086);
}

status_t Gralloc4Mapper::setSmpte2086(buffer_handle_t bufferHandle,
                                      std::optional<ui::Smpte2086> smpte2086) const {
    return set(bufferHandle, gralloc4::MetadataType_Smpte2086, smpte2086,
               gralloc4::encodeSmpte2086);
}

status_t Gralloc4Mapper::getCta861_3(buffer_handle_t bufferHandle,
                                     std::optional<ui::Cta861_3>* outCta861_3) const {
    return get(bufferHandle, gralloc4::MetadataType_Cta861_3, gralloc4::decodeCta861_3,
               outCta861_3);
}

status_t Gralloc4Mapper::setCta861_3(buffer_handle_t bufferHandle,
                                     std::optional<ui::Cta861_3> cta861_3) const {
    return set(bufferHandle, gralloc4::MetadataType_Cta861_3, cta861_3, gralloc4::encodeCta861_3);
}

status_t Gralloc4Mapper::getSmpte2094_40(
        buffer_handle_t bufferHandle, std::optional<std::vector<uint8_t>>* outSmpte2094_40) const {
    return get(bufferHandle, gralloc4::MetadataType_Smpte2094_40, gralloc4::decodeSmpte2094_40,
               outSmpte2094_40);
}

status_t Gralloc4Mapper::setSmpte2094_40(buffer_handle_t bufferHandle,
                                         std::optional<std::vector<uint8_t>> smpte2094_40) const {
    return set(bufferHandle, gralloc4::MetadataType_Smpte2094_40, smpte2094_40,
               gralloc4::encodeSmpte2094_40);
}

status_t Gralloc4Mapper::getSmpte2094_10(
        buffer_handle_t bufferHandle, std::optional<std::vector<uint8_t>>* outSmpte2094_10) const {
    return get(bufferHandle, gralloc4::MetadataType_Smpte2094_10, gralloc4::decodeSmpte2094_10,
               outSmpte2094_10);
}

status_t Gralloc4Mapper::setSmpte2094_10(buffer_handle_t bufferHandle,
                                         std::optional<std::vector<uint8_t>> smpte2094_10) const {
    return set(bufferHandle, gralloc4::MetadataType_Smpte2094_10, smpte2094_10,
               gralloc4::encodeSmpte2094_10);
}

template <class T>
status_t Gralloc4Mapper::getDefault(uint32_t width, uint32_t height, PixelFormat format,
                                    uint32_t layerCount, uint64_t usage,
                                    const MetadataType& metadataType,
                                    DecodeFunction<T> decodeFunction, T* outMetadata) const {
    if (!outMetadata) {
        return BAD_VALUE;
    }

    IMapper::BufferDescriptorInfo descriptorInfo;
    if (auto error = sBufferDescriptorInfo("getDefault", width, height, format, layerCount, usage,
                                           &descriptorInfo) != OK) {
        return error;
    }

    hidl_vec<uint8_t> vec;
    Error error;
    auto ret = mMapper->getFromBufferDescriptorInfo(descriptorInfo, metadataType,
                                                    [&](const auto& tmpError,
                                                        const hidl_vec<uint8_t>& tmpVec) {
                                                        error = tmpError;
                                                        vec = tmpVec;
                                                    });

    if (!ret.isOk()) {
        error = kTransactionError;
    }

    if (error != Error::NONE) {
        ALOGE("getDefault(%s, %" PRIu64 ", ...) failed with %d", metadataType.name.c_str(),
              metadataType.value, error);
        return static_cast<status_t>(error);
    }

    return decodeFunction(vec, outMetadata);
}

status_t Gralloc4Mapper::getDefaultPixelFormatFourCC(uint32_t width, uint32_t height,
                                                     PixelFormat format, uint32_t layerCount,
                                                     uint64_t usage,
                                                     uint32_t* outPixelFormatFourCC) const {
    return getDefault(width, height, format, layerCount, usage,
                      gralloc4::MetadataType_PixelFormatFourCC, gralloc4::decodePixelFormatFourCC,
                      outPixelFormatFourCC);
}

status_t Gralloc4Mapper::getDefaultPixelFormatModifier(uint32_t width, uint32_t height,
                                                       PixelFormat format, uint32_t layerCount,
                                                       uint64_t usage,
                                                       uint64_t* outPixelFormatModifier) const {
    return getDefault(width, height, format, layerCount, usage,
                      gralloc4::MetadataType_PixelFormatModifier,
                      gralloc4::decodePixelFormatModifier, outPixelFormatModifier);
}

status_t Gralloc4Mapper::getDefaultAllocationSize(uint32_t width, uint32_t height,
                                                  PixelFormat format, uint32_t layerCount,
                                                  uint64_t usage,
                                                  uint64_t* outAllocationSize) const {
    return getDefault(width, height, format, layerCount, usage,
                      gralloc4::MetadataType_AllocationSize, gralloc4::decodeAllocationSize,
                      outAllocationSize);
}

status_t Gralloc4Mapper::getDefaultProtectedContent(uint32_t width, uint32_t height,
                                                    PixelFormat format, uint32_t layerCount,
                                                    uint64_t usage,
                                                    uint64_t* outProtectedContent) const {
    return getDefault(width, height, format, layerCount, usage,
                      gralloc4::MetadataType_ProtectedContent, gralloc4::decodeProtectedContent,
                      outProtectedContent);
}

status_t Gralloc4Mapper::getDefaultCompression(uint32_t width, uint32_t height, PixelFormat format,
                                               uint32_t layerCount, uint64_t usage,
                                               ExtendableType* outCompression) const {
    return getDefault(width, height, format, layerCount, usage, gralloc4::MetadataType_Compression,
                      gralloc4::decodeCompression, outCompression);
}

status_t Gralloc4Mapper::getDefaultCompression(uint32_t width, uint32_t height, PixelFormat format,
                                               uint32_t layerCount, uint64_t usage,
                                               ui::Compression* outCompression) const {
    if (!outCompression) {
        return BAD_VALUE;
    }
    ExtendableType compression;
    status_t error = getDefaultCompression(width, height, format, layerCount, usage, &compression);
    if (error) {
        return error;
    }
    if (!gralloc4::isStandardCompression(compression)) {
        return BAD_TYPE;
    }
    *outCompression = gralloc4::getStandardCompressionValue(compression);
    return NO_ERROR;
}

status_t Gralloc4Mapper::getDefaultInterlaced(uint32_t width, uint32_t height, PixelFormat format,
                                              uint32_t layerCount, uint64_t usage,
                                              ExtendableType* outInterlaced) const {
    return getDefault(width, height, format, layerCount, usage, gralloc4::MetadataType_Interlaced,
                      gralloc4::decodeInterlaced, outInterlaced);
}

status_t Gralloc4Mapper::getDefaultInterlaced(uint32_t width, uint32_t height, PixelFormat format,
                                              uint32_t layerCount, uint64_t usage,
                                              ui::Interlaced* outInterlaced) const {
    if (!outInterlaced) {
        return BAD_VALUE;
    }
    ExtendableType interlaced;
    status_t error = getDefaultInterlaced(width, height, format, layerCount, usage, &interlaced);
    if (error) {
        return error;
    }
    if (!gralloc4::isStandardInterlaced(interlaced)) {
        return BAD_TYPE;
    }
    *outInterlaced = gralloc4::getStandardInterlacedValue(interlaced);
    return NO_ERROR;
}

status_t Gralloc4Mapper::getDefaultChromaSiting(uint32_t width, uint32_t height, PixelFormat format,
                                                uint32_t layerCount, uint64_t usage,
                                                ExtendableType* outChromaSiting) const {
    return getDefault(width, height, format, layerCount, usage, gralloc4::MetadataType_ChromaSiting,
                      gralloc4::decodeChromaSiting, outChromaSiting);
}

status_t Gralloc4Mapper::getDefaultChromaSiting(uint32_t width, uint32_t height, PixelFormat format,
                                                uint32_t layerCount, uint64_t usage,
                                                ui::ChromaSiting* outChromaSiting) const {
    if (!outChromaSiting) {
        return BAD_VALUE;
    }
    ExtendableType chromaSiting;
    status_t error =
            getDefaultChromaSiting(width, height, format, layerCount, usage, &chromaSiting);
    if (error) {
        return error;
    }
    if (!gralloc4::isStandardChromaSiting(chromaSiting)) {
        return BAD_TYPE;
    }
    *outChromaSiting = gralloc4::getStandardChromaSitingValue(chromaSiting);
    return NO_ERROR;
}

status_t Gralloc4Mapper::getDefaultPlaneLayouts(
        uint32_t width, uint32_t height, PixelFormat format, uint32_t layerCount, uint64_t usage,
        std::vector<ui::PlaneLayout>* outPlaneLayouts) const {
    return getDefault(width, height, format, layerCount, usage, gralloc4::MetadataType_PlaneLayouts,
                      gralloc4::decodePlaneLayouts, outPlaneLayouts);
}

std::vector<MetadataTypeDescription> Gralloc4Mapper::listSupportedMetadataTypes() const {
    hidl_vec<MetadataTypeDescription> descriptions;
    Error error;
    auto ret = mMapper->listSupportedMetadataTypes(
            [&](const auto& tmpError, const auto& tmpDescriptions) {
                error = tmpError;
                descriptions = tmpDescriptions;
            });

    if (!ret.isOk()) {
        error = kTransactionError;
    }

    if (error != Error::NONE) {
        ALOGE("listSupportedMetadataType() failed with %d", error);
        return {};
    }

    return static_cast<std::vector<MetadataTypeDescription>>(descriptions);
}

template <class T>
status_t Gralloc4Mapper::metadataDumpHelper(const BufferDump& bufferDump,
                                            StandardMetadataType metadataType,
                                            DecodeFunction<T> decodeFunction, T* outT) const {
    const auto& metadataDump = bufferDump.metadataDump;

    auto itr =
            std::find_if(metadataDump.begin(), metadataDump.end(),
                         [&](const MetadataDump& tmpMetadataDump) {
                             if (!gralloc4::isStandardMetadataType(tmpMetadataDump.metadataType)) {
                                 return false;
                             }
                             return metadataType ==
                                     gralloc4::getStandardMetadataTypeValue(
                                             tmpMetadataDump.metadataType);
                         });
    if (itr == metadataDump.end()) {
        return BAD_VALUE;
    }

    return decodeFunction(itr->metadata, outT);
}

status_t Gralloc4Mapper::bufferDumpHelper(const BufferDump& bufferDump, std::ostringstream* outDump,
                                          uint64_t* outAllocationSize, bool less) const {
    uint64_t bufferId;
    std::string name;
    uint64_t width;
    uint64_t height;
    uint64_t layerCount;
    ui::PixelFormat pixelFormatRequested;
    uint32_t pixelFormatFourCC;
    uint64_t pixelFormatModifier;
    uint64_t usage;
    AidlDataspace dataspace;
    uint64_t allocationSize;
    uint64_t protectedContent;
    ExtendableType compression;
    ExtendableType interlaced;
    ExtendableType chromaSiting;
    std::vector<ui::PlaneLayout> planeLayouts;

    status_t error = metadataDumpHelper(bufferDump, StandardMetadataType::BUFFER_ID,
                                        gralloc4::decodeBufferId, &bufferId);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::NAME, gralloc4::decodeName, &name);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::WIDTH, gralloc4::decodeWidth,
                               &width);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::HEIGHT, gralloc4::decodeHeight,
                               &height);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::LAYER_COUNT,
                               gralloc4::decodeLayerCount, &layerCount);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::PIXEL_FORMAT_REQUESTED,
                               gralloc4::decodePixelFormatRequested, &pixelFormatRequested);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::PIXEL_FORMAT_FOURCC,
                               gralloc4::decodePixelFormatFourCC, &pixelFormatFourCC);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::PIXEL_FORMAT_MODIFIER,
                               gralloc4::decodePixelFormatModifier, &pixelFormatModifier);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::USAGE, gralloc4::decodeUsage,
                               &usage);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::DATASPACE,
                               gralloc4::decodeDataspace, &dataspace);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::ALLOCATION_SIZE,
                               gralloc4::decodeAllocationSize, &allocationSize);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::PROTECTED_CONTENT,
                               gralloc4::decodeProtectedContent, &protectedContent);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::COMPRESSION,
                               gralloc4::decodeCompression, &compression);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::INTERLACED,
                               gralloc4::decodeInterlaced, &interlaced);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::CHROMA_SITING,
                               gralloc4::decodeChromaSiting, &chromaSiting);
    if (error != NO_ERROR) {
        return error;
    }
    error = metadataDumpHelper(bufferDump, StandardMetadataType::PLANE_LAYOUTS,
                               gralloc4::decodePlaneLayouts, &planeLayouts);
    if (error != NO_ERROR) {
        return error;
    }

    if (outAllocationSize) {
        *outAllocationSize = allocationSize;
    }
    double allocationSizeKiB = static_cast<double>(allocationSize) / 1024;

    *outDump << "+ name:" << name << ", id:" << bufferId << ", size:" << std::fixed
             << allocationSizeKiB << "KiB, w/h:" << width << "x" << height << ", usage: 0x"
             << std::hex << usage << std::dec
             << ", req fmt:" << static_cast<int32_t>(pixelFormatRequested)
             << ", fourcc/mod:" << pixelFormatFourCC << "/" << pixelFormatModifier
             << ", dataspace: 0x" << std::hex << static_cast<uint32_t>(dataspace) << std::dec
             << ", compressed: ";

    if (less) {
        bool isCompressed = !gralloc4::isStandardCompression(compression) ||
                (gralloc4::getStandardCompressionValue(compression) != ui::Compression::NONE);
        *outDump << std::boolalpha << isCompressed << "\n";
    } else {
        *outDump << gralloc4::getCompressionName(compression) << "\n";
    }

    bool firstPlane = true;
    for (const auto& planeLayout : planeLayouts) {
        if (firstPlane) {
            firstPlane = false;
            *outDump << "\tplanes: ";
        } else {
            *outDump << "\t        ";
        }

        for (size_t i = 0; i < planeLayout.components.size(); i++) {
            const auto& planeLayoutComponent = planeLayout.components[i];
            *outDump << gralloc4::getPlaneLayoutComponentTypeName(planeLayoutComponent.type);
            if (i < planeLayout.components.size() - 1) {
                *outDump << "/";
            } else {
                *outDump << ":\t";
            }
        }
        *outDump << " w/h:" << planeLayout.widthInSamples << "x" << planeLayout.heightInSamples
                 << ", stride:" << planeLayout.strideInBytes
                 << " bytes, size:" << planeLayout.totalSizeInBytes;
        if (!less) {
            *outDump << ", inc:" << planeLayout.sampleIncrementInBits
                     << " bits, subsampling w/h:" << planeLayout.horizontalSubsampling << "x"
                     << planeLayout.verticalSubsampling;
        }
        *outDump << "\n";
    }

    if (!less) {
        *outDump << "\tlayer cnt: " << layerCount << ", protected content: " << protectedContent
                 << ", interlaced: " << gralloc4::getInterlacedName(interlaced)
                 << ", chroma siting:" << gralloc4::getChromaSitingName(chromaSiting) << "\n";
    }

    return NO_ERROR;
}

std::string Gralloc4Mapper::dumpBuffer(buffer_handle_t bufferHandle, bool less) const {
    auto buffer = const_cast<native_handle_t*>(bufferHandle);

    BufferDump bufferDump;
    Error error;
    auto ret = mMapper->dumpBuffer(buffer, [&](const auto& tmpError, const auto& tmpBufferDump) {
        error = tmpError;
        bufferDump = tmpBufferDump;
    });

    if (!ret.isOk()) {
        error = kTransactionError;
    }

    if (error != Error::NONE) {
        ALOGE("dumpBuffer() failed with %d", error);
        return "";
    }

    std::ostringstream stream;
    stream.precision(2);

    status_t err = bufferDumpHelper(bufferDump, &stream, nullptr, less);
    if (err != NO_ERROR) {
        ALOGE("bufferDumpHelper() failed with %d", err);
        return "";
    }

    return stream.str();
}

std::string Gralloc4Mapper::dumpBuffers(bool less) const {
    hidl_vec<BufferDump> bufferDumps;
    Error error;
    auto ret = mMapper->dumpBuffers([&](const auto& tmpError, const auto& tmpBufferDump) {
        error = tmpError;
        bufferDumps = tmpBufferDump;
    });

    if (!ret.isOk()) {
        error = kTransactionError;
    }

    if (error != Error::NONE) {
        ALOGE("dumpBuffer() failed with %d", error);
        return "";
    }

    uint64_t totalAllocationSize = 0;
    std::ostringstream stream;
    stream.precision(2);

    stream << "Imported gralloc buffers:\n";

    for (const auto& bufferDump : bufferDumps) {
        uint64_t allocationSize = 0;
        status_t err = bufferDumpHelper(bufferDump, &stream, &allocationSize, less);
        if (err != NO_ERROR) {
            ALOGE("bufferDumpHelper() failed with %d", err);
            return "";
        }
        totalAllocationSize += allocationSize;
    }

    double totalAllocationSizeKiB = static_cast<double>(totalAllocationSize) / 1024;
    stream << "Total imported by gralloc: " << totalAllocationSizeKiB << "KiB\n";
    return stream.str();
}

Gralloc4Allocator::Gralloc4Allocator(const Gralloc4Mapper& mapper) : mMapper(mapper) {
    mAllocator = IAllocator::getService();
    if (__builtin_available(android 31, *)) {
        if (hasIAllocatorAidl()) {
            // TODO(b/269517338): Perform the isolated checking for this in service manager instead.
            uid_t aid = multiuser_get_app_id(getuid());
            if (aid >= AID_ISOLATED_START && aid <= AID_ISOLATED_END) {
                mAidlAllocator = AidlIAllocator::fromBinder(ndk::SpAIBinder(
                        AServiceManager_getService(kAidlAllocatorServiceName.c_str())));
            } else {
                mAidlAllocator = AidlIAllocator::fromBinder(ndk::SpAIBinder(
                        AServiceManager_waitForService(kAidlAllocatorServiceName.c_str())));
            }
            ALOGE_IF(!mAidlAllocator, "AIDL IAllocator declared but failed to get service");
        }
    }
    if (mAllocator == nullptr && mAidlAllocator == nullptr) {
        ALOGW("allocator 4.x is not supported");
        return;
    }
}

bool Gralloc4Allocator::isLoaded() const {
    return mAllocator != nullptr || mAidlAllocator != nullptr;
}

std::string Gralloc4Allocator::dumpDebugInfo(bool less) const {
    return mMapper.dumpBuffers(less);
}

status_t Gralloc4Allocator::allocate(std::string requestorName, uint32_t width, uint32_t height,
                                     android::PixelFormat format, uint32_t layerCount,
                                     uint64_t usage, uint32_t bufferCount, uint32_t* outStride,
                                     buffer_handle_t* outBufferHandles, bool importBuffers) const {
    IMapper::BufferDescriptorInfo descriptorInfo;
    if (auto error = sBufferDescriptorInfo(requestorName, width, height, format, layerCount, usage,
                                           &descriptorInfo) != OK) {
        return error;
    }

    BufferDescriptor descriptor;
    status_t error = mMapper.createDescriptor(static_cast<void*>(&descriptorInfo),
                                              static_cast<void*>(&descriptor));
    if (error != NO_ERROR) {
        return error;
    }

    if (mAidlAllocator) {
        AllocationResult result;
        auto status = mAidlAllocator->allocate(descriptor, bufferCount, &result);
        if (!status.isOk()) {
            error = status.getExceptionCode();
            if (error == EX_SERVICE_SPECIFIC) {
                error = status.getServiceSpecificError();
            }
            if (error == OK) {
                error = UNKNOWN_ERROR;
            }
        } else {
            if (importBuffers) {
                for (uint32_t i = 0; i < bufferCount; i++) {
                    auto handle = makeFromAidl(result.buffers[i]);
                    error = mMapper.importBuffer(handle, &outBufferHandles[i]);
                    native_handle_delete(handle);
                    if (error != NO_ERROR) {
                        for (uint32_t j = 0; j < i; j++) {
                            mMapper.freeBuffer(outBufferHandles[j]);
                            outBufferHandles[j] = nullptr;
                        }
                        break;
                    }
                }
            } else {
                for (uint32_t i = 0; i < bufferCount; i++) {
                    outBufferHandles[i] = dupFromAidl(result.buffers[i]);
                    if (!outBufferHandles[i]) {
                        for (uint32_t j = 0; j < i; j++) {
                            auto buffer = const_cast<native_handle_t*>(outBufferHandles[j]);
                            native_handle_close(buffer);
                            native_handle_delete(buffer);
                            outBufferHandles[j] = nullptr;
                        }
                    }
                }
            }
        }
        *outStride = result.stride;
        // Release all the resources held by AllocationResult (specifically any remaining FDs)
        result = {};
        // make sure the kernel driver sees BC_FREE_BUFFER and closes the fds now
        hardware::IPCThreadState::self()->flushCommands();
        return error;
    }

    auto ret = mAllocator->allocate(descriptor, bufferCount,
                                    [&](const auto& tmpError, const auto& tmpStride,
                                        const auto& tmpBuffers) {
                                        error = static_cast<status_t>(tmpError);
                                        if (tmpError != Error::NONE) {
                                            return;
                                        }

                                        if (importBuffers) {
                                            for (uint32_t i = 0; i < bufferCount; i++) {
                                                error = mMapper.importBuffer(tmpBuffers[i],
                                                                             &outBufferHandles[i]);
                                                if (error != NO_ERROR) {
                                                    for (uint32_t j = 0; j < i; j++) {
                                                        mMapper.freeBuffer(outBufferHandles[j]);
                                                        outBufferHandles[j] = nullptr;
                                                    }
                                                    return;
                                                }
                                            }
                                        } else {
                                            for (uint32_t i = 0; i < bufferCount; i++) {
                                                outBufferHandles[i] = native_handle_clone(
                                                        tmpBuffers[i].getNativeHandle());
                                                if (!outBufferHandles[i]) {
                                                    for (uint32_t j = 0; j < i; j++) {
                                                        auto buffer = const_cast<native_handle_t*>(
                                                                outBufferHandles[j]);
                                                        native_handle_close(buffer);
                                                        native_handle_delete(buffer);
                                                        outBufferHandles[j] = nullptr;
                                                    }
                                                }
                                            }
                                        }
                                        *outStride = tmpStride;
                                    });

    // make sure the kernel driver sees BC_FREE_BUFFER and closes the fds now
    hardware::IPCThreadState::self()->flushCommands();

    return (ret.isOk()) ? error : static_cast<status_t>(kTransactionError);
}

} // namespace android
