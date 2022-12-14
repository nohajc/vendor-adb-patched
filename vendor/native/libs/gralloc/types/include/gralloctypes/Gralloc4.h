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

#pragma once

#include <aidl/android/hardware/graphics/common/BlendMode.h>
#include <aidl/android/hardware/graphics/common/ChromaSiting.h>
#include <aidl/android/hardware/graphics/common/Compression.h>
#include <aidl/android/hardware/graphics/common/Cta861_3.h>
#include <aidl/android/hardware/graphics/common/Dataspace.h>
#include <aidl/android/hardware/graphics/common/ExtendableType.h>
#include <aidl/android/hardware/graphics/common/Interlaced.h>
#include <aidl/android/hardware/graphics/common/PlaneLayout.h>
#include <aidl/android/hardware/graphics/common/PlaneLayoutComponentType.h>
#include <aidl/android/hardware/graphics/common/Rect.h>
#include <aidl/android/hardware/graphics/common/Smpte2086.h>
#include <aidl/android/hardware/graphics/common/StandardMetadataType.h>
#include <aidl/android/hardware/graphics/common/XyColor.h>
#include <android/hardware/graphics/mapper/4.0/IMapper.h>

namespace android {
namespace gralloc4 {

#define GRALLOC4_STANDARD_METADATA_TYPE "android.hardware.graphics.common.StandardMetadataType"
#define GRALLOC4_STANDARD_CHROMA_SITING "android.hardware.graphics.common.ChromaSiting"
#define GRALLOC4_STANDARD_COMPRESSION "android.hardware.graphics.common.Compression"
#define GRALLOC4_STANDARD_INTERLACED "android.hardware.graphics.common.Interlaced"
#define GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE \
    "android.hardware.graphics.common.PlaneLayoutComponentType"

/*---------------------------------------------------------------------------------------------*/
/**
 * Definitions of the standard buffer metadata types. It is recommended that everyone uses
 * these definitions directly for standard buffer metadata types.
 */
static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_BufferId = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::BUFFER_ID)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_Name = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::NAME)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_Width = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::WIDTH)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_Height = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::HEIGHT)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_LayerCount = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::LAYER_COUNT)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_PixelFormatRequested = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::PIXEL_FORMAT_REQUESTED)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_PixelFormatFourCC = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::PIXEL_FORMAT_FOURCC)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_PixelFormatModifier = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::PIXEL_FORMAT_MODIFIER)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_Usage = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::USAGE)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_AllocationSize = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::ALLOCATION_SIZE)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_ProtectedContent = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::PROTECTED_CONTENT)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_Compression = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::COMPRESSION)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_Interlaced = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::INTERLACED)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_ChromaSiting = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::CHROMA_SITING)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_PlaneLayouts = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::PLANE_LAYOUTS)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_Crop = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::CROP)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_Dataspace = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::DATASPACE)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType MetadataType_BlendMode = {
        GRALLOC4_STANDARD_METADATA_TYPE, static_cast<int64_t>(aidl::android::hardware::graphics::common::StandardMetadataType::BLEND_MODE)
};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType
        MetadataType_Smpte2086 = {GRALLOC4_STANDARD_METADATA_TYPE,
                                  static_cast<int64_t>(aidl::android::hardware::graphics::common::
                                                               StandardMetadataType::SMPTE2086)};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType
        MetadataType_Cta861_3 = {GRALLOC4_STANDARD_METADATA_TYPE,
                                 static_cast<int64_t>(aidl::android::hardware::graphics::common::
                                                              StandardMetadataType::CTA861_3)};

static const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType
        MetadataType_Smpte2094_40 = {GRALLOC4_STANDARD_METADATA_TYPE,
                                     static_cast<int64_t>(
                                             aidl::android::hardware::graphics::common::
                                                     StandardMetadataType::SMPTE2094_40)};

/*---------------------------------------------------------------------------------------------*/

/**
 * Definitions of the standard compression strategies. It is recommended that everyone uses
 * these definitions directly for standard compression strategies.
 */
static const aidl::android::hardware::graphics::common::ExtendableType Compression_None =
        {GRALLOC4_STANDARD_COMPRESSION,
         static_cast<int64_t>(aidl::android::hardware::graphics::common::Compression::NONE)};

static const aidl::android::hardware::graphics::common::ExtendableType
        Compression_DisplayStreamCompression =
                {GRALLOC4_STANDARD_COMPRESSION,
                 static_cast<int64_t>(aidl::android::hardware::graphics::common::Compression::
                                              DISPLAY_STREAM_COMPRESSION)};

/*---------------------------------------------------------------------------------------------*/

/**
 * Definitions of the standard interlaced strategies. It is recommended that everyone uses
 * these definitions directly for standard interlaced strategies.
 */
static const aidl::android::hardware::graphics::common::ExtendableType Interlaced_None =
        {GRALLOC4_STANDARD_INTERLACED,
         static_cast<int64_t>(aidl::android::hardware::graphics::common::Interlaced::NONE)};

static const aidl::android::hardware::graphics::common::ExtendableType Interlaced_TopBottom =
        {GRALLOC4_STANDARD_INTERLACED,
         static_cast<int64_t>(aidl::android::hardware::graphics::common::Interlaced::TOP_BOTTOM)};

static const aidl::android::hardware::graphics::common::ExtendableType Interlaced_RightLeft =
        {GRALLOC4_STANDARD_INTERLACED,
         static_cast<int64_t>(aidl::android::hardware::graphics::common::Interlaced::RIGHT_LEFT)};

/*---------------------------------------------------------------------------------------------*/

/**
 * Definitions of the standard chroma siting. It is recommended that everyone uses
 * these definitions directly for standard chroma siting.
 */
static const aidl::android::hardware::graphics::common::ExtendableType ChromaSiting_None =
        {GRALLOC4_STANDARD_CHROMA_SITING,
         static_cast<int64_t>(aidl::android::hardware::graphics::common::ChromaSiting::NONE)};

static const aidl::android::hardware::graphics::common::ExtendableType ChromaSiting_Unknown =
        {GRALLOC4_STANDARD_CHROMA_SITING,
         static_cast<int64_t>(aidl::android::hardware::graphics::common::ChromaSiting::UNKNOWN)};

static const aidl::android::hardware::graphics::common::ExtendableType
        ChromaSiting_SitedInterstitial = {GRALLOC4_STANDARD_CHROMA_SITING,
                                          static_cast<int64_t>(
                                                  aidl::android::hardware::graphics::common::
                                                          ChromaSiting::SITED_INTERSTITIAL)};

static const aidl::android::hardware::graphics::common::ExtendableType
        ChromaSiting_CositedHorizontal = {GRALLOC4_STANDARD_CHROMA_SITING,
                                          static_cast<int64_t>(
                                                  aidl::android::hardware::graphics::common::
                                                          ChromaSiting::COSITED_HORIZONTAL)};

/*---------------------------------------------------------------------------------------------*/

/**
 * Definitions of the standard plane layout component types. It is recommended that everyone uses
 * these definitions directly for standard plane layout component types
 */
static const aidl::android::hardware::graphics::common::ExtendableType PlaneLayoutComponentType_Y =
        {GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
         static_cast<int64_t>(
                 aidl::android::hardware::graphics::common::PlaneLayoutComponentType::Y)};

static const aidl::android::hardware::graphics::common::ExtendableType PlaneLayoutComponentType_CB =
        {GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
         static_cast<int64_t>(
                 aidl::android::hardware::graphics::common::PlaneLayoutComponentType::CB)};

static const aidl::android::hardware::graphics::common::ExtendableType PlaneLayoutComponentType_CR =
        {GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
         static_cast<int64_t>(
                 aidl::android::hardware::graphics::common::PlaneLayoutComponentType::CR)};

static const aidl::android::hardware::graphics::common::ExtendableType PlaneLayoutComponentType_R =
        {GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
         static_cast<int64_t>(
                 aidl::android::hardware::graphics::common::PlaneLayoutComponentType::R)};

static const aidl::android::hardware::graphics::common::ExtendableType PlaneLayoutComponentType_G =
        {GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
         static_cast<int64_t>(
                 aidl::android::hardware::graphics::common::PlaneLayoutComponentType::G)};

static const aidl::android::hardware::graphics::common::ExtendableType PlaneLayoutComponentType_B =
        {GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
         static_cast<int64_t>(
                 aidl::android::hardware::graphics::common::PlaneLayoutComponentType::B)};

static const aidl::android::hardware::graphics::common::ExtendableType PlaneLayoutComponentType_A =
        {GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
         static_cast<int64_t>(
                 aidl::android::hardware::graphics::common::PlaneLayoutComponentType::A)};

static const aidl::android::hardware::graphics::common::ExtendableType
        PlaneLayoutComponentType_RAW =
                {GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
                 static_cast<int64_t>(
                         aidl::android::hardware::graphics::common::PlaneLayoutComponentType::RAW)};

/*---------------------------------------------------------------------------------------------*/

/**
 * The functions below encode and decode BufferDescriptorInfo into a byte stream.
 */
status_t encodeBufferDescriptorInfo(const android::hardware::graphics::mapper::V4_0::IMapper::BufferDescriptorInfo& bufferDescriptorInfo, android::hardware::hidl_vec<uint8_t>* outBufferDescriptorInfo);
status_t decodeBufferDescriptorInfo(const android::hardware::hidl_vec<uint8_t>& bufferDescriptorInfo, android::hardware::graphics::mapper::V4_0::IMapper::BufferDescriptorInfo* outBufferDescriptorInfo);

/**
 * The functions below encode and decode standard metadata into a byte stream. It is STRONGLY
 * recommended that both the vendor and system partitions use these functions when getting
 * and setting metadata through gralloc 4 (IMapper 4.0).
 */
status_t encodeBufferId(uint64_t bufferId, android::hardware::hidl_vec<uint8_t>* outBufferId);
status_t decodeBufferId(const android::hardware::hidl_vec<uint8_t>& bufferId, uint64_t* outBufferId);

status_t encodeName(const std::string& name, android::hardware::hidl_vec<uint8_t>* outName);
status_t decodeName(const android::hardware::hidl_vec<uint8_t>& name, std::string* outName);

status_t encodeWidth(uint64_t width, android::hardware::hidl_vec<uint8_t>* outWidth);
status_t decodeWidth(const android::hardware::hidl_vec<uint8_t>& width, uint64_t* outWidth);

status_t encodeHeight(uint64_t height, android::hardware::hidl_vec<uint8_t>* outHeight);
status_t decodeHeight(const android::hardware::hidl_vec<uint8_t>& height, uint64_t* outHeight);

status_t encodeLayerCount(uint64_t layerCount, android::hardware::hidl_vec<uint8_t>* outLayerCount);
status_t decodeLayerCount(const android::hardware::hidl_vec<uint8_t>& layerCount, uint64_t* outLayerCount);

status_t encodePixelFormatRequested(const hardware::graphics::common::V1_2::PixelFormat& pixelFormatRequested, android::hardware::hidl_vec<uint8_t>* outPixelFormatRequested);
status_t decodePixelFormatRequested(const android::hardware::hidl_vec<uint8_t>& pixelFormatRequested, hardware::graphics::common::V1_2::PixelFormat* outPixelFormatRequested);

status_t encodePixelFormatFourCC(uint32_t pixelFormatFourCC, android::hardware::hidl_vec<uint8_t>* outPixelFormatFourCC);
status_t decodePixelFormatFourCC(const android::hardware::hidl_vec<uint8_t>& pixelFormatFourCC, uint32_t* outPixelFormatFourCC);

status_t encodePixelFormatModifier(uint64_t pixelFormatModifier, android::hardware::hidl_vec<uint8_t>* outPixelFormatModifier);
status_t decodePixelFormatModifier(const android::hardware::hidl_vec<uint8_t>& pixelFormatModifier, uint64_t* outPixelFormatModifier);

status_t encodeUsage(uint64_t usage, android::hardware::hidl_vec<uint8_t>* outUsage);
status_t decodeUsage(const android::hardware::hidl_vec<uint8_t>& usage, uint64_t* outUsage);

status_t encodeAllocationSize(uint64_t allocationSize, android::hardware::hidl_vec<uint8_t>* outAllocationSize);
status_t decodeAllocationSize(const android::hardware::hidl_vec<uint8_t>& allocationSize, uint64_t* outAllocationSize);

status_t encodeProtectedContent(uint64_t protectedContent, android::hardware::hidl_vec<uint8_t>* outProtectedContent);
status_t decodeProtectedContent(const android::hardware::hidl_vec<uint8_t>& protectedContent, uint64_t* outProtectedContent);

status_t encodeCompression(const aidl::android::hardware::graphics::common::ExtendableType& compression, android::hardware::hidl_vec<uint8_t>* outCompression);
status_t decodeCompression(const android::hardware::hidl_vec<uint8_t>& compression, aidl::android::hardware::graphics::common::ExtendableType* outCompression);

status_t encodeInterlaced(const aidl::android::hardware::graphics::common::ExtendableType& interlaced, android::hardware::hidl_vec<uint8_t>* outInterlaced);
status_t decodeInterlaced(const android::hardware::hidl_vec<uint8_t>& interlaced, aidl::android::hardware::graphics::common::ExtendableType* outInterlaced);

status_t encodeChromaSiting(const aidl::android::hardware::graphics::common::ExtendableType& chromaSiting, android::hardware::hidl_vec<uint8_t>* outChromaSiting);
status_t decodeChromaSiting(const android::hardware::hidl_vec<uint8_t>& chromaSiting, aidl::android::hardware::graphics::common::ExtendableType* outChromaSiting);

status_t encodePlaneLayouts(const std::vector<aidl::android::hardware::graphics::common::PlaneLayout>& planeLayouts, android::hardware::hidl_vec<uint8_t>* outPlaneLayouts);
status_t decodePlaneLayouts(const android::hardware::hidl_vec<uint8_t>& planeLayouts, std::vector<aidl::android::hardware::graphics::common::PlaneLayout>* outPlaneLayouts);

status_t encodeCrop(const std::vector<aidl::android::hardware::graphics::common::Rect>& crop, android::hardware::hidl_vec<uint8_t>* outCrop);
status_t decodeCrop(const android::hardware::hidl_vec<uint8_t>& crop, std::vector<aidl::android::hardware::graphics::common::Rect>* outCrop);

status_t encodeDataspace(const aidl::android::hardware::graphics::common::Dataspace& dataspace, android::hardware::hidl_vec<uint8_t>* outDataspace);
status_t decodeDataspace(const android::hardware::hidl_vec<uint8_t>& dataspace, aidl::android::hardware::graphics::common::Dataspace* outDataspace);

status_t encodeBlendMode(const aidl::android::hardware::graphics::common::BlendMode& blendMode, android::hardware::hidl_vec<uint8_t>* outBlendMode);
status_t decodeBlendMode(const android::hardware::hidl_vec<uint8_t>& blendMode, aidl::android::hardware::graphics::common::BlendMode* outBlendMode);

status_t encodeSmpte2086(
        const std::optional<aidl::android::hardware::graphics::common::Smpte2086>& smpte2086,
        android::hardware::hidl_vec<uint8_t>* outSmpte2086);
status_t decodeSmpte2086(
        const android::hardware::hidl_vec<uint8_t>& smpte2086,
        std::optional<aidl::android::hardware::graphics::common::Smpte2086>* outSmpte2086);

status_t encodeCta861_3(
        const std::optional<aidl::android::hardware::graphics::common::Cta861_3>& cta861_3,
        android::hardware::hidl_vec<uint8_t>* outCta861_3);
status_t decodeCta861_3(
        const android::hardware::hidl_vec<uint8_t>& cta861_3,
        std::optional<aidl::android::hardware::graphics::common::Cta861_3>* outCta861_3);

status_t encodeSmpte2094_40(const std::optional<std::vector<uint8_t>>& smpte2094_40,
                            android::hardware::hidl_vec<uint8_t>* outSmpte2094_40);
status_t decodeSmpte2094_40(const android::hardware::hidl_vec<uint8_t>& smpte2094_40,
                            std::optional<std::vector<uint8_t>>* outSmpte2094_40);

/**
 * The functions below can be used to encode and decode vendor metadata types.
 */
status_t encodeUint32(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        uint32_t input, android::hardware::hidl_vec<uint8_t>* output);
status_t decodeUint32(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        const android::hardware::hidl_vec<uint8_t>& input, uint32_t* output);

status_t encodeInt32(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        int32_t input, android::hardware::hidl_vec<uint8_t>* output);
status_t decodeInt32(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        const android::hardware::hidl_vec<uint8_t>& input, int32_t* output);

status_t encodeUint64(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        uint64_t input, android::hardware::hidl_vec<uint8_t>* output);
status_t decodeUint64(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        const android::hardware::hidl_vec<uint8_t>& input, uint64_t* output);

status_t encodeInt64(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        int64_t input, android::hardware::hidl_vec<uint8_t>* output);
status_t decodeInt64(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        const android::hardware::hidl_vec<uint8_t>& input, int64_t* output);

status_t encodeFloat(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        float input, android::hardware::hidl_vec<uint8_t>* output);
status_t decodeFloat(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        const android::hardware::hidl_vec<uint8_t>& input, float* output);

status_t encodeDouble(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        double input, android::hardware::hidl_vec<uint8_t>* output);
status_t decodeDouble(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        const android::hardware::hidl_vec<uint8_t>& input, double* output);

status_t encodeString(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        const std::string& input, android::hardware::hidl_vec<uint8_t>* output);
status_t decodeString(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType,
        const android::hardware::hidl_vec<uint8_t>& input, std::string* output);

/**
 * The functions below can be used to parse extendable types.
 */
bool isStandardMetadataType(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType);
bool isStandardCompression(
        const aidl::android::hardware::graphics::common::ExtendableType& compression);
bool isStandardInterlaced(
        const aidl::android::hardware::graphics::common::ExtendableType& interlaced);
bool isStandardChromaSiting(
        const aidl::android::hardware::graphics::common::ExtendableType& chromaSiting);
bool isStandardPlaneLayoutComponentType(
        const aidl::android::hardware::graphics::common::ExtendableType& planeLayoutComponentType);

aidl::android::hardware::graphics::common::StandardMetadataType getStandardMetadataTypeValue(
        const android::hardware::graphics::mapper::V4_0::IMapper::MetadataType& metadataType);
aidl::android::hardware::graphics::common::Compression getStandardCompressionValue(
        const aidl::android::hardware::graphics::common::ExtendableType& compression);
aidl::android::hardware::graphics::common::Interlaced getStandardInterlacedValue(
        const aidl::android::hardware::graphics::common::ExtendableType& interlaced);
aidl::android::hardware::graphics::common::ChromaSiting getStandardChromaSitingValue(
        const aidl::android::hardware::graphics::common::ExtendableType& chromaSiting);
aidl::android::hardware::graphics::common::PlaneLayoutComponentType
getStandardPlaneLayoutComponentTypeValue(
        const aidl::android::hardware::graphics::common::ExtendableType& planeLayoutComponentType);

/**
 * The functions below return string representations of ExtendableTypes
 */
std::string getCompressionName(
        const aidl::android::hardware::graphics::common::ExtendableType& compression);
std::string getInterlacedName(
        const aidl::android::hardware::graphics::common::ExtendableType& interlaced);
std::string getChromaSitingName(
        const aidl::android::hardware::graphics::common::ExtendableType& chromaSiting);
std::string getPlaneLayoutComponentTypeName(
        const aidl::android::hardware::graphics::common::ExtendableType& planeLayoutComponentType);

} // namespace gralloc4

} // namespace android
