/*
 * Copyright (C) 2018 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "DisplayIdentification"

#include <algorithm>
#include <cctype>
#include <numeric>
#include <optional>

#include <log/log.h>

#include <ui/DisplayIdentification.h>

namespace android {
namespace {

template <class T>
inline T load(const void* p) {
    static_assert(std::is_integral<T>::value, "T must be integral");

    T r;
    std::memcpy(&r, p, sizeof(r));
    return r;
}

uint64_t rotateByAtLeast1(uint64_t val, uint8_t shift) {
    return (val >> shift) | (val << (64 - shift));
}

uint64_t shiftMix(uint64_t val) {
    return val ^ (val >> 47);
}

uint64_t hash64Len16(uint64_t u, uint64_t v) {
    constexpr uint64_t kMul = 0x9ddfea08eb382d69;
    uint64_t a = (u ^ v) * kMul;
    a ^= (a >> 47);
    uint64_t b = (v ^ a) * kMul;
    b ^= (b >> 47);
    b *= kMul;
    return b;
}

uint64_t hash64Len0To16(const char* s, uint64_t len) {
    constexpr uint64_t k2 = 0x9ae16a3b2f90404f;
    constexpr uint64_t k3 = 0xc949d7c7509e6557;

    if (len > 8) {
        const uint64_t a = load<uint64_t>(s);
        const uint64_t b = load<uint64_t>(s + len - 8);
        return hash64Len16(a, rotateByAtLeast1(b + len, static_cast<uint8_t>(len))) ^ b;
    }
    if (len >= 4) {
        const uint32_t a = load<uint32_t>(s);
        const uint32_t b = load<uint32_t>(s + len - 4);
        return hash64Len16(len + (a << 3), b);
    }
    if (len > 0) {
        const unsigned char a = static_cast<unsigned char>(s[0]);
        const unsigned char b = static_cast<unsigned char>(s[len >> 1]);
        const unsigned char c = static_cast<unsigned char>(s[len - 1]);
        const uint32_t y = static_cast<uint32_t>(a) + (static_cast<uint32_t>(b) << 8);
        const uint32_t z = static_cast<uint32_t>(len) + (static_cast<uint32_t>(c) << 2);
        return shiftMix(y * k2 ^ z * k3) * k2;
    }
    return k2;
}

using byte_view = std::basic_string_view<uint8_t>;

constexpr size_t kEdidBlockSize = 128;
constexpr size_t kEdidHeaderLength = 5;

constexpr uint16_t kVirtualEdidManufacturerId = 0xffffu;

std::optional<uint8_t> getEdidDescriptorType(const byte_view& view) {
    if (view.size() < kEdidHeaderLength || view[0] || view[1] || view[2] || view[4]) {
        return {};
    }

    return view[3];
}

std::string_view parseEdidText(const byte_view& view) {
    std::string_view text(reinterpret_cast<const char*>(view.data()), view.size());
    text = text.substr(0, text.find('\n'));

    if (!std::all_of(text.begin(), text.end(), ::isprint)) {
        ALOGW("Invalid EDID: ASCII text is not printable.");
        return {};
    }

    return text;
}

// Big-endian 16-bit value encodes three 5-bit letters where A is 0b00001.
template <size_t I>
char getPnpLetter(uint16_t id) {
    static_assert(I < 3);
    const char letter = 'A' + (static_cast<uint8_t>(id >> ((2 - I) * 5)) & 0b00011111) - 1;
    return letter < 'A' || letter > 'Z' ? '\0' : letter;
}

DeviceProductInfo buildDeviceProductInfo(const Edid& edid) {
    DeviceProductInfo info;
    info.name.assign(edid.displayName);
    info.productId = std::to_string(edid.productId);
    info.manufacturerPnpId = edid.pnpId;

    constexpr uint8_t kModelYearFlag = 0xff;
    constexpr uint32_t kYearOffset = 1990;

    const auto year = edid.manufactureOrModelYear + kYearOffset;
    if (edid.manufactureWeek == kModelYearFlag) {
        info.manufactureOrModelDate = DeviceProductInfo::ModelYear{.year = year};
    } else if (edid.manufactureWeek == 0) {
        DeviceProductInfo::ManufactureYear date;
        date.year = year;
        info.manufactureOrModelDate = date;
    } else {
        DeviceProductInfo::ManufactureWeekAndYear date;
        date.year = year;
        date.week = edid.manufactureWeek;
        info.manufactureOrModelDate = date;
    }

    if (edid.cea861Block && edid.cea861Block->hdmiVendorDataBlock) {
        const auto& address = edid.cea861Block->hdmiVendorDataBlock->physicalAddress;
        info.relativeAddress = {address.a, address.b, address.c, address.d};
    }
    return info;
}

Cea861ExtensionBlock parseCea861Block(const byte_view& block) {
    Cea861ExtensionBlock cea861Block;

    constexpr size_t kRevisionNumberOffset = 1;
    cea861Block.revisionNumber = block[kRevisionNumberOffset];

    constexpr size_t kDetailedTimingDescriptorsOffset = 2;
    const size_t dtdStart =
            std::min(kEdidBlockSize, static_cast<size_t>(block[kDetailedTimingDescriptorsOffset]));

    // Parse data blocks.
    for (size_t dataBlockOffset = 4; dataBlockOffset < dtdStart;) {
        const uint8_t header = block[dataBlockOffset];
        const uint8_t tag = header >> 5;
        const size_t bodyLength = header & 0b11111;
        constexpr size_t kDataBlockHeaderSize = 1;
        const size_t dataBlockSize = bodyLength + kDataBlockHeaderSize;

        if (block.size() < dataBlockOffset + dataBlockSize) {
            ALOGW("Invalid EDID: CEA 861 data block is truncated.");
            break;
        }

        const byte_view dataBlock(block.data() + dataBlockOffset, dataBlockSize);
        constexpr uint8_t kVendorSpecificDataBlockTag = 0x3;

        if (tag == kVendorSpecificDataBlockTag) {
            const uint32_t ieeeRegistrationId = static_cast<uint32_t>(
                    dataBlock[1] | (dataBlock[2] << 8) | (dataBlock[3] << 16));
            constexpr uint32_t kHdmiIeeeRegistrationId = 0xc03;

            if (ieeeRegistrationId == kHdmiIeeeRegistrationId) {
                const uint8_t a = dataBlock[4] >> 4;
                const uint8_t b = dataBlock[4] & 0b1111;
                const uint8_t c = dataBlock[5] >> 4;
                const uint8_t d = dataBlock[5] & 0b1111;
                cea861Block.hdmiVendorDataBlock =
                        HdmiVendorDataBlock{.physicalAddress = HdmiPhysicalAddress{a, b, c, d}};
            } else {
                ALOGV("Ignoring vendor specific data block for vendor with IEEE OUI %x",
                      ieeeRegistrationId);
            }
        } else {
            ALOGV("Ignoring CEA-861 data block with tag %x", tag);
        }
        dataBlockOffset += bodyLength + kDataBlockHeaderSize;
    }

    return cea861Block;
}

} // namespace

bool isEdid(const DisplayIdentificationData& data) {
    const uint8_t kMagic[] = {0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0};
    return data.size() >= sizeof(kMagic) &&
            std::equal(std::begin(kMagic), std::end(kMagic), data.begin());
}

std::optional<Edid> parseEdid(const DisplayIdentificationData& edid) {
    if (edid.size() < kEdidBlockSize) {
        ALOGW("Invalid EDID: structure is truncated.");
        // Attempt parsing even if EDID is malformed.
    } else {
        ALOGW_IF(std::accumulate(edid.begin(), edid.begin() + kEdidBlockSize,
                                 static_cast<uint8_t>(0)),
                 "Invalid EDID: structure does not checksum.");
    }

    constexpr size_t kManufacturerOffset = 8;
    if (edid.size() < kManufacturerOffset + sizeof(uint16_t)) {
        ALOGE("Invalid EDID: manufacturer ID is truncated.");
        return {};
    }

    // Plug and play ID encoded as big-endian 16-bit value.
    const uint16_t manufacturerId =
            static_cast<uint16_t>((edid[kManufacturerOffset] << 8) | edid[kManufacturerOffset + 1]);

    const auto pnpId = getPnpId(manufacturerId);
    if (!pnpId) {
        ALOGE("Invalid EDID: manufacturer ID is not a valid PnP ID.");
        return {};
    }

    constexpr size_t kProductIdOffset = 10;
    if (edid.size() < kProductIdOffset + sizeof(uint16_t)) {
        ALOGE("Invalid EDID: product ID is truncated.");
        return {};
    }
    const uint16_t productId =
            static_cast<uint16_t>(edid[kProductIdOffset] | (edid[kProductIdOffset + 1] << 8));

    constexpr size_t kManufactureWeekOffset = 16;
    if (edid.size() < kManufactureWeekOffset + sizeof(uint8_t)) {
        ALOGE("Invalid EDID: manufacture week is truncated.");
        return {};
    }
    const uint8_t manufactureWeek = edid[kManufactureWeekOffset];
    ALOGW_IF(0x37 <= manufactureWeek && manufactureWeek <= 0xfe,
             "Invalid EDID: week of manufacture cannot be in the range [0x37, 0xfe].");

    constexpr size_t kManufactureYearOffset = 17;
    if (edid.size() < kManufactureYearOffset + sizeof(uint8_t)) {
        ALOGE("Invalid EDID: manufacture year is truncated.");
        return {};
    }
    const uint8_t manufactureOrModelYear = edid[kManufactureYearOffset];
    ALOGW_IF(manufactureOrModelYear <= 0xf,
             "Invalid EDID: model year or manufacture year cannot be in the range [0x0, 0xf].");

    constexpr size_t kDescriptorOffset = 54;
    if (edid.size() < kDescriptorOffset) {
        ALOGE("Invalid EDID: descriptors are missing.");
        return {};
    }

    byte_view view(edid.data(), edid.size());
    view.remove_prefix(kDescriptorOffset);

    std::string_view displayName;
    std::string_view serialNumber;
    std::string_view asciiText;

    constexpr size_t kDescriptorCount = 4;
    constexpr size_t kDescriptorLength = 18;

    for (size_t i = 0; i < kDescriptorCount; i++) {
        if (view.size() < kDescriptorLength) {
            break;
        }

        if (const auto type = getEdidDescriptorType(view)) {
            byte_view descriptor(view.data(), kDescriptorLength);
            descriptor.remove_prefix(kEdidHeaderLength);

            switch (*type) {
                case 0xfc:
                    displayName = parseEdidText(descriptor);
                    break;
                case 0xfe:
                    asciiText = parseEdidText(descriptor);
                    break;
                case 0xff:
                    serialNumber = parseEdidText(descriptor);
                    break;
            }
        }

        view.remove_prefix(kDescriptorLength);
    }

    std::string_view modelString = displayName;

    if (modelString.empty()) {
        ALOGW("Invalid EDID: falling back to serial number due to missing display name.");
        modelString = serialNumber;
    }
    if (modelString.empty()) {
        ALOGW("Invalid EDID: falling back to ASCII text due to missing serial number.");
        modelString = asciiText;
    }
    if (modelString.empty()) {
        ALOGE("Invalid EDID: display name and fallback descriptors are missing.");
        return {};
    }

    // Hash model string instead of using product code or (integer) serial number, since the latter
    // have been observed to change on some displays with multiple inputs. Use a stable hash instead
    // of std::hash which is only required to be same within a single execution of a program.
    const uint32_t modelHash = static_cast<uint32_t>(cityHash64Len0To16(modelString));

    // Parse extension blocks.
    std::optional<Cea861ExtensionBlock> cea861Block;
    if (edid.size() < kEdidBlockSize) {
        ALOGW("Invalid EDID: block 0 is truncated.");
    } else {
        constexpr size_t kNumExtensionsOffset = 126;
        const size_t numExtensions = edid[kNumExtensionsOffset];
        view = byte_view(edid.data(), edid.size());
        for (size_t blockNumber = 1; blockNumber <= numExtensions; blockNumber++) {
            view.remove_prefix(kEdidBlockSize);
            if (view.size() < kEdidBlockSize) {
                ALOGW("Invalid EDID: block %zu is truncated.", blockNumber);
                break;
            }

            const byte_view block(view.data(), kEdidBlockSize);
            ALOGW_IF(std::accumulate(block.begin(), block.end(), static_cast<uint8_t>(0)),
                     "Invalid EDID: block %zu does not checksum.", blockNumber);
            const uint8_t tag = block[0];

            constexpr uint8_t kCea861BlockTag = 0x2;
            if (tag == kCea861BlockTag) {
                cea861Block = parseCea861Block(block);
            } else {
                ALOGV("Ignoring block number %zu with tag %x.", blockNumber, tag);
            }
        }
    }

    return Edid{.manufacturerId = manufacturerId,
                .productId = productId,
                .pnpId = *pnpId,
                .modelHash = modelHash,
                .displayName = displayName,
                .manufactureOrModelYear = manufactureOrModelYear,
                .manufactureWeek = manufactureWeek,
                .cea861Block = cea861Block};
}

std::optional<PnpId> getPnpId(uint16_t manufacturerId) {
    const char a = getPnpLetter<0>(manufacturerId);
    const char b = getPnpLetter<1>(manufacturerId);
    const char c = getPnpLetter<2>(manufacturerId);
    return a && b && c ? std::make_optional(PnpId{a, b, c}) : std::nullopt;
}

std::optional<PnpId> getPnpId(PhysicalDisplayId displayId) {
    return getPnpId(displayId.getManufacturerId());
}

std::optional<DisplayIdentificationInfo> parseDisplayIdentificationData(
        uint8_t port, const DisplayIdentificationData& data) {
    if (!isEdid(data)) {
        ALOGE("Display identification data has unknown format.");
        return {};
    }

    const auto edid = parseEdid(data);
    if (!edid) {
        return {};
    }

    const auto displayId = PhysicalDisplayId::fromEdid(port, edid->manufacturerId, edid->modelHash);
    return DisplayIdentificationInfo{.id = displayId,
                                     .name = std::string(edid->displayName),
                                     .deviceProductInfo = buildDeviceProductInfo(*edid)};
}

PhysicalDisplayId getVirtualDisplayId(uint32_t id) {
    return PhysicalDisplayId::fromEdid(0, kVirtualEdidManufacturerId, id);
}

uint64_t cityHash64Len0To16(std::string_view sv) {
    auto len = sv.length();
    if (len > 16) {
        ALOGE("%s called with length %zu. Only hashing the first 16 chars", __FUNCTION__, len);
        len = 16;
    }
    return hash64Len0To16(sv.data(), len);
}

} // namespace android