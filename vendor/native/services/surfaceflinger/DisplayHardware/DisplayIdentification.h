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

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ui/DeviceProductInfo.h>
#include <ui/PhysicalDisplayId.h>

#define LEGACY_DISPLAY_TYPE_PRIMARY 0
#define LEGACY_DISPLAY_TYPE_EXTERNAL 1

namespace android {

struct DisplayId {
    using Type = PhysicalDisplayId;
    Type value;

    uint16_t manufacturerId() const;

    static DisplayId fromEdid(uint8_t port, uint16_t manufacturerId, uint32_t modelHash);
};

inline bool operator==(DisplayId lhs, DisplayId rhs) {
    return lhs.value == rhs.value;
}

inline bool operator!=(DisplayId lhs, DisplayId rhs) {
    return !(lhs == rhs);
}

inline std::string to_string(DisplayId displayId) {
    return std::to_string(displayId.value);
}

using DisplayIdentificationData = std::vector<uint8_t>;

struct DisplayIdentificationInfo {
    DisplayId id;
    std::string name;
    std::optional<DeviceProductInfo> deviceProductInfo;
};

struct ExtensionBlock {
    uint8_t tag;
    uint8_t revisionNumber;
};

struct HdmiPhysicalAddress {
    // The address describes the path from the display sink in the network of connected HDMI
    // devices. The format of the address is "a.b.c.d". For example, address 2.1.0.0 means we are
    // connected to port 1 of a device which is connected to port 2 of the sink.
    uint8_t a, b, c, d;
};

struct HdmiVendorDataBlock {
    HdmiPhysicalAddress physicalAddress;
};

struct Cea861ExtensionBlock : ExtensionBlock {
    std::optional<HdmiVendorDataBlock> hdmiVendorDataBlock;
};

struct Edid {
    uint16_t manufacturerId;
    uint16_t productId;
    PnpId pnpId;
    uint32_t modelHash;
    std::string_view displayName;
    uint8_t manufactureOrModelYear;
    uint8_t manufactureWeek;
    std::optional<Cea861ExtensionBlock> cea861Block;
};

bool isEdid(const DisplayIdentificationData&);
std::optional<Edid> parseEdid(const DisplayIdentificationData&);
std::optional<PnpId> getPnpId(uint16_t manufacturerId);
std::optional<PnpId> getPnpId(DisplayId);

std::optional<DisplayIdentificationInfo> parseDisplayIdentificationData(
        uint8_t port, const DisplayIdentificationData&);

DisplayId getFallbackDisplayId(uint8_t port);
DisplayId getVirtualDisplayId(uint32_t id);

} // namespace android

namespace std {

template <>
struct hash<android::DisplayId> {
    size_t operator()(android::DisplayId displayId) const {
        return hash<android::DisplayId::Type>()(displayId.value);
    }
};

} // namespace std
