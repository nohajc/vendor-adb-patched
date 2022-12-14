/*
 * Copyright 2020 The Android Open Source Project
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
#include <type_traits>
#include <variant>
#include <vector>

#include <utils/Flattenable.h>

namespace android {

// NUL-terminated plug and play ID.
using PnpId = std::array<char, 4>;

// Product-specific information about the display or the directly connected device on the
// display chain. For example, if the display is transitively connected, this field may contain
// product information about the intermediate device.
struct DeviceProductInfo : LightFlattenable<DeviceProductInfo> {
    struct ModelYear {
        uint32_t year;
    };

    struct ManufactureYear : ModelYear {};

    struct ManufactureWeekAndYear : ManufactureYear {
        // 1-base week number. Week numbering may not be consistent between manufacturers.
        uint8_t week;
    };

    // Display name.
    std::string name;

    // Manufacturer Plug and Play ID.
    PnpId manufacturerPnpId;

    // Manufacturer product ID.
    std::string productId;

    using ManufactureOrModelDate = std::variant<ModelYear, ManufactureYear, ManufactureWeekAndYear>;
    static_assert(std::is_trivially_copyable_v<ManufactureOrModelDate>);
    ManufactureOrModelDate manufactureOrModelDate;

    // Relative address in the display network. Empty vector indicates that the
    // address is unavailable.
    // For example, for HDMI connected device this will be the physical address.
    std::vector<uint8_t> relativeAddress;

    bool isFixedSize() const { return false; }
    size_t getFlattenedSize() const;
    status_t flatten(void* buffer, size_t size) const;
    status_t unflatten(void const* buffer, size_t size);

    void dump(std::string& result) const;
};

} // namespace android
