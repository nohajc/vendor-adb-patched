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

#include <cstdint>
#include <optional>
#include <string>

namespace android {

// ID of a physical or a virtual display. This class acts as a type safe wrapper around uint64_t.
// The encoding of the ID is type-specific for bits 0 to 61.
struct DisplayId {
    // Flag indicating that the display is virtual.
    static constexpr uint64_t FLAG_VIRTUAL = 1ULL << 63;

    // Flag indicating that the ID is stable across reboots.
    static constexpr uint64_t FLAG_STABLE = 1ULL << 62;

    // TODO(b/162612135) Remove default constructor
    DisplayId() = default;
    constexpr DisplayId(const DisplayId&) = default;
    DisplayId& operator=(const DisplayId&) = default;

    uint64_t value;

    // For deserialization.
    static constexpr std::optional<DisplayId> fromValue(uint64_t);

    // As above, but also upcast to Id.
    template <typename Id>
    static constexpr std::optional<Id> fromValue(uint64_t value) {
        if (const auto id = Id::tryCast(DisplayId(value))) {
            return id;
        }
        return {};
    }

protected:
    explicit constexpr DisplayId(uint64_t id) : value(id) {}
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

// DisplayId of a physical display, such as the internal display or externally connected display.
struct PhysicalDisplayId : DisplayId {
    static constexpr std::optional<PhysicalDisplayId> tryCast(DisplayId id) {
        if (id.value & FLAG_VIRTUAL) {
            return std::nullopt;
        }
        return {PhysicalDisplayId(id)};
    }

    // Returns a stable ID based on EDID information.
    static constexpr PhysicalDisplayId fromEdid(uint8_t port, uint16_t manufacturerId,
                                                uint32_t modelHash) {
        return PhysicalDisplayId(FLAG_STABLE, port, manufacturerId, modelHash);
    }

    // Returns an unstable ID. If EDID is available using "fromEdid" is preferred.
    static constexpr PhysicalDisplayId fromPort(uint8_t port) {
        constexpr uint16_t kManufacturerId = 0;
        constexpr uint32_t kModelHash = 0;
        return PhysicalDisplayId(0, port, kManufacturerId, kModelHash);
    }

    // TODO(b/162612135) Remove default constructor
    PhysicalDisplayId() = default;

    constexpr uint16_t getManufacturerId() const { return static_cast<uint16_t>(value >> 40); }
    constexpr uint8_t getPort() const { return static_cast<uint8_t>(value); }

private:
    constexpr PhysicalDisplayId(uint64_t flags, uint8_t port, uint16_t manufacturerId,
                                uint32_t modelHash)
          : DisplayId(flags | (static_cast<uint64_t>(manufacturerId) << 40) |
                      (static_cast<uint64_t>(modelHash) << 8) | port) {}

    explicit constexpr PhysicalDisplayId(DisplayId other) : DisplayId(other) {}
};

struct VirtualDisplayId : DisplayId {
    using BaseId = uint32_t;

    // Flag indicating that this virtual display is backed by the GPU.
    static constexpr uint64_t FLAG_GPU = 1ULL << 61;

    static constexpr std::optional<VirtualDisplayId> tryCast(DisplayId id) {
        if (id.value & FLAG_VIRTUAL) {
            return {VirtualDisplayId(id)};
        }
        return std::nullopt;
    }

protected:
    constexpr VirtualDisplayId(uint64_t flags, BaseId baseId)
          : DisplayId(DisplayId::FLAG_VIRTUAL | flags | baseId) {}

    explicit constexpr VirtualDisplayId(DisplayId other) : DisplayId(other) {}
};

struct HalVirtualDisplayId : VirtualDisplayId {
    explicit constexpr HalVirtualDisplayId(BaseId baseId) : VirtualDisplayId(0, baseId) {}

    static constexpr std::optional<HalVirtualDisplayId> tryCast(DisplayId id) {
        if ((id.value & FLAG_VIRTUAL) && !(id.value & VirtualDisplayId::FLAG_GPU)) {
            return {HalVirtualDisplayId(id)};
        }
        return std::nullopt;
    }

private:
    explicit constexpr HalVirtualDisplayId(DisplayId other) : VirtualDisplayId(other) {}
};

struct GpuVirtualDisplayId : VirtualDisplayId {
    explicit constexpr GpuVirtualDisplayId(BaseId baseId)
          : VirtualDisplayId(VirtualDisplayId::FLAG_GPU, baseId) {}

    static constexpr std::optional<GpuVirtualDisplayId> tryCast(DisplayId id) {
        if ((id.value & FLAG_VIRTUAL) && (id.value & VirtualDisplayId::FLAG_GPU)) {
            return {GpuVirtualDisplayId(id)};
        }
        return std::nullopt;
    }

private:
    explicit constexpr GpuVirtualDisplayId(DisplayId other) : VirtualDisplayId(other) {}
};

// HalDisplayId is the ID of a display which is managed by HWC.
// PhysicalDisplayId and HalVirtualDisplayId are implicitly convertible to HalDisplayId.
struct HalDisplayId : DisplayId {
    constexpr HalDisplayId(HalVirtualDisplayId other) : DisplayId(other) {}
    constexpr HalDisplayId(PhysicalDisplayId other) : DisplayId(other) {}

    static constexpr std::optional<HalDisplayId> tryCast(DisplayId id) {
        if (GpuVirtualDisplayId::tryCast(id)) {
            return std::nullopt;
        }
        return {HalDisplayId(id)};
    }

private:
    explicit constexpr HalDisplayId(DisplayId other) : DisplayId(other) {}
};

constexpr std::optional<DisplayId> DisplayId::fromValue(uint64_t value) {
    if (const auto id = fromValue<PhysicalDisplayId>(value)) {
        return id;
    }
    if (const auto id = fromValue<VirtualDisplayId>(value)) {
        return id;
    }
    return {};
}

static_assert(sizeof(DisplayId) == sizeof(uint64_t));
static_assert(sizeof(HalDisplayId) == sizeof(uint64_t));
static_assert(sizeof(VirtualDisplayId) == sizeof(uint64_t));

static_assert(sizeof(PhysicalDisplayId) == sizeof(uint64_t));
static_assert(sizeof(HalVirtualDisplayId) == sizeof(uint64_t));
static_assert(sizeof(GpuVirtualDisplayId) == sizeof(uint64_t));

} // namespace android

namespace std {

template <>
struct hash<android::DisplayId> {
    size_t operator()(android::DisplayId displayId) const {
        return hash<uint64_t>()(displayId.value);
    }
};

template <>
struct hash<android::PhysicalDisplayId> : hash<android::DisplayId> {};

template <>
struct hash<android::HalVirtualDisplayId> : hash<android::DisplayId> {};

template <>
struct hash<android::GpuVirtualDisplayId> : hash<android::DisplayId> {};

template <>
struct hash<android::HalDisplayId> : hash<android::DisplayId> {};

} // namespace std
