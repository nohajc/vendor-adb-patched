/*
 * Copyright 2021 The Android Open Source Project
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

#include "DisplayMode.h"

#include <cstdint>
#include <optional>
#include <vector>

#include <ui/GraphicTypes.h>
#include <ui/HdrCapabilities.h>
#include <utils/Flattenable.h>

namespace android::ui {

// Information about a physical display which may change on hotplug reconnect.
struct DynamicDisplayInfo : LightFlattenable<DynamicDisplayInfo> {
    std::vector<ui::DisplayMode> supportedDisplayModes;

    // This struct is going to be serialized over binder, so
    // we can't use size_t because it may have different width
    // in the client process.
    int32_t activeDisplayModeId;

    std::vector<ui::ColorMode> supportedColorModes;
    ui::ColorMode activeColorMode;
    HdrCapabilities hdrCapabilities;

    // True if the display reports support for HDMI 2.1 Auto Low Latency Mode.
    // For more information, see the HDMI 2.1 specification.
    bool autoLowLatencyModeSupported;

    // True if the display reports support for Game Content Type.
    // For more information, see the HDMI 1.4 specification.
    bool gameContentTypeSupported;

    std::optional<ui::DisplayMode> getActiveDisplayMode() const;

    bool isFixedSize() const { return false; }
    size_t getFlattenedSize() const;
    status_t flatten(void* buffer, size_t size) const;
    status_t unflatten(const void* buffer, size_t size);
};

} // namespace android::ui
