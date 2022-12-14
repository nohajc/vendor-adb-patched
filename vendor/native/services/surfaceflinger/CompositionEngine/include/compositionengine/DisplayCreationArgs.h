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

#include <cstdint>
#include <optional>
#include <string>

#include <ui/DisplayInfo.h>
#include <ui/PixelFormat.h>
#include <ui/Size.h>

#include "DisplayHardware/DisplayIdentification.h"
#include "DisplayHardware/PowerAdvisor.h"

namespace android::compositionengine {

class CompositionEngine;

/**
 * A parameter object for creating Display instances
 */
struct DisplayCreationArgs {
    struct Physical {
        DisplayId id;
        DisplayConnectionType type;
    };

    // Required for physical displays. Gives the HWC display id for the existing
    // display along with the connection type.
    std::optional<Physical> physical;

    // Size of the display in pixels
    ui::Size pixels = ui::Size::INVALID;

    // Pixel format of the display
    ui::PixelFormat pixelFormat = static_cast<ui::PixelFormat>(PIXEL_FORMAT_UNKNOWN);

    // True if virtual displays should be created with the HWC API if possible
    bool useHwcVirtualDisplays = false;

    // True if this display should be considered secure
    bool isSecure = false;

    // Gives the initial layer stack id to be used for the display
    uint32_t layerStackId = ~0u;

    // Optional pointer to the power advisor interface, if one is needed for
    // this display.
    Hwc2::PowerAdvisor* powerAdvisor = nullptr;

    // Debugging. Human readable name for the display.
    std::string name;
};

/**
 * A helper for setting up a DisplayCreationArgs value in-line.
 * Prefer this builder over raw structure initialization.
 */
class DisplayCreationArgsBuilder {
public:
    DisplayCreationArgs build() { return std::move(mArgs); }

    DisplayCreationArgsBuilder& setPhysical(DisplayCreationArgs::Physical physical) {
        mArgs.physical = physical;
        return *this;
    }

    DisplayCreationArgsBuilder& setPixels(ui::Size pixels) {
        mArgs.pixels = pixels;
        return *this;
    }

    DisplayCreationArgsBuilder& setPixelFormat(ui::PixelFormat pixelFormat) {
        mArgs.pixelFormat = pixelFormat;
        return *this;
    }

    DisplayCreationArgsBuilder& setUseHwcVirtualDisplays(bool useHwcVirtualDisplays) {
        mArgs.useHwcVirtualDisplays = useHwcVirtualDisplays;
        return *this;
    }

    DisplayCreationArgsBuilder& setIsSecure(bool isSecure) {
        mArgs.isSecure = isSecure;
        return *this;
    }

    DisplayCreationArgsBuilder& setLayerStackId(uint32_t layerStackId) {
        mArgs.layerStackId = layerStackId;
        return *this;
    }

    DisplayCreationArgsBuilder& setPowerAdvisor(Hwc2::PowerAdvisor* powerAdvisor) {
        mArgs.powerAdvisor = powerAdvisor;
        return *this;
    }

    DisplayCreationArgsBuilder& setName(std::string name) {
        mArgs.name = std::move(name);
        return *this;
    }

private:
    DisplayCreationArgs mArgs;
};

} // namespace android::compositionengine
