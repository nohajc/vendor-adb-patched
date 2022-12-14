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

#include <ui/DisplayId.h>
#include <ui/Size.h>
#include <ui/StaticDisplayInfo.h>

#include "DisplayHardware/PowerAdvisor.h"

namespace android::compositionengine {

class CompositionEngine;

/**
 * A parameter object for creating Display instances
 */
struct DisplayCreationArgs {
    DisplayId id;

    // Size of the display in pixels
    ui::Size pixels = ui::kInvalidSize;

    // True if this display should be considered secure
    bool isSecure = false;

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

    DisplayCreationArgsBuilder& setId(DisplayId id) {
        mArgs.id = id;
        return *this;
    }

    DisplayCreationArgsBuilder& setPixels(ui::Size pixels) {
        mArgs.pixels = pixels;
        return *this;
    }

    DisplayCreationArgsBuilder& setIsSecure(bool isSecure) {
        mArgs.isSecure = isSecure;
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
