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

#include <cstddef>
#include <memory>

#include <android-base/stringprintf.h>
#include <android/configuration.h>
#include <ftl/small_map.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMode.h>
#include <ui/Size.h>
#include <utils/Timers.h>

#include <scheduler/Fps.h>

#include "DisplayHardware/Hal.h"
#include "Scheduler/StrongTyping.h"

namespace android {

namespace hal = android::hardware::graphics::composer::hal;

class DisplayMode;
using DisplayModePtr = std::shared_ptr<const DisplayMode>;

// Prevent confusion with fps_approx_ops on the underlying Fps.
bool operator<(const DisplayModePtr&, const DisplayModePtr&) = delete;
bool operator>(const DisplayModePtr&, const DisplayModePtr&) = delete;
bool operator<=(const DisplayModePtr&, const DisplayModePtr&) = delete;
bool operator>=(const DisplayModePtr&, const DisplayModePtr&) = delete;

using DisplayModeId = StrongTyping<ui::DisplayModeId, struct DisplayModeIdTag, Compare>;

using DisplayModes = ftl::SmallMap<DisplayModeId, DisplayModePtr, 3>;
using DisplayModeIterator = DisplayModes::const_iterator;

class DisplayMode {
public:
    class Builder {
    public:
        explicit Builder(hal::HWConfigId id) : mDisplayMode(new DisplayMode(id)) {}

        DisplayModePtr build() {
            return std::const_pointer_cast<const DisplayMode>(std::move(mDisplayMode));
        }

        Builder& setId(DisplayModeId id) {
            mDisplayMode->mId = id;
            return *this;
        }

        Builder& setPhysicalDisplayId(PhysicalDisplayId id) {
            mDisplayMode->mPhysicalDisplayId = id;
            return *this;
        }

        Builder& setResolution(ui::Size resolution) {
            mDisplayMode->mResolution = resolution;
            return *this;
        }

        Builder& setVsyncPeriod(nsecs_t vsyncPeriod) {
            mDisplayMode->mFps = Fps::fromPeriodNsecs(vsyncPeriod);
            return *this;
        }

        Builder& setDpiX(int32_t dpiX) {
            if (dpiX == -1) {
                mDisplayMode->mDpi.x = getDefaultDensity();
            } else {
                mDisplayMode->mDpi.x = dpiX / 1000.f;
            }
            return *this;
        }

        Builder& setDpiY(int32_t dpiY) {
            if (dpiY == -1) {
                mDisplayMode->mDpi.y = getDefaultDensity();
            } else {
                mDisplayMode->mDpi.y = dpiY / 1000.f;
            }
            return *this;
        }

        Builder& setGroup(int32_t group) {
            mDisplayMode->mGroup = group;
            return *this;
        }

    private:
        float getDefaultDensity() {
            // Default density is based on TVs: 1080p displays get XHIGH density, lower-
            // resolution displays get TV density. Maybe eventually we'll need to update
            // it for 4k displays, though hopefully those will just report accurate DPI
            // information to begin with. This is also used for virtual displays and
            // older HWC implementations, so be careful about orientation.

            if (std::max(mDisplayMode->getWidth(), mDisplayMode->getHeight()) >= 1080) {
                return ACONFIGURATION_DENSITY_XHIGH;
            } else {
                return ACONFIGURATION_DENSITY_TV;
            }
        }

        std::shared_ptr<DisplayMode> mDisplayMode;
    };

    DisplayModeId getId() const { return mId; }

    hal::HWConfigId getHwcId() const { return mHwcId; }
    PhysicalDisplayId getPhysicalDisplayId() const { return mPhysicalDisplayId; }

    ui::Size getResolution() const { return mResolution; }
    int32_t getWidth() const { return mResolution.getWidth(); }
    int32_t getHeight() const { return mResolution.getHeight(); }

    Fps getFps() const { return mFps; }
    nsecs_t getVsyncPeriod() const { return mFps.getPeriodNsecs(); }

    struct Dpi {
        float x = -1;
        float y = -1;

        bool operator==(Dpi other) const { return x == other.x && y == other.y; }
    };

    Dpi getDpi() const { return mDpi; }

    // Switches between modes in the same group are seamless, i.e.
    // without visual interruptions such as a black screen.
    int32_t getGroup() const { return mGroup; }

private:
    explicit DisplayMode(hal::HWConfigId id) : mHwcId(id) {}

    const hal::HWConfigId mHwcId;
    DisplayModeId mId;

    PhysicalDisplayId mPhysicalDisplayId;

    ui::Size mResolution;
    Fps mFps;
    Dpi mDpi;
    int32_t mGroup = -1;
};

inline bool equalsExceptDisplayModeId(const DisplayMode& lhs, const DisplayMode& rhs) {
    return lhs.getHwcId() == rhs.getHwcId() && lhs.getResolution() == rhs.getResolution() &&
            lhs.getVsyncPeriod() == rhs.getVsyncPeriod() && lhs.getDpi() == rhs.getDpi() &&
            lhs.getGroup() == rhs.getGroup();
}

inline std::string to_string(const DisplayMode& mode) {
    return base::StringPrintf("{id=%d, hwcId=%d, resolution=%dx%d, refreshRate=%s, "
                              "dpi=%.2fx%.2f, group=%d}",
                              mode.getId().value(), mode.getHwcId(), mode.getWidth(),
                              mode.getHeight(), to_string(mode.getFps()).c_str(), mode.getDpi().x,
                              mode.getDpi().y, mode.getGroup());
}

template <typename... DisplayModePtrs>
inline DisplayModes makeModes(const DisplayModePtrs&... modePtrs) {
    DisplayModes modes;
    // Note: The omission of std::move(modePtrs) is intentional, because order of evaluation for
    // arguments is unspecified.
    (modes.try_emplace(modePtrs->getId(), modePtrs), ...);
    return modes;
}

} // namespace android
