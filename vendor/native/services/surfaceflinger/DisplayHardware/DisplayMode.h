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

#include "DisplayHardware/Hal.h"
#include "Fps.h"
#include "Scheduler/StrongTyping.h"

#include <android-base/stringprintf.h>
#include <android/configuration.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMode.h>
#include <ui/Size.h>
#include <utils/Timers.h>

#include <cstddef>
#include <memory>
#include <vector>

namespace android {

namespace hal = android::hardware::graphics::composer::hal;

class DisplayMode;
using DisplayModePtr = std::shared_ptr<const DisplayMode>;
using DisplayModes = std::vector<DisplayModePtr>;
using DisplayModeId = StrongTyping<ui::DisplayModeId, struct DisplayModeIdTag, Compare, Hash>;

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

        Builder& setWidth(int32_t width) {
            mDisplayMode->mWidth = width;
            return *this;
        }

        Builder& setHeight(int32_t height) {
            mDisplayMode->mHeight = height;
            return *this;
        }

        Builder& setVsyncPeriod(int32_t vsyncPeriod) {
            mDisplayMode->mFps = Fps::fromPeriodNsecs(vsyncPeriod);
            return *this;
        }

        Builder& setDpiX(int32_t dpiX) {
            if (dpiX == -1) {
                mDisplayMode->mDpiX = getDefaultDensity();
            } else {
                mDisplayMode->mDpiX = dpiX / 1000.0f;
            }
            return *this;
        }

        Builder& setDpiY(int32_t dpiY) {
            if (dpiY == -1) {
                mDisplayMode->mDpiY = getDefaultDensity();
            } else {
                mDisplayMode->mDpiY = dpiY / 1000.0f;
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

            auto longDimension = std::max(mDisplayMode->mWidth, mDisplayMode->mHeight);
            if (longDimension >= 1080) {
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

    int32_t getWidth() const { return mWidth; }
    int32_t getHeight() const { return mHeight; }
    ui::Size getSize() const { return {mWidth, mHeight}; }
    Fps getFps() const { return mFps; }
    nsecs_t getVsyncPeriod() const { return mFps.getPeriodNsecs(); }
    float getDpiX() const { return mDpiX; }
    float getDpiY() const { return mDpiY; }

    // Switches between modes in the same group are seamless, i.e.
    // without visual interruptions such as a black screen.
    int32_t getGroup() const { return mGroup; }

    bool equalsExceptDisplayModeId(const DisplayModePtr& other) const {
        return mHwcId == other->mHwcId && mWidth == other->mWidth && mHeight == other->mHeight &&
                getVsyncPeriod() == other->getVsyncPeriod() && mDpiX == other->mDpiX &&
                mDpiY == other->mDpiY && mGroup == other->mGroup;
    }

private:
    explicit DisplayMode(hal::HWConfigId id) : mHwcId(id) {}

    hal::HWConfigId mHwcId;
    DisplayModeId mId;
    PhysicalDisplayId mPhysicalDisplayId;

    int32_t mWidth = -1;
    int32_t mHeight = -1;
    Fps mFps;
    float mDpiX = -1;
    float mDpiY = -1;
    int32_t mGroup = -1;
};

inline std::string to_string(const DisplayMode& mode) {
    return base::StringPrintf("{id=%d, hwcId=%d, width=%d, height=%d, refreshRate=%s, "
                              "dpiX=%.2f, dpiY=%.2f, group=%d}",
                              mode.getId().value(), mode.getHwcId(), mode.getWidth(),
                              mode.getHeight(), to_string(mode.getFps()).c_str(), mode.getDpiX(),
                              mode.getDpiY(), mode.getGroup());
}

} // namespace android