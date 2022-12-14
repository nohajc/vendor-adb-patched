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

#include <apex/display.h>
#include <gui/SurfaceComposerClient.h>
#include <ui/DisplayMode.h>
#include <ui/DynamicDisplayInfo.h>
#include <ui/GraphicTypes.h>
#include <ui/PixelFormat.h>
#include <ui/StaticDisplayInfo.h>

#include <algorithm>
#include <optional>
#include <type_traits>
#include <vector>

namespace android::display::impl {

/**
 * Implementation of ADisplayConfig
 */
struct DisplayConfigImpl {
    /**
     * The ID of the display configuration.
     */
    size_t id;

    /**
     * The width in pixels of the display configuration.
     */
    int32_t width{0};

    /**
     * The height in pixels of the display configuration.
     */

    int32_t height{0};

    /**
     * The display density.
     */
    float density{0};

    /**
     * The refresh rate of the display configuration, in frames per second.
     */
    float fps{0.0};

    /**
     * The vsync offset at which surfaceflinger runs, in nanoseconds.
     */
    int64_t sfOffset{0};

    /**
     * The vsync offset at which applications run, in nanoseconds.
     */
    int64_t appOffset{0};
};

// DisplayConfigImpl allocation is not managed through C++ memory apis, so
// preventing calling the destructor here.
static_assert(std::is_trivially_destructible<DisplayConfigImpl>::value);

/**
 * Implementation of ADisplay
 */
struct DisplayImpl {
    /**
     * A physical display ID, unique to this display.
     */
    PhysicalDisplayId id;

    /**
     * The type of the display, i.e. whether it is an internal or external
     * display.
     */
    ADisplayType type;

    /**
     * The preferred WCG dataspace
     */
    ADataSpace wcgDataspace;

    /**
     * The preferred WCG pixel format
     */
    AHardwareBuffer_Format wcgPixelFormat;

    /**
     * Number of supported configs
     */
    size_t numConfigs;

    /**
     * Set of supported configs by this display.
     */
    DisplayConfigImpl* configs;
};

// DisplayImpl allocation is not managed through C++ memory apis, so
// preventing calling the destructor here.
static_assert(std::is_trivially_destructible<DisplayImpl>::value);

} // namespace android::display::impl

using namespace android;
using namespace android::display::impl;

#define CHECK_NOT_NULL(name) \
    LOG_ALWAYS_FATAL_IF(name == nullptr, "nullptr passed as " #name " argument");

namespace {

sp<IBinder> getToken(ADisplay* display) {
    DisplayImpl* impl = reinterpret_cast<DisplayImpl*>(display);
    return SurfaceComposerClient::getPhysicalDisplayToken(impl->id);
}

} // namespace

namespace android {

int ADisplay_acquirePhysicalDisplays(ADisplay*** outDisplays) {
    const std::vector<PhysicalDisplayId> ids = SurfaceComposerClient::getPhysicalDisplayIds();
    const size_t size = ids.size();
    if (size == 0) {
        return NO_INIT;
    }

    std::vector<DisplayConfigImpl> modesPerDisplay[size];
    int numModes = 0;
    for (int i = 0; i < size; ++i) {
        const sp<IBinder> token = SurfaceComposerClient::getPhysicalDisplayToken(ids[i]);

        ui::StaticDisplayInfo staticInfo;
        if (const status_t status = SurfaceComposerClient::getStaticDisplayInfo(token, &staticInfo);
            status != OK) {
            return status;
        }

        ui::DynamicDisplayInfo dynamicInfo;
        if (const status_t status =
                    SurfaceComposerClient::getDynamicDisplayInfo(token, &dynamicInfo);
            status != OK) {
            return status;
        }
        const auto& modes = dynamicInfo.supportedDisplayModes;
        if (modes.empty()) {
            return NO_INIT;
        }

        numModes += modes.size();
        modesPerDisplay[i].reserve(modes.size());
        for (int j = 0; j < modes.size(); ++j) {
            const ui::DisplayMode& mode = modes[j];
            modesPerDisplay[i].emplace_back(
                    DisplayConfigImpl{static_cast<size_t>(mode.id), mode.resolution.getWidth(),
                                      mode.resolution.getHeight(), staticInfo.density,
                                      mode.refreshRate, mode.sfVsyncOffset, mode.appVsyncOffset});
        }
    }

    const std::optional<PhysicalDisplayId> internalId =
            SurfaceComposerClient::getInternalDisplayId();
    ui::Dataspace defaultDataspace;
    ui::PixelFormat defaultPixelFormat;
    ui::Dataspace wcgDataspace;
    ui::PixelFormat wcgPixelFormat;

    const status_t status =
            SurfaceComposerClient::getCompositionPreference(&defaultDataspace, &defaultPixelFormat,
                                                            &wcgDataspace, &wcgPixelFormat);
    if (status != NO_ERROR) {
        return status;
    }

    // Here we allocate all our required memory in one block. The layout is as
    // follows:
    // ------------------------------------------------------------
    // | DisplayImpl pointers | DisplayImpls | DisplayConfigImpls |
    // ------------------------------------------------------------
    //
    // The caller will be given a DisplayImpl** which points to the beginning of
    // the block of DisplayImpl pointers.
    // Each DisplayImpl* points to a DisplayImpl in the second block.
    // Each DisplayImpl contains a DisplayConfigImpl*, which points to a
    // contiguous block of DisplayConfigImpls specific to that display.
    DisplayImpl** const impls = reinterpret_cast<DisplayImpl**>(
            malloc((sizeof(DisplayImpl) + sizeof(DisplayImpl*)) * size +
                   sizeof(DisplayConfigImpl) * numModes));
    DisplayImpl* const displayData = reinterpret_cast<DisplayImpl*>(impls + size);
    DisplayConfigImpl* configData = reinterpret_cast<DisplayConfigImpl*>(displayData + size);

    for (size_t i = 0; i < size; ++i) {
        const PhysicalDisplayId id = ids[i];
        const ADisplayType type = (internalId == id) ? ADisplayType::DISPLAY_TYPE_INTERNAL
                                                     : ADisplayType::DISPLAY_TYPE_EXTERNAL;
        const std::vector<DisplayConfigImpl>& configs = modesPerDisplay[i];
        memcpy(configData, configs.data(), sizeof(DisplayConfigImpl) * configs.size());

        displayData[i] = DisplayImpl{id,
                                     type,
                                     static_cast<ADataSpace>(wcgDataspace),
                                     static_cast<AHardwareBuffer_Format>(wcgPixelFormat),
                                     configs.size(),
                                     configData};
        impls[i] = displayData + i;
        // Advance the configData pointer so that future configs are written to
        // the correct display.
        configData += configs.size();
    }

    *outDisplays = reinterpret_cast<ADisplay**>(impls);
    return size;
}

void ADisplay_release(ADisplay** displays) {
    if (displays == nullptr) {
        return;
    }
    free(displays);
}

float ADisplay_getMaxSupportedFps(ADisplay* display) {
    CHECK_NOT_NULL(display);
    DisplayImpl* impl = reinterpret_cast<DisplayImpl*>(display);
    float maxFps = 0.0;
    for (int i = 0; i < impl->numConfigs; ++i) {
        maxFps = std::max(maxFps, impl->configs[i].fps);
    }
    return maxFps;
}

ADisplayType ADisplay_getDisplayType(ADisplay* display) {
    CHECK_NOT_NULL(display);

    return reinterpret_cast<DisplayImpl*>(display)->type;
}

void ADisplay_getPreferredWideColorFormat(ADisplay* display, ADataSpace* outDataspace,
                                          AHardwareBuffer_Format* outPixelFormat) {
    CHECK_NOT_NULL(display);
    CHECK_NOT_NULL(outDataspace);
    CHECK_NOT_NULL(outPixelFormat);

    DisplayImpl* impl = reinterpret_cast<DisplayImpl*>(display);
    *outDataspace = impl->wcgDataspace;
    *outPixelFormat = impl->wcgPixelFormat;
}

int ADisplay_getCurrentConfig(ADisplay* display, ADisplayConfig** outConfig) {
    CHECK_NOT_NULL(display);

    sp<IBinder> token = getToken(display);
    ui::DynamicDisplayInfo info;
    if (const auto status = SurfaceComposerClient::getDynamicDisplayInfo(token, &info);
        status != OK) {
        return status;
    }

    DisplayImpl* impl = reinterpret_cast<DisplayImpl*>(display);
    for (size_t i = 0; i < impl->numConfigs; i++) {
        auto* config = impl->configs + i;
        if (config->id == info.activeDisplayModeId) {
            *outConfig = reinterpret_cast<ADisplayConfig*>(config);
            return OK;
        }
    }

    return NAME_NOT_FOUND;
}

float ADisplayConfig_getDensity(ADisplayConfig* config) {
    CHECK_NOT_NULL(config);

    return reinterpret_cast<DisplayConfigImpl*>(config)->density;
}

int32_t ADisplayConfig_getWidth(ADisplayConfig* config) {
    CHECK_NOT_NULL(config);

    return reinterpret_cast<DisplayConfigImpl*>(config)->width;
}

int32_t ADisplayConfig_getHeight(ADisplayConfig* config) {
    CHECK_NOT_NULL(config);

    return reinterpret_cast<DisplayConfigImpl*>(config)->height;
}

float ADisplayConfig_getFps(ADisplayConfig* config) {
    CHECK_NOT_NULL(config);

    return reinterpret_cast<DisplayConfigImpl*>(config)->fps;
}

int64_t ADisplayConfig_getCompositorOffsetNanos(ADisplayConfig* config) {
    CHECK_NOT_NULL(config);

    return reinterpret_cast<DisplayConfigImpl*>(config)->sfOffset;
}

int64_t ADisplayConfig_getAppVsyncOffsetNanos(ADisplayConfig* config) {
    CHECK_NOT_NULL(config);

    return reinterpret_cast<DisplayConfigImpl*>(config)->appOffset;
}

} // namespace android
