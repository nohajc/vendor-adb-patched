//
// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <utility>

#include <gui/bufferqueue/2.0/B2HGraphicBufferProducer.h>

#include "AutomotiveDisplayProxyService.h"

namespace android {
namespace frameworks {
namespace automotive {
namespace display {
namespace V1_0 {
namespace implementation {


Return<sp<IGraphicBufferProducer>>
AutomotiveDisplayProxyService::getIGraphicBufferProducer(uint64_t id) {
    auto it = mDisplays.find(id);
    sp<IBinder> displayToken = nullptr;
    sp<SurfaceControl> surfaceControl = nullptr;
    if (it == mDisplays.end()) {
        displayToken = SurfaceComposerClient::getPhysicalDisplayToken(PhysicalDisplayId(id));
        if (displayToken == nullptr) {
            ALOGE("Given display id, 0x%lX, is invalid.", (unsigned long)id);
            return nullptr;
        }

        // Get the resolution from stored display state.
        ui::DisplayMode displayMode = {};
        auto err = SurfaceComposerClient::getActiveDisplayMode(displayToken, &displayMode);
        if (err != NO_ERROR) {
            ALOGE("Failed to get display mode of %lX.  "
                  "This display will be ignored.", (unsigned long)id);
            return nullptr;
        }

        ui::DisplayState displayState = {};
        err = SurfaceComposerClient::getDisplayState(displayToken, &displayState);
        if (err != NO_ERROR) {
            ALOGE("Failed to get current display status of %lX.  "
                  "This display will be ignored.", (unsigned long)id);
            return nullptr;
        }

        auto displayWidth  = displayMode.resolution.getWidth();
        auto displayHeight = displayMode.resolution.getHeight();
        if ((displayState.orientation != ui::ROTATION_0) &&
            (displayState.orientation != ui::ROTATION_180)) {
            std::swap(displayWidth, displayHeight);
        }

        sp<android::SurfaceComposerClient> surfaceClient = new SurfaceComposerClient();
        err = surfaceClient->initCheck();
        if (err != NO_ERROR) {
            ALOGE("SurfaceComposerClient::initCheck error: %#x", err);
            return nullptr;
        }

        // Create a SurfaceControl instance
        surfaceControl = surfaceClient->createSurface(
                String8::format("AutomotiveDisplay::%lX", (unsigned long)id),
                displayWidth, displayHeight,
                PIXEL_FORMAT_RGBX_8888, ISurfaceComposerClient::eOpaque);
        if (surfaceControl == nullptr || !surfaceControl->isValid()) {
            ALOGE("Failed to create SurfaceControl.");
            return nullptr;
        }

        // Store
        DisplayDesc descriptor = {displayToken, surfaceControl};
        mDisplays.insert_or_assign(id, std::move(descriptor));
    } else {
        displayToken = it->second.token;
        surfaceControl = it->second.surfaceControl;
    }

    // SurfaceControl::getSurface is guaranteed to be not null.
    auto targetSurface = surfaceControl->getSurface();
    return new ::android::hardware::graphics::bufferqueue::V2_0::utils::
               B2HGraphicBufferProducer(targetSurface->getIGraphicBufferProducer());
}


Return<bool> AutomotiveDisplayProxyService::showWindow(uint64_t id) {
    auto it = mDisplays.find(id);
    if (it == mDisplays.end()) {
        ALOGE("Given display token is invalid or unknown.");
        return false;
    }

    ui::DisplayState displayState;
    auto err = SurfaceComposerClient::getDisplayState(it->second.token, &displayState);
    if (err != NO_ERROR) {
        ALOGE("Failed to get current state of the display 0x%lX", (unsigned long)id);
        return false;
    }

    SurfaceComposerClient::Transaction t;
    t.setDisplayLayerStack(it->second.token, displayState.layerStack);
    t.setLayerStack(it->second.surfaceControl, displayState.layerStack);

    status_t status = t.setLayer(it->second.surfaceControl, 0x7FFFFFFF)
                      .show(it->second.surfaceControl)
                      .apply();

    return status == NO_ERROR;
}


Return<bool> AutomotiveDisplayProxyService::hideWindow(uint64_t id) {
    auto it = mDisplays.find(id);
    if (it == mDisplays.end()) {
        ALOGE("Given display token is invalid or unknown.");
        return false;
    }

    status_t status = SurfaceComposerClient::Transaction{}
                      .hide(it->second.surfaceControl)
                      .apply();

    return status == NO_ERROR;
}


Return<void> AutomotiveDisplayProxyService::getDisplayIdList(getDisplayIdList_cb _cb) {
    hardware::hidl_vec<uint64_t> ids;

    // Get stable IDs of all available displays and get their tokens and
    // descriptors.
    auto displayIds = SurfaceComposerClient::getPhysicalDisplayIds();
    ids.resize(displayIds.size());
    for (auto i = 0; i < displayIds.size(); ++i) {
        ids[i] = displayIds[i].value;
    }

    _cb(ids);
    return hardware::Void();
}


Return<void> AutomotiveDisplayProxyService::getDisplayInfo(uint64_t id, getDisplayInfo_cb _cb) {
    HwDisplayConfig activeConfig;
    HwDisplayState  activeState;

    auto displayToken = SurfaceComposerClient::getPhysicalDisplayToken(PhysicalDisplayId(id));
    if (displayToken == nullptr) {
        ALOGE("Given display id, 0x%lX, is invalid.", (unsigned long)id);
    } else {
        ui::DisplayMode displayMode = {};
        auto err = SurfaceComposerClient::getActiveDisplayMode(displayToken, &displayMode);
        if (err != NO_ERROR) {
            ALOGW("Failed to get display mode of %lX.  "
                  "This display will be ignored.", (unsigned long)id);
        }

        ui::DisplayState displayState = {};
        err = SurfaceComposerClient::getDisplayState(displayToken, &displayState);
        if (err != NO_ERROR) {
            ALOGW("Failed to get current display status of %lX.  "
                  "This display will be ignored.", (unsigned long)id);
        }

        activeConfig.setToExternal((uint8_t*)&displayMode, sizeof(ui::DisplayMode));
        activeState.setToExternal((uint8_t*)&displayState, sizeof(DisplayState));
    }

    _cb(activeConfig, activeState);
    return hardware::Void();
}


}  // namespace implementation
}  // namespace V1_0
}  // namespace display
}  // namespace automotive
}  // namespace frameworks
}  // namespace android

