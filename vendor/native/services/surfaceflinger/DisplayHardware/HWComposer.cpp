/*
 * Copyright (C) 2010 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

// #define LOG_NDEBUG 0

#undef LOG_TAG
#define LOG_TAG "HWComposer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "HWComposer.h"

#include <compositionengine/Output.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <log/log.h>
#include <ui/DebugUtils.h>
#include <ui/GraphicBuffer.h>
#include <utils/Errors.h>
#include <utils/Trace.h>

#include "../Layer.h" // needed only for debugging
#include "../Promise.h"
#include "../SurfaceFlinger.h"
#include "ComposerHal.h"
#include "HWC2.h"

#define LOG_HWC_DISPLAY_ERROR(hwcDisplayId, msg) \
    ALOGE("%s failed for HWC display %" PRIu64 ": %s", __FUNCTION__, hwcDisplayId, msg)

#define LOG_DISPLAY_ERROR(displayId, msg) \
    ALOGE("%s failed for display %s: %s", __FUNCTION__, to_string(displayId).c_str(), msg)

#define LOG_HWC_ERROR(what, error, displayId)                          \
    ALOGE("%s: %s failed for display %s: %s (%d)", __FUNCTION__, what, \
          to_string(displayId).c_str(), to_string(error).c_str(), static_cast<int32_t>(error))

#define RETURN_IF_INVALID_DISPLAY(displayId, ...)            \
    do {                                                     \
        if (mDisplayData.count(displayId) == 0) {            \
            LOG_DISPLAY_ERROR(displayId, "Invalid display"); \
            return __VA_ARGS__;                              \
        }                                                    \
    } while (false)

#define RETURN_IF_HWC_ERROR_FOR(what, error, displayId, ...) \
    do {                                                     \
        if (error != hal::Error::NONE) {                     \
            LOG_HWC_ERROR(what, error, displayId);           \
            return __VA_ARGS__;                              \
        }                                                    \
    } while (false)

#define RETURN_IF_HWC_ERROR(error, displayId, ...) \
    RETURN_IF_HWC_ERROR_FOR(__FUNCTION__, error, displayId, __VA_ARGS__)

namespace hal = android::hardware::graphics::composer::hal;

namespace {

using android::hardware::Return;
using android::hardware::Void;
using android::HWC2::ComposerCallback;

class ComposerCallbackBridge : public hal::IComposerCallback {
public:
    ComposerCallbackBridge(ComposerCallback* callback, int32_t sequenceId,
                           bool vsyncSwitchingSupported)
          : mCallback(callback),
            mSequenceId(sequenceId),
            mVsyncSwitchingSupported(vsyncSwitchingSupported) {}

    android::hardware::Return<void> onHotplug(hal::HWDisplayId display,
                                              hal::Connection conn) override {
        mCallback->onHotplugReceived(mSequenceId, display, conn);
        return android::hardware::Void();
    }

    android::hardware::Return<void> onRefresh(hal::HWDisplayId display) override {
        mCallback->onRefreshReceived(mSequenceId, display);
        return android::hardware::Void();
    }

    android::hardware::Return<void> onVsync(hal::HWDisplayId display, int64_t timestamp) override {
        if (!mVsyncSwitchingSupported) {
            mCallback->onVsyncReceived(mSequenceId, display, timestamp, std::nullopt);
        } else {
            ALOGW("Unexpected onVsync callback on composer >= 2.4, ignoring.");
        }
        return android::hardware::Void();
    }

    android::hardware::Return<void> onVsync_2_4(hal::HWDisplayId display, int64_t timestamp,
                                                hal::VsyncPeriodNanos vsyncPeriodNanos) override {
        if (mVsyncSwitchingSupported) {
            mCallback->onVsyncReceived(mSequenceId, display, timestamp,
                                       std::make_optional(vsyncPeriodNanos));
        } else {
            ALOGW("Unexpected onVsync_2_4 callback on composer <= 2.3, ignoring.");
        }
        return android::hardware::Void();
    }

    android::hardware::Return<void> onVsyncPeriodTimingChanged(
            hal::HWDisplayId display,
            const hal::VsyncPeriodChangeTimeline& updatedTimeline) override {
        mCallback->onVsyncPeriodTimingChangedReceived(mSequenceId, display, updatedTimeline);
        return android::hardware::Void();
    }

    android::hardware::Return<void> onSeamlessPossible(hal::HWDisplayId display) override {
        mCallback->onSeamlessPossible(mSequenceId, display);
        return android::hardware::Void();
    }

private:
    ComposerCallback* mCallback;
    const int32_t mSequenceId;
    const bool mVsyncSwitchingSupported;
};

} // namespace

namespace android {

HWComposer::~HWComposer() = default;

namespace impl {

HWComposer::HWComposer(std::unique_ptr<Hwc2::Composer> composer) : mComposer(std::move(composer)) {
}

HWComposer::HWComposer(const std::string& composerServiceName)
      : mComposer(std::make_unique<Hwc2::impl::Composer>(composerServiceName)) {
}

HWComposer::~HWComposer() {
    mDisplayData.clear();
}

void HWComposer::setConfiguration(HWC2::ComposerCallback* callback, int32_t sequenceId) {
    loadCapabilities();
    loadLayerMetadataSupport();

    if (mRegisteredCallback) {
        ALOGW("Callback already registered. Ignored extra registration attempt.");
        return;
    }
    mRegisteredCallback = true;
    sp<ComposerCallbackBridge> callbackBridge(
            new ComposerCallbackBridge(callback, sequenceId,
                                       mComposer->isVsyncPeriodSwitchSupported()));
    mComposer->registerCallback(callbackBridge);
}

bool HWComposer::getDisplayIdentificationData(hal::HWDisplayId hwcDisplayId, uint8_t* outPort,
                                              DisplayIdentificationData* outData) const {
    const auto error = static_cast<hal::Error>(
            mComposer->getDisplayIdentificationData(hwcDisplayId, outPort, outData));
    if (error != hal::Error::NONE) {
        if (error != hal::Error::UNSUPPORTED) {
            LOG_HWC_DISPLAY_ERROR(hwcDisplayId, to_string(error).c_str());
        }
        return false;
    }
    return true;
}

bool HWComposer::hasCapability(hal::Capability capability) const {
    return mCapabilities.count(capability) > 0;
}

bool HWComposer::hasDisplayCapability(DisplayId displayId,
                                      hal::DisplayCapability capability) const {
    RETURN_IF_INVALID_DISPLAY(displayId, false);
    return mDisplayData.at(displayId).hwcDisplay->getCapabilities().count(capability) > 0;
}

std::optional<DisplayIdentificationInfo> HWComposer::onHotplug(hal::HWDisplayId hwcDisplayId,
                                                               hal::Connection connection) {
    switch (connection) {
        case hal::Connection::CONNECTED:
            return onHotplugConnect(hwcDisplayId);
        case hal::Connection::DISCONNECTED:
            return onHotplugDisconnect(hwcDisplayId);
        case hal::Connection::INVALID:
            return {};
    }
}

bool HWComposer::onVsync(hal::HWDisplayId hwcDisplayId, int64_t timestamp) {
    const auto displayId = toPhysicalDisplayId(hwcDisplayId);
    if (!displayId) {
        LOG_HWC_DISPLAY_ERROR(hwcDisplayId, "Invalid HWC display");
        return false;
    }

    RETURN_IF_INVALID_DISPLAY(*displayId, false);

    auto& displayData = mDisplayData[*displayId];
    if (displayData.isVirtual) {
        LOG_DISPLAY_ERROR(*displayId, "Invalid operation on virtual display");
        return false;
    }

    {
        std::lock_guard lock(displayData.lastHwVsyncLock);

        // There have been reports of HWCs that signal several vsync events
        // with the same timestamp when turning the display off and on. This
        // is a bug in the HWC implementation, but filter the extra events
        // out here so they don't cause havoc downstream.
        if (timestamp == displayData.lastHwVsync) {
            ALOGW("Ignoring duplicate VSYNC event from HWC for display %s (t=%" PRId64 ")",
                  to_string(*displayId).c_str(), timestamp);
            return false;
        }

        displayData.lastHwVsync = timestamp;
    }

    const auto tag = "HW_VSYNC_" + to_string(*displayId);
    ATRACE_INT(tag.c_str(), displayData.vsyncTraceToggle);
    displayData.vsyncTraceToggle = !displayData.vsyncTraceToggle;

    return true;
}

std::optional<DisplayId> HWComposer::allocateVirtualDisplay(uint32_t width, uint32_t height,
                                                            ui::PixelFormat* format) {
    if (mRemainingHwcVirtualDisplays == 0) {
        ALOGE("%s: No remaining virtual displays", __FUNCTION__);
        return {};
    }

    if (SurfaceFlinger::maxVirtualDisplaySize != 0 &&
        (width > SurfaceFlinger::maxVirtualDisplaySize ||
         height > SurfaceFlinger::maxVirtualDisplaySize)) {
        ALOGE("%s: Display size %ux%u exceeds maximum dimension of %" PRIu64, __FUNCTION__, width,
              height, SurfaceFlinger::maxVirtualDisplaySize);
        return {};
    }
    hal::HWDisplayId hwcDisplayId = 0;
    const auto error = static_cast<hal::Error>(
            mComposer->createVirtualDisplay(width, height, format, &hwcDisplayId));
    if (error != hal::Error::NONE) {
        ALOGE("%s: Failed to create HWC virtual display", __FUNCTION__);
        return {};
    }

    auto display = std::make_unique<HWC2::impl::Display>(*mComposer.get(), mCapabilities,
                                                         hwcDisplayId, hal::DisplayType::VIRTUAL);
    display->setConnected(true);

    DisplayId displayId;
    if (mFreeVirtualDisplayIds.empty()) {
        displayId = getVirtualDisplayId(mNextVirtualDisplayId++);
    } else {
        displayId = *mFreeVirtualDisplayIds.begin();
        mFreeVirtualDisplayIds.erase(displayId);
    }

    auto& displayData = mDisplayData[displayId];
    displayData.hwcDisplay = std::move(display);
    displayData.isVirtual = true;

    --mRemainingHwcVirtualDisplays;
    return displayId;
}

void HWComposer::allocatePhysicalDisplay(hal::HWDisplayId hwcDisplayId, DisplayId displayId) {
    if (!mInternalHwcDisplayId) {
        mInternalHwcDisplayId = hwcDisplayId;
    } else if (mInternalHwcDisplayId != hwcDisplayId && !mExternalHwcDisplayId) {
        mExternalHwcDisplayId = hwcDisplayId;
    }

    auto& displayData = mDisplayData[displayId];
    auto newDisplay =
            std::make_unique<HWC2::impl::Display>(*mComposer.get(), mCapabilities, hwcDisplayId,
                                                  hal::DisplayType::PHYSICAL);
    newDisplay->setConnected(true);
    displayData.hwcDisplay = std::move(newDisplay);
    mPhysicalDisplayIdMap[hwcDisplayId] = displayId;
}

HWC2::Layer* HWComposer::createLayer(DisplayId displayId) {
    RETURN_IF_INVALID_DISPLAY(displayId, nullptr);

    HWC2::Layer* layer;
    auto error = mDisplayData[displayId].hwcDisplay->createLayer(&layer);
    RETURN_IF_HWC_ERROR(error, displayId, nullptr);
    return layer;
}

void HWComposer::destroyLayer(DisplayId displayId, HWC2::Layer* layer) {
    RETURN_IF_INVALID_DISPLAY(displayId);

    auto error = mDisplayData[displayId].hwcDisplay->destroyLayer(layer);
    RETURN_IF_HWC_ERROR(error, displayId);
}

nsecs_t HWComposer::getRefreshTimestamp(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, 0);
    const auto& displayData = mDisplayData.at(displayId);
    // this returns the last refresh timestamp.
    // if the last one is not available, we estimate it based on
    // the refresh period and whatever closest timestamp we have.
    std::lock_guard lock(displayData.lastHwVsyncLock);
    nsecs_t now = systemTime(CLOCK_MONOTONIC);
    auto vsyncPeriodNanos = getDisplayVsyncPeriod(displayId);
    return now - ((now - displayData.lastHwVsync) % vsyncPeriodNanos);
}

bool HWComposer::isConnected(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, false);
    return mDisplayData.at(displayId).hwcDisplay->isConnected();
}

std::vector<std::shared_ptr<const HWC2::Display::Config>> HWComposer::getConfigs(
        DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, {});

    const auto& displayData = mDisplayData.at(displayId);
    auto configs = displayData.hwcDisplay->getConfigs();
    if (displayData.configMap.empty()) {
        for (size_t i = 0; i < configs.size(); ++i) {
            displayData.configMap[i] = configs[i];
        }
    }
    return configs;
}

std::shared_ptr<const HWC2::Display::Config> HWComposer::getActiveConfig(
        DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, nullptr);

    std::shared_ptr<const HWC2::Display::Config> config;
    auto error = mDisplayData.at(displayId).hwcDisplay->getActiveConfig(&config);
    if (error == hal::Error::BAD_CONFIG) {
        LOG_DISPLAY_ERROR(displayId, "No active config");
        return nullptr;
    }

    RETURN_IF_HWC_ERROR(error, displayId, nullptr);

    if (!config) {
        LOG_DISPLAY_ERROR(displayId, "Unknown config");
        return nullptr;
    }

    return config;
}

// Composer 2.4

DisplayConnectionType HWComposer::getDisplayConnectionType(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, DisplayConnectionType::Internal);
    const auto& hwcDisplay = mDisplayData.at(displayId).hwcDisplay;

    DisplayConnectionType type;
    const auto error = hwcDisplay->getConnectionType(&type);

    const auto FALLBACK_TYPE = hwcDisplay->getId() == mInternalHwcDisplayId
            ? DisplayConnectionType::Internal
            : DisplayConnectionType::External;

    RETURN_IF_HWC_ERROR(error, displayId, FALLBACK_TYPE);
    return type;
}

bool HWComposer::isVsyncPeriodSwitchSupported(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, false);
    return mDisplayData.at(displayId).hwcDisplay->isVsyncPeriodSwitchSupported();
}

nsecs_t HWComposer::getDisplayVsyncPeriod(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, 0);

    nsecs_t vsyncPeriodNanos;
    auto error = mDisplayData.at(displayId).hwcDisplay->getDisplayVsyncPeriod(&vsyncPeriodNanos);
    RETURN_IF_HWC_ERROR(error, displayId, 0);
    return vsyncPeriodNanos;
}

int HWComposer::getActiveConfigIndex(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, -1);

    int index;
    auto error = mDisplayData.at(displayId).hwcDisplay->getActiveConfigIndex(&index);
    if (error == hal::Error::BAD_CONFIG) {
        LOG_DISPLAY_ERROR(displayId, "No active config");
        return -1;
    }

    RETURN_IF_HWC_ERROR(error, displayId, -1);

    if (index < 0) {
        LOG_DISPLAY_ERROR(displayId, "Unknown config");
        return -1;
    }

    return index;
}

std::vector<ui::ColorMode> HWComposer::getColorModes(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, {});

    std::vector<ui::ColorMode> modes;
    auto error = mDisplayData.at(displayId).hwcDisplay->getColorModes(&modes);
    RETURN_IF_HWC_ERROR(error, displayId, {});
    return modes;
}

status_t HWComposer::setActiveColorMode(DisplayId displayId, ui::ColorMode mode,
                                        ui::RenderIntent renderIntent) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    auto error = displayData.hwcDisplay->setColorMode(mode, renderIntent);
    RETURN_IF_HWC_ERROR_FOR(("setColorMode(" + decodeColorMode(mode) + ", " +
                             decodeRenderIntent(renderIntent) + ")")
                                    .c_str(),
                            error, displayId, UNKNOWN_ERROR);

    return NO_ERROR;
}

void HWComposer::setVsyncEnabled(DisplayId displayId, hal::Vsync enabled) {
    RETURN_IF_INVALID_DISPLAY(displayId);
    auto& displayData = mDisplayData[displayId];

    if (displayData.isVirtual) {
        LOG_DISPLAY_ERROR(displayId, "Invalid operation on virtual display");
        return;
    }

    // NOTE: we use our own internal lock here because we have to call
    // into the HWC with the lock held, and we want to make sure
    // that even if HWC blocks (which it shouldn't), it won't
    // affect other threads.
    std::lock_guard lock(displayData.vsyncEnabledLock);
    if (enabled == displayData.vsyncEnabled) {
        return;
    }

    ATRACE_CALL();
    auto error = displayData.hwcDisplay->setVsyncEnabled(enabled);
    RETURN_IF_HWC_ERROR(error, displayId);

    displayData.vsyncEnabled = enabled;

    const auto tag = "HW_VSYNC_ON_" + to_string(displayId);
    ATRACE_INT(tag.c_str(), enabled == hal::Vsync::ENABLE ? 1 : 0);
}

status_t HWComposer::setClientTarget(DisplayId displayId, uint32_t slot,
                                     const sp<Fence>& acquireFence, const sp<GraphicBuffer>& target,
                                     ui::Dataspace dataspace) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    ALOGV("%s for display %s", __FUNCTION__, to_string(displayId).c_str());
    auto& hwcDisplay = mDisplayData[displayId].hwcDisplay;
    auto error = hwcDisplay->setClientTarget(slot, target, acquireFence, dataspace);
    RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    return NO_ERROR;
}

status_t HWComposer::getDeviceCompositionChanges(
        DisplayId displayId, bool frameUsesClientComposition,
        std::optional<android::HWComposer::DeviceRequestedChanges>* outChanges) {
    ATRACE_CALL();

    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    auto& hwcDisplay = displayData.hwcDisplay;
    if (!hwcDisplay->isConnected()) {
        return NO_ERROR;
    }

    uint32_t numTypes = 0;
    uint32_t numRequests = 0;

    hal::Error error = hal::Error::NONE;

    // First try to skip validate altogether when there is no client
    // composition.  When there is client composition, since we haven't
    // rendered to the client target yet, we should not attempt to skip
    // validate.
    displayData.validateWasSkipped = false;
    if (!frameUsesClientComposition) {
        sp<Fence> outPresentFence;
        uint32_t state = UINT32_MAX;
        error = hwcDisplay->presentOrValidate(&numTypes, &numRequests, &outPresentFence , &state);
        if (!hasChangesError(error)) {
            RETURN_IF_HWC_ERROR_FOR("presentOrValidate", error, displayId, UNKNOWN_ERROR);
        }
        if (state == 1) { //Present Succeeded.
            std::unordered_map<HWC2::Layer*, sp<Fence>> releaseFences;
            error = hwcDisplay->getReleaseFences(&releaseFences);
            displayData.releaseFences = std::move(releaseFences);
            displayData.lastPresentFence = outPresentFence;
            displayData.validateWasSkipped = true;
            displayData.presentError = error;
            return NO_ERROR;
        }
        // Present failed but Validate ran.
    } else {
        error = hwcDisplay->validate(&numTypes, &numRequests);
    }
    ALOGV("SkipValidate failed, Falling back to SLOW validate/present");
    if (!hasChangesError(error)) {
        RETURN_IF_HWC_ERROR_FOR("validate", error, displayId, BAD_INDEX);
    }

    android::HWComposer::DeviceRequestedChanges::ChangedTypes changedTypes;
    changedTypes.reserve(numTypes);
    error = hwcDisplay->getChangedCompositionTypes(&changedTypes);
    RETURN_IF_HWC_ERROR_FOR("getChangedCompositionTypes", error, displayId, BAD_INDEX);

    auto displayRequests = static_cast<hal::DisplayRequest>(0);
    android::HWComposer::DeviceRequestedChanges::LayerRequests layerRequests;
    layerRequests.reserve(numRequests);
    error = hwcDisplay->getRequests(&displayRequests, &layerRequests);
    RETURN_IF_HWC_ERROR_FOR("getRequests", error, displayId, BAD_INDEX);

    DeviceRequestedChanges::ClientTargetProperty clientTargetProperty;
    error = hwcDisplay->getClientTargetProperty(&clientTargetProperty);

    outChanges->emplace(DeviceRequestedChanges{std::move(changedTypes), std::move(displayRequests),
                                               std::move(layerRequests),
                                               std::move(clientTargetProperty)});
    error = hwcDisplay->acceptChanges();
    RETURN_IF_HWC_ERROR_FOR("acceptChanges", error, displayId, BAD_INDEX);

    return NO_ERROR;
}

sp<Fence> HWComposer::getPresentFence(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, Fence::NO_FENCE);
    return mDisplayData.at(displayId).lastPresentFence;
}

sp<Fence> HWComposer::getLayerReleaseFence(DisplayId displayId, HWC2::Layer* layer) const {
    RETURN_IF_INVALID_DISPLAY(displayId, Fence::NO_FENCE);
    const auto& displayFences = mDisplayData.at(displayId).releaseFences;
    auto fence = displayFences.find(layer);
    if (fence == displayFences.end()) {
        ALOGV("getLayerReleaseFence: Release fence not found");
        return Fence::NO_FENCE;
    }
    return fence->second;
}

status_t HWComposer::presentAndGetReleaseFences(DisplayId displayId) {
    ATRACE_CALL();

    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    auto& hwcDisplay = displayData.hwcDisplay;

    if (displayData.validateWasSkipped) {
        // explicitly flush all pending commands
        auto error = static_cast<hal::Error>(mComposer->executeCommands());
        RETURN_IF_HWC_ERROR_FOR("executeCommands", error, displayId, UNKNOWN_ERROR);
        RETURN_IF_HWC_ERROR_FOR("present", displayData.presentError, displayId, UNKNOWN_ERROR);
        return NO_ERROR;
    }

    auto error = hwcDisplay->present(&displayData.lastPresentFence);
    RETURN_IF_HWC_ERROR_FOR("present", error, displayId, UNKNOWN_ERROR);

    std::unordered_map<HWC2::Layer*, sp<Fence>> releaseFences;
    error = hwcDisplay->getReleaseFences(&releaseFences);
    RETURN_IF_HWC_ERROR_FOR("getReleaseFences", error, displayId, UNKNOWN_ERROR);

    displayData.releaseFences = std::move(releaseFences);

    return NO_ERROR;
}

status_t HWComposer::setPowerMode(DisplayId displayId, hal::PowerMode mode) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    const auto& displayData = mDisplayData[displayId];
    if (displayData.isVirtual) {
        LOG_DISPLAY_ERROR(displayId, "Invalid operation on virtual display");
        return INVALID_OPERATION;
    }

    if (mode == hal::PowerMode::OFF) {
        setVsyncEnabled(displayId, hal::Vsync::DISABLE);
    }

    auto& hwcDisplay = displayData.hwcDisplay;
    switch (mode) {
        case hal::PowerMode::OFF:
        case hal::PowerMode::ON:
            ALOGV("setPowerMode: Calling HWC %s", to_string(mode).c_str());
            {
                auto error = hwcDisplay->setPowerMode(mode);
                if (error != hal::Error::NONE) {
                    LOG_HWC_ERROR(("setPowerMode(" + to_string(mode) + ")").c_str(), error,
                                  displayId);
                }
            }
            break;
        case hal::PowerMode::DOZE:
        case hal::PowerMode::DOZE_SUSPEND:
            ALOGV("setPowerMode: Calling HWC %s", to_string(mode).c_str());
            {
                bool supportsDoze = false;
                auto error = hwcDisplay->supportsDoze(&supportsDoze);
                if (error != hal::Error::NONE) {
                    LOG_HWC_ERROR("supportsDoze", error, displayId);
                }

                if (!supportsDoze) {
                    mode = hal::PowerMode::ON;
                }

                error = hwcDisplay->setPowerMode(mode);
                if (error != hal::Error::NONE) {
                    LOG_HWC_ERROR(("setPowerMode(" + to_string(mode) + ")").c_str(), error,
                                  displayId);
                }
            }
            break;
        default:
            ALOGV("setPowerMode: Not calling HWC");
            break;
    }

    return NO_ERROR;
}

status_t HWComposer::setActiveConfigWithConstraints(
        DisplayId displayId, size_t configId, const hal::VsyncPeriodChangeConstraints& constraints,
        hal::VsyncPeriodChangeTimeline* outTimeline) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    if (displayData.configMap.count(configId) == 0) {
        LOG_DISPLAY_ERROR(displayId, ("Invalid config " + std::to_string(configId)).c_str());
        return BAD_INDEX;
    }

    auto error =
            displayData.hwcDisplay->setActiveConfigWithConstraints(displayData.configMap[configId],
                                                                   constraints, outTimeline);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::setColorTransform(DisplayId displayId, const mat4& transform) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& displayData = mDisplayData[displayId];
    bool isIdentity = transform == mat4();
    auto error = displayData.hwcDisplay
                         ->setColorTransform(transform,
                                             isIdentity ? hal::ColorTransform::IDENTITY
                                                        : hal::ColorTransform::ARBITRARY_MATRIX);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

void HWComposer::disconnectDisplay(DisplayId displayId) {
    RETURN_IF_INVALID_DISPLAY(displayId);
    auto& displayData = mDisplayData[displayId];

    // If this was a virtual display, add its slot back for reuse by future
    // virtual displays
    if (displayData.isVirtual) {
        mFreeVirtualDisplayIds.insert(displayId);
        ++mRemainingHwcVirtualDisplays;
    }

    const auto hwcDisplayId = displayData.hwcDisplay->getId();

    // TODO(b/74619554): Select internal/external display from remaining displays.
    if (hwcDisplayId == mInternalHwcDisplayId) {
        mInternalHwcDisplayId.reset();
    } else if (hwcDisplayId == mExternalHwcDisplayId) {
        mExternalHwcDisplayId.reset();
    }
    mPhysicalDisplayIdMap.erase(hwcDisplayId);
    mDisplayData.erase(displayId);
}

status_t HWComposer::setOutputBuffer(DisplayId displayId, const sp<Fence>& acquireFence,
                                     const sp<GraphicBuffer>& buffer) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto& displayData = mDisplayData[displayId];

    if (!displayData.isVirtual) {
        LOG_DISPLAY_ERROR(displayId, "Invalid operation on physical display");
        return INVALID_OPERATION;
    }

    auto error = displayData.hwcDisplay->setOutputBuffer(buffer, acquireFence);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

void HWComposer::clearReleaseFences(DisplayId displayId) {
    RETURN_IF_INVALID_DISPLAY(displayId);
    mDisplayData[displayId].releaseFences.clear();
}

status_t HWComposer::getHdrCapabilities(DisplayId displayId, HdrCapabilities* outCapabilities) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);

    auto& hwcDisplay = mDisplayData[displayId].hwcDisplay;
    auto error = hwcDisplay->getHdrCapabilities(outCapabilities);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

int32_t HWComposer::getSupportedPerFrameMetadata(DisplayId displayId) const {
    RETURN_IF_INVALID_DISPLAY(displayId, 0);
    return mDisplayData.at(displayId).hwcDisplay->getSupportedPerFrameMetadata();
}

std::vector<ui::RenderIntent> HWComposer::getRenderIntents(DisplayId displayId,
                                                           ui::ColorMode colorMode) const {
    RETURN_IF_INVALID_DISPLAY(displayId, {});

    std::vector<ui::RenderIntent> renderIntents;
    auto error = mDisplayData.at(displayId).hwcDisplay->getRenderIntents(colorMode, &renderIntents);
    RETURN_IF_HWC_ERROR(error, displayId, {});
    return renderIntents;
}

mat4 HWComposer::getDataspaceSaturationMatrix(DisplayId displayId, ui::Dataspace dataspace) {
    RETURN_IF_INVALID_DISPLAY(displayId, {});

    mat4 matrix;
    auto error = mDisplayData[displayId].hwcDisplay->getDataspaceSaturationMatrix(dataspace,
            &matrix);
    RETURN_IF_HWC_ERROR(error, displayId, {});
    return matrix;
}

status_t HWComposer::getDisplayedContentSamplingAttributes(DisplayId displayId,
                                                           ui::PixelFormat* outFormat,
                                                           ui::Dataspace* outDataspace,
                                                           uint8_t* outComponentMask) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error =
            mDisplayData[displayId]
                    .hwcDisplay->getDisplayedContentSamplingAttributes(outFormat, outDataspace,
                                                                       outComponentMask);
    if (error == hal::Error::UNSUPPORTED) RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::setDisplayContentSamplingEnabled(DisplayId displayId, bool enabled,
                                                      uint8_t componentMask, uint64_t maxFrames) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error =
            mDisplayData[displayId].hwcDisplay->setDisplayContentSamplingEnabled(enabled,
                                                                                 componentMask,
                                                                                 maxFrames);

    if (error == hal::Error::UNSUPPORTED) RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    if (error == hal::Error::BAD_PARAMETER) RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::getDisplayedContentSample(DisplayId displayId, uint64_t maxFrames,
                                               uint64_t timestamp, DisplayedFrameStats* outStats) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error =
            mDisplayData[displayId].hwcDisplay->getDisplayedContentSample(maxFrames, timestamp,
                                                                          outStats);
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

std::future<status_t> HWComposer::setDisplayBrightness(DisplayId displayId, float brightness) {
    RETURN_IF_INVALID_DISPLAY(displayId, promise::yield<status_t>(BAD_INDEX));
    auto& display = mDisplayData[displayId].hwcDisplay;

    return promise::chain(display->setDisplayBrightness(brightness))
            .then([displayId](hal::Error error) -> status_t {
                if (error == hal::Error::UNSUPPORTED) {
                    RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
                }
                if (error == hal::Error::BAD_PARAMETER) {
                    RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
                }
                RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
                return NO_ERROR;
            });
}

status_t HWComposer::setAutoLowLatencyMode(DisplayId displayId, bool on) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData[displayId].hwcDisplay->setAutoLowLatencyMode(on);
    if (error == hal::Error::UNSUPPORTED) {
        RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    }
    if (error == hal::Error::BAD_PARAMETER) {
        RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    }
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);
    return NO_ERROR;
}

status_t HWComposer::getSupportedContentTypes(
        DisplayId displayId, std::vector<hal::ContentType>* outSupportedContentTypes) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error =
            mDisplayData[displayId].hwcDisplay->getSupportedContentTypes(outSupportedContentTypes);

    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);

    return NO_ERROR;
}

status_t HWComposer::setContentType(DisplayId displayId, hal::ContentType contentType) {
    RETURN_IF_INVALID_DISPLAY(displayId, BAD_INDEX);
    const auto error = mDisplayData[displayId].hwcDisplay->setContentType(contentType);
    if (error == hal::Error::UNSUPPORTED) {
        RETURN_IF_HWC_ERROR(error, displayId, INVALID_OPERATION);
    }
    if (error == hal::Error::BAD_PARAMETER) {
        RETURN_IF_HWC_ERROR(error, displayId, BAD_VALUE);
    }
    RETURN_IF_HWC_ERROR(error, displayId, UNKNOWN_ERROR);

    return NO_ERROR;
}

const std::unordered_map<std::string, bool>& HWComposer::getSupportedLayerGenericMetadata() const {
    return mSupportedLayerGenericMetadata;
}

void HWComposer::dump(std::string& result) const {
    result.append(mComposer->dumpDebugInfo());
}

std::optional<DisplayId> HWComposer::toPhysicalDisplayId(hal::HWDisplayId hwcDisplayId) const {
    if (const auto it = mPhysicalDisplayIdMap.find(hwcDisplayId);
        it != mPhysicalDisplayIdMap.end()) {
        return it->second;
    }
    return {};
}

std::optional<hal::HWDisplayId> HWComposer::fromPhysicalDisplayId(DisplayId displayId) const {
    if (const auto it = mDisplayData.find(displayId);
        it != mDisplayData.end() && !it->second.isVirtual) {
        return it->second.hwcDisplay->getId();
    }
    return {};
}

bool HWComposer::shouldIgnoreHotplugConnect(hal::HWDisplayId hwcDisplayId,
                                            bool hasDisplayIdentificationData) const {
    if (mHasMultiDisplaySupport && !hasDisplayIdentificationData) {
        ALOGE("Ignoring connection of display %" PRIu64 " without identification data",
              hwcDisplayId);
        return true;
    }

    if (!mHasMultiDisplaySupport && mInternalHwcDisplayId && mExternalHwcDisplayId) {
        ALOGE("Ignoring connection of tertiary display %" PRIu64, hwcDisplayId);
        return true;
    }

    return false;
}

std::optional<DisplayIdentificationInfo> HWComposer::onHotplugConnect(
        hal::HWDisplayId hwcDisplayId) {
    std::optional<DisplayIdentificationInfo> info;
    if (const auto displayId = toPhysicalDisplayId(hwcDisplayId)) {
        info = DisplayIdentificationInfo{.id = *displayId,
                                         .name = std::string(),
                                         .deviceProductInfo = std::nullopt};
    } else {
        uint8_t port;
        DisplayIdentificationData data;
        const bool hasDisplayIdentificationData =
                getDisplayIdentificationData(hwcDisplayId, &port, &data);
        if (mPhysicalDisplayIdMap.empty()) {
            mHasMultiDisplaySupport = hasDisplayIdentificationData;
            ALOGI("Switching to %s multi-display mode",
                  mHasMultiDisplaySupport ? "generalized" : "legacy");
        }

        if (shouldIgnoreHotplugConnect(hwcDisplayId, hasDisplayIdentificationData)) {
            return {};
        }

        info = [this, hwcDisplayId, &port, &data, hasDisplayIdentificationData] {
            const bool isPrimary = !mInternalHwcDisplayId;
            if (mHasMultiDisplaySupport) {
                if (const auto info = parseDisplayIdentificationData(port, data)) {
                    return *info;
                }
                ALOGE("Failed to parse identification data for display %" PRIu64, hwcDisplayId);
            } else {
                ALOGW_IF(hasDisplayIdentificationData,
                         "Ignoring identification data for display %" PRIu64, hwcDisplayId);
                port = isPrimary ? LEGACY_DISPLAY_TYPE_PRIMARY : LEGACY_DISPLAY_TYPE_EXTERNAL;
            }

            return DisplayIdentificationInfo{.id = getFallbackDisplayId(port),
                                             .name = isPrimary ? "Internal display"
                                                               : "External display",
                                             .deviceProductInfo = std::nullopt};
        }();
    }

    if (!isConnected(info->id)) {
        allocatePhysicalDisplay(hwcDisplayId, info->id);
    }
    return info;
}

std::optional<DisplayIdentificationInfo> HWComposer::onHotplugDisconnect(
        hal::HWDisplayId hwcDisplayId) {
    const auto displayId = toPhysicalDisplayId(hwcDisplayId);
    if (!displayId) {
        ALOGE("Ignoring disconnection of invalid HWC display %" PRIu64, hwcDisplayId);
        return {};
    }

    // The display will later be destroyed by a call to
    // destroyDisplay(). For now we just mark it disconnected.
    if (isConnected(*displayId)) {
        mDisplayData[*displayId].hwcDisplay->setConnected(false);
    } else {
        ALOGW("Attempted to disconnect unknown display %" PRIu64, hwcDisplayId);
    }
    // The cleanup of Disconnect is handled through HWComposer::disconnectDisplay
    // via SurfaceFlinger's onHotplugReceived callback handling
    return DisplayIdentificationInfo{.id = *displayId,
                                     .name = std::string(),
                                     .deviceProductInfo = std::nullopt};
}

void HWComposer::loadCapabilities() {
    static_assert(sizeof(hal::Capability) == sizeof(int32_t), "Capability size has changed");
    auto capabilities = mComposer->getCapabilities();
    for (auto capability : capabilities) {
        mCapabilities.emplace(static_cast<hal::Capability>(capability));
    }
}

void HWComposer::loadLayerMetadataSupport() {
    mSupportedLayerGenericMetadata.clear();

    std::vector<Hwc2::IComposerClient::LayerGenericMetadataKey> supportedMetadataKeyInfo;
    const auto error = mComposer->getLayerGenericMetadataKeys(&supportedMetadataKeyInfo);
    if (error != hardware::graphics::composer::V2_4::Error::NONE) {
        ALOGE("%s: %s failed: %s (%d)", __FUNCTION__, "getLayerGenericMetadataKeys",
              toString(error).c_str(), static_cast<int32_t>(error));
        return;
    }

    for (const auto& [name, mandatory] : supportedMetadataKeyInfo) {
        mSupportedLayerGenericMetadata.emplace(name, mandatory);
    }
}

uint32_t HWComposer::getMaxVirtualDisplayCount() const {
    return mComposer->getMaxVirtualDisplayCount();
}

} // namespace impl
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
