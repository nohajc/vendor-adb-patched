/*
 * Copyright (C) 2007 The Android Open Source Project
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
#define LOG_TAG "DisplayDevice"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <compositionengine/CompositionEngine.h>
#include <compositionengine/Display.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/DisplayColorProfileCreationArgs.h>
#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/DisplaySurface.h>
#include <compositionengine/ProjectionSpace.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/RenderSurfaceCreationArgs.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <configstore/Utils.h>
#include <log/log.h>
#include <system/window.h>
#include <ui/GraphicTypes.h>

#include "DisplayDevice.h"
#include "Layer.h"
#include "RefreshRateOverlay.h"
#include "SurfaceFlinger.h"

namespace android {

namespace hal = hardware::graphics::composer::hal;

ui::Transform::RotationFlags DisplayDevice::sPrimaryDisplayRotationFlags = ui::Transform::ROT_0;

DisplayDeviceCreationArgs::DisplayDeviceCreationArgs(
        const sp<SurfaceFlinger>& flinger, HWComposer& hwComposer, const wp<IBinder>& displayToken,
        std::shared_ptr<compositionengine::Display> compositionDisplay)
      : flinger(flinger),
        hwComposer(hwComposer),
        displayToken(displayToken),
        compositionDisplay(compositionDisplay) {}

DisplayDevice::DisplayDevice(DisplayDeviceCreationArgs& args)
      : mFlinger(args.flinger),
        mHwComposer(args.hwComposer),
        mDisplayToken(args.displayToken),
        mSequenceId(args.sequenceId),
        mConnectionType(args.connectionType),
        mCompositionDisplay{args.compositionDisplay},
        mActiveModeFPSTrace("ActiveModeFPS -" + to_string(getId())),
        mActiveModeFPSHwcTrace("ActiveModeFPS_HWC -" + to_string(getId())),
        mPhysicalOrientation(args.physicalOrientation),
        mSupportedModes(std::move(args.supportedModes)),
        mIsPrimary(args.isPrimary),
        mRefreshRateConfigs(std::move(args.refreshRateConfigs)) {
    mCompositionDisplay->editState().isSecure = args.isSecure;
    mCompositionDisplay->createRenderSurface(
            compositionengine::RenderSurfaceCreationArgsBuilder()
                    .setDisplayWidth(ANativeWindow_getWidth(args.nativeWindow.get()))
                    .setDisplayHeight(ANativeWindow_getHeight(args.nativeWindow.get()))
                    .setNativeWindow(std::move(args.nativeWindow))
                    .setDisplaySurface(std::move(args.displaySurface))
                    .setMaxTextureCacheSize(
                            static_cast<size_t>(SurfaceFlinger::maxFrameBufferAcquiredBuffers))
                    .build());

    if (!mFlinger->mDisableClientCompositionCache &&
        SurfaceFlinger::maxFrameBufferAcquiredBuffers > 0) {
        mCompositionDisplay->createClientCompositionCache(
                static_cast<uint32_t>(SurfaceFlinger::maxFrameBufferAcquiredBuffers));
    }

    mCompositionDisplay->setPredictCompositionStrategy(mFlinger->mPredictCompositionStrategy);
    mCompositionDisplay->setTreat170mAsSrgb(mFlinger->mTreat170mAsSrgb);
    mCompositionDisplay->createDisplayColorProfile(
            compositionengine::DisplayColorProfileCreationArgsBuilder()
                    .setHasWideColorGamut(args.hasWideColorGamut)
                    .setHdrCapabilities(std::move(args.hdrCapabilities))
                    .setSupportedPerFrameMetadata(args.supportedPerFrameMetadata)
                    .setHwcColorModes(std::move(args.hwcColorModes))
                    .Build());

    if (!mCompositionDisplay->isValid()) {
        ALOGE("Composition Display did not validate!");
    }

    mCompositionDisplay->getRenderSurface()->initialize();

    if (args.initialPowerMode.has_value()) setPowerMode(args.initialPowerMode.value());

    // initialize the display orientation transform.
    setProjection(ui::ROTATION_0, Rect::INVALID_RECT, Rect::INVALID_RECT);
}

DisplayDevice::~DisplayDevice() = default;

void DisplayDevice::disconnect() {
    mCompositionDisplay->disconnect();
}

int DisplayDevice::getWidth() const {
    return mCompositionDisplay->getState().displaySpace.getBounds().width;
}

int DisplayDevice::getHeight() const {
    return mCompositionDisplay->getState().displaySpace.getBounds().height;
}

void DisplayDevice::setDisplayName(const std::string& displayName) {
    if (!displayName.empty()) {
        // never override the name with an empty name
        mDisplayName = displayName;
        mCompositionDisplay->setName(displayName);
    }
}

void DisplayDevice::setDeviceProductInfo(std::optional<DeviceProductInfo> info) {
    mDeviceProductInfo = std::move(info);
}

uint32_t DisplayDevice::getPageFlipCount() const {
    return mCompositionDisplay->getRenderSurface()->getPageFlipCount();
}

auto DisplayDevice::getInputInfo() const -> InputInfo {
    gui::DisplayInfo info;
    info.displayId = getLayerStack().id;

    // The physical orientation is set when the orientation of the display panel is
    // different than the default orientation of the device. Other services like
    // InputFlinger do not know about this, so we do not need to expose the physical
    // orientation of the panel outside of SurfaceFlinger.
    const ui::Rotation inversePhysicalOrientation = ui::ROTATION_0 - mPhysicalOrientation;
    auto width = getWidth();
    auto height = getHeight();
    if (inversePhysicalOrientation == ui::ROTATION_90 ||
        inversePhysicalOrientation == ui::ROTATION_270) {
        std::swap(width, height);
    }
    const ui::Transform undoPhysicalOrientation(ui::Transform::toRotationFlags(
                                                        inversePhysicalOrientation),
                                                width, height);
    const auto& displayTransform = undoPhysicalOrientation * getTransform();
    // Send the inverse display transform to input so it can convert display coordinates to
    // logical display.
    info.transform = displayTransform.inverse();

    info.logicalWidth = getLayerStackSpaceRect().width();
    info.logicalHeight = getLayerStackSpaceRect().height();

    return {.info = info,
            .transform = displayTransform,
            .receivesInput = receivesInput(),
            .isSecure = isSecure()};
}

void DisplayDevice::setPowerMode(hal::PowerMode mode) {
    if (mode == hal::PowerMode::OFF || mode == hal::PowerMode::ON) {
        if (mStagedBrightness && mBrightness != mStagedBrightness) {
            getCompositionDisplay()->setNextBrightness(*mStagedBrightness);
            mBrightness = *mStagedBrightness;
        }
        mStagedBrightness = std::nullopt;
        getCompositionDisplay()->applyDisplayBrightness(true);
    }

    mPowerMode = mode;

    getCompositionDisplay()->setCompositionEnabled(mPowerMode.has_value() &&
                                                   *mPowerMode != hal::PowerMode::OFF);
}

void DisplayDevice::enableLayerCaching(bool enable) {
    getCompositionDisplay()->setLayerCachingEnabled(enable);
}

std::optional<hal::PowerMode> DisplayDevice::getPowerMode() const {
    return mPowerMode;
}

bool DisplayDevice::isPoweredOn() const {
    return mPowerMode && *mPowerMode != hal::PowerMode::OFF;
}

void DisplayDevice::setActiveMode(DisplayModeId id) {
    const auto mode = getMode(id);
    LOG_FATAL_IF(!mode, "Cannot set active mode which is not supported.");
    ATRACE_INT(mActiveModeFPSTrace.c_str(), mode->getFps().getIntValue());
    mActiveMode = mode;
    if (mRefreshRateConfigs) {
        mRefreshRateConfigs->setActiveModeId(mActiveMode->getId());
    }
    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->changeRefreshRate(mActiveMode->getFps());
    }
}

status_t DisplayDevice::initiateModeChange(const ActiveModeInfo& info,
                                           const hal::VsyncPeriodChangeConstraints& constraints,
                                           hal::VsyncPeriodChangeTimeline* outTimeline) {
    if (!info.mode || info.mode->getPhysicalDisplayId() != getPhysicalId()) {
        ALOGE("Trying to initiate a mode change to invalid mode %s on display %s",
              info.mode ? std::to_string(info.mode->getId().value()).c_str() : "null",
              to_string(getId()).c_str());
        return BAD_VALUE;
    }
    mNumModeSwitchesInPolicy++;
    mUpcomingActiveMode = info;
    ATRACE_INT(mActiveModeFPSHwcTrace.c_str(), info.mode->getFps().getIntValue());
    return mHwComposer.setActiveModeWithConstraints(getPhysicalId(), info.mode->getHwcId(),
                                                    constraints, outTimeline);
}

const DisplayModePtr& DisplayDevice::getActiveMode() const {
    return mActiveMode;
}

const DisplayModes& DisplayDevice::getSupportedModes() const {
    return mSupportedModes;
}

DisplayModePtr DisplayDevice::getMode(DisplayModeId modeId) const {
    const DisplayModePtr nullMode;
    return mSupportedModes.get(modeId).value_or(std::cref(nullMode));
}

std::optional<DisplayModeId> DisplayDevice::translateModeId(hal::HWConfigId hwcId) const {
    const auto it =
            std::find_if(mSupportedModes.begin(), mSupportedModes.end(),
                         [hwcId](const auto& pair) { return pair.second->getHwcId() == hwcId; });
    if (it != mSupportedModes.end()) {
        return it->second->getId();
    }
    return {};
}

nsecs_t DisplayDevice::getVsyncPeriodFromHWC() const {
    const auto physicalId = getPhysicalId();
    if (!mHwComposer.isConnected(physicalId)) {
        return 0;
    }

    nsecs_t vsyncPeriod;
    const auto status = mHwComposer.getDisplayVsyncPeriod(physicalId, &vsyncPeriod);
    if (status == NO_ERROR) {
        return vsyncPeriod;
    }

    return getActiveMode()->getFps().getPeriodNsecs();
}

nsecs_t DisplayDevice::getRefreshTimestamp() const {
    const nsecs_t now = systemTime(CLOCK_MONOTONIC);
    const auto vsyncPeriodNanos = getVsyncPeriodFromHWC();
    return now - ((now - mLastHwVsync) % vsyncPeriodNanos);
}

void DisplayDevice::onVsync(nsecs_t timestamp) {
    mLastHwVsync = timestamp;
}

ui::Dataspace DisplayDevice::getCompositionDataSpace() const {
    return mCompositionDisplay->getState().dataspace;
}

void DisplayDevice::setLayerStack(ui::LayerStack stack) {
    mCompositionDisplay->setLayerFilter({stack, isInternal()});
    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->setLayerStack(stack);
    }
}

void DisplayDevice::setFlags(uint32_t flags) {
    mFlags = flags;
}

void DisplayDevice::setDisplaySize(int width, int height) {
    LOG_FATAL_IF(!isVirtual(), "Changing the display size is supported only for virtual displays.");
    const auto size = ui::Size(width, height);
    mCompositionDisplay->setDisplaySize(size);
    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->setViewport(size);
    }
}

void DisplayDevice::setProjection(ui::Rotation orientation, Rect layerStackSpaceRect,
                                  Rect orientedDisplaySpaceRect) {
    mOrientation = orientation;

    if (isPrimary()) {
        sPrimaryDisplayRotationFlags = ui::Transform::toRotationFlags(orientation);
    }

    // We need to take care of display rotation for globalTransform for case if the panel is not
    // installed aligned with device orientation.
    const auto transformOrientation = orientation + mPhysicalOrientation;

    const auto& state = getCompositionDisplay()->getState();

    // If the layer stack and destination frames have never been set, then configure them to be the
    // same as the physical device, taking into account the total transform.
    if (!orientedDisplaySpaceRect.isValid()) {
        ui::Size bounds = state.displaySpace.getBounds();
        bounds.rotate(transformOrientation);
        orientedDisplaySpaceRect = Rect(bounds);
    }
    if (layerStackSpaceRect.isEmpty()) {
        ui::Size bounds = state.framebufferSpace.getBounds();
        bounds.rotate(transformOrientation);
        layerStackSpaceRect = Rect(bounds);
    }
    getCompositionDisplay()->setProjection(transformOrientation, layerStackSpaceRect,
                                           orientedDisplaySpaceRect);
}

void DisplayDevice::stageBrightness(float brightness) {
    mStagedBrightness = brightness;
}

void DisplayDevice::persistBrightness(bool needsComposite) {
    if (mStagedBrightness && mBrightness != mStagedBrightness) {
        if (needsComposite) {
            getCompositionDisplay()->setNextBrightness(*mStagedBrightness);
        }
        mBrightness = *mStagedBrightness;
    }
    mStagedBrightness = std::nullopt;
}

std::optional<float> DisplayDevice::getStagedBrightness() const {
    return mStagedBrightness;
}

ui::Transform::RotationFlags DisplayDevice::getPrimaryDisplayRotationFlags() {
    return sPrimaryDisplayRotationFlags;
}

std::string DisplayDevice::getDebugName() const {
    using namespace std::string_literals;

    std::string name = "Display "s + to_string(getId()) + " ("s;

    if (mConnectionType) {
        name += isInternal() ? "internal"s : "external"s;
    } else {
        name += "virtual"s;
    }

    if (isPrimary()) {
        name += ", primary"s;
    }

    return name + ", \""s + mDisplayName + "\")"s;
}

void DisplayDevice::dump(std::string& result) const {
    using namespace std::string_literals;

    result += getDebugName();

    if (!isVirtual()) {
        result += "\n   deviceProductInfo="s;
        if (mDeviceProductInfo) {
            mDeviceProductInfo->dump(result);
        } else {
            result += "{}"s;
        }
    }

    result += "\n   powerMode="s;
    result += mPowerMode.has_value() ? to_string(mPowerMode.value()) : "OFF(reset)";
    result += '\n';

    if (mRefreshRateConfigs) {
        mRefreshRateConfigs->dump(result);
    }
}

bool DisplayDevice::hasRenderIntent(ui::RenderIntent intent) const {
    return mCompositionDisplay->getDisplayColorProfile()->hasRenderIntent(intent);
}

DisplayId DisplayDevice::getId() const {
    return mCompositionDisplay->getId();
}

bool DisplayDevice::isSecure() const {
    return mCompositionDisplay->isSecure();
}

const Rect DisplayDevice::getBounds() const {
    return mCompositionDisplay->getState().displaySpace.getBoundsAsRect();
}

const Region& DisplayDevice::getUndefinedRegion() const {
    return mCompositionDisplay->getState().undefinedRegion;
}

bool DisplayDevice::needsFiltering() const {
    return mCompositionDisplay->getState().needsFiltering;
}

ui::LayerStack DisplayDevice::getLayerStack() const {
    return mCompositionDisplay->getState().layerFilter.layerStack;
}

ui::Transform::RotationFlags DisplayDevice::getTransformHint() const {
    return mCompositionDisplay->getTransformHint();
}

const ui::Transform& DisplayDevice::getTransform() const {
    return mCompositionDisplay->getState().transform;
}

const Rect& DisplayDevice::getLayerStackSpaceRect() const {
    return mCompositionDisplay->getState().layerStackSpace.getContent();
}

const Rect& DisplayDevice::getOrientedDisplaySpaceRect() const {
    return mCompositionDisplay->getState().orientedDisplaySpace.getContent();
}

bool DisplayDevice::hasWideColorGamut() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasWideColorGamut();
}

bool DisplayDevice::hasHDR10PlusSupport() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasHDR10PlusSupport();
}

bool DisplayDevice::hasHDR10Support() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasHDR10Support();
}

bool DisplayDevice::hasHLGSupport() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasHLGSupport();
}

bool DisplayDevice::hasDolbyVisionSupport() const {
    return mCompositionDisplay->getDisplayColorProfile()->hasDolbyVisionSupport();
}

int DisplayDevice::getSupportedPerFrameMetadata() const {
    return mCompositionDisplay->getDisplayColorProfile()->getSupportedPerFrameMetadata();
}

void DisplayDevice::overrideHdrTypes(const std::vector<ui::Hdr>& hdrTypes) {
    mOverrideHdrTypes = hdrTypes;
}

HdrCapabilities DisplayDevice::getHdrCapabilities() const {
    const HdrCapabilities& capabilities =
            mCompositionDisplay->getDisplayColorProfile()->getHdrCapabilities();
    std::vector<ui::Hdr> hdrTypes = capabilities.getSupportedHdrTypes();
    if (!mOverrideHdrTypes.empty()) {
        hdrTypes = mOverrideHdrTypes;
    }
    return HdrCapabilities(hdrTypes, capabilities.getDesiredMaxLuminance(),
                           capabilities.getDesiredMaxAverageLuminance(),
                           capabilities.getDesiredMinLuminance());
}

void DisplayDevice::enableRefreshRateOverlay(bool enable, bool showSpinnner) {
    if (!enable) {
        mRefreshRateOverlay.reset();
        return;
    }

    const auto fpsRange = mRefreshRateConfigs->getSupportedRefreshRateRange();
    mRefreshRateOverlay = std::make_unique<RefreshRateOverlay>(fpsRange, showSpinnner);
    mRefreshRateOverlay->setLayerStack(getLayerStack());
    mRefreshRateOverlay->setViewport(getSize());
    mRefreshRateOverlay->changeRefreshRate(getActiveMode()->getFps());
}

bool DisplayDevice::onKernelTimerChanged(std::optional<DisplayModeId> desiredModeId,
                                         bool timerExpired) {
    if (mRefreshRateConfigs && mRefreshRateOverlay) {
        const auto newRefreshRate =
                mRefreshRateConfigs->onKernelTimerChanged(desiredModeId, timerExpired);
        if (newRefreshRate) {
            mRefreshRateOverlay->changeRefreshRate(*newRefreshRate);
            return true;
        }
    }

    return false;
}

void DisplayDevice::animateRefreshRateOverlay() {
    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->animate();
    }
}

bool DisplayDevice::setDesiredActiveMode(const ActiveModeInfo& info, bool force) {
    ATRACE_CALL();

    LOG_ALWAYS_FATAL_IF(!info.mode, "desired mode not provided");
    LOG_ALWAYS_FATAL_IF(getPhysicalId() != info.mode->getPhysicalDisplayId(), "DisplayId mismatch");

    ALOGV("%s(%s)", __func__, to_string(*info.mode).c_str());

    std::scoped_lock lock(mActiveModeLock);
    if (mDesiredActiveModeChanged) {
        // If a mode change is pending, just cache the latest request in mDesiredActiveMode
        const auto prevConfig = mDesiredActiveMode.event;
        mDesiredActiveMode = info;
        mDesiredActiveMode.event = mDesiredActiveMode.event | prevConfig;
        return false;
    }

    // Check if we are already at the desired mode
    if (!force && getActiveMode()->getId() == info.mode->getId()) {
        return false;
    }

    // Initiate a mode change.
    mDesiredActiveModeChanged = true;
    mDesiredActiveMode = info;
    return true;
}

std::optional<DisplayDevice::ActiveModeInfo> DisplayDevice::getDesiredActiveMode() const {
    std::scoped_lock lock(mActiveModeLock);
    if (mDesiredActiveModeChanged) return mDesiredActiveMode;
    return std::nullopt;
}

void DisplayDevice::clearDesiredActiveModeState() {
    std::scoped_lock lock(mActiveModeLock);
    mDesiredActiveMode.event = scheduler::DisplayModeEvent::None;
    mDesiredActiveModeChanged = false;
}

status_t DisplayDevice::setRefreshRatePolicy(
        const std::optional<scheduler::RefreshRateConfigs::Policy>& policy, bool overridePolicy) {
    const auto oldPolicy = mRefreshRateConfigs->getCurrentPolicy();
    const status_t setPolicyResult = overridePolicy
            ? mRefreshRateConfigs->setOverridePolicy(policy)
            : mRefreshRateConfigs->setDisplayManagerPolicy(*policy);

    if (setPolicyResult == OK) {
        const int numModeChanges = mNumModeSwitchesInPolicy.exchange(0);

        ALOGI("Display %s policy changed\n"
              "Previous: {%s}\n"
              "Current:  {%s}\n"
              "%d mode changes were performed under the previous policy",
              to_string(getId()).c_str(), oldPolicy.toString().c_str(),
              policy ? policy->toString().c_str() : "null", numModeChanges);
    }

    return setPolicyResult;
}

std::atomic<int32_t> DisplayDeviceState::sNextSequenceId(1);

}  // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
