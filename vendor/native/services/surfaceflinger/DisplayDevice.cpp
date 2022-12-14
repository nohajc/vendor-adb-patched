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

#include <android-base/stringprintf.h>
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

using android::base::StringAppendF;

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

    mCompositionDisplay->createDisplayColorProfile(
            compositionengine::DisplayColorProfileCreationArgs{args.hasWideColorGamut,
                                                               std::move(args.hdrCapabilities),
                                                               args.supportedPerFrameMetadata,
                                                               args.hwcColorModes});

    if (!mCompositionDisplay->isValid()) {
        ALOGE("Composition Display did not validate!");
    }

    mCompositionDisplay->getRenderSurface()->initialize();

    setPowerMode(args.initialPowerMode);

    // initialize the display orientation transform.
    setProjection(ui::ROTATION_0, Rect::INVALID_RECT, Rect::INVALID_RECT);
}

DisplayDevice::~DisplayDevice() = default;

void DisplayDevice::disconnect() {
    mCompositionDisplay->disconnect();
}

int DisplayDevice::getWidth() const {
    return mCompositionDisplay->getState().displaySpace.bounds.getWidth();
}

int DisplayDevice::getHeight() const {
    return mCompositionDisplay->getState().displaySpace.bounds.getHeight();
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

// ----------------------------------------------------------------------------
void DisplayDevice::setPowerMode(hal::PowerMode mode) {
    mPowerMode = mode;
    getCompositionDisplay()->setCompositionEnabled(mPowerMode != hal::PowerMode::OFF);
}

void DisplayDevice::enableLayerCaching(bool enable) {
    getCompositionDisplay()->setLayerCachingEnabled(enable);
}

hal::PowerMode DisplayDevice::getPowerMode() const {
    return mPowerMode;
}

bool DisplayDevice::isPoweredOn() const {
    return mPowerMode != hal::PowerMode::OFF;
}

void DisplayDevice::setActiveMode(DisplayModeId id) {
    const auto mode = getMode(id);
    LOG_FATAL_IF(!mode, "Cannot set active mode which is not supported.");
    ATRACE_INT(mActiveModeFPSTrace.c_str(), mode->getFps().getIntValue());
    mActiveMode = mode;
    if (mRefreshRateConfigs) {
        mRefreshRateConfigs->setCurrentModeId(mActiveMode->getId());
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
    const auto it = std::find_if(mSupportedModes.begin(), mSupportedModes.end(),
                                 [&](DisplayModePtr mode) { return mode->getId() == modeId; });
    if (it != mSupportedModes.end()) {
        return *it;
    }
    return nullptr;
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
    mCompositionDisplay->setLayerStackFilter(stack, isInternal());
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

    if (!orientedDisplaySpaceRect.isValid()) {
        // The destination frame can be invalid if it has never been set,
        // in that case we assume the whole display size.
        orientedDisplaySpaceRect = getCompositionDisplay()->getState().displaySpace.bounds;
    }

    if (layerStackSpaceRect.isEmpty()) {
        // The layerStackSpaceRect can be invalid if it has never been set, in that case
        // we assume the whole framebuffer size.
        layerStackSpaceRect = getCompositionDisplay()->getState().framebufferSpace.bounds;
        if (orientation == ui::ROTATION_90 || orientation == ui::ROTATION_270) {
            std::swap(layerStackSpaceRect.right, layerStackSpaceRect.bottom);
        }
    }

    // We need to take care of display rotation for globalTransform for case if the panel is not
    // installed aligned with device orientation.
    const auto transformOrientation = orientation + mPhysicalOrientation;
    getCompositionDisplay()->setProjection(transformOrientation, layerStackSpaceRect,
                                           orientedDisplaySpaceRect);
}

ui::Transform::RotationFlags DisplayDevice::getPrimaryDisplayRotationFlags() {
    return sPrimaryDisplayRotationFlags;
}

std::string DisplayDevice::getDebugName() const {
    const char* type = "virtual";
    if (mConnectionType) {
        type = isInternal() ? "internal" : "external";
    }

    return base::StringPrintf("DisplayDevice{%s, %s%s, \"%s\"}", to_string(getId()).c_str(), type,
                              isPrimary() ? ", primary" : "", mDisplayName.c_str());
}

void DisplayDevice::dump(std::string& result) const {
    StringAppendF(&result, "+ %s\n", getDebugName().c_str());
    StringAppendF(&result, "   powerMode=%s (%d)\n", to_string(mPowerMode).c_str(),
                  static_cast<int32_t>(mPowerMode));
    const auto activeMode = getActiveMode();
    StringAppendF(&result, "   activeMode=%s\n",
                  activeMode ? to_string(*activeMode).c_str() : "none");

    result.append("   supportedModes=\n");

    for (const auto& mode : mSupportedModes) {
        result.append("     ");
        result.append(to_string(*mode));
        result.append("\n");
    }
    StringAppendF(&result, "   deviceProductInfo=");
    if (mDeviceProductInfo) {
        mDeviceProductInfo->dump(result);
    } else {
        result.append("{}");
    }
    result.append("\n");
    getCompositionDisplay()->dump(result);

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

const Rect& DisplayDevice::getBounds() const {
    return mCompositionDisplay->getState().displaySpace.bounds;
}

const Region& DisplayDevice::getUndefinedRegion() const {
    return mCompositionDisplay->getState().undefinedRegion;
}

bool DisplayDevice::needsFiltering() const {
    return mCompositionDisplay->getState().needsFiltering;
}

ui::LayerStack DisplayDevice::getLayerStack() const {
    return mCompositionDisplay->getState().layerStackId;
}

ui::Transform::RotationFlags DisplayDevice::getTransformHint() const {
    return mCompositionDisplay->getTransformHint();
}

const ui::Transform& DisplayDevice::getTransform() const {
    return mCompositionDisplay->getState().transform;
}

const Rect& DisplayDevice::getLayerStackSpaceRect() const {
    return mCompositionDisplay->getState().layerStackSpace.content;
}

const Rect& DisplayDevice::getOrientedDisplaySpaceRect() const {
    return mCompositionDisplay->getState().orientedDisplaySpace.content;
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

    const auto [lowFps, highFps] = mRefreshRateConfigs->getSupportedRefreshRateRange();
    mRefreshRateOverlay = std::make_unique<RefreshRateOverlay>(*mFlinger, lowFps.getIntValue(),
                                                               highFps.getIntValue(), showSpinnner);
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

void DisplayDevice::onInvalidate() {
    if (mRefreshRateOverlay) {
        mRefreshRateOverlay->onInvalidate();
    }
}

bool DisplayDevice::setDesiredActiveMode(const ActiveModeInfo& info) {
    ATRACE_CALL();

    LOG_ALWAYS_FATAL_IF(!info.mode, "desired mode not provided");
    LOG_ALWAYS_FATAL_IF(getPhysicalId() != info.mode->getPhysicalDisplayId(), "DisplayId mismatch");

    ALOGV("%s(%s)", __func__, to_string(*info.mode).c_str());

    std::scoped_lock lock(mActiveModeLock);
    if (mDesiredActiveModeChanged) {
        // If a mode change is pending, just cache the latest request in mDesiredActiveMode
        const Scheduler::ModeEvent prevConfig = mDesiredActiveMode.event;
        mDesiredActiveMode = info;
        mDesiredActiveMode.event = mDesiredActiveMode.event | prevConfig;
        return false;
    }

    // Check if we are already at the desired mode
    if (getActiveMode()->getId() == info.mode->getId()) {
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
    mDesiredActiveMode.event = Scheduler::ModeEvent::None;
    mDesiredActiveModeChanged = false;
}

std::atomic<int32_t> DisplayDeviceState::sNextSequenceId(1);

}  // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
