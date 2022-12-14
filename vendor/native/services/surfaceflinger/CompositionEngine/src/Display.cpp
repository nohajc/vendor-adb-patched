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

#include <android-base/stringprintf.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/CompositionRefreshArgs.h>
#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/DisplaySurface.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/impl/Display.h>
#include <compositionengine/impl/DisplayColorProfile.h>
#include <compositionengine/impl/DumpHelpers.h>
#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/impl/RenderSurface.h>

#include <utils/Trace.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include "DisplayHardware/HWComposer.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

#include "DisplayHardware/PowerAdvisor.h"

using aidl::android::hardware::graphics::composer3::Capability;
using aidl::android::hardware::graphics::composer3::DisplayCapability;

namespace android::compositionengine::impl {

std::shared_ptr<Display> createDisplay(
        const compositionengine::CompositionEngine& compositionEngine,
        const compositionengine::DisplayCreationArgs& args) {
    return createDisplayTemplated<Display>(compositionEngine, args);
}

Display::~Display() = default;

void Display::setConfiguration(const compositionengine::DisplayCreationArgs& args) {
    mId = args.id;
    mPowerAdvisor = args.powerAdvisor;
    editState().isSecure = args.isSecure;
    editState().displaySpace.setBounds(args.pixels);
    setName(args.name);
}

bool Display::isValid() const {
    return Output::isValid() && mPowerAdvisor;
}

DisplayId Display::getId() const {
    return mId;
}

bool Display::isSecure() const {
    return getState().isSecure;
}

bool Display::isVirtual() const {
    return VirtualDisplayId::tryCast(mId).has_value();
}

std::optional<DisplayId> Display::getDisplayId() const {
    return mId;
}

void Display::disconnect() {
    if (mIsDisconnected) {
        return;
    }

    mIsDisconnected = true;

    if (const auto id = HalDisplayId::tryCast(mId)) {
        getCompositionEngine().getHwComposer().disconnectDisplay(*id);
    }
}

void Display::setColorTransform(const compositionengine::CompositionRefreshArgs& args) {
    Output::setColorTransform(args);
    const auto halDisplayId = HalDisplayId::tryCast(mId);
    if (mIsDisconnected || !halDisplayId || CC_LIKELY(!args.colorTransformMatrix)) {
        return;
    }

    auto& hwc = getCompositionEngine().getHwComposer();
    status_t result = hwc.setColorTransform(*halDisplayId, *args.colorTransformMatrix);
    ALOGE_IF(result != NO_ERROR, "Failed to set color transform on display \"%s\": %d",
             to_string(mId).c_str(), result);
}

void Display::setColorProfile(const ColorProfile& colorProfile) {
    const ui::Dataspace targetDataspace =
            getDisplayColorProfile()->getTargetDataspace(colorProfile.mode, colorProfile.dataspace,
                                                         colorProfile.colorSpaceAgnosticDataspace);

    if (colorProfile.mode == getState().colorMode &&
        colorProfile.dataspace == getState().dataspace &&
        colorProfile.renderIntent == getState().renderIntent &&
        targetDataspace == getState().targetDataspace) {
        return;
    }

    if (isVirtual()) {
        ALOGW("%s: Invalid operation on virtual display", __func__);
        return;
    }

    Output::setColorProfile(colorProfile);

    const auto physicalId = PhysicalDisplayId::tryCast(mId);
    LOG_FATAL_IF(!physicalId);
    getCompositionEngine().getHwComposer().setActiveColorMode(*physicalId, colorProfile.mode,
                                                              colorProfile.renderIntent);
}

void Display::dump(std::string& out) const {
    const char* const type = isVirtual() ? "virtual" : "physical";
    base::StringAppendF(&out, "Display %s (%s, \"%s\")", to_string(mId).c_str(), type,
                        getName().c_str());

    out.append("\n   Composition Display State:\n");
    Output::dumpBase(out);
}

void Display::createDisplayColorProfile(const DisplayColorProfileCreationArgs& args) {
    setDisplayColorProfile(compositionengine::impl::createDisplayColorProfile(args));
}

void Display::createRenderSurface(const RenderSurfaceCreationArgs& args) {
    setRenderSurface(
            compositionengine::impl::createRenderSurface(getCompositionEngine(), *this, args));
}

void Display::createClientCompositionCache(uint32_t cacheSize) {
    cacheClientCompositionRequests(cacheSize);
}

std::unique_ptr<compositionengine::OutputLayer> Display::createOutputLayer(
        const sp<compositionengine::LayerFE>& layerFE) const {
    auto outputLayer = impl::createOutputLayer(*this, layerFE);

    if (const auto halDisplayId = HalDisplayId::tryCast(mId);
        outputLayer && !mIsDisconnected && halDisplayId) {
        auto& hwc = getCompositionEngine().getHwComposer();
        auto hwcLayer = hwc.createLayer(*halDisplayId);
        ALOGE_IF(!hwcLayer, "Failed to create a HWC layer for a HWC supported display %s",
                 getName().c_str());
        outputLayer->setHwcLayer(std::move(hwcLayer));
    }
    return outputLayer;
}

void Display::setReleasedLayers(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    Output::setReleasedLayers(refreshArgs);

    if (mIsDisconnected || GpuVirtualDisplayId::tryCast(mId) ||
        refreshArgs.layersWithQueuedFrames.empty()) {
        return;
    }

    // For layers that are being removed from a HWC display, and that have
    // queued frames, add them to a a list of released layers so we can properly
    // set a fence.
    compositionengine::Output::ReleasedLayers releasedLayers;

    // Any non-null entries in the current list of layers are layers that are no
    // longer going to be visible
    for (auto* outputLayer : getOutputLayersOrderedByZ()) {
        if (!outputLayer) {
            continue;
        }

        compositionengine::LayerFE* layerFE = &outputLayer->getLayerFE();
        const bool hasQueuedFrames =
                std::any_of(refreshArgs.layersWithQueuedFrames.cbegin(),
                            refreshArgs.layersWithQueuedFrames.cend(),
                            [layerFE](sp<compositionengine::LayerFE> layerWithQueuedFrames) {
                                return layerFE == layerWithQueuedFrames.get();
                            });

        if (hasQueuedFrames) {
            releasedLayers.emplace_back(layerFE);
        }
    }

    setReleasedLayers(std::move(releasedLayers));
}

void Display::applyDisplayBrightness(const bool applyImmediately) {
    auto& hwc = getCompositionEngine().getHwComposer();
    const auto halDisplayId = HalDisplayId::tryCast(*getDisplayId());
    if (const auto physicalDisplayId = PhysicalDisplayId::tryCast(*halDisplayId);
        physicalDisplayId && getState().displayBrightness) {
        const status_t result =
                hwc.setDisplayBrightness(*physicalDisplayId, *getState().displayBrightness,
                                         getState().displayBrightnessNits,
                                         Hwc2::Composer::DisplayBrightnessOptions{
                                                 .applyImmediately = applyImmediately})
                        .get();
        ALOGE_IF(result != NO_ERROR, "setDisplayBrightness failed for %s: %d, (%s)",
                 getName().c_str(), result, strerror(-result));
    }
    // Clear out the display brightness now that it's been communicated to composer.
    editState().displayBrightness.reset();
}

void Display::beginFrame() {
    Output::beginFrame();

    // If we don't have a HWC display, then we are done.
    const auto halDisplayId = HalDisplayId::tryCast(mId);
    if (!halDisplayId) {
        return;
    }

    applyDisplayBrightness(false);
}

bool Display::chooseCompositionStrategy(
        std::optional<android::HWComposer::DeviceRequestedChanges>* outChanges) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (mIsDisconnected) {
        return false;
    }

    // If we don't have a HWC display, then we are done.
    const auto halDisplayId = HalDisplayId::tryCast(mId);
    if (!halDisplayId) {
        return false;
    }

    const nsecs_t startTime = systemTime();

    // Get any composition changes requested by the HWC device, and apply them.
    std::optional<android::HWComposer::DeviceRequestedChanges> changes;
    auto& hwc = getCompositionEngine().getHwComposer();
    const bool requiresClientComposition = anyLayersRequireClientComposition();
    if (status_t result =
                hwc.getDeviceCompositionChanges(*halDisplayId, requiresClientComposition,
                                                getState().earliestPresentTime,
                                                getState().previousPresentFence,
                                                getState().expectedPresentTime, outChanges);
        result != NO_ERROR) {
        ALOGE("chooseCompositionStrategy failed for %s: %d (%s)", getName().c_str(), result,
              strerror(-result));
        return false;
    }

    if (isPowerHintSessionEnabled()) {
        mPowerAdvisor->setHwcValidateTiming(mId, startTime, systemTime());
        mPowerAdvisor->setRequiresClientComposition(mId, requiresClientComposition);
    }

    return true;
}

void Display::applyCompositionStrategy(const std::optional<DeviceRequestedChanges>& changes) {
    if (changes) {
        applyChangedTypesToLayers(changes->changedTypes);
        applyDisplayRequests(changes->displayRequests);
        applyLayerRequestsToLayers(changes->layerRequests);
        applyClientTargetRequests(changes->clientTargetProperty);
    }

    // Determine what type of composition we are doing from the final state
    auto& state = editState();
    state.usesClientComposition = anyLayersRequireClientComposition();
    state.usesDeviceComposition = !allLayersRequireClientComposition();
}

bool Display::getSkipColorTransform() const {
    const auto& hwc = getCompositionEngine().getHwComposer();
    if (const auto halDisplayId = HalDisplayId::tryCast(mId)) {
        return hwc.hasDisplayCapability(*halDisplayId,
                                        DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM);
    }

    return hwc.hasCapability(Capability::SKIP_CLIENT_COLOR_TRANSFORM);
}

bool Display::allLayersRequireClientComposition() const {
    const auto layers = getOutputLayersOrderedByZ();
    return std::all_of(layers.begin(), layers.end(),
                       [](const auto& layer) { return layer->requiresClientComposition(); });
}

void Display::applyChangedTypesToLayers(const ChangedTypes& changedTypes) {
    if (changedTypes.empty()) {
        return;
    }

    for (auto* layer : getOutputLayersOrderedByZ()) {
        auto hwcLayer = layer->getHwcLayer();
        if (!hwcLayer) {
            continue;
        }

        if (auto it = changedTypes.find(hwcLayer); it != changedTypes.end()) {
            layer->applyDeviceCompositionTypeChange(
                    static_cast<aidl::android::hardware::graphics::composer3::Composition>(
                            it->second));
        }
    }
}

void Display::applyDisplayRequests(const DisplayRequests& displayRequests) {
    auto& state = editState();
    state.flipClientTarget = (static_cast<uint32_t>(displayRequests) &
                              static_cast<uint32_t>(hal::DisplayRequest::FLIP_CLIENT_TARGET)) != 0;
    // Note: HWC2::DisplayRequest::WriteClientTargetToOutput is currently ignored.
}

void Display::applyLayerRequestsToLayers(const LayerRequests& layerRequests) {
    for (auto* layer : getOutputLayersOrderedByZ()) {
        layer->prepareForDeviceLayerRequests();

        auto hwcLayer = layer->getHwcLayer();
        if (!hwcLayer) {
            continue;
        }

        if (auto it = layerRequests.find(hwcLayer); it != layerRequests.end()) {
            layer->applyDeviceLayerRequest(
                    static_cast<Hwc2::IComposerClient::LayerRequest>(it->second));
        }
    }
}

void Display::applyClientTargetRequests(const ClientTargetProperty& clientTargetProperty) {
    if (static_cast<ui::Dataspace>(clientTargetProperty.clientTargetProperty.dataspace) ==
        ui::Dataspace::UNKNOWN) {
        return;
    }

    editState().dataspace =
            static_cast<ui::Dataspace>(clientTargetProperty.clientTargetProperty.dataspace);
    editState().clientTargetBrightness = clientTargetProperty.brightness;
    editState().clientTargetDimmingStage = clientTargetProperty.dimmingStage;
    getRenderSurface()->setBufferDataspace(editState().dataspace);
    getRenderSurface()->setBufferPixelFormat(
            static_cast<ui::PixelFormat>(clientTargetProperty.clientTargetProperty.pixelFormat));
}

compositionengine::Output::FrameFences Display::presentAndGetFrameFences() {
    auto fences = impl::Output::presentAndGetFrameFences();

    const auto halDisplayIdOpt = HalDisplayId::tryCast(mId);
    if (mIsDisconnected || !halDisplayIdOpt) {
        return fences;
    }

    auto& hwc = getCompositionEngine().getHwComposer();

    const nsecs_t startTime = systemTime();

    if (isPowerHintSessionEnabled()) {
        if (!getCompositionEngine().getHwComposer().getComposer()->isSupported(
                    Hwc2::Composer::OptionalFeature::ExpectedPresentTime) &&
            getState().previousPresentFence->getSignalTime() != Fence::SIGNAL_TIME_PENDING) {
            mPowerAdvisor->setHwcPresentDelayedTime(mId, getState().earliestPresentTime);
        }
    }

    hwc.presentAndGetReleaseFences(*halDisplayIdOpt, getState().earliestPresentTime,
                                   getState().previousPresentFence);

    if (isPowerHintSessionEnabled()) {
        mPowerAdvisor->setHwcPresentTiming(mId, startTime, systemTime());
    }

    fences.presentFence = hwc.getPresentFence(*halDisplayIdOpt);

    // TODO(b/121291683): Change HWComposer call to return entire map
    for (const auto* layer : getOutputLayersOrderedByZ()) {
        auto hwcLayer = layer->getHwcLayer();
        if (!hwcLayer) {
            continue;
        }

        fences.layerFences.emplace(hwcLayer, hwc.getLayerReleaseFence(*halDisplayIdOpt, hwcLayer));
    }

    hwc.clearReleaseFences(*halDisplayIdOpt);

    return fences;
}

void Display::setExpensiveRenderingExpected(bool enabled) {
    Output::setExpensiveRenderingExpected(enabled);

    if (mPowerAdvisor && !GpuVirtualDisplayId::tryCast(mId)) {
        mPowerAdvisor->setExpensiveRenderingExpected(mId, enabled);
    }
}

bool Display::isPowerHintSessionEnabled() {
    return mPowerAdvisor != nullptr && mPowerAdvisor->usePowerHintSession();
}

void Display::setHintSessionGpuFence(std::unique_ptr<FenceTime>&& gpuFence) {
    mPowerAdvisor->setGpuFenceTime(mId, std::move(gpuFence));
}

void Display::finishFrame(const compositionengine::CompositionRefreshArgs& refreshArgs,
                          GpuCompositionResult&& result) {
    // We only need to actually compose the display if:
    // 1) It is being handled by hardware composer, which may need this to
    //    keep its virtual display state machine in sync, or
    // 2) There is work to be done (the dirty region isn't empty)
    if (GpuVirtualDisplayId::tryCast(mId) && !mustRecompose()) {
        ALOGV("Skipping display composition");
        return;
    }

    impl::Output::finishFrame(refreshArgs, std::move(result));

    if (isPowerHintSessionEnabled()) {
        auto& hwc = getCompositionEngine().getHwComposer();
        if (auto halDisplayId = HalDisplayId::tryCast(mId)) {
            mPowerAdvisor->setSkippedValidate(mId, hwc.getValidateSkipped(*halDisplayId));
        }
    }
}

} // namespace android::compositionengine::impl
