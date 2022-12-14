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

namespace android::compositionengine::impl {

std::shared_ptr<Display> createDisplay(
        const compositionengine::CompositionEngine& compositionEngine,
        const compositionengine::DisplayCreationArgs& args) {
    return createDisplayTemplated<Display>(compositionEngine, args);
}

Display::~Display() = default;

void Display::setConfiguration(const compositionengine::DisplayCreationArgs& args) {
    mId = args.id;
    mIsVirtual = !args.connectionType;
    mPowerAdvisor = args.powerAdvisor;
    editState().isSecure = args.isSecure;
    editState().displaySpace.bounds = Rect(args.pixels);
    setLayerStackFilter(args.layerStackId,
                        args.connectionType == ui::DisplayConnectionType::Internal);
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
    return mIsVirtual;
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

    if (mIsVirtual) {
        ALOGW("%s: Invalid operation on virtual display", __FUNCTION__);
        return;
    }

    Output::setColorProfile(colorProfile);

    const auto physicalId = PhysicalDisplayId::tryCast(mId);
    LOG_FATAL_IF(!physicalId);
    getCompositionEngine().getHwComposer().setActiveColorMode(*physicalId, colorProfile.mode,
                                                              colorProfile.renderIntent);
}

void Display::dump(std::string& out) const {
    using android::base::StringAppendF;

    StringAppendF(&out, "   Composition Display State: [\"%s\"]", getName().c_str());

    out.append("\n   ");
    dumpVal(out, "isVirtual", mIsVirtual);
    dumpVal(out, "DisplayId", to_string(mId));
    out.append("\n");

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

void Display::chooseCompositionStrategy() {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (mIsDisconnected) {
        return;
    }

    // Default to the base settings -- client composition only.
    Output::chooseCompositionStrategy();

    // If we don't have a HWC display, then we are done.
    const auto halDisplayId = HalDisplayId::tryCast(mId);
    if (!halDisplayId) {
        return;
    }

    // Get any composition changes requested by the HWC device, and apply them.
    std::optional<android::HWComposer::DeviceRequestedChanges> changes;
    auto& hwc = getCompositionEngine().getHwComposer();
    if (status_t result =
                hwc.getDeviceCompositionChanges(*halDisplayId, anyLayersRequireClientComposition(),
                                                getState().earliestPresentTime,
                                                getState().previousPresentFence, &changes);
        result != NO_ERROR) {
        ALOGE("chooseCompositionStrategy failed for %s: %d (%s)", getName().c_str(), result,
              strerror(-result));
        return;
    }
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
                                        hal::DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM);
    }

    return hwc.hasCapability(hal::Capability::SKIP_CLIENT_COLOR_TRANSFORM);
}

bool Display::anyLayersRequireClientComposition() const {
    const auto layers = getOutputLayersOrderedByZ();
    return std::any_of(layers.begin(), layers.end(),
                       [](const auto& layer) { return layer->requiresClientComposition(); });
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
                    static_cast<Hwc2::IComposerClient::Composition>(it->second));
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
    if (clientTargetProperty.dataspace == ui::Dataspace::UNKNOWN) {
        return;
    }

    editState().dataspace = clientTargetProperty.dataspace;
    getRenderSurface()->setBufferDataspace(clientTargetProperty.dataspace);
    getRenderSurface()->setBufferPixelFormat(clientTargetProperty.pixelFormat);
}

compositionengine::Output::FrameFences Display::presentAndGetFrameFences() {
    auto fences = impl::Output::presentAndGetFrameFences();

    const auto halDisplayIdOpt = HalDisplayId::tryCast(mId);
    if (mIsDisconnected || !halDisplayIdOpt) {
        return fences;
    }

    auto& hwc = getCompositionEngine().getHwComposer();
    hwc.presentAndGetReleaseFences(*halDisplayIdOpt, getState().earliestPresentTime,
                                   getState().previousPresentFence);

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

void Display::finishFrame(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    // We only need to actually compose the display if:
    // 1) It is being handled by hardware composer, which may need this to
    //    keep its virtual display state machine in sync, or
    // 2) There is work to be done (the dirty region isn't empty)
    if (GpuVirtualDisplayId::tryCast(mId) &&
        getDirtyRegion(refreshArgs.repaintEverything).isEmpty()) {
        ALOGV("Skipping display composition");
        return;
    }

    impl::Output::finishFrame(refreshArgs);
}

} // namespace android::compositionengine::impl
