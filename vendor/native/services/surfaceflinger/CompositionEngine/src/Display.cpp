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
    mIsVirtual = !args.physical;
    mId = args.physical ? std::make_optional(args.physical->id) : std::nullopt;
    mPowerAdvisor = args.powerAdvisor;

    editState().isSecure = args.isSecure;

    setLayerStackFilter(args.layerStackId,
                        args.physical ? args.physical->type == DisplayConnectionType::Internal
                                      : false);
    setName(args.name);

    if (!args.physical && args.useHwcVirtualDisplays) {
        mId = maybeAllocateDisplayIdForVirtualDisplay(args.pixels, args.pixelFormat);
    }
}

std::optional<DisplayId> Display::maybeAllocateDisplayIdForVirtualDisplay(
        ui::Size pixels, ui::PixelFormat pixelFormat) const {
    auto& hwc = getCompositionEngine().getHwComposer();
    return hwc.allocateVirtualDisplay(static_cast<uint32_t>(pixels.width),
                                      static_cast<uint32_t>(pixels.height), &pixelFormat);
}

bool Display::isValid() const {
    return Output::isValid() && mPowerAdvisor;
}

const std::optional<DisplayId>& Display::getId() const {
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

void Display::setDisplayIdForTesting(std::optional<DisplayId> displayId) {
    mId = displayId;
}

void Display::disconnect() {
    if (!mId) {
        return;
    }

    auto& hwc = getCompositionEngine().getHwComposer();
    hwc.disconnectDisplay(*mId);
    mId.reset();
}

void Display::setColorTransform(const compositionengine::CompositionRefreshArgs& args) {
    Output::setColorTransform(args);

    if (!mId || CC_LIKELY(!args.colorTransformMatrix)) {
        return;
    }

    auto& hwc = getCompositionEngine().getHwComposer();
    status_t result = hwc.setColorTransform(*mId, *args.colorTransformMatrix);
    ALOGE_IF(result != NO_ERROR, "Failed to set color transform on display \"%s\": %d",
             mId ? to_string(*mId).c_str() : "", result);
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

    auto& hwc = getCompositionEngine().getHwComposer();
    hwc.setActiveColorMode(*mId, colorProfile.mode, colorProfile.renderIntent);
}

void Display::dump(std::string& out) const {
    using android::base::StringAppendF;

    StringAppendF(&out, "   Composition Display State: [\"%s\"]", getName().c_str());

    out.append("\n   ");

    dumpVal(out, "isVirtual", mIsVirtual);
    if (mId) {
        dumpVal(out, "hwcId", to_string(*mId));
    } else {
        StringAppendF(&out, "no hwcId, ");
    }

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
    auto result = impl::createOutputLayer(*this, layerFE);

    if (result && mId) {
        auto& hwc = getCompositionEngine().getHwComposer();
        auto displayId = *mId;
        // Note: For the moment we ensure it is safe to take a reference to the
        // HWComposer implementation by destroying all the OutputLayers (and
        // hence the HWC2::Layers they own) before setting a new HWComposer. See
        // for example SurfaceFlinger::updateVrFlinger().
        // TODO(b/121291683): Make this safer.
        auto hwcLayer = std::shared_ptr<HWC2::Layer>(hwc.createLayer(displayId),
                                                     [&hwc, displayId](HWC2::Layer* layer) {
                                                         hwc.destroyLayer(displayId, layer);
                                                     });
        ALOGE_IF(!hwcLayer, "Failed to create a HWC layer for a HWC supported display %s",
                 getName().c_str());
        result->setHwcLayer(std::move(hwcLayer));
    }
    return result;
}

void Display::setReleasedLayers(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    Output::setReleasedLayers(refreshArgs);

    if (!mId || refreshArgs.layersWithQueuedFrames.empty()) {
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

    // Default to the base settings -- client composition only.
    Output::chooseCompositionStrategy();

    // If we don't have a HWC display, then we are done
    if (!mId) {
        return;
    }

    // Get any composition changes requested by the HWC device, and apply them.
    std::optional<android::HWComposer::DeviceRequestedChanges> changes;
    auto& hwc = getCompositionEngine().getHwComposer();
    if (status_t result = hwc.getDeviceCompositionChanges(*mId, anyLayersRequireClientComposition(),
                                                          &changes);
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
    return mId ? hwc.hasDisplayCapability(*mId, hal::DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM)
               : hwc.hasCapability(hal::Capability::SKIP_CLIENT_COLOR_TRANSFORM);
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
    auto outputState = editState();
    outputState.dataspace = clientTargetProperty.dataspace;
    getRenderSurface()->setBufferDataspace(clientTargetProperty.dataspace);
    getRenderSurface()->setBufferPixelFormat(clientTargetProperty.pixelFormat);
}

compositionengine::Output::FrameFences Display::presentAndGetFrameFences() {
    auto result = impl::Output::presentAndGetFrameFences();

    if (!mId) {
        return result;
    }

    auto& hwc = getCompositionEngine().getHwComposer();
    hwc.presentAndGetReleaseFences(*mId);

    result.presentFence = hwc.getPresentFence(*mId);

    // TODO(b/121291683): Change HWComposer call to return entire map
    for (const auto* layer : getOutputLayersOrderedByZ()) {
        auto hwcLayer = layer->getHwcLayer();
        if (!hwcLayer) {
            continue;
        }

        result.layerFences.emplace(hwcLayer, hwc.getLayerReleaseFence(*mId, hwcLayer));
    }

    hwc.clearReleaseFences(*mId);

    return result;
}

void Display::setExpensiveRenderingExpected(bool enabled) {
    Output::setExpensiveRenderingExpected(enabled);

    if (mPowerAdvisor && mId) {
        mPowerAdvisor->setExpensiveRenderingExpected(*mId, enabled);
    }
}

void Display::finishFrame(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    // We only need to actually compose the display if:
    // 1) It is being handled by hardware composer, which may need this to
    //    keep its virtual display state machine in sync, or
    // 2) There is work to be done (the dirty region isn't empty)
    if (!mId) {
        if (getDirtyRegion(refreshArgs.repaintEverything).isEmpty()) {
            ALOGV("Skipping display composition");
            return;
        }
    }

    impl::Output::finishFrame(refreshArgs);
}

} // namespace android::compositionengine::impl
