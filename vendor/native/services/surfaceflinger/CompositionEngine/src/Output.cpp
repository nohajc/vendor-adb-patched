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

#include <thread>

#include <android-base/stringprintf.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/CompositionRefreshArgs.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/impl/Output.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <renderengine/DisplaySettings.h>
#include <renderengine/RenderEngine.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

#include <ui/DebugUtils.h>
#include <ui/HdrCapabilities.h>
#include <utils/Trace.h>

#include "TracedOrdinal.h"

namespace android::compositionengine {

Output::~Output() = default;

namespace impl {

namespace {

template <typename T>
class Reversed {
public:
    explicit Reversed(const T& container) : mContainer(container) {}
    auto begin() { return mContainer.rbegin(); }
    auto end() { return mContainer.rend(); }

private:
    const T& mContainer;
};

// Helper for enumerating over a container in reverse order
template <typename T>
Reversed<T> reversed(const T& c) {
    return Reversed<T>(c);
}

} // namespace

std::shared_ptr<Output> createOutput(
        const compositionengine::CompositionEngine& compositionEngine) {
    return createOutputTemplated<Output>(compositionEngine);
}

Output::~Output() = default;

bool Output::isValid() const {
    return mDisplayColorProfile && mDisplayColorProfile->isValid() && mRenderSurface &&
            mRenderSurface->isValid();
}

std::optional<DisplayId> Output::getDisplayId() const {
    return {};
}

const std::string& Output::getName() const {
    return mName;
}

void Output::setName(const std::string& name) {
    mName = name;
}

void Output::setCompositionEnabled(bool enabled) {
    auto& outputState = editState();
    if (outputState.isEnabled == enabled) {
        return;
    }

    outputState.isEnabled = enabled;
    dirtyEntireOutput();
}

void Output::setProjection(const ui::Transform& transform, uint32_t orientation, const Rect& frame,
                           const Rect& viewport, const Rect& sourceClip,
                           const Rect& destinationClip, bool needsFiltering) {
    auto& outputState = editState();
    outputState.transform = transform;
    outputState.orientation = orientation;
    outputState.sourceClip = sourceClip;
    outputState.destinationClip = destinationClip;
    outputState.frame = frame;
    outputState.viewport = viewport;
    outputState.needsFiltering = needsFiltering;

    dirtyEntireOutput();
}

// TODO(b/121291683): Rename setSize() once more is moved.
void Output::setBounds(const ui::Size& size) {
    mRenderSurface->setDisplaySize(size);
    // TODO(b/121291683): Rename outputState.size once more is moved.
    editState().bounds = Rect(mRenderSurface->getSize());

    dirtyEntireOutput();
}

void Output::setLayerStackFilter(uint32_t layerStackId, bool isInternal) {
    auto& outputState = editState();
    outputState.layerStackId = layerStackId;
    outputState.layerStackInternal = isInternal;

    dirtyEntireOutput();
}

void Output::setColorTransform(const compositionengine::CompositionRefreshArgs& args) {
    auto& colorTransformMatrix = editState().colorTransformMatrix;
    if (!args.colorTransformMatrix || colorTransformMatrix == args.colorTransformMatrix) {
        return;
    }

    colorTransformMatrix = *args.colorTransformMatrix;

    dirtyEntireOutput();
}

void Output::setColorProfile(const ColorProfile& colorProfile) {
    ui::Dataspace targetDataspace =
            getDisplayColorProfile()->getTargetDataspace(colorProfile.mode, colorProfile.dataspace,
                                                         colorProfile.colorSpaceAgnosticDataspace);

    auto& outputState = editState();
    if (outputState.colorMode == colorProfile.mode &&
        outputState.dataspace == colorProfile.dataspace &&
        outputState.renderIntent == colorProfile.renderIntent &&
        outputState.targetDataspace == targetDataspace) {
        return;
    }

    outputState.colorMode = colorProfile.mode;
    outputState.dataspace = colorProfile.dataspace;
    outputState.renderIntent = colorProfile.renderIntent;
    outputState.targetDataspace = targetDataspace;

    mRenderSurface->setBufferDataspace(colorProfile.dataspace);

    ALOGV("Set active color mode: %s (%d), active render intent: %s (%d)",
          decodeColorMode(colorProfile.mode).c_str(), colorProfile.mode,
          decodeRenderIntent(colorProfile.renderIntent).c_str(), colorProfile.renderIntent);

    dirtyEntireOutput();
}

void Output::dump(std::string& out) const {
    using android::base::StringAppendF;

    StringAppendF(&out, "   Composition Output State: [\"%s\"]", mName.c_str());

    out.append("\n   ");

    dumpBase(out);
}

void Output::dumpBase(std::string& out) const {
    dumpState(out);

    if (mDisplayColorProfile) {
        mDisplayColorProfile->dump(out);
    } else {
        out.append("    No display color profile!\n");
    }

    if (mRenderSurface) {
        mRenderSurface->dump(out);
    } else {
        out.append("    No render surface!\n");
    }

    android::base::StringAppendF(&out, "\n   %zu Layers\n", getOutputLayerCount());
    for (const auto* outputLayer : getOutputLayersOrderedByZ()) {
        if (!outputLayer) {
            continue;
        }
        outputLayer->dump(out);
    }
}

compositionengine::DisplayColorProfile* Output::getDisplayColorProfile() const {
    return mDisplayColorProfile.get();
}

void Output::setDisplayColorProfile(std::unique_ptr<compositionengine::DisplayColorProfile> mode) {
    mDisplayColorProfile = std::move(mode);
}

const Output::ReleasedLayers& Output::getReleasedLayersForTest() const {
    return mReleasedLayers;
}

void Output::setDisplayColorProfileForTest(
        std::unique_ptr<compositionengine::DisplayColorProfile> mode) {
    mDisplayColorProfile = std::move(mode);
}

compositionengine::RenderSurface* Output::getRenderSurface() const {
    return mRenderSurface.get();
}

void Output::setRenderSurface(std::unique_ptr<compositionengine::RenderSurface> surface) {
    mRenderSurface = std::move(surface);
    editState().bounds = Rect(mRenderSurface->getSize());

    dirtyEntireOutput();
}

void Output::cacheClientCompositionRequests(uint32_t cacheSize) {
    if (cacheSize == 0) {
        mClientCompositionRequestCache.reset();
    } else {
        mClientCompositionRequestCache = std::make_unique<ClientCompositionRequestCache>(cacheSize);
    }
};

void Output::setRenderSurfaceForTest(std::unique_ptr<compositionengine::RenderSurface> surface) {
    mRenderSurface = std::move(surface);
}

Region Output::getDirtyRegion(bool repaintEverything) const {
    const auto& outputState = getState();
    Region dirty(outputState.viewport);
    if (!repaintEverything) {
        dirty.andSelf(outputState.dirtyRegion);
    }
    return dirty;
}

bool Output::belongsInOutput(std::optional<uint32_t> layerStackId, bool internalOnly) const {
    // The layerStackId's must match, and also the layer must not be internal
    // only when not on an internal output.
    const auto& outputState = getState();
    return layerStackId && (*layerStackId == outputState.layerStackId) &&
            (!internalOnly || outputState.layerStackInternal);
}

bool Output::belongsInOutput(const sp<compositionengine::LayerFE>& layerFE) const {
    const auto* layerFEState = layerFE->getCompositionState();
    return layerFEState && belongsInOutput(layerFEState->layerStackId, layerFEState->internalOnly);
}

std::unique_ptr<compositionengine::OutputLayer> Output::createOutputLayer(
        const sp<LayerFE>& layerFE) const {
    return impl::createOutputLayer(*this, layerFE);
}

compositionengine::OutputLayer* Output::getOutputLayerForLayer(const sp<LayerFE>& layerFE) const {
    auto index = findCurrentOutputLayerForLayer(layerFE);
    return index ? getOutputLayerOrderedByZByIndex(*index) : nullptr;
}

std::optional<size_t> Output::findCurrentOutputLayerForLayer(
        const sp<compositionengine::LayerFE>& layer) const {
    for (size_t i = 0; i < getOutputLayerCount(); i++) {
        auto outputLayer = getOutputLayerOrderedByZByIndex(i);
        if (outputLayer && &outputLayer->getLayerFE() == layer.get()) {
            return i;
        }
    }
    return std::nullopt;
}

void Output::setReleasedLayers(Output::ReleasedLayers&& layers) {
    mReleasedLayers = std::move(layers);
}

void Output::prepare(const compositionengine::CompositionRefreshArgs& refreshArgs,
                     LayerFESet& geomSnapshots) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    rebuildLayerStacks(refreshArgs, geomSnapshots);
}

void Output::present(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    updateColorProfile(refreshArgs);
    updateAndWriteCompositionState(refreshArgs);
    setColorTransform(refreshArgs);
    beginFrame();
    prepareFrame();
    devOptRepaintFlash(refreshArgs);
    finishFrame(refreshArgs);
    postFramebuffer();
}

void Output::rebuildLayerStacks(const compositionengine::CompositionRefreshArgs& refreshArgs,
                                LayerFESet& layerFESet) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    auto& outputState = editState();

    // Do nothing if this output is not enabled or there is no need to perform this update
    if (!outputState.isEnabled || CC_LIKELY(!refreshArgs.updatingOutputGeometryThisFrame)) {
        return;
    }

    // Process the layers to determine visibility and coverage
    compositionengine::Output::CoverageState coverage{layerFESet};
    collectVisibleLayers(refreshArgs, coverage);

    // Compute the resulting coverage for this output, and store it for later
    const ui::Transform& tr = outputState.transform;
    Region undefinedRegion{outputState.bounds};
    undefinedRegion.subtractSelf(tr.transform(coverage.aboveOpaqueLayers));

    outputState.undefinedRegion = undefinedRegion;
    outputState.dirtyRegion.orSelf(coverage.dirtyRegion);
}

void Output::collectVisibleLayers(const compositionengine::CompositionRefreshArgs& refreshArgs,
                                  compositionengine::Output::CoverageState& coverage) {
    // Evaluate the layers from front to back to determine what is visible. This
    // also incrementally calculates the coverage information for each layer as
    // well as the entire output.
    for (auto layer : reversed(refreshArgs.layers)) {
        // Incrementally process the coverage for each layer
        ensureOutputLayerIfVisible(layer, coverage);

        // TODO(b/121291683): Stop early if the output is completely covered and
        // no more layers could even be visible underneath the ones on top.
    }

    setReleasedLayers(refreshArgs);

    finalizePendingOutputLayers();

    // Generate a simple Z-order values to each visible output layer
    uint32_t zOrder = 0;
    for (auto* outputLayer : getOutputLayersOrderedByZ()) {
        outputLayer->editState().z = zOrder++;
    }
}

void Output::ensureOutputLayerIfVisible(sp<compositionengine::LayerFE>& layerFE,
                                        compositionengine::Output::CoverageState& coverage) {
    // Ensure we have a snapshot of the basic geometry layer state. Limit the
    // snapshots to once per frame for each candidate layer, as layers may
    // appear on multiple outputs.
    if (!coverage.latchedLayers.count(layerFE)) {
        coverage.latchedLayers.insert(layerFE);
        layerFE->prepareCompositionState(compositionengine::LayerFE::StateSubset::BasicGeometry);
    }

    // Only consider the layers on the given layer stack
    if (!belongsInOutput(layerFE)) {
        return;
    }

    // Obtain a read-only pointer to the front-end layer state
    const auto* layerFEState = layerFE->getCompositionState();
    if (CC_UNLIKELY(!layerFEState)) {
        return;
    }

    // handle hidden surfaces by setting the visible region to empty
    if (CC_UNLIKELY(!layerFEState->isVisible)) {
        return;
    }

    /*
     * opaqueRegion: area of a surface that is fully opaque.
     */
    Region opaqueRegion;

    /*
     * visibleRegion: area of a surface that is visible on screen and not fully
     * transparent. This is essentially the layer's footprint minus the opaque
     * regions above it. Areas covered by a translucent surface are considered
     * visible.
     */
    Region visibleRegion;

    /*
     * coveredRegion: area of a surface that is covered by all visible regions
     * above it (which includes the translucent areas).
     */
    Region coveredRegion;

    /*
     * transparentRegion: area of a surface that is hinted to be completely
     * transparent. This is only used to tell when the layer has no visible non-
     * transparent regions and can be removed from the layer list. It does not
     * affect the visibleRegion of this layer or any layers beneath it. The hint
     * may not be correct if apps don't respect the SurfaceView restrictions
     * (which, sadly, some don't).
     */
    Region transparentRegion;

    /*
     * shadowRegion: Region cast by the layer's shadow.
     */
    Region shadowRegion;

    const ui::Transform& tr = layerFEState->geomLayerTransform;

    // Get the visible region
    // TODO(b/121291683): Is it worth creating helper methods on LayerFEState
    // for computations like this?
    const Rect visibleRect(tr.transform(layerFEState->geomLayerBounds));
    visibleRegion.set(visibleRect);

    if (layerFEState->shadowRadius > 0.0f) {
        // if the layer casts a shadow, offset the layers visible region and
        // calculate the shadow region.
        const auto inset = static_cast<int32_t>(ceilf(layerFEState->shadowRadius) * -1.0f);
        Rect visibleRectWithShadows(visibleRect);
        visibleRectWithShadows.inset(inset, inset, inset, inset);
        visibleRegion.set(visibleRectWithShadows);
        shadowRegion = visibleRegion.subtract(visibleRect);
    }

    if (visibleRegion.isEmpty()) {
        return;
    }

    // Remove the transparent area from the visible region
    if (!layerFEState->isOpaque) {
        if (tr.preserveRects()) {
            // transform the transparent region
            transparentRegion = tr.transform(layerFEState->transparentRegionHint);
        } else {
            // transformation too complex, can't do the
            // transparent region optimization.
            transparentRegion.clear();
        }
    }

    // compute the opaque region
    const auto layerOrientation = tr.getOrientation();
    if (layerFEState->isOpaque && ((layerOrientation & ui::Transform::ROT_INVALID) == 0)) {
        // If we one of the simple category of transforms (0/90/180/270 rotation
        // + any flip), then the opaque region is the layer's footprint.
        // Otherwise we don't try and compute the opaque region since there may
        // be errors at the edges, and we treat the entire layer as
        // translucent.
        opaqueRegion.set(visibleRect);
    }

    // Clip the covered region to the visible region
    coveredRegion = coverage.aboveCoveredLayers.intersect(visibleRegion);

    // Update accumAboveCoveredLayers for next (lower) layer
    coverage.aboveCoveredLayers.orSelf(visibleRegion);

    // subtract the opaque region covered by the layers above us
    visibleRegion.subtractSelf(coverage.aboveOpaqueLayers);

    if (visibleRegion.isEmpty()) {
        return;
    }

    // Get coverage information for the layer as previously displayed,
    // also taking over ownership from mOutputLayersorderedByZ.
    auto prevOutputLayerIndex = findCurrentOutputLayerForLayer(layerFE);
    auto prevOutputLayer =
            prevOutputLayerIndex ? getOutputLayerOrderedByZByIndex(*prevOutputLayerIndex) : nullptr;

    //  Get coverage information for the layer as previously displayed
    // TODO(b/121291683): Define kEmptyRegion as a constant in Region.h
    const Region kEmptyRegion;
    const Region& oldVisibleRegion =
            prevOutputLayer ? prevOutputLayer->getState().visibleRegion : kEmptyRegion;
    const Region& oldCoveredRegion =
            prevOutputLayer ? prevOutputLayer->getState().coveredRegion : kEmptyRegion;

    // compute this layer's dirty region
    Region dirty;
    if (layerFEState->contentDirty) {
        // we need to invalidate the whole region
        dirty = visibleRegion;
        // as well, as the old visible region
        dirty.orSelf(oldVisibleRegion);
    } else {
        /* compute the exposed region:
         *   the exposed region consists of two components:
         *   1) what's VISIBLE now and was COVERED before
         *   2) what's EXPOSED now less what was EXPOSED before
         *
         * note that (1) is conservative, we start with the whole visible region
         * but only keep what used to be covered by something -- which mean it
         * may have been exposed.
         *
         * (2) handles areas that were not covered by anything but got exposed
         * because of a resize.
         *
         */
        const Region newExposed = visibleRegion - coveredRegion;
        const Region oldExposed = oldVisibleRegion - oldCoveredRegion;
        dirty = (visibleRegion & oldCoveredRegion) | (newExposed - oldExposed);
    }
    dirty.subtractSelf(coverage.aboveOpaqueLayers);

    // accumulate to the screen dirty region
    coverage.dirtyRegion.orSelf(dirty);

    // Update accumAboveOpaqueLayers for next (lower) layer
    coverage.aboveOpaqueLayers.orSelf(opaqueRegion);

    // Compute the visible non-transparent region
    Region visibleNonTransparentRegion = visibleRegion.subtract(transparentRegion);

    // Perform the final check to see if this layer is visible on this output
    // TODO(b/121291683): Why does this not use visibleRegion? (see outputSpaceVisibleRegion below)
    const auto& outputState = getState();
    Region drawRegion(outputState.transform.transform(visibleNonTransparentRegion));
    drawRegion.andSelf(outputState.bounds);
    if (drawRegion.isEmpty()) {
        return;
    }

    Region visibleNonShadowRegion = visibleRegion.subtract(shadowRegion);

    // The layer is visible. Either reuse the existing outputLayer if we have
    // one, or create a new one if we do not.
    auto result = ensureOutputLayer(prevOutputLayerIndex, layerFE);

    // Store the layer coverage information into the layer state as some of it
    // is useful later.
    auto& outputLayerState = result->editState();
    outputLayerState.visibleRegion = visibleRegion;
    outputLayerState.visibleNonTransparentRegion = visibleNonTransparentRegion;
    outputLayerState.coveredRegion = coveredRegion;
    outputLayerState.outputSpaceVisibleRegion =
            outputState.transform.transform(visibleNonShadowRegion.intersect(outputState.viewport));
    outputLayerState.shadowRegion = shadowRegion;
}

void Output::setReleasedLayers(const compositionengine::CompositionRefreshArgs&) {
    // The base class does nothing with this call.
}

void Output::updateLayerStateFromFE(const CompositionRefreshArgs& args) const {
    for (auto* layer : getOutputLayersOrderedByZ()) {
        layer->getLayerFE().prepareCompositionState(
                args.updatingGeometryThisFrame ? LayerFE::StateSubset::GeometryAndContent
                                               : LayerFE::StateSubset::Content);
    }
}

void Output::updateAndWriteCompositionState(
        const compositionengine::CompositionRefreshArgs& refreshArgs) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (!getState().isEnabled) {
        return;
    }

    mLayerRequestingBackgroundBlur = findLayerRequestingBackgroundComposition();
    bool forceClientComposition = mLayerRequestingBackgroundBlur != nullptr;

    for (auto* layer : getOutputLayersOrderedByZ()) {
        layer->updateCompositionState(refreshArgs.updatingGeometryThisFrame,
                                      refreshArgs.devOptForceClientComposition ||
                                              forceClientComposition,
                                      refreshArgs.internalDisplayRotationFlags);

        if (mLayerRequestingBackgroundBlur == layer) {
            forceClientComposition = false;
        }

        // Send the updated state to the HWC, if appropriate.
        layer->writeStateToHWC(refreshArgs.updatingGeometryThisFrame);
    }
}

compositionengine::OutputLayer* Output::findLayerRequestingBackgroundComposition() const {
    compositionengine::OutputLayer* layerRequestingBgComposition = nullptr;
    for (auto* layer : getOutputLayersOrderedByZ()) {
        if (layer->getLayerFE().getCompositionState()->backgroundBlurRadius > 0) {
            layerRequestingBgComposition = layer;
        }
    }
    return layerRequestingBgComposition;
}

void Output::updateColorProfile(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    setColorProfile(pickColorProfile(refreshArgs));
}

// Returns a data space that fits all visible layers.  The returned data space
// can only be one of
//  - Dataspace::SRGB (use legacy dataspace and let HWC saturate when colors are enhanced)
//  - Dataspace::DISPLAY_P3
//  - Dataspace::DISPLAY_BT2020
// The returned HDR data space is one of
//  - Dataspace::UNKNOWN
//  - Dataspace::BT2020_HLG
//  - Dataspace::BT2020_PQ
ui::Dataspace Output::getBestDataspace(ui::Dataspace* outHdrDataSpace,
                                       bool* outIsHdrClientComposition) const {
    ui::Dataspace bestDataSpace = ui::Dataspace::V0_SRGB;
    *outHdrDataSpace = ui::Dataspace::UNKNOWN;

    for (const auto* layer : getOutputLayersOrderedByZ()) {
        switch (layer->getLayerFE().getCompositionState()->dataspace) {
            case ui::Dataspace::V0_SCRGB:
            case ui::Dataspace::V0_SCRGB_LINEAR:
            case ui::Dataspace::BT2020:
            case ui::Dataspace::BT2020_ITU:
            case ui::Dataspace::BT2020_LINEAR:
            case ui::Dataspace::DISPLAY_BT2020:
                bestDataSpace = ui::Dataspace::DISPLAY_BT2020;
                break;
            case ui::Dataspace::DISPLAY_P3:
                bestDataSpace = ui::Dataspace::DISPLAY_P3;
                break;
            case ui::Dataspace::BT2020_PQ:
            case ui::Dataspace::BT2020_ITU_PQ:
                bestDataSpace = ui::Dataspace::DISPLAY_P3;
                *outHdrDataSpace = ui::Dataspace::BT2020_PQ;
                *outIsHdrClientComposition =
                        layer->getLayerFE().getCompositionState()->forceClientComposition;
                break;
            case ui::Dataspace::BT2020_HLG:
            case ui::Dataspace::BT2020_ITU_HLG:
                bestDataSpace = ui::Dataspace::DISPLAY_P3;
                // When there's mixed PQ content and HLG content, we set the HDR
                // data space to be BT2020_PQ and convert HLG to PQ.
                if (*outHdrDataSpace == ui::Dataspace::UNKNOWN) {
                    *outHdrDataSpace = ui::Dataspace::BT2020_HLG;
                }
                break;
            default:
                break;
        }
    }

    return bestDataSpace;
}

compositionengine::Output::ColorProfile Output::pickColorProfile(
        const compositionengine::CompositionRefreshArgs& refreshArgs) const {
    if (refreshArgs.outputColorSetting == OutputColorSetting::kUnmanaged) {
        return ColorProfile{ui::ColorMode::NATIVE, ui::Dataspace::UNKNOWN,
                            ui::RenderIntent::COLORIMETRIC,
                            refreshArgs.colorSpaceAgnosticDataspace};
    }

    ui::Dataspace hdrDataSpace;
    bool isHdrClientComposition = false;
    ui::Dataspace bestDataSpace = getBestDataspace(&hdrDataSpace, &isHdrClientComposition);

    switch (refreshArgs.forceOutputColorMode) {
        case ui::ColorMode::SRGB:
            bestDataSpace = ui::Dataspace::V0_SRGB;
            break;
        case ui::ColorMode::DISPLAY_P3:
            bestDataSpace = ui::Dataspace::DISPLAY_P3;
            break;
        default:
            break;
    }

    // respect hdrDataSpace only when there is no legacy HDR support
    const bool isHdr = hdrDataSpace != ui::Dataspace::UNKNOWN &&
            !mDisplayColorProfile->hasLegacyHdrSupport(hdrDataSpace) && !isHdrClientComposition;
    if (isHdr) {
        bestDataSpace = hdrDataSpace;
    }

    ui::RenderIntent intent;
    switch (refreshArgs.outputColorSetting) {
        case OutputColorSetting::kManaged:
        case OutputColorSetting::kUnmanaged:
            intent = isHdr ? ui::RenderIntent::TONE_MAP_COLORIMETRIC
                           : ui::RenderIntent::COLORIMETRIC;
            break;
        case OutputColorSetting::kEnhanced:
            intent = isHdr ? ui::RenderIntent::TONE_MAP_ENHANCE : ui::RenderIntent::ENHANCE;
            break;
        default: // vendor display color setting
            intent = static_cast<ui::RenderIntent>(refreshArgs.outputColorSetting);
            break;
    }

    ui::ColorMode outMode;
    ui::Dataspace outDataSpace;
    ui::RenderIntent outRenderIntent;
    mDisplayColorProfile->getBestColorMode(bestDataSpace, intent, &outDataSpace, &outMode,
                                           &outRenderIntent);

    return ColorProfile{outMode, outDataSpace, outRenderIntent,
                        refreshArgs.colorSpaceAgnosticDataspace};
}

void Output::beginFrame() {
    auto& outputState = editState();
    const bool dirty = !getDirtyRegion(false).isEmpty();
    const bool empty = getOutputLayerCount() == 0;
    const bool wasEmpty = !outputState.lastCompositionHadVisibleLayers;

    // If nothing has changed (!dirty), don't recompose.
    // If something changed, but we don't currently have any visible layers,
    //   and didn't when we last did a composition, then skip it this time.
    // The second rule does two things:
    // - When all layers are removed from a display, we'll emit one black
    //   frame, then nothing more until we get new layers.
    // - When a display is created with a private layer stack, we won't
    //   emit any black frames until a layer is added to the layer stack.
    const bool mustRecompose = dirty && !(empty && wasEmpty);

    const char flagPrefix[] = {'-', '+'};
    static_cast<void>(flagPrefix);
    ALOGV_IF("%s: %s composition for %s (%cdirty %cempty %cwasEmpty)", __FUNCTION__,
             mustRecompose ? "doing" : "skipping", getName().c_str(), flagPrefix[dirty],
             flagPrefix[empty], flagPrefix[wasEmpty]);

    mRenderSurface->beginFrame(mustRecompose);

    if (mustRecompose) {
        outputState.lastCompositionHadVisibleLayers = !empty;
    }
}

void Output::prepareFrame() {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    const auto& outputState = getState();
    if (!outputState.isEnabled) {
        return;
    }

    chooseCompositionStrategy();

    mRenderSurface->prepareFrame(outputState.usesClientComposition,
                                 outputState.usesDeviceComposition);
}

void Output::devOptRepaintFlash(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    if (CC_LIKELY(!refreshArgs.devOptFlashDirtyRegionsDelay)) {
        return;
    }

    if (getState().isEnabled) {
        // transform the dirty region into this screen's coordinate space
        const Region dirtyRegion = getDirtyRegion(refreshArgs.repaintEverything);
        if (!dirtyRegion.isEmpty()) {
            base::unique_fd readyFence;
            // redraw the whole screen
            static_cast<void>(composeSurfaces(dirtyRegion, refreshArgs));

            mRenderSurface->queueBuffer(std::move(readyFence));
        }
    }

    postFramebuffer();

    std::this_thread::sleep_for(*refreshArgs.devOptFlashDirtyRegionsDelay);

    prepareFrame();
}

void Output::finishFrame(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (!getState().isEnabled) {
        return;
    }

    // Repaint the framebuffer (if needed), getting the optional fence for when
    // the composition completes.
    auto optReadyFence = composeSurfaces(Region::INVALID_REGION, refreshArgs);
    if (!optReadyFence) {
        return;
    }

    // swap buffers (presentation)
    mRenderSurface->queueBuffer(std::move(*optReadyFence));
}

std::optional<base::unique_fd> Output::composeSurfaces(
        const Region& debugRegion, const compositionengine::CompositionRefreshArgs& refreshArgs) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    const auto& outputState = getState();
    OutputCompositionState& outputCompositionState = editState();
    const TracedOrdinal<bool> hasClientComposition = {"hasClientComposition",
                                                      outputState.usesClientComposition};

    auto& renderEngine = getCompositionEngine().getRenderEngine();
    const bool supportsProtectedContent = renderEngine.supportsProtectedContent();

    // If we the display is secure, protected content support is enabled, and at
    // least one layer has protected content, we need to use a secure back
    // buffer.
    if (outputState.isSecure && supportsProtectedContent) {
        auto layers = getOutputLayersOrderedByZ();
        bool needsProtected = std::any_of(layers.begin(), layers.end(), [](auto* layer) {
            return layer->getLayerFE().getCompositionState()->hasProtectedContent;
        });
        if (needsProtected != renderEngine.isProtected()) {
            renderEngine.useProtectedContext(needsProtected);
        }
        if (needsProtected != mRenderSurface->isProtected() &&
            needsProtected == renderEngine.isProtected()) {
            mRenderSurface->setProtected(needsProtected);
        }
    } else if (!outputState.isSecure && renderEngine.isProtected()) {
        renderEngine.useProtectedContext(false);
    }

    base::unique_fd fd;
    sp<GraphicBuffer> buf;

    // If we aren't doing client composition on this output, but do have a
    // flipClientTarget request for this frame on this output, we still need to
    // dequeue a buffer.
    if (hasClientComposition || outputState.flipClientTarget) {
        buf = mRenderSurface->dequeueBuffer(&fd);
        if (buf == nullptr) {
            ALOGW("Dequeuing buffer for display [%s] failed, bailing out of "
                  "client composition for this frame",
                  mName.c_str());
            return {};
        }
    }

    base::unique_fd readyFence;
    if (!hasClientComposition) {
        setExpensiveRenderingExpected(false);
        return readyFence;
    }

    ALOGV("hasClientComposition");

    renderengine::DisplaySettings clientCompositionDisplay;
    clientCompositionDisplay.physicalDisplay = outputState.destinationClip;
    clientCompositionDisplay.clip = outputState.sourceClip;
    clientCompositionDisplay.orientation = outputState.orientation;
    clientCompositionDisplay.outputDataspace = mDisplayColorProfile->hasWideColorGamut()
            ? outputState.dataspace
            : ui::Dataspace::UNKNOWN;
    clientCompositionDisplay.maxLuminance =
            mDisplayColorProfile->getHdrCapabilities().getDesiredMaxLuminance();

    // Compute the global color transform matrix.
    if (!outputState.usesDeviceComposition && !getSkipColorTransform()) {
        clientCompositionDisplay.colorTransform = outputState.colorTransformMatrix;
    }

    // Note: Updated by generateClientCompositionRequests
    clientCompositionDisplay.clearRegion = Region::INVALID_REGION;

    // Generate the client composition requests for the layers on this output.
    std::vector<LayerFE::LayerSettings> clientCompositionLayers =
            generateClientCompositionRequests(supportsProtectedContent,
                                              clientCompositionDisplay.clearRegion,
                                              clientCompositionDisplay.outputDataspace);
    appendRegionFlashRequests(debugRegion, clientCompositionLayers);

    // Check if the client composition requests were rendered into the provided graphic buffer. If
    // so, we can reuse the buffer and avoid client composition.
    if (mClientCompositionRequestCache) {
        if (mClientCompositionRequestCache->exists(buf->getId(), clientCompositionDisplay,
                                                   clientCompositionLayers)) {
            outputCompositionState.reusedClientComposition = true;
            setExpensiveRenderingExpected(false);
            return readyFence;
        }
        mClientCompositionRequestCache->add(buf->getId(), clientCompositionDisplay,
                                            clientCompositionLayers);
    }

    // We boost GPU frequency here because there will be color spaces conversion
    // or complex GPU shaders and it's expensive. We boost the GPU frequency so that
    // GPU composition can finish in time. We must reset GPU frequency afterwards,
    // because high frequency consumes extra battery.
    const bool expensiveBlurs =
            refreshArgs.blursAreExpensive && mLayerRequestingBackgroundBlur != nullptr;
    const bool expensiveRenderingExpected =
            clientCompositionDisplay.outputDataspace == ui::Dataspace::DISPLAY_P3 || expensiveBlurs;
    if (expensiveRenderingExpected) {
        setExpensiveRenderingExpected(true);
    }

    std::vector<const renderengine::LayerSettings*> clientCompositionLayerPointers;
    clientCompositionLayerPointers.reserve(clientCompositionLayers.size());
    std::transform(clientCompositionLayers.begin(), clientCompositionLayers.end(),
                   std::back_inserter(clientCompositionLayerPointers),
                   [](LayerFE::LayerSettings& settings) -> renderengine::LayerSettings* {
                       return &settings;
                   });

    const nsecs_t renderEngineStart = systemTime();
    status_t status =
            renderEngine.drawLayers(clientCompositionDisplay, clientCompositionLayerPointers,
                                    buf->getNativeBuffer(), /*useFramebufferCache=*/true,
                                    std::move(fd), &readyFence);

    if (status != NO_ERROR && mClientCompositionRequestCache) {
        // If rendering was not successful, remove the request from the cache.
        mClientCompositionRequestCache->remove(buf->getId());
    }

    auto& timeStats = getCompositionEngine().getTimeStats();
    if (readyFence.get() < 0) {
        timeStats.recordRenderEngineDuration(renderEngineStart, systemTime());
    } else {
        timeStats.recordRenderEngineDuration(renderEngineStart,
                                             std::make_shared<FenceTime>(
                                                     new Fence(dup(readyFence.get()))));
    }

    return readyFence;
}

std::vector<LayerFE::LayerSettings> Output::generateClientCompositionRequests(
        bool supportsProtectedContent, Region& clearRegion, ui::Dataspace outputDataspace) {
    std::vector<LayerFE::LayerSettings> clientCompositionLayers;
    ALOGV("Rendering client layers");

    const auto& outputState = getState();
    const Region viewportRegion(outputState.viewport);
    const bool useIdentityTransform = false;
    bool firstLayer = true;
    // Used when a layer clears part of the buffer.
    Region stubRegion;

    for (auto* layer : getOutputLayersOrderedByZ()) {
        const auto& layerState = layer->getState();
        const auto* layerFEState = layer->getLayerFE().getCompositionState();
        auto& layerFE = layer->getLayerFE();

        const Region clip(viewportRegion.intersect(layerState.visibleRegion));
        ALOGV("Layer: %s", layerFE.getDebugName());
        if (clip.isEmpty()) {
            ALOGV("  Skipping for empty clip");
            firstLayer = false;
            continue;
        }

        const bool clientComposition = layer->requiresClientComposition();

        // We clear the client target for non-client composed layers if
        // requested by the HWC. We skip this if the layer is not an opaque
        // rectangle, as by definition the layer must blend with whatever is
        // underneath. We also skip the first layer as the buffer target is
        // guaranteed to start out cleared.
        const bool clearClientComposition =
                layerState.clearClientTarget && layerFEState->isOpaque && !firstLayer;

        ALOGV("  Composition type: client %d clear %d", clientComposition, clearClientComposition);

        // If the layer casts a shadow but the content casting the shadow is occluded, skip
        // composing the non-shadow content and only draw the shadows.
        const bool realContentIsVisible = clientComposition &&
                !layerState.visibleRegion.subtract(layerState.shadowRegion).isEmpty();

        if (clientComposition || clearClientComposition) {
            compositionengine::LayerFE::ClientCompositionTargetSettings targetSettings{
                    clip,
                    useIdentityTransform,
                    layer->needsFiltering() || outputState.needsFiltering,
                    outputState.isSecure,
                    supportsProtectedContent,
                    clientComposition ? clearRegion : stubRegion,
                    outputState.viewport,
                    outputDataspace,
                    realContentIsVisible,
                    !clientComposition, /* clearContent  */
            };
            std::vector<LayerFE::LayerSettings> results =
                    layerFE.prepareClientCompositionList(targetSettings);
            if (realContentIsVisible && !results.empty()) {
                layer->editState().clientCompositionTimestamp = systemTime();
            }

            clientCompositionLayers.insert(clientCompositionLayers.end(),
                                           std::make_move_iterator(results.begin()),
                                           std::make_move_iterator(results.end()));
            results.clear();
        }

        firstLayer = false;
    }

    return clientCompositionLayers;
}

void Output::appendRegionFlashRequests(
        const Region& flashRegion, std::vector<LayerFE::LayerSettings>& clientCompositionLayers) {
    if (flashRegion.isEmpty()) {
        return;
    }

    LayerFE::LayerSettings layerSettings;
    layerSettings.source.buffer.buffer = nullptr;
    layerSettings.source.solidColor = half3(1.0, 0.0, 1.0);
    layerSettings.alpha = half(1.0);

    for (const auto& rect : flashRegion) {
        layerSettings.geometry.boundaries = rect.toFloatRect();
        clientCompositionLayers.push_back(layerSettings);
    }
}

void Output::setExpensiveRenderingExpected(bool) {
    // The base class does nothing with this call.
}

void Output::postFramebuffer() {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (!getState().isEnabled) {
        return;
    }

    auto& outputState = editState();
    outputState.dirtyRegion.clear();
    mRenderSurface->flip();

    auto frame = presentAndGetFrameFences();

    mRenderSurface->onPresentDisplayCompleted();

    for (auto* layer : getOutputLayersOrderedByZ()) {
        // The layer buffer from the previous frame (if any) is released
        // by HWC only when the release fence from this frame (if any) is
        // signaled.  Always get the release fence from HWC first.
        sp<Fence> releaseFence = Fence::NO_FENCE;

        if (auto hwcLayer = layer->getHwcLayer()) {
            if (auto f = frame.layerFences.find(hwcLayer); f != frame.layerFences.end()) {
                releaseFence = f->second;
            }
        }

        // If the layer was client composited in the previous frame, we
        // need to merge with the previous client target acquire fence.
        // Since we do not track that, always merge with the current
        // client target acquire fence when it is available, even though
        // this is suboptimal.
        // TODO(b/121291683): Track previous frame client target acquire fence.
        if (outputState.usesClientComposition) {
            releaseFence =
                    Fence::merge("LayerRelease", releaseFence, frame.clientTargetAcquireFence);
        }

        layer->getLayerFE().onLayerDisplayed(releaseFence);
    }

    // We've got a list of layers needing fences, that are disjoint with
    // OutputLayersOrderedByZ.  The best we can do is to
    // supply them with the present fence.
    for (auto& weakLayer : mReleasedLayers) {
        if (auto layer = weakLayer.promote(); layer != nullptr) {
            layer->onLayerDisplayed(frame.presentFence);
        }
    }

    // Clear out the released layers now that we're done with them.
    mReleasedLayers.clear();
}

void Output::dirtyEntireOutput() {
    auto& outputState = editState();
    outputState.dirtyRegion.set(outputState.bounds);
}

void Output::chooseCompositionStrategy() {
    // The base output implementation can only do client composition
    auto& outputState = editState();
    outputState.usesClientComposition = true;
    outputState.usesDeviceComposition = false;
    outputState.reusedClientComposition = false;
}

bool Output::getSkipColorTransform() const {
    return true;
}

compositionengine::Output::FrameFences Output::presentAndGetFrameFences() {
    compositionengine::Output::FrameFences result;
    if (getState().usesClientComposition) {
        result.clientTargetAcquireFence = mRenderSurface->getClientTargetAcquireFence();
    }
    return result;
}

} // namespace impl
} // namespace android::compositionengine
