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

#include <SurfaceFlingerProperties.sysprop.h>
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
#include <compositionengine/impl/planner/Planner.h>

#include <thread>

#include "renderengine/ExternalTexture.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <renderengine/DisplaySettings.h>
#include <renderengine/RenderEngine.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

#include <android-base/properties.h>
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

struct ScaleVector {
    float x;
    float y;
};

// Returns a ScaleVector (x, y) such that from.scale(x, y) = to',
// where to' will have the same size as "to". In the case where "from" and "to"
// start at the origin to'=to.
ScaleVector getScale(const Rect& from, const Rect& to) {
    return {.x = static_cast<float>(to.width()) / from.width(),
            .y = static_cast<float>(to.height()) / from.height()};
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

void Output::setLayerCachingEnabled(bool enabled) {
    if (enabled == (mPlanner != nullptr)) {
        return;
    }

    if (enabled) {
        mPlanner = std::make_unique<planner::Planner>(getCompositionEngine().getRenderEngine());
        if (mRenderSurface) {
            mPlanner->setDisplaySize(mRenderSurface->getSize());
        }
    } else {
        mPlanner.reset();
    }

    for (auto* outputLayer : getOutputLayersOrderedByZ()) {
        if (!outputLayer) {
            continue;
        }

        outputLayer->editState().overrideInfo = {};
    }
}

void Output::setLayerCachingTexturePoolEnabled(bool enabled) {
    if (mPlanner) {
        mPlanner->setTexturePoolEnabled(enabled);
    }
}

void Output::setProjection(ui::Rotation orientation, const Rect& layerStackSpaceRect,
                           const Rect& orientedDisplaySpaceRect) {
    auto& outputState = editState();

    outputState.displaySpace.orientation = orientation;
    LOG_FATAL_IF(outputState.displaySpace.bounds == Rect::INVALID_RECT,
                 "The display bounds are unknown.");

    // Compute orientedDisplaySpace
    ui::Size orientedSize = outputState.displaySpace.bounds.getSize();
    if (orientation == ui::ROTATION_90 || orientation == ui::ROTATION_270) {
        std::swap(orientedSize.width, orientedSize.height);
    }
    outputState.orientedDisplaySpace.bounds = Rect(orientedSize);
    outputState.orientedDisplaySpace.content = orientedDisplaySpaceRect;

    // Compute displaySpace.content
    const uint32_t transformOrientationFlags = ui::Transform::toRotationFlags(orientation);
    ui::Transform rotation;
    if (transformOrientationFlags != ui::Transform::ROT_INVALID) {
        const auto displaySize = outputState.displaySpace.bounds;
        rotation.set(transformOrientationFlags, displaySize.width(), displaySize.height());
    }
    outputState.displaySpace.content = rotation.transform(orientedDisplaySpaceRect);

    // Compute framebufferSpace
    outputState.framebufferSpace.orientation = orientation;
    LOG_FATAL_IF(outputState.framebufferSpace.bounds == Rect::INVALID_RECT,
                 "The framebuffer bounds are unknown.");
    const auto scale =
            getScale(outputState.displaySpace.bounds, outputState.framebufferSpace.bounds);
    outputState.framebufferSpace.content = outputState.displaySpace.content.scale(scale.x, scale.y);

    // Compute layerStackSpace
    outputState.layerStackSpace.content = layerStackSpaceRect;
    outputState.layerStackSpace.bounds = layerStackSpaceRect;

    outputState.transform = outputState.layerStackSpace.getTransform(outputState.displaySpace);
    outputState.needsFiltering = outputState.transform.needsBilinearFiltering();
    dirtyEntireOutput();
}

void Output::setDisplaySize(const ui::Size& size) {
    mRenderSurface->setDisplaySize(size);

    auto& state = editState();

    // Update framebuffer space
    const Rect newBounds(size);
    state.framebufferSpace.bounds = newBounds;

    // Update display space
    state.displaySpace.bounds = newBounds;
    state.transform = state.layerStackSpace.getTransform(state.displaySpace);

    // Update oriented display space
    const auto orientation = state.displaySpace.orientation;
    ui::Size orientedSize = size;
    if (orientation == ui::ROTATION_90 || orientation == ui::ROTATION_270) {
        std::swap(orientedSize.width, orientedSize.height);
    }
    const Rect newOrientedBounds(orientedSize);
    state.orientedDisplaySpace.bounds = newOrientedBounds;

    if (mPlanner) {
        mPlanner->setDisplaySize(size);
    }

    dirtyEntireOutput();
}

ui::Transform::RotationFlags Output::getTransformHint() const {
    return static_cast<ui::Transform::RotationFlags>(getState().transform.getOrientation());
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

void Output::setDisplayBrightness(float sdrWhitePointNits, float displayBrightnessNits) {
    auto& outputState = editState();
    if (outputState.sdrWhitePointNits == sdrWhitePointNits &&
        outputState.displayBrightnessNits == displayBrightnessNits) {
        // Nothing changed
        return;
    }
    outputState.sdrWhitePointNits = sdrWhitePointNits;
    outputState.displayBrightnessNits = displayBrightnessNits;
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

void Output::dumpPlannerInfo(const Vector<String16>& args, std::string& out) const {
    if (!mPlanner) {
        base::StringAppendF(&out, "Planner is disabled\n");
        return;
    }
    base::StringAppendF(&out, "Planner info for display [%s]\n", mName.c_str());
    mPlanner->dump(args, out);
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
    const auto size = mRenderSurface->getSize();
    editState().framebufferSpace.bounds = Rect(size);
    if (mPlanner) {
        mPlanner->setDisplaySize(size);
    }
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
    Region dirty(outputState.layerStackSpace.content);
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
    updateCompositionState(refreshArgs);
    planComposition();
    writeCompositionState(refreshArgs);
    setColorTransform(refreshArgs);
    beginFrame();
    prepareFrame();
    devOptRepaintFlash(refreshArgs);
    finishFrame(refreshArgs);
    postFramebuffer();
    renderCachedSets(refreshArgs);
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
    Region undefinedRegion{outputState.displaySpace.bounds};
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
    drawRegion.andSelf(outputState.displaySpace.bounds);
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
    outputLayerState.outputSpaceVisibleRegion = outputState.transform.transform(
            visibleNonShadowRegion.intersect(outputState.layerStackSpace.content));
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

void Output::updateCompositionState(const compositionengine::CompositionRefreshArgs& refreshArgs) {
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
    }
}

void Output::planComposition() {
    if (!mPlanner || !getState().isEnabled) {
        return;
    }

    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    mPlanner->plan(getOutputLayersOrderedByZ());
}

void Output::writeCompositionState(const compositionengine::CompositionRefreshArgs& refreshArgs) {
    ATRACE_CALL();
    ALOGV(__FUNCTION__);

    if (!getState().isEnabled) {
        return;
    }

    editState().earliestPresentTime = refreshArgs.earliestPresentTime;
    editState().previousPresentFence = refreshArgs.previousPresentFence;

    compositionengine::OutputLayer* peekThroughLayer = nullptr;
    sp<GraphicBuffer> previousOverride = nullptr;
    bool includeGeometry = refreshArgs.updatingGeometryThisFrame;
    uint32_t z = 0;
    bool overrideZ = false;
    for (auto* layer : getOutputLayersOrderedByZ()) {
        if (layer == peekThroughLayer) {
            // No longer needed, although it should not show up again, so
            // resetting it is not truly needed either.
            peekThroughLayer = nullptr;

            // peekThroughLayer was already drawn ahead of its z order.
            continue;
        }
        bool skipLayer = false;
        const auto& overrideInfo = layer->getState().overrideInfo;
        if (overrideInfo.buffer != nullptr) {
            if (previousOverride && overrideInfo.buffer->getBuffer() == previousOverride) {
                ALOGV("Skipping redundant buffer");
                skipLayer = true;
            } else {
                // First layer with the override buffer.
                if (overrideInfo.peekThroughLayer) {
                    peekThroughLayer = overrideInfo.peekThroughLayer;

                    // Draw peekThroughLayer first.
                    overrideZ = true;
                    includeGeometry = true;
                    constexpr bool isPeekingThrough = true;
                    peekThroughLayer->writeStateToHWC(includeGeometry, false, z++, overrideZ,
                                                      isPeekingThrough);
                }

                previousOverride = overrideInfo.buffer->getBuffer();
            }
        }

        constexpr bool isPeekingThrough = false;
        layer->writeStateToHWC(includeGeometry, skipLayer, z++, overrideZ, isPeekingThrough);
    }
}

compositionengine::OutputLayer* Output::findLayerRequestingBackgroundComposition() const {
    compositionengine::OutputLayer* layerRequestingBgComposition = nullptr;
    for (auto* layer : getOutputLayersOrderedByZ()) {
        auto* compState = layer->getLayerFE().getCompositionState();

        // If any layer has a sideband stream, we will disable blurs. In that case, we don't
        // want to force client composition because of the blur.
        if (compState->sidebandStream != nullptr) {
            return nullptr;
        }
        if (compState->isOpaque) {
            continue;
        }
        if (compState->backgroundBlurRadius > 0 || compState->blurRegions.size() > 0) {
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

    if (mPlanner) {
        mPlanner->reportFinalPlan(getOutputLayersOrderedByZ());
    }

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

    std::shared_ptr<renderengine::ExternalTexture> tex;

    // If we aren't doing client composition on this output, but do have a
    // flipClientTarget request for this frame on this output, we still need to
    // dequeue a buffer.
    if (hasClientComposition || outputState.flipClientTarget) {
        tex = mRenderSurface->dequeueBuffer(&fd);
        if (tex == nullptr) {
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
    clientCompositionDisplay.physicalDisplay = outputState.framebufferSpace.content;
    clientCompositionDisplay.clip = outputState.layerStackSpace.content;
    clientCompositionDisplay.orientation =
            ui::Transform::toRotationFlags(outputState.displaySpace.orientation);
    clientCompositionDisplay.outputDataspace = mDisplayColorProfile->hasWideColorGamut()
            ? outputState.dataspace
            : ui::Dataspace::UNKNOWN;

    // If we have a valid current display brightness use that, otherwise fall back to the
    // display's max desired
    clientCompositionDisplay.maxLuminance = outputState.displayBrightnessNits > 0.f
            ? outputState.displayBrightnessNits
            : mDisplayColorProfile->getHdrCapabilities().getDesiredMaxLuminance();
    clientCompositionDisplay.sdrWhitePointNits = outputState.sdrWhitePointNits;

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
        if (mClientCompositionRequestCache->exists(tex->getBuffer()->getId(),
                                                   clientCompositionDisplay,
                                                   clientCompositionLayers)) {
            outputCompositionState.reusedClientComposition = true;
            setExpensiveRenderingExpected(false);
            return readyFence;
        }
        mClientCompositionRequestCache->add(tex->getBuffer()->getId(), clientCompositionDisplay,
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
    // Only use the framebuffer cache when rendering to an internal display
    // TODO(b/173560331): This is only to help mitigate memory leaks from virtual displays because
    // right now we don't have a concrete eviction policy for output buffers: GLESRenderEngine
    // bounds its framebuffer cache but Skia RenderEngine has no current policy. The best fix is
    // probably to encapsulate the output buffer into a structure that dispatches resource cleanup
    // over to RenderEngine, in which case this flag can be removed from the drawLayers interface.
    const bool useFramebufferCache = outputState.layerStackInternal;
    status_t status =
            renderEngine.drawLayers(clientCompositionDisplay, clientCompositionLayerPointers, tex,
                                    useFramebufferCache, std::move(fd), &readyFence);

    if (status != NO_ERROR && mClientCompositionRequestCache) {
        // If rendering was not successful, remove the request from the cache.
        mClientCompositionRequestCache->remove(tex->getBuffer()->getId());
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
    const Region viewportRegion(outputState.layerStackSpace.content);
    bool firstLayer = true;
    // Used when a layer clears part of the buffer.
    Region stubRegion;

    bool disableBlurs = false;
    sp<GraphicBuffer> previousOverrideBuffer = nullptr;

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

        disableBlurs |= layerFEState->sidebandStream != nullptr;

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
            std::vector<LayerFE::LayerSettings> results;
            if (layer->getState().overrideInfo.buffer != nullptr) {
                if (layer->getState().overrideInfo.buffer->getBuffer() != previousOverrideBuffer) {
                    results = layer->getOverrideCompositionList();
                    previousOverrideBuffer = layer->getState().overrideInfo.buffer->getBuffer();
                    ALOGV("Replacing [%s] with override in RE", layer->getLayerFE().getDebugName());
                } else {
                    ALOGV("Skipping redundant override buffer for [%s] in RE",
                          layer->getLayerFE().getDebugName());
                }
            } else {
                LayerFE::ClientCompositionTargetSettings::BlurSetting blurSetting = disableBlurs
                        ? LayerFE::ClientCompositionTargetSettings::BlurSetting::Disabled
                        : (layer->getState().overrideInfo.disableBackgroundBlur
                                   ? LayerFE::ClientCompositionTargetSettings::BlurSetting::
                                             BlurRegionsOnly
                                   : LayerFE::ClientCompositionTargetSettings::BlurSetting::
                                             Enabled);
                compositionengine::LayerFE::ClientCompositionTargetSettings
                        targetSettings{.clip = clip,
                                       .needsFiltering = layer->needsFiltering() ||
                                               outputState.needsFiltering,
                                       .isSecure = outputState.isSecure,
                                       .supportsProtectedContent = supportsProtectedContent,
                                       .clearRegion = clientComposition ? clearRegion : stubRegion,
                                       .viewport = outputState.layerStackSpace.content,
                                       .dataspace = outputDataspace,
                                       .realContentIsVisible = realContentIsVisible,
                                       .clearContent = !clientComposition,
                                       .blurSetting = blurSetting};
                results = layerFE.prepareClientCompositionList(targetSettings);
                if (realContentIsVisible && !results.empty()) {
                    layer->editState().clientCompositionTimestamp = systemTime();
                }
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

void Output::renderCachedSets(const CompositionRefreshArgs& refreshArgs) {
    if (mPlanner) {
        mPlanner->renderCachedSets(getState(), refreshArgs.nextInvalidateTime);
    }
}

void Output::dirtyEntireOutput() {
    auto& outputState = editState();
    outputState.dirtyRegion.set(outputState.displaySpace.bounds);
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
