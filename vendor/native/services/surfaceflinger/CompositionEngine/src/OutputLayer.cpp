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
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/Output.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include "DisplayHardware/HWComposer.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

namespace android::compositionengine {

OutputLayer::~OutputLayer() = default;

namespace impl {

namespace {

FloatRect reduce(const FloatRect& win, const Region& exclude) {
    if (CC_LIKELY(exclude.isEmpty())) {
        return win;
    }
    // Convert through Rect (by rounding) for lack of FloatRegion
    return Region(Rect{win}).subtract(exclude).getBounds().toFloatRect();
}

} // namespace

std::unique_ptr<OutputLayer> createOutputLayer(const compositionengine::Output& output,
                                               const sp<compositionengine::LayerFE>& layerFE) {
    return createOutputLayerTemplated<OutputLayer>(output, layerFE);
}

OutputLayer::~OutputLayer() = default;

void OutputLayer::setHwcLayer(std::shared_ptr<HWC2::Layer> hwcLayer) {
    auto& state = editState();
    if (hwcLayer) {
        state.hwc.emplace(std::move(hwcLayer));
    } else {
        state.hwc.reset();
    }
}

Rect OutputLayer::calculateInitialCrop() const {
    const auto& layerState = *getLayerFE().getCompositionState();

    // apply the projection's clipping to the window crop in
    // layerstack space, and convert-back to layer space.
    // if there are no window scaling involved, this operation will map to full
    // pixels in the buffer.

    FloatRect activeCropFloat =
            reduce(layerState.geomLayerBounds, layerState.transparentRegionHint);

    const Rect& viewport = getOutput().getState().viewport;
    const ui::Transform& layerTransform = layerState.geomLayerTransform;
    const ui::Transform& inverseLayerTransform = layerState.geomInverseLayerTransform;
    // Transform to screen space.
    activeCropFloat = layerTransform.transform(activeCropFloat);
    activeCropFloat = activeCropFloat.intersect(viewport.toFloatRect());
    // Back to layer space to work with the content crop.
    activeCropFloat = inverseLayerTransform.transform(activeCropFloat);

    // This needs to be here as transform.transform(Rect) computes the
    // transformed rect and then takes the bounding box of the result before
    // returning. This means
    // transform.inverse().transform(transform.transform(Rect)) != Rect
    // in which case we need to make sure the final rect is clipped to the
    // display bounds.
    Rect activeCrop{activeCropFloat};
    if (!activeCrop.intersect(layerState.geomBufferSize, &activeCrop)) {
        activeCrop.clear();
    }
    return activeCrop;
}

FloatRect OutputLayer::calculateOutputSourceCrop() const {
    const auto& layerState = *getLayerFE().getCompositionState();
    const auto& outputState = getOutput().getState();

    if (!layerState.geomUsesSourceCrop) {
        return {};
    }

    // the content crop is the area of the content that gets scaled to the
    // layer's size. This is in buffer space.
    FloatRect crop = layerState.geomContentCrop.toFloatRect();

    // In addition there is a WM-specified crop we pull from our drawing state.
    Rect activeCrop = calculateInitialCrop();
    const Rect& bufferSize = layerState.geomBufferSize;

    int winWidth = bufferSize.getWidth();
    int winHeight = bufferSize.getHeight();

    // The bufferSize for buffer state layers can be unbounded ([0, 0, -1, -1])
    // if display frame hasn't been set and the parent is an unbounded layer.
    if (winWidth < 0 && winHeight < 0) {
        return crop;
    }

    // Transform the window crop to match the buffer coordinate system,
    // which means using the inverse of the current transform set on the
    // SurfaceFlingerConsumer.
    uint32_t invTransform = layerState.geomBufferTransform;
    if (layerState.geomBufferUsesDisplayInverseTransform) {
        /*
         * the code below applies the primary display's inverse transform to the
         * buffer
         */
        uint32_t invTransformOrient = outputState.orientation;
        // calculate the inverse transform
        if (invTransformOrient & HAL_TRANSFORM_ROT_90) {
            invTransformOrient ^= HAL_TRANSFORM_FLIP_V | HAL_TRANSFORM_FLIP_H;
        }
        // and apply to the current transform
        invTransform =
                (ui::Transform(invTransformOrient) * ui::Transform(invTransform)).getOrientation();
    }

    if (invTransform & HAL_TRANSFORM_ROT_90) {
        // If the activeCrop has been rotate the ends are rotated but not
        // the space itself so when transforming ends back we can't rely on
        // a modification of the axes of rotation. To account for this we
        // need to reorient the inverse rotation in terms of the current
        // axes of rotation.
        bool isHFlipped = (invTransform & HAL_TRANSFORM_FLIP_H) != 0;
        bool isVFlipped = (invTransform & HAL_TRANSFORM_FLIP_V) != 0;
        if (isHFlipped == isVFlipped) {
            invTransform ^= HAL_TRANSFORM_FLIP_V | HAL_TRANSFORM_FLIP_H;
        }
        std::swap(winWidth, winHeight);
    }
    const Rect winCrop =
            activeCrop.transform(invTransform, bufferSize.getWidth(), bufferSize.getHeight());

    // below, crop is intersected with winCrop expressed in crop's coordinate space
    const float xScale = crop.getWidth() / float(winWidth);
    const float yScale = crop.getHeight() / float(winHeight);

    const float insetLeft = winCrop.left * xScale;
    const float insetTop = winCrop.top * yScale;
    const float insetRight = (winWidth - winCrop.right) * xScale;
    const float insetBottom = (winHeight - winCrop.bottom) * yScale;

    crop.left += insetLeft;
    crop.top += insetTop;
    crop.right -= insetRight;
    crop.bottom -= insetBottom;

    return crop;
}

Rect OutputLayer::calculateOutputDisplayFrame() const {
    const auto& layerState = *getLayerFE().getCompositionState();
    const auto& outputState = getOutput().getState();

    // apply the layer's transform, followed by the display's global transform
    // here we're guaranteed that the layer's transform preserves rects
    Region activeTransparentRegion = layerState.transparentRegionHint;
    const ui::Transform& layerTransform = layerState.geomLayerTransform;
    const ui::Transform& inverseLayerTransform = layerState.geomInverseLayerTransform;
    const Rect& bufferSize = layerState.geomBufferSize;
    Rect activeCrop = layerState.geomCrop;
    if (!activeCrop.isEmpty() && bufferSize.isValid()) {
        activeCrop = layerTransform.transform(activeCrop);
        if (!activeCrop.intersect(outputState.viewport, &activeCrop)) {
            activeCrop.clear();
        }
        activeCrop = inverseLayerTransform.transform(activeCrop, true);
        // This needs to be here as transform.transform(Rect) computes the
        // transformed rect and then takes the bounding box of the result before
        // returning. This means
        // transform.inverse().transform(transform.transform(Rect)) != Rect
        // in which case we need to make sure the final rect is clipped to the
        // display bounds.
        if (!activeCrop.intersect(bufferSize, &activeCrop)) {
            activeCrop.clear();
        }
        // mark regions outside the crop as transparent
        activeTransparentRegion.orSelf(Rect(0, 0, bufferSize.getWidth(), activeCrop.top));
        activeTransparentRegion.orSelf(
                Rect(0, activeCrop.bottom, bufferSize.getWidth(), bufferSize.getHeight()));
        activeTransparentRegion.orSelf(Rect(0, activeCrop.top, activeCrop.left, activeCrop.bottom));
        activeTransparentRegion.orSelf(
                Rect(activeCrop.right, activeCrop.top, bufferSize.getWidth(), activeCrop.bottom));
    }

    // reduce uses a FloatRect to provide more accuracy during the
    // transformation. We then round upon constructing 'frame'.
    Rect frame{
            layerTransform.transform(reduce(layerState.geomLayerBounds, activeTransparentRegion))};
    if (!frame.intersect(outputState.viewport, &frame)) {
        frame.clear();
    }
    const ui::Transform displayTransform{outputState.transform};

    return displayTransform.transform(frame);
}

uint32_t OutputLayer::calculateOutputRelativeBufferTransform(
        uint32_t internalDisplayRotationFlags) const {
    const auto& layerState = *getLayerFE().getCompositionState();
    const auto& outputState = getOutput().getState();

    /*
     * Transformations are applied in this order:
     * 1) buffer orientation/flip/mirror
     * 2) state transformation (window manager)
     * 3) layer orientation (screen orientation)
     * (NOTE: the matrices are multiplied in reverse order)
     */
    const ui::Transform& layerTransform = layerState.geomLayerTransform;
    const ui::Transform displayTransform{outputState.transform};
    const ui::Transform bufferTransform{layerState.geomBufferTransform};
    ui::Transform transform(displayTransform * layerTransform * bufferTransform);

    if (layerState.geomBufferUsesDisplayInverseTransform) {
        /*
         * We must apply the internal display's inverse transform to the buffer
         * transform, and not the one for the output this layer is on.
         */
        uint32_t invTransform = internalDisplayRotationFlags;

        // calculate the inverse transform
        if (invTransform & HAL_TRANSFORM_ROT_90) {
            invTransform ^= HAL_TRANSFORM_FLIP_V | HAL_TRANSFORM_FLIP_H;
        }

        /*
         * Here we cancel out the orientation component of the WM transform.
         * The scaling and translate components are already included in our bounds
         * computation so it's enough to just omit it in the composition.
         * See comment in BufferLayer::prepareClientLayer with ref to b/36727915 for why.
         */
        transform = ui::Transform(invTransform) * displayTransform * bufferTransform;
    }

    // this gives us only the "orientation" component of the transform
    return transform.getOrientation();
}

void OutputLayer::updateCompositionState(
        bool includeGeometry, bool forceClientComposition,
        ui::Transform::RotationFlags internalDisplayRotationFlags) {
    const auto* layerFEState = getLayerFE().getCompositionState();
    if (!layerFEState) {
        return;
    }

    const auto& outputState = getOutput().getState();
    const auto& profile = *getOutput().getDisplayColorProfile();
    auto& state = editState();

    if (includeGeometry) {
        // Clear the forceClientComposition flag before it is set for any
        // reason. Note that since it can be set by some checks below when
        // updating the geometry state, we only clear it when updating the
        // geometry since those conditions for forcing client composition won't
        // go away otherwise.
        state.forceClientComposition = false;

        state.displayFrame = calculateOutputDisplayFrame();
        state.sourceCrop = calculateOutputSourceCrop();
        state.bufferTransform = static_cast<Hwc2::Transform>(
                calculateOutputRelativeBufferTransform(internalDisplayRotationFlags));

        if ((layerFEState->isSecure && !outputState.isSecure) ||
            (state.bufferTransform & ui::Transform::ROT_INVALID)) {
            state.forceClientComposition = true;
        }
    }

    // Determine the output dependent dataspace for this layer. If it is
    // colorspace agnostic, it just uses the dataspace chosen for the output to
    // avoid the need for color conversion.
    state.dataspace = layerFEState->isColorspaceAgnostic &&
                    outputState.targetDataspace != ui::Dataspace::UNKNOWN
            ? outputState.targetDataspace
            : layerFEState->dataspace;

    // These are evaluated every frame as they can potentially change at any
    // time.
    if (layerFEState->forceClientComposition || !profile.isDataspaceSupported(state.dataspace) ||
        forceClientComposition) {
        state.forceClientComposition = true;
    }
}

void OutputLayer::writeStateToHWC(bool includeGeometry) {
    const auto& state = getState();
    // Skip doing this if there is no HWC interface
    if (!state.hwc) {
        return;
    }

    auto& hwcLayer = (*state.hwc).hwcLayer;
    if (!hwcLayer) {
        ALOGE("[%s] failed to write composition state to HWC -- no hwcLayer for output %s",
              getLayerFE().getDebugName(), getOutput().getName().c_str());
        return;
    }

    const auto* outputIndependentState = getLayerFE().getCompositionState();
    if (!outputIndependentState) {
        return;
    }

    auto requestedCompositionType = outputIndependentState->compositionType;

    if (includeGeometry) {
        writeOutputDependentGeometryStateToHWC(hwcLayer.get(), requestedCompositionType);
        writeOutputIndependentGeometryStateToHWC(hwcLayer.get(), *outputIndependentState);
    }

    writeOutputDependentPerFrameStateToHWC(hwcLayer.get());
    writeOutputIndependentPerFrameStateToHWC(hwcLayer.get(), *outputIndependentState);

    writeCompositionTypeToHWC(hwcLayer.get(), requestedCompositionType);

    // Always set the layer color after setting the composition type.
    writeSolidColorStateToHWC(hwcLayer.get(), *outputIndependentState);
}

void OutputLayer::writeOutputDependentGeometryStateToHWC(
        HWC2::Layer* hwcLayer, hal::Composition requestedCompositionType) {
    const auto& outputDependentState = getState();

    if (auto error = hwcLayer->setDisplayFrame(outputDependentState.displayFrame);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set display frame [%d, %d, %d, %d]: %s (%d)",
              getLayerFE().getDebugName(), outputDependentState.displayFrame.left,
              outputDependentState.displayFrame.top, outputDependentState.displayFrame.right,
              outputDependentState.displayFrame.bottom, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setSourceCrop(outputDependentState.sourceCrop);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set source crop [%.3f, %.3f, %.3f, %.3f]: "
              "%s (%d)",
              getLayerFE().getDebugName(), outputDependentState.sourceCrop.left,
              outputDependentState.sourceCrop.top, outputDependentState.sourceCrop.right,
              outputDependentState.sourceCrop.bottom, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setZOrder(outputDependentState.z); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set Z %u: %s (%d)", getLayerFE().getDebugName(),
              outputDependentState.z, to_string(error).c_str(), static_cast<int32_t>(error));
    }

    // Solid-color layers should always use an identity transform.
    const auto bufferTransform = requestedCompositionType != hal::Composition::SOLID_COLOR
            ? outputDependentState.bufferTransform
            : static_cast<hal::Transform>(0);
    if (auto error = hwcLayer->setTransform(static_cast<hal::Transform>(bufferTransform));
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set transform %s: %s (%d)", getLayerFE().getDebugName(),
              toString(outputDependentState.bufferTransform).c_str(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeOutputIndependentGeometryStateToHWC(
        HWC2::Layer* hwcLayer, const LayerFECompositionState& outputIndependentState) {
    if (auto error = hwcLayer->setBlendMode(outputIndependentState.blendMode);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set blend mode %s: %s (%d)", getLayerFE().getDebugName(),
              toString(outputIndependentState.blendMode).c_str(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setPlaneAlpha(outputIndependentState.alpha);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set plane alpha %.3f: %s (%d)", getLayerFE().getDebugName(),
              outputIndependentState.alpha, to_string(error).c_str(), static_cast<int32_t>(error));
    }

    for (const auto& [name, entry] : outputIndependentState.metadata) {
        if (auto error = hwcLayer->setLayerGenericMetadata(name, entry.mandatory, entry.value);
            error != hal::Error::NONE) {
            ALOGE("[%s] Failed to set generic metadata %s %s (%d)", getLayerFE().getDebugName(),
                  name.c_str(), to_string(error).c_str(), static_cast<int32_t>(error));
        }
    }
}

void OutputLayer::writeOutputDependentPerFrameStateToHWC(HWC2::Layer* hwcLayer) {
    const auto& outputDependentState = getState();

    // TODO(lpique): b/121291683 outputSpaceVisibleRegion is output-dependent geometry
    // state and should not change every frame.
    if (auto error = hwcLayer->setVisibleRegion(outputDependentState.outputSpaceVisibleRegion);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set visible region: %s (%d)", getLayerFE().getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        outputDependentState.outputSpaceVisibleRegion.dump(LOG_TAG);
    }

    if (auto error = hwcLayer->setDataspace(outputDependentState.dataspace);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set dataspace %d: %s (%d)", getLayerFE().getDebugName(),
              outputDependentState.dataspace, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeOutputIndependentPerFrameStateToHWC(
        HWC2::Layer* hwcLayer, const LayerFECompositionState& outputIndependentState) {
    switch (auto error = hwcLayer->setColorTransform(outputIndependentState.colorTransform)) {
        case hal::Error::NONE:
            break;
        case hal::Error::UNSUPPORTED:
            editState().forceClientComposition = true;
            break;
        default:
            ALOGE("[%s] Failed to set color transform: %s (%d)", getLayerFE().getDebugName(),
                  to_string(error).c_str(), static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setSurfaceDamage(outputIndependentState.surfaceDamage);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set surface damage: %s (%d)", getLayerFE().getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        outputIndependentState.surfaceDamage.dump(LOG_TAG);
    }

    // Content-specific per-frame state
    switch (outputIndependentState.compositionType) {
        case hal::Composition::SOLID_COLOR:
            // For compatibility, should be written AFTER the composition type.
            break;
        case hal::Composition::SIDEBAND:
            writeSidebandStateToHWC(hwcLayer, outputIndependentState);
            break;
        case hal::Composition::CURSOR:
        case hal::Composition::DEVICE:
            writeBufferStateToHWC(hwcLayer, outputIndependentState);
            break;
        case hal::Composition::INVALID:
        case hal::Composition::CLIENT:
            // Ignored
            break;
    }
}

void OutputLayer::writeSolidColorStateToHWC(HWC2::Layer* hwcLayer,
                                            const LayerFECompositionState& outputIndependentState) {
    if (outputIndependentState.compositionType != hal::Composition::SOLID_COLOR) {
        return;
    }

    hal::Color color = {static_cast<uint8_t>(std::round(255.0f * outputIndependentState.color.r)),
                        static_cast<uint8_t>(std::round(255.0f * outputIndependentState.color.g)),
                        static_cast<uint8_t>(std::round(255.0f * outputIndependentState.color.b)),
                        255};

    if (auto error = hwcLayer->setColor(color); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set color: %s (%d)", getLayerFE().getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
    }
}

void OutputLayer::writeSidebandStateToHWC(HWC2::Layer* hwcLayer,
                                          const LayerFECompositionState& outputIndependentState) {
    if (auto error = hwcLayer->setSidebandStream(outputIndependentState.sidebandStream->handle());
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set sideband stream %p: %s (%d)", getLayerFE().getDebugName(),
              outputIndependentState.sidebandStream->handle(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeBufferStateToHWC(HWC2::Layer* hwcLayer,
                                        const LayerFECompositionState& outputIndependentState) {
    auto supportedPerFrameMetadata =
            getOutput().getDisplayColorProfile()->getSupportedPerFrameMetadata();
    if (auto error = hwcLayer->setPerFrameMetadata(supportedPerFrameMetadata,
                                                   outputIndependentState.hdrMetadata);
        error != hal::Error::NONE && error != hal::Error::UNSUPPORTED) {
        ALOGE("[%s] Failed to set hdrMetadata: %s (%d)", getLayerFE().getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
    }

    uint32_t hwcSlot = 0;
    sp<GraphicBuffer> hwcBuffer;
    // We need access to the output-dependent state for the buffer cache there,
    // though otherwise the buffer is not output-dependent.
    editState().hwc->hwcBufferCache.getHwcBuffer(outputIndependentState.bufferSlot,
                                                 outputIndependentState.buffer, &hwcSlot,
                                                 &hwcBuffer);

    if (auto error = hwcLayer->setBuffer(hwcSlot, hwcBuffer, outputIndependentState.acquireFence);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set buffer %p: %s (%d)", getLayerFE().getDebugName(),
              outputIndependentState.buffer->handle, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeCompositionTypeToHWC(HWC2::Layer* hwcLayer,
                                            hal::Composition requestedCompositionType) {
    auto& outputDependentState = editState();

    // If we are forcing client composition, we need to tell the HWC
    if (outputDependentState.forceClientComposition) {
        requestedCompositionType = hal::Composition::CLIENT;
    }

    // Set the requested composition type with the HWC whenever it changes
    if (outputDependentState.hwc->hwcCompositionType != requestedCompositionType) {
        outputDependentState.hwc->hwcCompositionType = requestedCompositionType;

        if (auto error = hwcLayer->setCompositionType(requestedCompositionType);
            error != hal::Error::NONE) {
            ALOGE("[%s] Failed to set composition type %s: %s (%d)", getLayerFE().getDebugName(),
                  toString(requestedCompositionType).c_str(), to_string(error).c_str(),
                  static_cast<int32_t>(error));
        }
    }
}

void OutputLayer::writeCursorPositionToHWC() const {
    // Skip doing this if there is no HWC interface
    auto hwcLayer = getHwcLayer();
    if (!hwcLayer) {
        return;
    }

    const auto* layerFEState = getLayerFE().getCompositionState();
    if (!layerFEState) {
        return;
    }

    const auto& outputState = getOutput().getState();

    Rect frame = layerFEState->cursorFrame;
    frame.intersect(outputState.viewport, &frame);
    Rect position = outputState.transform.transform(frame);

    if (auto error = hwcLayer->setCursorPosition(position.left, position.top);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set cursor position to (%d, %d): %s (%d)",
              getLayerFE().getDebugName(), position.left, position.top, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

HWC2::Layer* OutputLayer::getHwcLayer() const {
    const auto& state = getState();
    return state.hwc ? state.hwc->hwcLayer.get() : nullptr;
}

bool OutputLayer::requiresClientComposition() const {
    const auto& state = getState();
    return !state.hwc || state.hwc->hwcCompositionType == hal::Composition::CLIENT;
}

bool OutputLayer::isHardwareCursor() const {
    const auto& state = getState();
    return state.hwc && state.hwc->hwcCompositionType == hal::Composition::CURSOR;
}

void OutputLayer::detectDisallowedCompositionTypeChange(hal::Composition from,
                                                        hal::Composition to) const {
    bool result = false;
    switch (from) {
        case hal::Composition::INVALID:
        case hal::Composition::CLIENT:
            result = false;
            break;

        case hal::Composition::DEVICE:
        case hal::Composition::SOLID_COLOR:
            result = (to == hal::Composition::CLIENT);
            break;

        case hal::Composition::CURSOR:
        case hal::Composition::SIDEBAND:
            result = (to == hal::Composition::CLIENT || to == hal::Composition::DEVICE);
            break;
    }

    if (!result) {
        ALOGE("[%s] Invalid device requested composition type change: %s (%d) --> %s (%d)",
              getLayerFE().getDebugName(), toString(from).c_str(), static_cast<int>(from),
              toString(to).c_str(), static_cast<int>(to));
    }
}

void OutputLayer::applyDeviceCompositionTypeChange(hal::Composition compositionType) {
    auto& state = editState();
    LOG_FATAL_IF(!state.hwc);
    auto& hwcState = *state.hwc;

    detectDisallowedCompositionTypeChange(hwcState.hwcCompositionType, compositionType);

    hwcState.hwcCompositionType = compositionType;
}

void OutputLayer::prepareForDeviceLayerRequests() {
    auto& state = editState();
    state.clearClientTarget = false;
}

void OutputLayer::applyDeviceLayerRequest(hal::LayerRequest request) {
    auto& state = editState();
    switch (request) {
        case hal::LayerRequest::CLEAR_CLIENT_TARGET:
            state.clearClientTarget = true;
            break;

        default:
            ALOGE("[%s] Unknown device layer request %s (%d)", getLayerFE().getDebugName(),
                  toString(request).c_str(), static_cast<int>(request));
            break;
    }
}

bool OutputLayer::needsFiltering() const {
    const auto& state = getState();
    const auto& displayFrame = state.displayFrame;
    const auto& sourceCrop = state.sourceCrop;
    return sourceCrop.getHeight() != displayFrame.getHeight() ||
            sourceCrop.getWidth() != displayFrame.getWidth();
}

void OutputLayer::dump(std::string& out) const {
    using android::base::StringAppendF;

    StringAppendF(&out, "  - Output Layer %p(%s)\n", this, getLayerFE().getDebugName());
    dumpState(out);
}

} // namespace impl
} // namespace android::compositionengine
