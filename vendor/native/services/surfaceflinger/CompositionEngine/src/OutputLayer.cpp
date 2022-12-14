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

#include <DisplayHardware/Hal.h>
#include <android-base/stringprintf.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/Output.h>
#include <compositionengine/impl/HwcBufferCache.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <cstdint>
#include "system/graphics-base-v1.0.h"

#include <ui/DataspaceUtils.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include "DisplayHardware/HWComposer.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

using aidl::android::hardware::graphics::composer3::Composition;

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

    const Rect& viewport = getOutput().getState().layerStackSpace.getContent();
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

FloatRect OutputLayer::calculateOutputSourceCrop(uint32_t internalDisplayRotationFlags) const {
    const auto& layerState = *getLayerFE().getCompositionState();

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
        uint32_t invTransformOrient = internalDisplayRotationFlags;
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
        if (!activeCrop.intersect(outputState.layerStackSpace.getContent(), &activeCrop)) {
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
    FloatRect geomLayerBounds = layerState.geomLayerBounds;

    // Some HWCs may clip client composited input to its displayFrame. Make sure
    // that this does not cut off the shadow.
    if (layerState.forceClientComposition && layerState.shadowRadius > 0.0f) {
        const auto outset = layerState.shadowRadius;
        geomLayerBounds.left -= outset;
        geomLayerBounds.top -= outset;
        geomLayerBounds.right += outset;
        geomLayerBounds.bottom += outset;
    }
    Rect frame{layerTransform.transform(reduce(geomLayerBounds, activeTransparentRegion))};
    if (!frame.intersect(outputState.layerStackSpace.getContent(), &frame)) {
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
        state.sourceCrop = calculateOutputSourceCrop(internalDisplayRotationFlags);
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

    // Override the dataspace transfer from 170M to sRGB if the device configuration requests this.
    // We do this here instead of in buffer info so that dumpsys can still report layers that are
    // using the 170M transfer. Also we only do this if the colorspace is not agnostic for the
    // layer, in case the color profile uses a 170M transfer function.
    if (outputState.treat170mAsSrgb && !layerFEState->isColorspaceAgnostic &&
        (state.dataspace & HAL_DATASPACE_TRANSFER_MASK) == HAL_DATASPACE_TRANSFER_SMPTE_170M) {
        state.dataspace = static_cast<ui::Dataspace>(
                (state.dataspace & HAL_DATASPACE_STANDARD_MASK) |
                (state.dataspace & HAL_DATASPACE_RANGE_MASK) | HAL_DATASPACE_TRANSFER_SRGB);
    }

    // For hdr content, treat the white point as the display brightness - HDR content should not be
    // boosted or dimmed.
    // If the layer explicitly requests to disable dimming, then don't dim either.
    if (isHdrDataspace(state.dataspace) ||
        getOutput().getState().displayBrightnessNits == getOutput().getState().sdrWhitePointNits ||
        getOutput().getState().displayBrightnessNits == 0.f || !layerFEState->dimmingEnabled) {
        state.dimmingRatio = 1.f;
        state.whitePointNits = getOutput().getState().displayBrightnessNits;
    } else {
        state.dimmingRatio = std::clamp(getOutput().getState().sdrWhitePointNits /
                                                getOutput().getState().displayBrightnessNits,
                                        0.f, 1.f);
        state.whitePointNits = getOutput().getState().sdrWhitePointNits;
    }

    // These are evaluated every frame as they can potentially change at any
    // time.
    if (layerFEState->forceClientComposition || !profile.isDataspaceSupported(state.dataspace) ||
        forceClientComposition) {
        state.forceClientComposition = true;
    }
}

void OutputLayer::writeStateToHWC(bool includeGeometry, bool skipLayer, uint32_t z,
                                  bool zIsOverridden, bool isPeekingThrough) {
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

    if (requestedCompositionType == Composition::SOLID_COLOR && state.overrideInfo.buffer) {
        // this should never happen, as SOLID_COLOR is skipped from caching, b/230073351
        requestedCompositionType = Composition::DEVICE;
    }

    // TODO(b/181172795): We now update geometry for all flattened layers. We should update it
    // only when the geometry actually changes
    const bool isOverridden =
            state.overrideInfo.buffer != nullptr || isPeekingThrough || zIsOverridden;
    const bool prevOverridden = state.hwc->stateOverridden;
    if (isOverridden || prevOverridden || skipLayer || includeGeometry) {
        writeOutputDependentGeometryStateToHWC(hwcLayer.get(), requestedCompositionType, z);
        writeOutputIndependentGeometryStateToHWC(hwcLayer.get(), *outputIndependentState,
                                                 skipLayer);
    }

    writeOutputDependentPerFrameStateToHWC(hwcLayer.get());
    writeOutputIndependentPerFrameStateToHWC(hwcLayer.get(), *outputIndependentState,
                                             requestedCompositionType, skipLayer);

    writeCompositionTypeToHWC(hwcLayer.get(), requestedCompositionType, isPeekingThrough,
                              skipLayer);

    if (requestedCompositionType == Composition::SOLID_COLOR) {
        writeSolidColorStateToHWC(hwcLayer.get(), *outputIndependentState);
    }

    editState().hwc->stateOverridden = isOverridden;
    editState().hwc->layerSkipped = skipLayer;
}

void OutputLayer::writeOutputDependentGeometryStateToHWC(HWC2::Layer* hwcLayer,
                                                         Composition requestedCompositionType,
                                                         uint32_t z) {
    const auto& outputDependentState = getState();

    Rect displayFrame = outputDependentState.displayFrame;
    FloatRect sourceCrop = outputDependentState.sourceCrop;

    if (outputDependentState.overrideInfo.buffer != nullptr) {
        displayFrame = outputDependentState.overrideInfo.displayFrame;
        sourceCrop =
                FloatRect(0.f, 0.f,
                          static_cast<float>(outputDependentState.overrideInfo.buffer->getBuffer()
                                                     ->getWidth()),
                          static_cast<float>(outputDependentState.overrideInfo.buffer->getBuffer()
                                                     ->getHeight()));
    }

    ALOGV("Writing display frame [%d, %d, %d, %d]", displayFrame.left, displayFrame.top,
          displayFrame.right, displayFrame.bottom);

    if (auto error = hwcLayer->setDisplayFrame(displayFrame); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set display frame [%d, %d, %d, %d]: %s (%d)",
              getLayerFE().getDebugName(), displayFrame.left, displayFrame.top, displayFrame.right,
              displayFrame.bottom, to_string(error).c_str(), static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setSourceCrop(sourceCrop); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set source crop [%.3f, %.3f, %.3f, %.3f]: "
              "%s (%d)",
              getLayerFE().getDebugName(), sourceCrop.left, sourceCrop.top, sourceCrop.right,
              sourceCrop.bottom, to_string(error).c_str(), static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setZOrder(z); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set Z %u: %s (%d)", getLayerFE().getDebugName(), z,
              to_string(error).c_str(), static_cast<int32_t>(error));
    }

    // Solid-color layers and overridden buffers should always use an identity transform.
    const auto bufferTransform = (requestedCompositionType != Composition::SOLID_COLOR &&
                                  getState().overrideInfo.buffer == nullptr)
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
        HWC2::Layer* hwcLayer, const LayerFECompositionState& outputIndependentState,
        bool skipLayer) {
    // If there is a peekThroughLayer, then this layer has a hole in it. We need to use
    // PREMULTIPLIED so it will peek through.
    const auto& overrideInfo = getState().overrideInfo;
    const auto blendMode = overrideInfo.buffer || overrideInfo.peekThroughLayer
            ? hardware::graphics::composer::hal::BlendMode::PREMULTIPLIED
            : outputIndependentState.blendMode;
    if (auto error = hwcLayer->setBlendMode(blendMode); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set blend mode %s: %s (%d)", getLayerFE().getDebugName(),
              toString(blendMode).c_str(), to_string(error).c_str(), static_cast<int32_t>(error));
    }

    const float alpha = skipLayer
            ? 0.0f
            : (getState().overrideInfo.buffer ? 1.0f : outputIndependentState.alpha);
    ALOGV("Writing alpha %f", alpha);

    if (auto error = hwcLayer->setPlaneAlpha(alpha); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set plane alpha %.3f: %s (%d)", getLayerFE().getDebugName(), alpha,
              to_string(error).c_str(), static_cast<int32_t>(error));
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
    Region visibleRegion = outputDependentState.overrideInfo.buffer
            ? Region(outputDependentState.overrideInfo.visibleRegion)
            : outputDependentState.outputSpaceVisibleRegion;
    if (auto error = hwcLayer->setVisibleRegion(visibleRegion); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set visible region: %s (%d)", getLayerFE().getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        visibleRegion.dump(LOG_TAG);
    }

    if (auto error =
                hwcLayer->setBlockingRegion(outputDependentState.outputSpaceBlockingRegionHint);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set blocking region: %s (%d)", getLayerFE().getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        outputDependentState.outputSpaceBlockingRegionHint.dump(LOG_TAG);
    }

    const auto dataspace = outputDependentState.overrideInfo.buffer
            ? outputDependentState.overrideInfo.dataspace
            : outputDependentState.dataspace;

    if (auto error = hwcLayer->setDataspace(dataspace); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set dataspace %d: %s (%d)", getLayerFE().getDebugName(), dataspace,
              to_string(error).c_str(), static_cast<int32_t>(error));
    }

    // Cached layers are not dimmed, which means that composer should attempt to dim.
    // Note that if the dimming ratio is large, then this may cause the cached layer
    // to kick back into GPU composition :(
    // Also note that this assumes that there are no HDR layers that are able to be cached.
    // Otherwise, this could cause HDR layers to be dimmed twice.
    const auto dimmingRatio = outputDependentState.overrideInfo.buffer
            ? (getOutput().getState().displayBrightnessNits != 0.f
                       ? std::clamp(getOutput().getState().sdrWhitePointNits /
                                            getOutput().getState().displayBrightnessNits,
                                    0.f, 1.f)
                       : 1.f)
            : outputDependentState.dimmingRatio;

    if (auto error = hwcLayer->setBrightness(dimmingRatio); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set brightness %f: %s (%d)", getLayerFE().getDebugName(),
              dimmingRatio, to_string(error).c_str(), static_cast<int32_t>(error));
    }
}

void OutputLayer::writeOutputIndependentPerFrameStateToHWC(
        HWC2::Layer* hwcLayer, const LayerFECompositionState& outputIndependentState,
        Composition compositionType, bool skipLayer) {
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

    const Region& surfaceDamage = getState().overrideInfo.buffer
            ? getState().overrideInfo.damageRegion
            : (getState().hwc->stateOverridden ? Region::INVALID_REGION
                                               : outputIndependentState.surfaceDamage);

    if (auto error = hwcLayer->setSurfaceDamage(surfaceDamage); error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set surface damage: %s (%d)", getLayerFE().getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        outputIndependentState.surfaceDamage.dump(LOG_TAG);
    }

    // Content-specific per-frame state
    switch (compositionType) {
        case Composition::SOLID_COLOR:
            // For compatibility, should be written AFTER the composition type.
            break;
        case Composition::SIDEBAND:
            writeSidebandStateToHWC(hwcLayer, outputIndependentState);
            break;
        case Composition::CURSOR:
        case Composition::DEVICE:
        case Composition::DISPLAY_DECORATION:
            writeBufferStateToHWC(hwcLayer, outputIndependentState, skipLayer);
            break;
        case Composition::INVALID:
        case Composition::CLIENT:
            // Ignored
            break;
    }
}

void OutputLayer::writeSolidColorStateToHWC(HWC2::Layer* hwcLayer,
                                            const LayerFECompositionState& outputIndependentState) {
    aidl::android::hardware::graphics::composer3::Color color = {outputIndependentState.color.r,
                                                                 outputIndependentState.color.g,
                                                                 outputIndependentState.color.b,
                                                                 1.0f};

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
                                        const LayerFECompositionState& outputIndependentState,
                                        bool skipLayer) {
    auto supportedPerFrameMetadata =
            getOutput().getDisplayColorProfile()->getSupportedPerFrameMetadata();
    if (auto error = hwcLayer->setPerFrameMetadata(supportedPerFrameMetadata,
                                                   outputIndependentState.hdrMetadata);
        error != hal::Error::NONE && error != hal::Error::UNSUPPORTED) {
        ALOGE("[%s] Failed to set hdrMetadata: %s (%d)", getLayerFE().getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
    }

    sp<GraphicBuffer> buffer = outputIndependentState.buffer;
    sp<Fence> acquireFence = outputIndependentState.acquireFence;
    int slot = outputIndependentState.bufferSlot;
    if (getState().overrideInfo.buffer != nullptr && !skipLayer) {
        buffer = getState().overrideInfo.buffer->getBuffer();
        acquireFence = getState().overrideInfo.acquireFence;
        slot = HwcBufferCache::FLATTENER_CACHING_SLOT;
    }

    ALOGV("Writing buffer %p", buffer.get());

    uint32_t hwcSlot = 0;
    sp<GraphicBuffer> hwcBuffer;
    // We need access to the output-dependent state for the buffer cache there,
    // though otherwise the buffer is not output-dependent.
    editState().hwc->hwcBufferCache.getHwcBuffer(slot, buffer, &hwcSlot, &hwcBuffer);

    if (auto error = hwcLayer->setBuffer(hwcSlot, hwcBuffer, acquireFence);
        error != hal::Error::NONE) {
        ALOGE("[%s] Failed to set buffer %p: %s (%d)", getLayerFE().getDebugName(), buffer->handle,
              to_string(error).c_str(), static_cast<int32_t>(error));
    }
}

void OutputLayer::writeCompositionTypeToHWC(HWC2::Layer* hwcLayer,
                                            Composition requestedCompositionType,
                                            bool isPeekingThrough, bool skipLayer) {
    auto& outputDependentState = editState();

    if (isClientCompositionForced(isPeekingThrough)) {
        // If we are forcing client composition, we need to tell the HWC
        requestedCompositionType = Composition::CLIENT;
    }

    // Set the requested composition type with the HWC whenever it changes
    // We also resend the composition type when this layer was previously skipped, to ensure that
    // the composition type is up-to-date.
    if (outputDependentState.hwc->hwcCompositionType != requestedCompositionType ||
        (outputDependentState.hwc->layerSkipped && !skipLayer)) {
        outputDependentState.hwc->hwcCompositionType = requestedCompositionType;

        if (auto error = hwcLayer->setCompositionType(requestedCompositionType);
            error != hal::Error::NONE) {
            ALOGE("[%s] Failed to set composition type %s: %s (%d)", getLayerFE().getDebugName(),
                  to_string(requestedCompositionType).c_str(), to_string(error).c_str(),
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
    frame.intersect(outputState.layerStackSpace.getContent(), &frame);
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
    return !state.hwc || state.hwc->hwcCompositionType == Composition::CLIENT;
}

bool OutputLayer::isHardwareCursor() const {
    const auto& state = getState();
    return state.hwc && state.hwc->hwcCompositionType == Composition::CURSOR;
}

void OutputLayer::detectDisallowedCompositionTypeChange(Composition from, Composition to) const {
    bool result = false;
    switch (from) {
        case Composition::INVALID:
        case Composition::CLIENT:
            result = false;
            break;

        case Composition::DEVICE:
        case Composition::SOLID_COLOR:
            result = (to == Composition::CLIENT);
            break;

        case Composition::CURSOR:
        case Composition::SIDEBAND:
        case Composition::DISPLAY_DECORATION:
            result = (to == Composition::CLIENT || to == Composition::DEVICE);
            break;
    }

    if (!result) {
        ALOGE("[%s] Invalid device requested composition type change: %s (%d) --> %s (%d)",
              getLayerFE().getDebugName(), to_string(from).c_str(), static_cast<int>(from),
              to_string(to).c_str(), static_cast<int>(to));
    }
}

bool OutputLayer::isClientCompositionForced(bool isPeekingThrough) const {
    return getState().forceClientComposition ||
            (!isPeekingThrough && getLayerFE().hasRoundedCorners());
}

void OutputLayer::applyDeviceCompositionTypeChange(Composition compositionType) {
    auto& state = editState();
    LOG_FATAL_IF(!state.hwc);
    auto& hwcState = *state.hwc;

    // Only detected disallowed changes if this was not a skip layer, because the
    // validated composition type may be arbitrary (usually DEVICE, to reflect that there were
    // fewer GPU layers)
    if (!hwcState.layerSkipped) {
        detectDisallowedCompositionTypeChange(hwcState.hwcCompositionType, compositionType);
    }

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

std::vector<LayerFE::LayerSettings> OutputLayer::getOverrideCompositionList() const {
    if (getState().overrideInfo.buffer == nullptr) {
        return {};
    }

    // Compute the geometry boundaries in layer stack space: we need to transform from the
    // framebuffer space of the override buffer to layer space.
    const ProjectionSpace& layerSpace = getOutput().getState().layerStackSpace;
    const ui::Transform transform = getState().overrideInfo.displaySpace.getTransform(layerSpace);
    const Rect boundaries = transform.transform(getState().overrideInfo.displayFrame);

    LayerFE::LayerSettings settings;
    settings.geometry = renderengine::Geometry{
            .boundaries = boundaries.toFloatRect(),
    };
    settings.bufferId = getState().overrideInfo.buffer->getBuffer()->getId();
    settings.source = renderengine::PixelSource{
            .buffer = renderengine::Buffer{
                    .buffer = getState().overrideInfo.buffer,
                    .fence = getState().overrideInfo.acquireFence,
                    // If the transform from layer space to display space contains a rotation, we
                    // need to undo the rotation in the texture transform
                    .textureTransform =
                            ui::Transform(transform.inverse().getOrientation(), 1, 1).asMatrix4(),
            }};
    settings.sourceDataspace = getState().overrideInfo.dataspace;
    settings.alpha = 1.0f;
    settings.whitePointNits = getOutput().getState().sdrWhitePointNits;

    return {static_cast<LayerFE::LayerSettings>(settings)};
}

void OutputLayer::dump(std::string& out) const {
    using android::base::StringAppendF;

    StringAppendF(&out, "  - Output Layer %p(%s)\n", this, getLayerFE().getDebugName());
    dumpState(out);
}

} // namespace impl
} // namespace android::compositionengine
