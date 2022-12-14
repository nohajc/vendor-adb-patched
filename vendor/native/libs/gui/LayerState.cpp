/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define LOG_TAG "LayerState"

#include <inttypes.h>

#include <utils/Errors.h>
#include <binder/Parcel.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/LayerState.h>

#include <cmath>

namespace android {

status_t layer_state_t::write(Parcel& output) const
{
    output.writeStrongBinder(surface);
    output.writeUint64(what);
    output.writeFloat(x);
    output.writeFloat(y);
    output.writeInt32(z);
    output.writeUint32(w);
    output.writeUint32(h);
    output.writeUint32(layerStack);
    output.writeFloat(alpha);
    output.writeUint32(flags);
    output.writeUint32(mask);
    *reinterpret_cast<layer_state_t::matrix22_t *>(
            output.writeInplace(sizeof(layer_state_t::matrix22_t))) = matrix;
    output.write(crop_legacy);
    output.writeStrongBinder(barrierHandle_legacy);
    output.writeStrongBinder(reparentHandle);
    output.writeUint64(frameNumber_legacy);
    output.writeInt32(overrideScalingMode);
    output.writeStrongBinder(IInterface::asBinder(barrierGbp_legacy));
    output.writeStrongBinder(relativeLayerHandle);
    output.writeStrongBinder(parentHandleForChild);
    output.writeFloat(color.r);
    output.writeFloat(color.g);
    output.writeFloat(color.b);
#ifndef NO_INPUT
    inputInfo.write(output);
#endif
    output.write(transparentRegion);
    output.writeUint32(transform);
    output.writeBool(transformToDisplayInverse);
    output.write(crop);
    output.write(frame);
    if (buffer) {
        output.writeBool(true);
        output.write(*buffer);
    } else {
        output.writeBool(false);
    }
    if (acquireFence) {
        output.writeBool(true);
        output.write(*acquireFence);
    } else {
        output.writeBool(false);
    }
    output.writeUint32(static_cast<uint32_t>(dataspace));
    output.write(hdrMetadata);
    output.write(surfaceDamageRegion);
    output.writeInt32(api);
    if (sidebandStream) {
        output.writeBool(true);
        output.writeNativeHandle(sidebandStream->handle());
    } else {
        output.writeBool(false);
    }

    memcpy(output.writeInplace(16 * sizeof(float)),
           colorTransform.asArray(), 16 * sizeof(float));
    output.writeFloat(cornerRadius);
    output.writeUint32(backgroundBlurRadius);
    output.writeStrongBinder(cachedBuffer.token.promote());
    output.writeUint64(cachedBuffer.id);
    output.writeParcelable(metadata);

    output.writeFloat(bgColorAlpha);
    output.writeUint32(static_cast<uint32_t>(bgColorDataspace));
    output.writeBool(colorSpaceAgnostic);

    auto err = output.writeVectorSize(listeners);
    if (err) {
        return err;
    }

    for (auto listener : listeners) {
        err = output.writeStrongBinder(listener.transactionCompletedListener);
        if (err) {
            return err;
        }
        err = output.writeInt64Vector(listener.callbackIds);
        if (err) {
            return err;
        }
    }
    output.writeFloat(shadowRadius);
    output.writeInt32(frameRateSelectionPriority);
    output.writeFloat(frameRate);
    output.writeByte(frameRateCompatibility);
    output.writeUint32(fixedTransformHint);
    return NO_ERROR;
}

status_t layer_state_t::read(const Parcel& input)
{
    surface = input.readStrongBinder();
    what = input.readUint64();
    x = input.readFloat();
    y = input.readFloat();
    z = input.readInt32();
    w = input.readUint32();
    h = input.readUint32();
    layerStack = input.readUint32();
    alpha = input.readFloat();
    flags = static_cast<uint8_t>(input.readUint32());
    mask = static_cast<uint8_t>(input.readUint32());
    const void* matrix_data = input.readInplace(sizeof(layer_state_t::matrix22_t));
    if (matrix_data) {
        matrix = *reinterpret_cast<layer_state_t::matrix22_t const *>(matrix_data);
    } else {
        return BAD_VALUE;
    }
    input.read(crop_legacy);
    barrierHandle_legacy = input.readStrongBinder();
    reparentHandle = input.readStrongBinder();
    frameNumber_legacy = input.readUint64();
    overrideScalingMode = input.readInt32();
    barrierGbp_legacy = interface_cast<IGraphicBufferProducer>(input.readStrongBinder());
    relativeLayerHandle = input.readStrongBinder();
    parentHandleForChild = input.readStrongBinder();
    color.r = input.readFloat();
    color.g = input.readFloat();
    color.b = input.readFloat();

#ifndef NO_INPUT
    inputInfo = InputWindowInfo::read(input);
#endif

    input.read(transparentRegion);
    transform = input.readUint32();
    transformToDisplayInverse = input.readBool();
    input.read(crop);
    input.read(frame);
    buffer = new GraphicBuffer();
    if (input.readBool()) {
        input.read(*buffer);
    }
    acquireFence = new Fence();
    if (input.readBool()) {
        input.read(*acquireFence);
    }
    dataspace = static_cast<ui::Dataspace>(input.readUint32());
    input.read(hdrMetadata);
    input.read(surfaceDamageRegion);
    api = input.readInt32();
    if (input.readBool()) {
        sidebandStream = NativeHandle::create(input.readNativeHandle(), true);
    }

    const void* color_transform_data = input.readInplace(16 * sizeof(float));
    if (color_transform_data) {
        colorTransform = mat4(static_cast<const float*>(color_transform_data));
    } else {
        return BAD_VALUE;
    }
    cornerRadius = input.readFloat();
    backgroundBlurRadius = input.readUint32();
    cachedBuffer.token = input.readStrongBinder();
    cachedBuffer.id = input.readUint64();
    input.readParcelable(&metadata);

    bgColorAlpha = input.readFloat();
    bgColorDataspace = static_cast<ui::Dataspace>(input.readUint32());
    colorSpaceAgnostic = input.readBool();

    int32_t numListeners = input.readInt32();
    listeners.clear();
    for (int i = 0; i < numListeners; i++) {
        auto listener = input.readStrongBinder();
        std::vector<CallbackId> callbackIds;
        input.readInt64Vector(&callbackIds);
        listeners.emplace_back(listener, callbackIds);
    }
    shadowRadius = input.readFloat();
    frameRateSelectionPriority = input.readInt32();
    frameRate = input.readFloat();
    frameRateCompatibility = input.readByte();
    fixedTransformHint = static_cast<ui::Transform::RotationFlags>(input.readUint32());
    return NO_ERROR;
}

status_t ComposerState::write(Parcel& output) const {
    return state.write(output);
}

status_t ComposerState::read(const Parcel& input) {
    return state.read(input);
}


DisplayState::DisplayState() :
    what(0),
    layerStack(0),
    viewport(Rect::EMPTY_RECT),
    frame(Rect::EMPTY_RECT),
    width(0),
    height(0) {
}

status_t DisplayState::write(Parcel& output) const {
    output.writeStrongBinder(token);
    output.writeStrongBinder(IInterface::asBinder(surface));
    output.writeUint32(what);
    output.writeUint32(layerStack);
    output.writeUint32(toRotationInt(orientation));
    output.write(viewport);
    output.write(frame);
    output.writeUint32(width);
    output.writeUint32(height);
    return NO_ERROR;
}

status_t DisplayState::read(const Parcel& input) {
    token = input.readStrongBinder();
    surface = interface_cast<IGraphicBufferProducer>(input.readStrongBinder());
    what = input.readUint32();
    layerStack = input.readUint32();
    orientation = ui::toRotation(input.readUint32());
    input.read(viewport);
    input.read(frame);
    width = input.readUint32();
    height = input.readUint32();
    return NO_ERROR;
}

void DisplayState::merge(const DisplayState& other) {
    if (other.what & eSurfaceChanged) {
        what |= eSurfaceChanged;
        surface = other.surface;
    }
    if (other.what & eLayerStackChanged) {
        what |= eLayerStackChanged;
        layerStack = other.layerStack;
    }
    if (other.what & eDisplayProjectionChanged) {
        what |= eDisplayProjectionChanged;
        orientation = other.orientation;
        viewport = other.viewport;
        frame = other.frame;
    }
    if (other.what & eDisplaySizeChanged) {
        what |= eDisplaySizeChanged;
        width = other.width;
        height = other.height;
    }
}

void layer_state_t::merge(const layer_state_t& other) {
    if (other.what & ePositionChanged) {
        what |= ePositionChanged;
        x = other.x;
        y = other.y;
    }
    if (other.what & eLayerChanged) {
        what |= eLayerChanged;
        what &= ~eRelativeLayerChanged;
        z = other.z;
    }
    if (other.what & eSizeChanged) {
        what |= eSizeChanged;
        w = other.w;
        h = other.h;
    }
    if (other.what & eAlphaChanged) {
        what |= eAlphaChanged;
        alpha = other.alpha;
    }
    if (other.what & eMatrixChanged) {
        what |= eMatrixChanged;
        matrix = other.matrix;
    }
    if (other.what & eTransparentRegionChanged) {
        what |= eTransparentRegionChanged;
        transparentRegion = other.transparentRegion;
    }
    if (other.what & eFlagsChanged) {
        what |= eFlagsChanged;
        flags &= ~other.mask;
        flags |= (other.flags & other.mask);
        mask |= other.mask;
    }
    if (other.what & eLayerStackChanged) {
        what |= eLayerStackChanged;
        layerStack = other.layerStack;
    }
    if (other.what & eCropChanged_legacy) {
        what |= eCropChanged_legacy;
        crop_legacy = other.crop_legacy;
    }
    if (other.what & eCornerRadiusChanged) {
        what |= eCornerRadiusChanged;
        cornerRadius = other.cornerRadius;
    }
    if (other.what & eBackgroundBlurRadiusChanged) {
        what |= eBackgroundBlurRadiusChanged;
        backgroundBlurRadius = other.backgroundBlurRadius;
    }
    if (other.what & eDeferTransaction_legacy) {
        what |= eDeferTransaction_legacy;
        barrierHandle_legacy = other.barrierHandle_legacy;
        barrierGbp_legacy = other.barrierGbp_legacy;
        frameNumber_legacy = other.frameNumber_legacy;
    }
    if (other.what & eOverrideScalingModeChanged) {
        what |= eOverrideScalingModeChanged;
        overrideScalingMode = other.overrideScalingMode;
    }
    if (other.what & eReparentChildren) {
        what |= eReparentChildren;
        reparentHandle = other.reparentHandle;
    }
    if (other.what & eDetachChildren) {
        what |= eDetachChildren;
    }
    if (other.what & eRelativeLayerChanged) {
        what |= eRelativeLayerChanged;
        what &= ~eLayerChanged;
        z = other.z;
        relativeLayerHandle = other.relativeLayerHandle;
    }
    if (other.what & eReparent) {
        what |= eReparent;
        parentHandleForChild = other.parentHandleForChild;
    }
    if (other.what & eDestroySurface) {
        what |= eDestroySurface;
    }
    if (other.what & eTransformChanged) {
        what |= eTransformChanged;
        transform = other.transform;
    }
    if (other.what & eTransformToDisplayInverseChanged) {
        what |= eTransformToDisplayInverseChanged;
        transformToDisplayInverse = other.transformToDisplayInverse;
    }
    if (other.what & eCropChanged) {
        what |= eCropChanged;
        crop = other.crop;
    }
    if (other.what & eFrameChanged) {
        what |= eFrameChanged;
        frame = other.frame;
    }
    if (other.what & eBufferChanged) {
        what |= eBufferChanged;
        buffer = other.buffer;
    }
    if (other.what & eAcquireFenceChanged) {
        what |= eAcquireFenceChanged;
        acquireFence = other.acquireFence;
    }
    if (other.what & eDataspaceChanged) {
        what |= eDataspaceChanged;
        dataspace = other.dataspace;
    }
    if (other.what & eHdrMetadataChanged) {
        what |= eHdrMetadataChanged;
        hdrMetadata = other.hdrMetadata;
    }
    if (other.what & eSurfaceDamageRegionChanged) {
        what |= eSurfaceDamageRegionChanged;
        surfaceDamageRegion = other.surfaceDamageRegion;
    }
    if (other.what & eApiChanged) {
        what |= eApiChanged;
        api = other.api;
    }
    if (other.what & eSidebandStreamChanged) {
        what |= eSidebandStreamChanged;
        sidebandStream = other.sidebandStream;
    }
    if (other.what & eColorTransformChanged) {
        what |= eColorTransformChanged;
        colorTransform = other.colorTransform;
    }
    if (other.what & eHasListenerCallbacksChanged) {
        what |= eHasListenerCallbacksChanged;
    }

#ifndef NO_INPUT
    if (other.what & eInputInfoChanged) {
        what |= eInputInfoChanged;
        inputInfo = other.inputInfo;
    }
#endif

    if (other.what & eCachedBufferChanged) {
        what |= eCachedBufferChanged;
        cachedBuffer = other.cachedBuffer;
    }
    if (other.what & eBackgroundColorChanged) {
        what |= eBackgroundColorChanged;
        color = other.color;
        bgColorAlpha = other.bgColorAlpha;
        bgColorDataspace = other.bgColorDataspace;
    }
    if (other.what & eMetadataChanged) {
        what |= eMetadataChanged;
        metadata.merge(other.metadata);
    }
    if (other.what & eShadowRadiusChanged) {
        what |= eShadowRadiusChanged;
        shadowRadius = other.shadowRadius;
    }
    if (other.what & eFrameRateSelectionPriority) {
        what |= eFrameRateSelectionPriority;
        frameRateSelectionPriority = other.frameRateSelectionPriority;
    }
    if (other.what & eFrameRateChanged) {
        what |= eFrameRateChanged;
        frameRate = other.frameRate;
        frameRateCompatibility = other.frameRateCompatibility;
    }
    if (other.what & eFixedTransformHintChanged) {
        what |= eFixedTransformHintChanged;
        fixedTransformHint = other.fixedTransformHint;
    }
    if ((other.what & what) != other.what) {
        ALOGE("Unmerged SurfaceComposer Transaction properties. LayerState::merge needs updating? "
              "other.what=0x%" PRIu64 " what=0x%" PRIu64,
              other.what, what);
    }
}

// ------------------------------- InputWindowCommands ----------------------------------------

void InputWindowCommands::merge(const InputWindowCommands& other) {
    syncInputWindows |= other.syncInputWindows;
}

void InputWindowCommands::clear() {
    syncInputWindows = false;
}

void InputWindowCommands::write(Parcel& output) const {
    output.writeBool(syncInputWindows);
}

void InputWindowCommands::read(const Parcel& input) {
    syncInputWindows = input.readBool();
}

bool ValidateFrameRate(float frameRate, int8_t compatibility, const char* inFunctionName) {
    const char* functionName = inFunctionName != nullptr ? inFunctionName : "call";
    int floatClassification = std::fpclassify(frameRate);
    if (frameRate < 0 || floatClassification == FP_INFINITE || floatClassification == FP_NAN) {
        ALOGE("%s failed - invalid frame rate %f", functionName, frameRate);
        return false;
    }

    if (compatibility != ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT &&
        compatibility != ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE) {
        ALOGE("%s failed - invalid compatibility value %d", functionName, compatibility);
        return false;
    }

    return true;
}

}; // namespace android
