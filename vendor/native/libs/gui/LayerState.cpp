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

#include <apex/window.h>
#include <inttypes.h>

#include <android/native_window.h>
#include <binder/Parcel.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
#include <private/gui/ParcelUtils.h>
#include <utils/Errors.h>

#include <cmath>

namespace android {

using gui::FocusRequest;
using gui::WindowInfoHandle;

layer_state_t::layer_state_t()
      : what(0),
        x(0),
        y(0),
        z(0),
        w(0),
        h(0),
        layerStack(0),
        alpha(0),
        flags(0),
        mask(0),
        reserved(0),
        cornerRadius(0.0f),
        backgroundBlurRadius(0),
        transform(0),
        transformToDisplayInverse(false),
        crop(Rect::INVALID_RECT),
        orientedDisplaySpaceRect(Rect::INVALID_RECT),
        dataspace(ui::Dataspace::UNKNOWN),
        surfaceDamageRegion(),
        api(-1),
        colorTransform(mat4()),
        bgColorAlpha(0),
        bgColorDataspace(ui::Dataspace::UNKNOWN),
        colorSpaceAgnostic(false),
        shadowRadius(0.0f),
        frameRateSelectionPriority(-1),
        frameRate(0.0f),
        frameRateCompatibility(ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT),
        changeFrameRateStrategy(ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS),
        fixedTransformHint(ui::Transform::ROT_INVALID),
        frameNumber(0),
        autoRefresh(false),
        isTrustedOverlay(false),
        bufferCrop(Rect::INVALID_RECT),
        destinationFrame(Rect::INVALID_RECT),
        releaseBufferListener(nullptr),
        dropInputMode(gui::DropInputMode::NONE) {
    matrix.dsdx = matrix.dtdy = 1.0f;
    matrix.dsdy = matrix.dtdx = 0.0f;
    hdrMetadata.validTypes = 0;
}

status_t layer_state_t::write(Parcel& output) const
{
    SAFE_PARCEL(output.writeStrongBinder, surface);
    SAFE_PARCEL(output.writeInt32, layerId);
    SAFE_PARCEL(output.writeUint64, what);
    SAFE_PARCEL(output.writeFloat, x);
    SAFE_PARCEL(output.writeFloat, y);
    SAFE_PARCEL(output.writeInt32, z);
    SAFE_PARCEL(output.writeUint32, w);
    SAFE_PARCEL(output.writeUint32, h);
    SAFE_PARCEL(output.writeUint32, layerStack);
    SAFE_PARCEL(output.writeFloat, alpha);
    SAFE_PARCEL(output.writeUint32, flags);
    SAFE_PARCEL(output.writeUint32, mask);
    SAFE_PARCEL(matrix.write, output);
    SAFE_PARCEL(output.write, crop);
    SAFE_PARCEL(SurfaceControl::writeNullableToParcel, output, reparentSurfaceControl);
    SAFE_PARCEL(SurfaceControl::writeNullableToParcel, output, relativeLayerSurfaceControl);
    SAFE_PARCEL(SurfaceControl::writeNullableToParcel, output, parentSurfaceControlForChild);
    SAFE_PARCEL(output.writeFloat, color.r);
    SAFE_PARCEL(output.writeFloat, color.g);
    SAFE_PARCEL(output.writeFloat, color.b);
    SAFE_PARCEL(windowInfoHandle->writeToParcel, &output);
    SAFE_PARCEL(output.write, transparentRegion);
    SAFE_PARCEL(output.writeUint32, transform);
    SAFE_PARCEL(output.writeBool, transformToDisplayInverse);
    SAFE_PARCEL(output.write, orientedDisplaySpaceRect);

    if (buffer) {
        SAFE_PARCEL(output.writeBool, true);
        SAFE_PARCEL(output.write, *buffer);
    } else {
        SAFE_PARCEL(output.writeBool, false);
    }

    if (acquireFence) {
        SAFE_PARCEL(output.writeBool, true);
        SAFE_PARCEL(output.write, *acquireFence);
    } else {
        SAFE_PARCEL(output.writeBool, false);
    }

    SAFE_PARCEL(output.writeUint32, static_cast<uint32_t>(dataspace));
    SAFE_PARCEL(output.write, hdrMetadata);
    SAFE_PARCEL(output.write, surfaceDamageRegion);
    SAFE_PARCEL(output.writeInt32, api);

    if (sidebandStream) {
        SAFE_PARCEL(output.writeBool, true);
        SAFE_PARCEL(output.writeNativeHandle, sidebandStream->handle());
    } else {
        SAFE_PARCEL(output.writeBool, false);
    }

    SAFE_PARCEL(output.write, colorTransform.asArray(), 16 * sizeof(float));
    SAFE_PARCEL(output.writeFloat, cornerRadius);
    SAFE_PARCEL(output.writeUint32, backgroundBlurRadius);
    SAFE_PARCEL(output.writeStrongBinder, cachedBuffer.token.promote());
    SAFE_PARCEL(output.writeUint64, cachedBuffer.id);
    SAFE_PARCEL(output.writeParcelable, metadata);
    SAFE_PARCEL(output.writeFloat, bgColorAlpha);
    SAFE_PARCEL(output.writeUint32, static_cast<uint32_t>(bgColorDataspace));
    SAFE_PARCEL(output.writeBool, colorSpaceAgnostic);
    SAFE_PARCEL(output.writeVectorSize, listeners);

    for (auto listener : listeners) {
        SAFE_PARCEL(output.writeStrongBinder, listener.transactionCompletedListener);
        SAFE_PARCEL(output.writeParcelableVector, listener.callbackIds);
    }
    SAFE_PARCEL(output.writeFloat, shadowRadius);
    SAFE_PARCEL(output.writeInt32, frameRateSelectionPriority);
    SAFE_PARCEL(output.writeFloat, frameRate);
    SAFE_PARCEL(output.writeByte, frameRateCompatibility);
    SAFE_PARCEL(output.writeByte, changeFrameRateStrategy);
    SAFE_PARCEL(output.writeUint32, fixedTransformHint);
    SAFE_PARCEL(output.writeUint64, frameNumber);
    SAFE_PARCEL(output.writeBool, autoRefresh);
    SAFE_PARCEL(output.writeStrongBinder, IInterface::asBinder(releaseBufferListener));

    SAFE_PARCEL(output.writeUint32, blurRegions.size());
    for (auto region : blurRegions) {
        SAFE_PARCEL(output.writeUint32, region.blurRadius);
        SAFE_PARCEL(output.writeFloat, region.cornerRadiusTL);
        SAFE_PARCEL(output.writeFloat, region.cornerRadiusTR);
        SAFE_PARCEL(output.writeFloat, region.cornerRadiusBL);
        SAFE_PARCEL(output.writeFloat, region.cornerRadiusBR);
        SAFE_PARCEL(output.writeFloat, region.alpha);
        SAFE_PARCEL(output.writeInt32, region.left);
        SAFE_PARCEL(output.writeInt32, region.top);
        SAFE_PARCEL(output.writeInt32, region.right);
        SAFE_PARCEL(output.writeInt32, region.bottom);
    }

    SAFE_PARCEL(output.write, stretchEffect);
    SAFE_PARCEL(output.write, bufferCrop);
    SAFE_PARCEL(output.write, destinationFrame);
    SAFE_PARCEL(output.writeBool, isTrustedOverlay);

    SAFE_PARCEL(output.writeStrongBinder, releaseBufferEndpoint);
    SAFE_PARCEL(output.writeUint32, static_cast<uint32_t>(dropInputMode));
    return NO_ERROR;
}

status_t layer_state_t::read(const Parcel& input)
{
    SAFE_PARCEL(input.readNullableStrongBinder, &surface);
    SAFE_PARCEL(input.readInt32, &layerId);
    SAFE_PARCEL(input.readUint64, &what);
    SAFE_PARCEL(input.readFloat, &x);
    SAFE_PARCEL(input.readFloat, &y);
    SAFE_PARCEL(input.readInt32, &z);
    SAFE_PARCEL(input.readUint32, &w);
    SAFE_PARCEL(input.readUint32, &h);
    SAFE_PARCEL(input.readUint32, &layerStack);
    SAFE_PARCEL(input.readFloat, &alpha);

    SAFE_PARCEL(input.readUint32, &flags);

    SAFE_PARCEL(input.readUint32, &mask);

    SAFE_PARCEL(matrix.read, input);
    SAFE_PARCEL(input.read, crop);
    SAFE_PARCEL(SurfaceControl::readNullableFromParcel, input, &reparentSurfaceControl);

    SAFE_PARCEL(SurfaceControl::readNullableFromParcel, input, &relativeLayerSurfaceControl);
    SAFE_PARCEL(SurfaceControl::readNullableFromParcel, input, &parentSurfaceControlForChild);

    float tmpFloat = 0;
    SAFE_PARCEL(input.readFloat, &tmpFloat);
    color.r = tmpFloat;
    SAFE_PARCEL(input.readFloat, &tmpFloat);
    color.g = tmpFloat;
    SAFE_PARCEL(input.readFloat, &tmpFloat);
    color.b = tmpFloat;
    SAFE_PARCEL(windowInfoHandle->readFromParcel, &input);

    SAFE_PARCEL(input.read, transparentRegion);
    SAFE_PARCEL(input.readUint32, &transform);
    SAFE_PARCEL(input.readBool, &transformToDisplayInverse);
    SAFE_PARCEL(input.read, orientedDisplaySpaceRect);

    bool tmpBool = false;
    SAFE_PARCEL(input.readBool, &tmpBool);
    if (tmpBool) {
        buffer = new GraphicBuffer();
        SAFE_PARCEL(input.read, *buffer);
    }

    SAFE_PARCEL(input.readBool, &tmpBool);
    if (tmpBool) {
        acquireFence = new Fence();
        SAFE_PARCEL(input.read, *acquireFence);
    }

    uint32_t tmpUint32 = 0;
    SAFE_PARCEL(input.readUint32, &tmpUint32);
    dataspace = static_cast<ui::Dataspace>(tmpUint32);

    SAFE_PARCEL(input.read, hdrMetadata);
    SAFE_PARCEL(input.read, surfaceDamageRegion);
    SAFE_PARCEL(input.readInt32, &api);
    SAFE_PARCEL(input.readBool, &tmpBool);
    if (tmpBool) {
        sidebandStream = NativeHandle::create(input.readNativeHandle(), true);
    }

    SAFE_PARCEL(input.read, &colorTransform, 16 * sizeof(float));
    SAFE_PARCEL(input.readFloat, &cornerRadius);
    SAFE_PARCEL(input.readUint32, &backgroundBlurRadius);
    sp<IBinder> tmpBinder;
    SAFE_PARCEL(input.readNullableStrongBinder, &tmpBinder);
    cachedBuffer.token = tmpBinder;
    SAFE_PARCEL(input.readUint64, &cachedBuffer.id);
    SAFE_PARCEL(input.readParcelable, &metadata);

    SAFE_PARCEL(input.readFloat, &bgColorAlpha);
    SAFE_PARCEL(input.readUint32, &tmpUint32);
    bgColorDataspace = static_cast<ui::Dataspace>(tmpUint32);
    SAFE_PARCEL(input.readBool, &colorSpaceAgnostic);

    int32_t numListeners = 0;
    SAFE_PARCEL_READ_SIZE(input.readInt32, &numListeners, input.dataSize());
    listeners.clear();
    for (int i = 0; i < numListeners; i++) {
        sp<IBinder> listener;
        std::vector<CallbackId> callbackIds;
        SAFE_PARCEL(input.readNullableStrongBinder, &listener);
        SAFE_PARCEL(input.readParcelableVector, &callbackIds);
        listeners.emplace_back(listener, callbackIds);
    }
    SAFE_PARCEL(input.readFloat, &shadowRadius);
    SAFE_PARCEL(input.readInt32, &frameRateSelectionPriority);
    SAFE_PARCEL(input.readFloat, &frameRate);
    SAFE_PARCEL(input.readByte, &frameRateCompatibility);
    SAFE_PARCEL(input.readByte, &changeFrameRateStrategy);
    SAFE_PARCEL(input.readUint32, &tmpUint32);
    fixedTransformHint = static_cast<ui::Transform::RotationFlags>(tmpUint32);
    SAFE_PARCEL(input.readUint64, &frameNumber);
    SAFE_PARCEL(input.readBool, &autoRefresh);

    tmpBinder = nullptr;
    SAFE_PARCEL(input.readNullableStrongBinder, &tmpBinder);
    if (tmpBinder) {
        releaseBufferListener = checked_interface_cast<ITransactionCompletedListener>(tmpBinder);
    }

    uint32_t numRegions = 0;
    SAFE_PARCEL(input.readUint32, &numRegions);
    blurRegions.clear();
    for (uint32_t i = 0; i < numRegions; i++) {
        BlurRegion region;
        SAFE_PARCEL(input.readUint32, &region.blurRadius);
        SAFE_PARCEL(input.readFloat, &region.cornerRadiusTL);
        SAFE_PARCEL(input.readFloat, &region.cornerRadiusTR);
        SAFE_PARCEL(input.readFloat, &region.cornerRadiusBL);
        SAFE_PARCEL(input.readFloat, &region.cornerRadiusBR);
        SAFE_PARCEL(input.readFloat, &region.alpha);
        SAFE_PARCEL(input.readInt32, &region.left);
        SAFE_PARCEL(input.readInt32, &region.top);
        SAFE_PARCEL(input.readInt32, &region.right);
        SAFE_PARCEL(input.readInt32, &region.bottom);
        blurRegions.push_back(region);
    }

    SAFE_PARCEL(input.read, stretchEffect);
    SAFE_PARCEL(input.read, bufferCrop);
    SAFE_PARCEL(input.read, destinationFrame);
    SAFE_PARCEL(input.readBool, &isTrustedOverlay);

    SAFE_PARCEL(input.readNullableStrongBinder, &releaseBufferEndpoint);

    uint32_t mode;
    SAFE_PARCEL(input.readUint32, &mode);
    dropInputMode = static_cast<gui::DropInputMode>(mode);
    return NO_ERROR;
}

status_t ComposerState::write(Parcel& output) const {
    return state.write(output);
}

status_t ComposerState::read(const Parcel& input) {
    return state.read(input);
}

DisplayState::DisplayState()
      : what(0),
        layerStack(0),
        flags(0),
        layerStackSpaceRect(Rect::EMPTY_RECT),
        orientedDisplaySpaceRect(Rect::EMPTY_RECT),
        width(0),
        height(0) {}

status_t DisplayState::write(Parcel& output) const {
    SAFE_PARCEL(output.writeStrongBinder, token);
    SAFE_PARCEL(output.writeStrongBinder, IInterface::asBinder(surface));
    SAFE_PARCEL(output.writeUint32, what);
    SAFE_PARCEL(output.writeUint32, layerStack);
    SAFE_PARCEL(output.writeUint32, flags);
    SAFE_PARCEL(output.writeUint32, toRotationInt(orientation));
    SAFE_PARCEL(output.write, layerStackSpaceRect);
    SAFE_PARCEL(output.write, orientedDisplaySpaceRect);
    SAFE_PARCEL(output.writeUint32, width);
    SAFE_PARCEL(output.writeUint32, height);
    return NO_ERROR;
}

status_t DisplayState::read(const Parcel& input) {
    SAFE_PARCEL(input.readStrongBinder, &token);
    sp<IBinder> tmpBinder;
    SAFE_PARCEL(input.readNullableStrongBinder, &tmpBinder);
    surface = interface_cast<IGraphicBufferProducer>(tmpBinder);

    SAFE_PARCEL(input.readUint32, &what);
    SAFE_PARCEL(input.readUint32, &layerStack);
    SAFE_PARCEL(input.readUint32, &flags);
    uint32_t tmpUint = 0;
    SAFE_PARCEL(input.readUint32, &tmpUint);
    orientation = ui::toRotation(tmpUint);

    SAFE_PARCEL(input.read, layerStackSpaceRect);
    SAFE_PARCEL(input.read, orientedDisplaySpaceRect);
    SAFE_PARCEL(input.readUint32, &width);
    SAFE_PARCEL(input.readUint32, &height);
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
    if (other.what & eFlagsChanged) {
        what |= eFlagsChanged;
        flags = other.flags;
    }
    if (other.what & eDisplayProjectionChanged) {
        what |= eDisplayProjectionChanged;
        orientation = other.orientation;
        layerStackSpaceRect = other.layerStackSpaceRect;
        orientedDisplaySpaceRect = other.orientedDisplaySpaceRect;
    }
    if (other.what & eDisplaySizeChanged) {
        what |= eDisplaySizeChanged;
        width = other.width;
        height = other.height;
    }
}

void layer_state_t::sanitize(int32_t permissions) {
    // TODO: b/109894387
    //
    // SurfaceFlinger's renderer is not prepared to handle cropping in the face of arbitrary
    // rotation. To see the problem observe that if we have a square parent, and a child
    // of the same size, then we rotate the child 45 degrees around its center, the child
    // must now be cropped to a non rectangular 8 sided region.
    //
    // Of course we can fix this in the future. For now, we are lucky, SurfaceControl is
    // private API, and arbitrary rotation is used in limited use cases, for instance:
    // - WindowManager only uses rotation in one case, which is on a top level layer in which
    //   cropping is not an issue.
    // - Launcher, as a privileged app, uses this to transition an application to PiP
    //   (picture-in-picture) mode.
    //
    // However given that abuse of rotation matrices could lead to surfaces extending outside
    // of cropped areas, we need to prevent non-root clients without permission
    // ACCESS_SURFACE_FLINGER nor ROTATE_SURFACE_FLINGER
    // (a.k.a. everyone except WindowManager / tests / Launcher) from setting non rectangle
    // preserving transformations.
    if (what & eMatrixChanged) {
        if (!(permissions & Permission::ROTATE_SURFACE_FLINGER)) {
            ui::Transform t;
            t.set(matrix.dsdx, matrix.dtdy, matrix.dtdx, matrix.dsdy);
            if (!t.preserveRects()) {
                what &= ~eMatrixChanged;
                ALOGE("Stripped non rect preserving matrix in sanitize");
            }
        }
    }

    if (what & layer_state_t::eInputInfoChanged) {
        if (!(permissions & Permission::ACCESS_SURFACE_FLINGER)) {
            what &= ~eInputInfoChanged;
            ALOGE("Stripped attempt to set eInputInfoChanged in sanitize");
        }
    }
    if (what & layer_state_t::eTrustedOverlayChanged) {
        if (!(permissions & Permission::ACCESS_SURFACE_FLINGER)) {
            what &= ~eTrustedOverlayChanged;
            ALOGE("Stripped attempt to set eTrustedOverlay in sanitize");
        }
    }
    if (what & layer_state_t::eDropInputModeChanged) {
        if (!(permissions & Permission::ACCESS_SURFACE_FLINGER)) {
            what &= ~eDropInputModeChanged;
            ALOGE("Stripped attempt to set eDropInputModeChanged in sanitize");
        }
    }
    if (what & layer_state_t::eFrameRateSelectionPriority) {
        if (!(permissions & Permission::ACCESS_SURFACE_FLINGER)) {
            what &= ~eFrameRateSelectionPriority;
            ALOGE("Stripped attempt to set eFrameRateSelectionPriority in sanitize");
        }
    }
    if (what & layer_state_t::eFrameRateChanged) {
        if (!ValidateFrameRate(frameRate, frameRateCompatibility,
                               changeFrameRateStrategy,
                               "layer_state_t::sanitize",
                               permissions & Permission::ACCESS_SURFACE_FLINGER)) {
            what &= ~eFrameRateChanged; // logged in ValidateFrameRate
        }
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
    if (other.what & eCornerRadiusChanged) {
        what |= eCornerRadiusChanged;
        cornerRadius = other.cornerRadius;
    }
    if (other.what & eBackgroundBlurRadiusChanged) {
        what |= eBackgroundBlurRadiusChanged;
        backgroundBlurRadius = other.backgroundBlurRadius;
    }
    if (other.what & eBlurRegionsChanged) {
        what |= eBlurRegionsChanged;
        blurRegions = other.blurRegions;
    }
    if (other.what & eRelativeLayerChanged) {
        what |= eRelativeLayerChanged;
        what &= ~eLayerChanged;
        z = other.z;
        relativeLayerSurfaceControl = other.relativeLayerSurfaceControl;
    }
    if (other.what & eReparent) {
        what |= eReparent;
        parentSurfaceControlForChild = other.parentSurfaceControlForChild;
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
    if (other.what & eBufferChanged) {
        what |= eBufferChanged;
        buffer = other.buffer;
        releaseBufferEndpoint = other.releaseBufferEndpoint;
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
    if (other.what & eInputInfoChanged) {
        what |= eInputInfoChanged;
        windowInfoHandle = new WindowInfoHandle(*other.windowInfoHandle);
    }
    if (other.what & eCachedBufferChanged) {
        what |= eCachedBufferChanged;
        cachedBuffer = other.cachedBuffer;
        releaseBufferEndpoint = other.releaseBufferEndpoint;
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
        changeFrameRateStrategy = other.changeFrameRateStrategy;
    }
    if (other.what & eFixedTransformHintChanged) {
        what |= eFixedTransformHintChanged;
        fixedTransformHint = other.fixedTransformHint;
    }
    if (other.what & eFrameNumberChanged) {
        what |= eFrameNumberChanged;
        frameNumber = other.frameNumber;
    }
    if (other.what & eAutoRefreshChanged) {
        what |= eAutoRefreshChanged;
        autoRefresh = other.autoRefresh;
    }
    if (other.what & eTrustedOverlayChanged) {
        what |= eTrustedOverlayChanged;
        isTrustedOverlay = other.isTrustedOverlay;
    }
    if (other.what & eReleaseBufferListenerChanged) {
        if (releaseBufferListener) {
            ALOGW("Overriding releaseBufferListener");
        }
        what |= eReleaseBufferListenerChanged;
        releaseBufferListener = other.releaseBufferListener;
    }
    if (other.what & eStretchChanged) {
        what |= eStretchChanged;
        stretchEffect = other.stretchEffect;
    }
    if (other.what & eBufferCropChanged) {
        what |= eBufferCropChanged;
        bufferCrop = other.bufferCrop;
    }
    if (other.what & eDestinationFrameChanged) {
        what |= eDestinationFrameChanged;
        destinationFrame = other.destinationFrame;
    }
    if (other.what & eDropInputModeChanged) {
        what |= eDropInputModeChanged;
        dropInputMode = other.dropInputMode;
    }
    if (other.what & eColorChanged) {
        what |= eColorChanged;
        color = other.color;
    }
    if ((other.what & what) != other.what) {
        ALOGE("Unmerged SurfaceComposer Transaction properties. LayerState::merge needs updating? "
              "other.what=0x%" PRIu64 " what=0x%" PRIu64,
              other.what, what);
    }
}

bool layer_state_t::hasBufferChanges() const {
    return (what & layer_state_t::eBufferChanged) || (what & layer_state_t::eCachedBufferChanged);
}

bool layer_state_t::hasValidBuffer() const {
    return buffer || cachedBuffer.isValid();
}

status_t layer_state_t::matrix22_t::write(Parcel& output) const {
    SAFE_PARCEL(output.writeFloat, dsdx);
    SAFE_PARCEL(output.writeFloat, dtdx);
    SAFE_PARCEL(output.writeFloat, dtdy);
    SAFE_PARCEL(output.writeFloat, dsdy);
    return NO_ERROR;
}

status_t layer_state_t::matrix22_t::read(const Parcel& input) {
    SAFE_PARCEL(input.readFloat, &dsdx);
    SAFE_PARCEL(input.readFloat, &dtdx);
    SAFE_PARCEL(input.readFloat, &dtdy);
    SAFE_PARCEL(input.readFloat, &dsdy);
    return NO_ERROR;
}

// ------------------------------- InputWindowCommands ----------------------------------------

bool InputWindowCommands::merge(const InputWindowCommands& other) {
    bool changes = false;
    changes |= !other.focusRequests.empty();
    focusRequests.insert(focusRequests.end(), std::make_move_iterator(other.focusRequests.begin()),
                         std::make_move_iterator(other.focusRequests.end()));
    changes |= other.syncInputWindows && !syncInputWindows;
    syncInputWindows |= other.syncInputWindows;
    return changes;
}

bool InputWindowCommands::empty() const {
    bool empty = true;
    empty = focusRequests.empty() && !syncInputWindows;
    return empty;
}

void InputWindowCommands::clear() {
    focusRequests.clear();
    syncInputWindows = false;
}

status_t InputWindowCommands::write(Parcel& output) const {
    SAFE_PARCEL(output.writeParcelableVector, focusRequests);
    SAFE_PARCEL(output.writeBool, syncInputWindows);
    return NO_ERROR;
}

status_t InputWindowCommands::read(const Parcel& input) {
    SAFE_PARCEL(input.readParcelableVector, &focusRequests);
    SAFE_PARCEL(input.readBool, &syncInputWindows);
    return NO_ERROR;
}

bool ValidateFrameRate(float frameRate, int8_t compatibility, int8_t changeFrameRateStrategy,
                       const char* inFunctionName, bool privileged) {
    const char* functionName = inFunctionName != nullptr ? inFunctionName : "call";
    int floatClassification = std::fpclassify(frameRate);
    if (frameRate < 0 || floatClassification == FP_INFINITE || floatClassification == FP_NAN) {
        ALOGE("%s failed - invalid frame rate %f", functionName, frameRate);
        return false;
    }

    if (compatibility != ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT &&
        compatibility != ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE &&
        (!privileged || compatibility != ANATIVEWINDOW_FRAME_RATE_EXACT)) {
        ALOGE("%s failed - invalid compatibility value %d privileged: %s", functionName,
              compatibility, privileged ? "yes" : "no");
        return false;
    }

    if (changeFrameRateStrategy != ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS &&
        changeFrameRateStrategy != ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS) {
        ALOGE("%s failed - invalid change frame rate strategy value %d", functionName,
              changeFrameRateStrategy);
    }

    return true;
}

// ----------------------------------------------------------------------------

status_t CaptureArgs::write(Parcel& output) const {
    SAFE_PARCEL(output.writeInt32, static_cast<int32_t>(pixelFormat));
    SAFE_PARCEL(output.write, sourceCrop);
    SAFE_PARCEL(output.writeFloat, frameScaleX);
    SAFE_PARCEL(output.writeFloat, frameScaleY);
    SAFE_PARCEL(output.writeBool, captureSecureLayers);
    SAFE_PARCEL(output.writeInt32, uid);
    SAFE_PARCEL(output.writeInt32, static_cast<int32_t>(dataspace));
    SAFE_PARCEL(output.writeBool, allowProtected);
    SAFE_PARCEL(output.writeBool, grayscale);
    return NO_ERROR;
}

status_t CaptureArgs::read(const Parcel& input) {
    int32_t value = 0;
    SAFE_PARCEL(input.readInt32, &value);
    pixelFormat = static_cast<ui::PixelFormat>(value);
    SAFE_PARCEL(input.read, sourceCrop);
    SAFE_PARCEL(input.readFloat, &frameScaleX);
    SAFE_PARCEL(input.readFloat, &frameScaleY);
    SAFE_PARCEL(input.readBool, &captureSecureLayers);
    SAFE_PARCEL(input.readInt32, &uid);
    SAFE_PARCEL(input.readInt32, &value);
    dataspace = static_cast<ui::Dataspace>(value);
    SAFE_PARCEL(input.readBool, &allowProtected);
    SAFE_PARCEL(input.readBool, &grayscale);
    return NO_ERROR;
}

status_t DisplayCaptureArgs::write(Parcel& output) const {
    SAFE_PARCEL(CaptureArgs::write, output);

    SAFE_PARCEL(output.writeStrongBinder, displayToken);
    SAFE_PARCEL(output.writeUint32, width);
    SAFE_PARCEL(output.writeUint32, height);
    SAFE_PARCEL(output.writeBool, useIdentityTransform);
    return NO_ERROR;
}

status_t DisplayCaptureArgs::read(const Parcel& input) {
    SAFE_PARCEL(CaptureArgs::read, input);

    SAFE_PARCEL(input.readStrongBinder, &displayToken);
    SAFE_PARCEL(input.readUint32, &width);
    SAFE_PARCEL(input.readUint32, &height);
    SAFE_PARCEL(input.readBool, &useIdentityTransform);
    return NO_ERROR;
}

status_t LayerCaptureArgs::write(Parcel& output) const {
    SAFE_PARCEL(CaptureArgs::write, output);

    SAFE_PARCEL(output.writeStrongBinder, layerHandle);
    SAFE_PARCEL(output.writeInt32, excludeHandles.size());
    for (auto el : excludeHandles) {
        SAFE_PARCEL(output.writeStrongBinder, el);
    }
    SAFE_PARCEL(output.writeBool, childrenOnly);
    return NO_ERROR;
}

status_t LayerCaptureArgs::read(const Parcel& input) {
    SAFE_PARCEL(CaptureArgs::read, input);

    SAFE_PARCEL(input.readStrongBinder, &layerHandle);

    int32_t numExcludeHandles = 0;
    SAFE_PARCEL_READ_SIZE(input.readInt32, &numExcludeHandles, input.dataSize());
    excludeHandles.reserve(numExcludeHandles);
    for (int i = 0; i < numExcludeHandles; i++) {
        sp<IBinder> binder;
        SAFE_PARCEL(input.readStrongBinder, &binder);
        excludeHandles.emplace(binder);
    }

    SAFE_PARCEL(input.readBool, &childrenOnly);
    return NO_ERROR;
}

}; // namespace android
