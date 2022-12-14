/*
 * Copyright (C) 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "BufferLayer"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "BufferLayer.h"

#include <compositionengine/CompositionEngine.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <cutils/compiler.h>
#include <cutils/native_handle.h>
#include <cutils/properties.h>
#include <gui/BufferItem.h>
#include <gui/BufferQueue.h>
#include <gui/GLConsumer.h>
#include <gui/LayerDebugInfo.h>
#include <gui/Surface.h>
#include <renderengine/RenderEngine.h>
#include <ui/DebugUtils.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/NativeHandle.h>
#include <utils/StopWatch.h>
#include <utils/Trace.h>

#include <cmath>
#include <cstdlib>
#include <mutex>
#include <sstream>

#include "Colorizer.h"
#include "DisplayDevice.h"
#include "FrameTracer/FrameTracer.h"
#include "LayerRejecter.h"
#include "TimeStats/TimeStats.h"

namespace android {

using gui::WindowInfo;

static constexpr float defaultMaxLuminance = 1000.0;

BufferLayer::BufferLayer(const LayerCreationArgs& args)
      : Layer(args),
        mTextureName(args.textureName),
        mCompositionState{mFlinger->getCompositionEngine().createLayerFECompositionState()} {
    ALOGV("Creating Layer %s", getDebugName());

    mPremultipliedAlpha = !(args.flags & ISurfaceComposerClient::eNonPremultiplied);

    mPotentialCursor = args.flags & ISurfaceComposerClient::eCursorWindow;
    mProtectedByApp = args.flags & ISurfaceComposerClient::eProtectedByApp;
}

BufferLayer::~BufferLayer() {
    if (!isClone()) {
        // The original layer and the clone layer share the same texture. Therefore, only one of
        // the layers, in this case the original layer, needs to handle the deletion. The original
        // layer and the clone should be removed at the same time so there shouldn't be any issue
        // with the clone layer trying to use the deleted texture.
        mFlinger->deleteTextureAsync(mTextureName);
    }
    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->onDestroy(layerId);
    mFlinger->mFrameTracer->onDestroy(layerId);
}

void BufferLayer::useSurfaceDamage() {
    if (mFlinger->mForceFullDamage) {
        surfaceDamageRegion = Region::INVALID_REGION;
    } else {
        surfaceDamageRegion = mBufferInfo.mSurfaceDamage;
    }
}

void BufferLayer::useEmptyDamage() {
    surfaceDamageRegion.clear();
}

bool BufferLayer::isOpaque(const Layer::State& s) const {
    // if we don't have a buffer or sidebandStream yet, we're translucent regardless of the
    // layer's opaque flag.
    if ((mSidebandStream == nullptr) && (mBufferInfo.mBuffer == nullptr)) {
        return false;
    }

    // if the layer has the opaque flag, then we're always opaque,
    // otherwise we use the current buffer's format.
    return ((s.flags & layer_state_t::eLayerOpaque) != 0) || getOpacityForFormat(getPixelFormat());
}

bool BufferLayer::isVisible() const {
    return !isHiddenByPolicy() && getAlpha() > 0.0f &&
            (mBufferInfo.mBuffer != nullptr || mSidebandStream != nullptr);
}

bool BufferLayer::isFixedSize() const {
    return getEffectiveScalingMode() != NATIVE_WINDOW_SCALING_MODE_FREEZE;
}

bool BufferLayer::usesSourceCrop() const {
    return true;
}

static constexpr mat4 inverseOrientation(uint32_t transform) {
    const mat4 flipH(-1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1);
    const mat4 flipV(1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1);
    const mat4 rot90(0, 1, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1);
    mat4 tr;

    if (transform & NATIVE_WINDOW_TRANSFORM_ROT_90) {
        tr = tr * rot90;
    }
    if (transform & NATIVE_WINDOW_TRANSFORM_FLIP_H) {
        tr = tr * flipH;
    }
    if (transform & NATIVE_WINDOW_TRANSFORM_FLIP_V) {
        tr = tr * flipV;
    }
    return inverse(tr);
}

std::optional<compositionengine::LayerFE::LayerSettings> BufferLayer::prepareClientComposition(
        compositionengine::LayerFE::ClientCompositionTargetSettings& targetSettings) {
    ATRACE_CALL();

    std::optional<compositionengine::LayerFE::LayerSettings> result =
            Layer::prepareClientComposition(targetSettings);
    if (!result) {
        return result;
    }

    if (CC_UNLIKELY(mBufferInfo.mBuffer == 0)) {
        // the texture has not been created yet, this Layer has
        // in fact never been drawn into. This happens frequently with
        // SurfaceView because the WindowManager can't know when the client
        // has drawn the first time.

        // If there is nothing under us, we paint the screen in black, otherwise
        // we just skip this update.

        // figure out if there is something below us
        Region under;
        bool finished = false;
        mFlinger->mDrawingState.traverseInZOrder([&](Layer* layer) {
            if (finished || layer == static_cast<BufferLayer const*>(this)) {
                finished = true;
                return;
            }

            under.orSelf(layer->getScreenBounds());
        });
        // if not everything below us is covered, we plug the holes!
        Region holes(targetSettings.clip.subtract(under));
        if (!holes.isEmpty()) {
            targetSettings.clearRegion.orSelf(holes);
        }

        if (mSidebandStream != nullptr) {
            // For surfaceview of tv sideband, there is no activeBuffer
            // in bufferqueue, we need return LayerSettings.
            return result;
        } else {
            return std::nullopt;
        }
    }
    const bool blackOutLayer = (isProtected() && !targetSettings.supportsProtectedContent) ||
            ((isSecure() || isProtected()) && !targetSettings.isSecure);
    const bool bufferCanBeUsedAsHwTexture =
            mBufferInfo.mBuffer->getBuffer()->getUsage() & GraphicBuffer::USAGE_HW_TEXTURE;
    compositionengine::LayerFE::LayerSettings& layer = *result;
    if (blackOutLayer || !bufferCanBeUsedAsHwTexture) {
        ALOGE_IF(!bufferCanBeUsedAsHwTexture, "%s is blacked out as buffer is not gpu readable",
                 mName.c_str());
        prepareClearClientComposition(layer, true /* blackout */);
        return layer;
    }

    const State& s(getDrawingState());
    layer.source.buffer.buffer = mBufferInfo.mBuffer;
    layer.source.buffer.isOpaque = isOpaque(s);
    layer.source.buffer.fence = mBufferInfo.mFence;
    layer.source.buffer.textureName = mTextureName;
    layer.source.buffer.usePremultipliedAlpha = getPremultipledAlpha();
    layer.source.buffer.isY410BT2020 = isHdrY410();
    bool hasSmpte2086 = mBufferInfo.mHdrMetadata.validTypes & HdrMetadata::SMPTE2086;
    bool hasCta861_3 = mBufferInfo.mHdrMetadata.validTypes & HdrMetadata::CTA861_3;
    float maxLuminance = 0.f;
    if (hasSmpte2086 && hasCta861_3) {
        maxLuminance = std::min(mBufferInfo.mHdrMetadata.smpte2086.maxLuminance,
                                mBufferInfo.mHdrMetadata.cta8613.maxContentLightLevel);
    } else if (hasSmpte2086) {
        maxLuminance = mBufferInfo.mHdrMetadata.smpte2086.maxLuminance;
    } else if (hasCta861_3) {
        maxLuminance = mBufferInfo.mHdrMetadata.cta8613.maxContentLightLevel;
    } else {
        switch (layer.sourceDataspace & HAL_DATASPACE_TRANSFER_MASK) {
            case HAL_DATASPACE_TRANSFER_ST2084:
            case HAL_DATASPACE_TRANSFER_HLG:
                // Behavior-match previous releases for HDR content
                maxLuminance = defaultMaxLuminance;
                break;
        }
    }
    layer.source.buffer.maxLuminanceNits = maxLuminance;
    layer.frameNumber = mCurrentFrameNumber;
    layer.bufferId = mBufferInfo.mBuffer ? mBufferInfo.mBuffer->getBuffer()->getId() : 0;

    const bool useFiltering =
            targetSettings.needsFiltering || mNeedsFiltering || bufferNeedsFiltering();

    // Query the texture matrix given our current filtering mode.
    float textureMatrix[16];
    getDrawingTransformMatrix(useFiltering, textureMatrix);

    if (getTransformToDisplayInverse()) {
        /*
         * the code below applies the primary display's inverse transform to
         * the texture transform
         */
        uint32_t transform = DisplayDevice::getPrimaryDisplayRotationFlags();
        mat4 tr = inverseOrientation(transform);

        /**
         * TODO(b/36727915): This is basically a hack.
         *
         * Ensure that regardless of the parent transformation,
         * this buffer is always transformed from native display
         * orientation to display orientation. For example, in the case
         * of a camera where the buffer remains in native orientation,
         * we want the pixels to always be upright.
         */
        sp<Layer> p = mDrawingParent.promote();
        if (p != nullptr) {
            const auto parentTransform = p->getTransform();
            tr = tr * inverseOrientation(parentTransform.getOrientation());
        }

        // and finally apply it to the original texture matrix
        const mat4 texTransform(mat4(static_cast<const float*>(textureMatrix)) * tr);
        memcpy(textureMatrix, texTransform.asArray(), sizeof(textureMatrix));
    }

    const Rect win{getBounds()};
    float bufferWidth = getBufferSize(s).getWidth();
    float bufferHeight = getBufferSize(s).getHeight();

    // BufferStateLayers can have a "buffer size" of [0, 0, -1, -1] when no display frame has
    // been set and there is no parent layer bounds. In that case, the scale is meaningless so
    // ignore them.
    if (!getBufferSize(s).isValid()) {
        bufferWidth = float(win.right) - float(win.left);
        bufferHeight = float(win.bottom) - float(win.top);
    }

    const float scaleHeight = (float(win.bottom) - float(win.top)) / bufferHeight;
    const float scaleWidth = (float(win.right) - float(win.left)) / bufferWidth;
    const float translateY = float(win.top) / bufferHeight;
    const float translateX = float(win.left) / bufferWidth;

    // Flip y-coordinates because GLConsumer expects OpenGL convention.
    mat4 tr = mat4::translate(vec4(.5, .5, 0, 1)) * mat4::scale(vec4(1, -1, 1, 1)) *
            mat4::translate(vec4(-.5, -.5, 0, 1)) *
            mat4::translate(vec4(translateX, translateY, 0, 1)) *
            mat4::scale(vec4(scaleWidth, scaleHeight, 1.0, 1.0));

    layer.source.buffer.useTextureFiltering = useFiltering;
    layer.source.buffer.textureTransform = mat4(static_cast<const float*>(textureMatrix)) * tr;

    return layer;
}

bool BufferLayer::isHdrY410() const {
    // pixel format is HDR Y410 masquerading as RGBA_1010102
    return (mBufferInfo.mDataspace == ui::Dataspace::BT2020_ITU_PQ &&
            mBufferInfo.mApi == NATIVE_WINDOW_API_MEDIA &&
            mBufferInfo.mPixelFormat == HAL_PIXEL_FORMAT_RGBA_1010102);
}

sp<compositionengine::LayerFE> BufferLayer::getCompositionEngineLayerFE() const {
    return asLayerFE();
}

compositionengine::LayerFECompositionState* BufferLayer::editCompositionState() {
    return mCompositionState.get();
}

const compositionengine::LayerFECompositionState* BufferLayer::getCompositionState() const {
    return mCompositionState.get();
}

void BufferLayer::preparePerFrameCompositionState() {
    Layer::preparePerFrameCompositionState();

    // Sideband layers
    auto* compositionState = editCompositionState();
    if (compositionState->sidebandStream.get()) {
        compositionState->compositionType = Hwc2::IComposerClient::Composition::SIDEBAND;
        return;
    } else {
        // Normal buffer layers
        compositionState->hdrMetadata = mBufferInfo.mHdrMetadata;
        compositionState->compositionType = mPotentialCursor
                ? Hwc2::IComposerClient::Composition::CURSOR
                : Hwc2::IComposerClient::Composition::DEVICE;
    }

    compositionState->buffer = getBuffer();
    compositionState->bufferSlot = (mBufferInfo.mBufferSlot == BufferQueue::INVALID_BUFFER_SLOT)
            ? 0
            : mBufferInfo.mBufferSlot;
    compositionState->acquireFence = mBufferInfo.mFence;
}

bool BufferLayer::onPreComposition(nsecs_t refreshStartTime) {
    if (mBufferInfo.mBuffer != nullptr) {
        Mutex::Autolock lock(mFrameEventHistoryMutex);
        mFrameEventHistory.addPreComposition(mCurrentFrameNumber, refreshStartTime);
    }
    mRefreshPending = false;
    return hasReadyFrame();
}
namespace {
TimeStats::SetFrameRateVote frameRateToSetFrameRateVotePayload(Layer::FrameRate frameRate) {
    using FrameRateCompatibility = TimeStats::SetFrameRateVote::FrameRateCompatibility;
    using Seamlessness = TimeStats::SetFrameRateVote::Seamlessness;
    const auto frameRateCompatibility = [frameRate] {
        switch (frameRate.type) {
            case Layer::FrameRateCompatibility::Default:
                return FrameRateCompatibility::Default;
            case Layer::FrameRateCompatibility::ExactOrMultiple:
                return FrameRateCompatibility::ExactOrMultiple;
            default:
                return FrameRateCompatibility::Undefined;
        }
    }();

    const auto seamlessness = [frameRate] {
        switch (frameRate.seamlessness) {
            case scheduler::Seamlessness::OnlySeamless:
                return Seamlessness::ShouldBeSeamless;
            case scheduler::Seamlessness::SeamedAndSeamless:
                return Seamlessness::NotRequired;
            default:
                return Seamlessness::Undefined;
        }
    }();

    return TimeStats::SetFrameRateVote{.frameRate = frameRate.rate.getValue(),
                                       .frameRateCompatibility = frameRateCompatibility,
                                       .seamlessness = seamlessness};
}
} // namespace

bool BufferLayer::onPostComposition(const DisplayDevice* display,
                                    const std::shared_ptr<FenceTime>& glDoneFence,
                                    const std::shared_ptr<FenceTime>& presentFence,
                                    const CompositorTiming& compositorTiming) {
    // mFrameLatencyNeeded is true when a new frame was latched for the
    // composition.
    if (!mBufferInfo.mFrameLatencyNeeded) return false;

    // Update mFrameEventHistory.
    {
        Mutex::Autolock lock(mFrameEventHistoryMutex);
        mFrameEventHistory.addPostComposition(mCurrentFrameNumber, glDoneFence, presentFence,
                                              compositorTiming);
        finalizeFrameEventHistory(glDoneFence, compositorTiming);
    }

    // Update mFrameTracker.
    nsecs_t desiredPresentTime = mBufferInfo.mDesiredPresentTime;
    mFrameTracker.setDesiredPresentTime(desiredPresentTime);

    const int32_t layerId = getSequence();
    mFlinger->mTimeStats->setDesiredTime(layerId, mCurrentFrameNumber, desiredPresentTime);

    const auto outputLayer = findOutputLayerForDisplay(display);
    if (outputLayer && outputLayer->requiresClientComposition()) {
        nsecs_t clientCompositionTimestamp = outputLayer->getState().clientCompositionTimestamp;
        mFlinger->mFrameTracer->traceTimestamp(layerId, getCurrentBufferId(), mCurrentFrameNumber,
                                               clientCompositionTimestamp,
                                               FrameTracer::FrameEvent::FALLBACK_COMPOSITION);
        // Update the SurfaceFrames in the drawing state
        if (mDrawingState.bufferSurfaceFrameTX) {
            mDrawingState.bufferSurfaceFrameTX->setGpuComposition();
        }
        for (auto& [token, surfaceFrame] : mDrawingState.bufferlessSurfaceFramesTX) {
            surfaceFrame->setGpuComposition();
        }
    }

    std::shared_ptr<FenceTime> frameReadyFence = mBufferInfo.mFenceTime;
    if (frameReadyFence->isValid()) {
        mFrameTracker.setFrameReadyFence(std::move(frameReadyFence));
    } else {
        // There was no fence for this frame, so assume that it was ready
        // to be presented at the desired present time.
        mFrameTracker.setFrameReadyTime(desiredPresentTime);
    }

    if (display) {
        const Fps refreshRate = display->refreshRateConfigs().getCurrentRefreshRate().getFps();
        const std::optional<Fps> renderRate =
                mFlinger->mScheduler->getFrameRateOverride(getOwnerUid());
        if (presentFence->isValid()) {
            mFlinger->mTimeStats->setPresentFence(layerId, mCurrentFrameNumber, presentFence,
                                                  refreshRate, renderRate,
                                                  frameRateToSetFrameRateVotePayload(
                                                          mDrawingState.frameRate),
                                                  getGameMode());
            mFlinger->mFrameTracer->traceFence(layerId, getCurrentBufferId(), mCurrentFrameNumber,
                                               presentFence,
                                               FrameTracer::FrameEvent::PRESENT_FENCE);
            mFrameTracker.setActualPresentFence(std::shared_ptr<FenceTime>(presentFence));
        } else if (const auto displayId = PhysicalDisplayId::tryCast(display->getId());
                   displayId && mFlinger->getHwComposer().isConnected(*displayId)) {
            // The HWC doesn't support present fences, so use the refresh
            // timestamp instead.
            const nsecs_t actualPresentTime = display->getRefreshTimestamp();
            mFlinger->mTimeStats->setPresentTime(layerId, mCurrentFrameNumber, actualPresentTime,
                                                 refreshRate, renderRate,
                                                 frameRateToSetFrameRateVotePayload(
                                                         mDrawingState.frameRate),
                                                 getGameMode());
            mFlinger->mFrameTracer->traceTimestamp(layerId, getCurrentBufferId(),
                                                   mCurrentFrameNumber, actualPresentTime,
                                                   FrameTracer::FrameEvent::PRESENT_FENCE);
            mFrameTracker.setActualPresentTime(actualPresentTime);
        }
    }

    mFrameTracker.advanceFrame();
    mBufferInfo.mFrameLatencyNeeded = false;
    return true;
}

void BufferLayer::gatherBufferInfo() {
    mBufferInfo.mPixelFormat =
            !mBufferInfo.mBuffer ? PIXEL_FORMAT_NONE : mBufferInfo.mBuffer->getBuffer()->format;
    mBufferInfo.mFrameLatencyNeeded = true;
}

bool BufferLayer::shouldPresentNow(nsecs_t expectedPresentTime) const {
    // If this is not a valid vsync for the layer's uid, return and try again later
    const bool isVsyncValidForUid =
            mFlinger->mScheduler->isVsyncValid(expectedPresentTime, mOwnerUid);
    if (!isVsyncValidForUid) {
        ATRACE_NAME("!isVsyncValidForUid");
        return false;
    }

    // AutoRefresh layers and sideband streams should always be presented
    if (getSidebandStreamChanged() || getAutoRefresh()) {
        return true;
    }

    // If this layer doesn't have a frame is shouldn't be presented
    if (!hasFrameUpdate()) {
        return false;
    }

    // Defer to the derived class to decide whether the next buffer is due for
    // presentation.
    return isBufferDue(expectedPresentTime);
}

bool BufferLayer::latchBuffer(bool& recomputeVisibleRegions, nsecs_t latchTime,
                              nsecs_t expectedPresentTime) {
    ATRACE_CALL();

    bool refreshRequired = latchSidebandStream(recomputeVisibleRegions);

    if (refreshRequired) {
        return refreshRequired;
    }

    if (!hasReadyFrame()) {
        return false;
    }

    // if we've already called updateTexImage() without going through
    // a composition step, we have to skip this layer at this point
    // because we cannot call updateTeximage() without a corresponding
    // compositionComplete() call.
    // we'll trigger an update in onPreComposition().
    if (mRefreshPending) {
        return false;
    }

    // If the head buffer's acquire fence hasn't signaled yet, return and
    // try again later
    if (!fenceHasSignaled()) {
        ATRACE_NAME("!fenceHasSignaled()");
        mFlinger->signalLayerUpdate();
        return false;
    }

    // Capture the old state of the layer for comparisons later
    const State& s(getDrawingState());
    const bool oldOpacity = isOpaque(s);

    BufferInfo oldBufferInfo = mBufferInfo;

    status_t err = updateTexImage(recomputeVisibleRegions, latchTime, expectedPresentTime);
    if (err != NO_ERROR) {
        return false;
    }

    err = updateActiveBuffer();
    if (err != NO_ERROR) {
        return false;
    }

    err = updateFrameNumber(latchTime);
    if (err != NO_ERROR) {
        return false;
    }

    gatherBufferInfo();

    mRefreshPending = true;
    if (oldBufferInfo.mBuffer == nullptr) {
        // the first time we receive a buffer, we need to trigger a
        // geometry invalidation.
        recomputeVisibleRegions = true;
    }

    if ((mBufferInfo.mCrop != oldBufferInfo.mCrop) ||
        (mBufferInfo.mTransform != oldBufferInfo.mTransform) ||
        (mBufferInfo.mScaleMode != oldBufferInfo.mScaleMode) ||
        (mBufferInfo.mTransformToDisplayInverse != oldBufferInfo.mTransformToDisplayInverse)) {
        recomputeVisibleRegions = true;
    }

    if (oldBufferInfo.mBuffer != nullptr) {
        uint32_t bufWidth = mBufferInfo.mBuffer->getBuffer()->getWidth();
        uint32_t bufHeight = mBufferInfo.mBuffer->getBuffer()->getHeight();
        if (bufWidth != uint32_t(oldBufferInfo.mBuffer->getBuffer()->width) ||
            bufHeight != uint32_t(oldBufferInfo.mBuffer->getBuffer()->height)) {
            recomputeVisibleRegions = true;
        }
    }

    if (oldOpacity != isOpaque(s)) {
        recomputeVisibleRegions = true;
    }

    return true;
}

bool BufferLayer::hasReadyFrame() const {
    return hasFrameUpdate() || getSidebandStreamChanged() || getAutoRefresh();
}

uint32_t BufferLayer::getEffectiveScalingMode() const {
    return mBufferInfo.mScaleMode;
}

bool BufferLayer::isProtected() const {
    return (mBufferInfo.mBuffer != nullptr) &&
            (mBufferInfo.mBuffer->getBuffer()->getUsage() & GRALLOC_USAGE_PROTECTED);
}

// As documented in libhardware header, formats in the range
// 0x100 - 0x1FF are specific to the HAL implementation, and
// are known to have no alpha channel
// TODO: move definition for device-specific range into
// hardware.h, instead of using hard-coded values here.
#define HARDWARE_IS_DEVICE_FORMAT(f) ((f) >= 0x100 && (f) <= 0x1FF)

bool BufferLayer::getOpacityForFormat(uint32_t format) {
    if (HARDWARE_IS_DEVICE_FORMAT(format)) {
        return true;
    }
    switch (format) {
        case HAL_PIXEL_FORMAT_RGBA_8888:
        case HAL_PIXEL_FORMAT_BGRA_8888:
        case HAL_PIXEL_FORMAT_RGBA_FP16:
        case HAL_PIXEL_FORMAT_RGBA_1010102:
            return false;
    }
    // in all other case, we have no blending (also for unknown formats)
    return true;
}

bool BufferLayer::needsFiltering(const DisplayDevice* display) const {
    const auto outputLayer = findOutputLayerForDisplay(display);
    if (outputLayer == nullptr) {
        return false;
    }

    // We need filtering if the sourceCrop rectangle size does not match the
    // displayframe rectangle size (not a 1:1 render)
    const auto& compositionState = outputLayer->getState();
    const auto displayFrame = compositionState.displayFrame;
    const auto sourceCrop = compositionState.sourceCrop;
    return sourceCrop.getHeight() != displayFrame.getHeight() ||
            sourceCrop.getWidth() != displayFrame.getWidth();
}

bool BufferLayer::needsFilteringForScreenshots(const DisplayDevice* display,
                                               const ui::Transform& inverseParentTransform) const {
    const auto outputLayer = findOutputLayerForDisplay(display);
    if (outputLayer == nullptr) {
        return false;
    }

    // We need filtering if the sourceCrop rectangle size does not match the
    // viewport rectangle size (not a 1:1 render)
    const auto& compositionState = outputLayer->getState();
    const ui::Transform& displayTransform = display->getTransform();
    const ui::Transform inverseTransform = inverseParentTransform * displayTransform.inverse();
    // Undo the transformation of the displayFrame so that we're back into
    // layer-stack space.
    const Rect frame = inverseTransform.transform(compositionState.displayFrame);
    const FloatRect sourceCrop = compositionState.sourceCrop;

    int32_t frameHeight = frame.getHeight();
    int32_t frameWidth = frame.getWidth();
    // If the display transform had a rotational component then undo the
    // rotation so that the orientation matches the source crop.
    if (displayTransform.getOrientation() & ui::Transform::ROT_90) {
        std::swap(frameHeight, frameWidth);
    }
    return sourceCrop.getHeight() != frameHeight || sourceCrop.getWidth() != frameWidth;
}

uint64_t BufferLayer::getHeadFrameNumber(nsecs_t expectedPresentTime) const {
    if (hasFrameUpdate()) {
        return getFrameNumber(expectedPresentTime);
    } else {
        return mCurrentFrameNumber;
    }
}

Rect BufferLayer::getBufferSize(const State& s) const {
    // If we have a sideband stream, or we are scaling the buffer then return the layer size since
    // we cannot determine the buffer size.
    if ((s.sidebandStream != nullptr) ||
        (getEffectiveScalingMode() != NATIVE_WINDOW_SCALING_MODE_FREEZE)) {
        return Rect(getActiveWidth(s), getActiveHeight(s));
    }

    if (mBufferInfo.mBuffer == nullptr) {
        return Rect::INVALID_RECT;
    }

    uint32_t bufWidth = mBufferInfo.mBuffer->getBuffer()->getWidth();
    uint32_t bufHeight = mBufferInfo.mBuffer->getBuffer()->getHeight();

    // Undo any transformations on the buffer and return the result.
    if (mBufferInfo.mTransform & ui::Transform::ROT_90) {
        std::swap(bufWidth, bufHeight);
    }

    if (getTransformToDisplayInverse()) {
        uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufWidth, bufHeight);
        }
    }

    return Rect(bufWidth, bufHeight);
}

FloatRect BufferLayer::computeSourceBounds(const FloatRect& parentBounds) const {
    const State& s(getDrawingState());

    // If we have a sideband stream, or we are scaling the buffer then return the layer size since
    // we cannot determine the buffer size.
    if ((s.sidebandStream != nullptr) ||
        (getEffectiveScalingMode() != NATIVE_WINDOW_SCALING_MODE_FREEZE)) {
        return FloatRect(0, 0, getActiveWidth(s), getActiveHeight(s));
    }

    if (mBufferInfo.mBuffer == nullptr) {
        return parentBounds;
    }

    uint32_t bufWidth = mBufferInfo.mBuffer->getBuffer()->getWidth();
    uint32_t bufHeight = mBufferInfo.mBuffer->getBuffer()->getHeight();

    // Undo any transformations on the buffer and return the result.
    if (mBufferInfo.mTransform & ui::Transform::ROT_90) {
        std::swap(bufWidth, bufHeight);
    }

    if (getTransformToDisplayInverse()) {
        uint32_t invTransform = DisplayDevice::getPrimaryDisplayRotationFlags();
        if (invTransform & ui::Transform::ROT_90) {
            std::swap(bufWidth, bufHeight);
        }
    }

    return FloatRect(0, 0, bufWidth, bufHeight);
}

void BufferLayer::latchAndReleaseBuffer() {
    mRefreshPending = false;
    if (hasReadyFrame()) {
        bool ignored = false;
        latchBuffer(ignored, systemTime(), 0 /* expectedPresentTime */);
    }
    releasePendingBuffer(systemTime());
}

PixelFormat BufferLayer::getPixelFormat() const {
    return mBufferInfo.mPixelFormat;
}

bool BufferLayer::getTransformToDisplayInverse() const {
    return mBufferInfo.mTransformToDisplayInverse;
}

Rect BufferLayer::getBufferCrop() const {
    // this is the crop rectangle that applies to the buffer
    // itself (as opposed to the window)
    if (!mBufferInfo.mCrop.isEmpty()) {
        // if the buffer crop is defined, we use that
        return mBufferInfo.mCrop;
    } else if (mBufferInfo.mBuffer != nullptr) {
        // otherwise we use the whole buffer
        return mBufferInfo.mBuffer->getBuffer()->getBounds();
    } else {
        // if we don't have a buffer yet, we use an empty/invalid crop
        return Rect();
    }
}

uint32_t BufferLayer::getBufferTransform() const {
    return mBufferInfo.mTransform;
}

ui::Dataspace BufferLayer::getDataSpace() const {
    return mBufferInfo.mDataspace;
}

ui::Dataspace BufferLayer::translateDataspace(ui::Dataspace dataspace) {
    ui::Dataspace updatedDataspace = dataspace;
    // translate legacy dataspaces to modern dataspaces
    switch (dataspace) {
        case ui::Dataspace::SRGB:
            updatedDataspace = ui::Dataspace::V0_SRGB;
            break;
        case ui::Dataspace::SRGB_LINEAR:
            updatedDataspace = ui::Dataspace::V0_SRGB_LINEAR;
            break;
        case ui::Dataspace::JFIF:
            updatedDataspace = ui::Dataspace::V0_JFIF;
            break;
        case ui::Dataspace::BT601_625:
            updatedDataspace = ui::Dataspace::V0_BT601_625;
            break;
        case ui::Dataspace::BT601_525:
            updatedDataspace = ui::Dataspace::V0_BT601_525;
            break;
        case ui::Dataspace::BT709:
            updatedDataspace = ui::Dataspace::V0_BT709;
            break;
        default:
            break;
    }

    return updatedDataspace;
}

sp<GraphicBuffer> BufferLayer::getBuffer() const {
    return mBufferInfo.mBuffer ? mBufferInfo.mBuffer->getBuffer() : nullptr;
}

void BufferLayer::getDrawingTransformMatrix(bool filteringEnabled, float outMatrix[16]) {
    GLConsumer::computeTransformMatrix(outMatrix,
                                       mBufferInfo.mBuffer ? mBufferInfo.mBuffer->getBuffer()
                                                           : nullptr,
                                       mBufferInfo.mCrop, mBufferInfo.mTransform, filteringEnabled);
}

void BufferLayer::setInitialValuesForClone(const sp<Layer>& clonedFrom) {
    Layer::setInitialValuesForClone(clonedFrom);

    sp<BufferLayer> bufferClonedFrom = static_cast<BufferLayer*>(clonedFrom.get());
    mPremultipliedAlpha = bufferClonedFrom->mPremultipliedAlpha;
    mPotentialCursor = bufferClonedFrom->mPotentialCursor;
    mProtectedByApp = bufferClonedFrom->mProtectedByApp;

    updateCloneBufferInfo();
}

void BufferLayer::updateCloneBufferInfo() {
    if (!isClone() || !isClonedFromAlive()) {
        return;
    }

    sp<BufferLayer> clonedFrom = static_cast<BufferLayer*>(getClonedFrom().get());
    mBufferInfo = clonedFrom->mBufferInfo;
    mSidebandStream = clonedFrom->mSidebandStream;
    surfaceDamageRegion = clonedFrom->surfaceDamageRegion;
    mCurrentFrameNumber = clonedFrom->mCurrentFrameNumber.load();
    mPreviousFrameNumber = clonedFrom->mPreviousFrameNumber;

    // After buffer info is updated, the drawingState from the real layer needs to be copied into
    // the cloned. This is because some properties of drawingState can change when latchBuffer is
    // called. However, copying the drawingState would also overwrite the cloned layer's relatives
    // and touchableRegionCrop. Therefore, temporarily store the relatives so they can be set in
    // the cloned drawingState again.
    wp<Layer> tmpZOrderRelativeOf = mDrawingState.zOrderRelativeOf;
    SortedVector<wp<Layer>> tmpZOrderRelatives = mDrawingState.zOrderRelatives;
    wp<Layer> tmpTouchableRegionCrop = mDrawingState.touchableRegionCrop;
    WindowInfo tmpInputInfo = mDrawingState.inputInfo;

    cloneDrawingState(clonedFrom.get());

    mDrawingState.touchableRegionCrop = tmpTouchableRegionCrop;
    mDrawingState.zOrderRelativeOf = tmpZOrderRelativeOf;
    mDrawingState.zOrderRelatives = tmpZOrderRelatives;
    mDrawingState.inputInfo = tmpInputInfo;
}

void BufferLayer::setTransformHint(ui::Transform::RotationFlags displayTransformHint) {
    mTransformHint = getFixedTransformHint();
    if (mTransformHint == ui::Transform::ROT_INVALID) {
        mTransformHint = displayTransformHint;
    }
}

bool BufferLayer::bufferNeedsFiltering() const {
    return isFixedSize();
}

} // namespace android

#if defined(__gl_h_)
#error "don't include gl/gl.h in this file"
#endif

#if defined(__gl2_h_)
#error "don't include gl2/gl2.h in this file"
#endif

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
