/*
 * Copyright (C) 2007 The Android Open Source Project
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

#pragma once

#include <compositionengine/LayerFE.h>
#include <gui/BufferQueue.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
#include <input/InputWindow.h>
#include <layerproto/LayerProtoHeader.h>
#include <math/vec4.h>
#include <renderengine/Mesh.h>
#include <renderengine/Texture.h>
#include <sys/types.h>
#include <ui/FloatRect.h>
#include <ui/FrameStats.h>
#include <ui/GraphicBuffer.h>
#include <ui/PixelFormat.h>
#include <ui/Region.h>
#include <ui/Transform.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include <chrono>
#include <cstdint>
#include <list>
#include <optional>
#include <vector>

#include "Client.h"
#include "ClientCache.h"
#include "DisplayHardware/ComposerHal.h"
#include "DisplayHardware/HWComposer.h"
#include "FrameTracker.h"
#include "LayerVector.h"
#include "MonitoredProducer.h"
#include "RenderArea.h"
#include "SurfaceFlinger.h"
#include "TransactionCompletedThread.h"

using namespace android::surfaceflinger;

namespace android {

// ---------------------------------------------------------------------------

class Client;
class Colorizer;
class DisplayDevice;
class GraphicBuffer;
class SurfaceFlinger;
class LayerDebugInfo;

namespace compositionengine {
class OutputLayer;
struct LayerFECompositionState;
}

namespace impl {
class SurfaceInterceptor;
}

// ---------------------------------------------------------------------------

struct LayerCreationArgs {
    LayerCreationArgs(SurfaceFlinger*, sp<Client>, std::string name, uint32_t w, uint32_t h,
                      uint32_t flags, LayerMetadata);

    SurfaceFlinger* flinger;
    const sp<Client> client;
    std::string name;
    uint32_t w;
    uint32_t h;
    uint32_t flags;
    LayerMetadata metadata;

    pid_t callingPid;
    uid_t callingUid;
    uint32_t textureName;
};

class Layer : public virtual RefBase, compositionengine::LayerFE {
    static std::atomic<int32_t> sSequence;
    // The following constants represent priority of the window. SF uses this information when
    // deciding which window has a priority when deciding about the refresh rate of the screen.
    // Priority 0 is considered the highest priority. -1 means that the priority is unset.
    static constexpr int32_t PRIORITY_UNSET = -1;
    // Windows that are in focus and voted for the preferred mode ID
    static constexpr int32_t PRIORITY_FOCUSED_WITH_MODE = 0;
    // // Windows that are in focus, but have not requested a specific mode ID.
    static constexpr int32_t PRIORITY_FOCUSED_WITHOUT_MODE = 1;
    // Windows that are not in focus, but voted for a specific mode ID.
    static constexpr int32_t PRIORITY_NOT_FOCUSED_WITH_MODE = 2;

public:
    mutable bool contentDirty{false};
    Region surfaceDamageRegion;

    // Layer serial number.  This gives layers an explicit ordering, so we
    // have a stable sort order when their layer stack and Z-order are
    // the same.
    int32_t sequence{sSequence++};

    enum { // flags for doTransaction()
        eDontUpdateGeometryState = 0x00000001,
        eVisibleRegion = 0x00000002,
        eInputInfoChanged = 0x00000004
    };

    struct Geometry {
        uint32_t w;
        uint32_t h;
        ui::Transform transform;

        inline bool operator==(const Geometry& rhs) const {
            return (w == rhs.w && h == rhs.h) && (transform.tx() == rhs.transform.tx()) &&
                    (transform.ty() == rhs.transform.ty());
        }
        inline bool operator!=(const Geometry& rhs) const { return !operator==(rhs); }
    };

    struct RoundedCornerState {
        RoundedCornerState() = default;
        RoundedCornerState(FloatRect cropRect, float radius)
              : cropRect(cropRect), radius(radius) {}

        // Rounded rectangle in local layer coordinate space.
        FloatRect cropRect = FloatRect();
        // Radius of the rounded rectangle.
        float radius = 0.0f;
    };

    // FrameRateCompatibility specifies how we should interpret the frame rate associated with
    // the layer.
    enum class FrameRateCompatibility {
        Default, // Layer didn't specify any specific handling strategy

        ExactOrMultiple, // Layer needs the exact frame rate (or a multiple of it) to present the
                         // content properly. Any other value will result in a pull down.

        NoVote, // Layer doesn't have any requirements for the refresh rate and
                // should not be considered when the display refresh rate is determined.
    };

    // Encapsulates the frame rate and compatibility of the layer. This information will be used
    // when the display refresh rate is determined.
    struct FrameRate {
        float rate;
        FrameRateCompatibility type;

        FrameRate() : rate(0), type(FrameRateCompatibility::Default) {}
        FrameRate(float rate, FrameRateCompatibility type) : rate(rate), type(type) {}

        bool operator==(const FrameRate& other) const {
            return rate == other.rate && type == other.type;
        }

        bool operator!=(const FrameRate& other) const { return !(*this == other); }

        // Convert an ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_* value to a
        // Layer::FrameRateCompatibility. Logs fatal if the compatibility value is invalid.
        static FrameRateCompatibility convertCompatibility(int8_t compatibility);
    };

    struct State {
        Geometry active_legacy;
        Geometry requested_legacy;
        int32_t z;

        // The identifier of the layer stack this layer belongs to. A layer can
        // only be associated to a single layer stack. A layer stack is a
        // z-ordered group of layers which can be associated to one or more
        // displays. Using the same layer stack on different displays is a way
        // to achieve mirroring.
        uint32_t layerStack;

        uint8_t flags;
        uint8_t reserved[2];
        int32_t sequence; // changes when visible regions can change
        bool modified;

        // Crop is expressed in layer space coordinate.
        Rect crop_legacy;
        Rect requestedCrop_legacy;

        // If set, defers this state update until the identified Layer
        // receives a frame with the given frameNumber
        wp<Layer> barrierLayer_legacy;
        uint64_t frameNumber_legacy;

        // the transparentRegion hint is a bit special, it's latched only
        // when we receive a buffer -- this is because it's "content"
        // dependent.
        Region activeTransparentRegion_legacy;
        Region requestedTransparentRegion_legacy;

        LayerMetadata metadata;

        // If non-null, a Surface this Surface's Z-order is interpreted relative to.
        wp<Layer> zOrderRelativeOf;
        bool isRelativeOf{false};

        // A list of surfaces whose Z-order is interpreted relative to ours.
        SortedVector<wp<Layer>> zOrderRelatives;

        half4 color;
        float cornerRadius;
        int backgroundBlurRadius;

        bool inputInfoChanged;
        InputWindowInfo inputInfo;
        wp<Layer> touchableRegionCrop;

        // dataspace is only used by BufferStateLayer and EffectLayer
        ui::Dataspace dataspace;

        // The fields below this point are only used by BufferStateLayer
        uint64_t frameNumber;
        Geometry active;

        uint32_t transform;
        bool transformToDisplayInverse;

        Rect crop;
        Region transparentRegionHint;

        sp<GraphicBuffer> buffer;
        client_cache_t clientCacheId;
        sp<Fence> acquireFence;
        HdrMetadata hdrMetadata;
        Region surfaceDamageRegion;
        int32_t api;

        sp<NativeHandle> sidebandStream;
        mat4 colorTransform;
        bool hasColorTransform;

        // pointer to background color layer that, if set, appears below the buffer state layer
        // and the buffer state layer's children.  Z order will be set to
        // INT_MIN
        sp<Layer> bgColorLayer;

        // The deque of callback handles for this frame. The back of the deque contains the most
        // recent callback handle.
        std::deque<sp<CallbackHandle>> callbackHandles;
        bool colorSpaceAgnostic;
        nsecs_t desiredPresentTime = -1;

        // Length of the cast shadow. If the radius is > 0, a shadow of length shadowRadius will
        // be rendered around the layer.
        float shadowRadius;

        // Priority of the layer assigned by Window Manager.
        int32_t frameRateSelectionPriority;

        FrameRate frameRate;

        // Indicates whether parents / children of this layer had set FrameRate
        bool treeHasFrameRateVote;

        // Set by window manager indicating the layer and all its children are
        // in a different orientation than the display. The hint suggests that
        // the graphic producers should receive a transform hint as if the
        // display was in this orientation. When the display changes to match
        // the layer orientation, the graphic producer may not need to allocate
        // a buffer of a different size. ui::Transform::ROT_INVALID means the
        // a fixed transform hint is not set.
        ui::Transform::RotationFlags fixedTransformHint;
    };

    explicit Layer(const LayerCreationArgs& args);
    virtual ~Layer();

    void onFirstRef() override;

    int getWindowType() const { return mWindowType; }

    void setPrimaryDisplayOnly() { mPrimaryDisplayOnly = true; }
    bool getPrimaryDisplayOnly() const { return mPrimaryDisplayOnly; }

    // ------------------------------------------------------------------------
    // Geometry setting functions.
    //
    // The following group of functions are used to specify the layers
    // bounds, and the mapping of the texture on to those bounds. According
    // to various settings changes to them may apply immediately, or be delayed until
    // a pending resize is completed by the producer submitting a buffer. For example
    // if we were to change the buffer size, and update the matrix ahead of the
    // new buffer arriving, then we would be stretching the buffer to a different
    // aspect before and after the buffer arriving, which probably isn't what we wanted.
    //
    // The first set of geometry functions are controlled by the scaling mode, described
    // in window.h. The scaling mode may be set by the client, as it submits buffers.
    // This value may be overriden through SurfaceControl, with setOverrideScalingMode.
    //
    // Put simply, if our scaling mode is SCALING_MODE_FREEZE, then
    // matrix updates will not be applied while a resize is pending
    // and the size and transform will remain in their previous state
    // until a new buffer is submitted. If the scaling mode is another value
    // then the old-buffer will immediately be scaled to the pending size
    // and the new matrix will be immediately applied following this scaling
    // transformation.

    // Set the default buffer size for the assosciated Producer, in pixels. This is
    // also the rendered size of the layer prior to any transformations. Parent
    // or local matrix transformations will not affect the size of the buffer,
    // but may affect it's on-screen size or clipping.
    virtual bool setSize(uint32_t w, uint32_t h);
    // Set a 2x2 transformation matrix on the layer. This transform
    // will be applied after parent transforms, but before any final
    // producer specified transform.
    virtual bool setMatrix(const layer_state_t::matrix22_t& matrix,
                           bool allowNonRectPreservingTransforms);

    // This second set of geometry attributes are controlled by
    // setGeometryAppliesWithResize, and their default mode is to be
    // immediate. If setGeometryAppliesWithResize is specified
    // while a resize is pending, then update of these attributes will
    // be delayed until the resize completes.

    // setPosition operates in parent buffer space (pre parent-transform) or display
    // space for top-level layers.
    virtual bool setPosition(float x, float y);
    // Buffer space
    virtual bool setCrop_legacy(const Rect& crop);

    // TODO(b/38182121): Could we eliminate the various latching modes by
    // using the layer hierarchy?
    // -----------------------------------------------------------------------
    virtual bool setLayer(int32_t z);
    virtual bool setRelativeLayer(const sp<IBinder>& relativeToHandle, int32_t relativeZ);

    virtual bool setAlpha(float alpha);
    virtual bool setColor(const half3& /*color*/) { return false; };

    // Set rounded corner radius for this layer and its children.
    //
    // We only support 1 radius per layer in the hierarchy, where parent layers have precedence.
    // The shape of the rounded corner rectangle is specified by the crop rectangle of the layer
    // from which we inferred the rounded corner radius.
    virtual bool setCornerRadius(float cornerRadius);
    // When non-zero, everything below this layer will be blurred by backgroundBlurRadius, which
    // is specified in pixels.
    virtual bool setBackgroundBlurRadius(int backgroundBlurRadius);
    virtual bool setTransparentRegionHint(const Region& transparent);
    virtual bool setFlags(uint8_t flags, uint8_t mask);
    virtual bool setLayerStack(uint32_t layerStack);
    virtual uint32_t getLayerStack() const;
    virtual void deferTransactionUntil_legacy(const sp<IBinder>& barrierHandle,
                                              uint64_t frameNumber);
    virtual void deferTransactionUntil_legacy(const sp<Layer>& barrierLayer, uint64_t frameNumber);
    virtual bool setOverrideScalingMode(int32_t overrideScalingMode);
    virtual bool setMetadata(const LayerMetadata& data);
    bool reparentChildren(const sp<IBinder>& newParentHandle);
    void reparentChildren(const sp<Layer>& newParent);
    virtual void setChildrenDrawingParent(const sp<Layer>& layer);
    virtual bool reparent(const sp<IBinder>& newParentHandle);
    virtual bool detachChildren();
    bool attachChildren();
    bool isLayerDetached() const { return mLayerDetached; }
    virtual bool setColorTransform(const mat4& matrix);
    virtual mat4 getColorTransform() const;
    virtual bool hasColorTransform() const;
    virtual bool isColorSpaceAgnostic() const { return mDrawingState.colorSpaceAgnostic; }

    // Used only to set BufferStateLayer state
    virtual bool setTransform(uint32_t /*transform*/) { return false; };
    virtual bool setTransformToDisplayInverse(bool /*transformToDisplayInverse*/) { return false; };
    virtual bool setCrop(const Rect& /*crop*/) { return false; };
    virtual bool setFrame(const Rect& /*frame*/) { return false; };
    virtual bool setBuffer(const sp<GraphicBuffer>& /*buffer*/, const sp<Fence>& /*acquireFence*/,
                           nsecs_t /*postTime*/, nsecs_t /*desiredPresentTime*/,
                           const client_cache_t& /*clientCacheId*/) {
        return false;
    };
    virtual bool setAcquireFence(const sp<Fence>& /*fence*/) { return false; };
    virtual bool setDataspace(ui::Dataspace /*dataspace*/) { return false; };
    virtual bool setHdrMetadata(const HdrMetadata& /*hdrMetadata*/) { return false; };
    virtual bool setSurfaceDamageRegion(const Region& /*surfaceDamage*/) { return false; };
    virtual bool setApi(int32_t /*api*/) { return false; };
    virtual bool setSidebandStream(const sp<NativeHandle>& /*sidebandStream*/) { return false; };
    virtual bool setTransactionCompletedListeners(
            const std::vector<sp<CallbackHandle>>& /*handles*/) {
        return false;
    };
    virtual void forceSendCallbacks() {}
    virtual bool addFrameEvent(const sp<Fence>& /*acquireFence*/, nsecs_t /*postedTime*/,
                               nsecs_t /*requestedPresentTime*/) {
        return false;
    }
    virtual bool setBackgroundColor(const half3& color, float alpha, ui::Dataspace dataspace);
    virtual bool setColorSpaceAgnostic(const bool agnostic);
    bool setShadowRadius(float shadowRadius);
    virtual bool setFrameRateSelectionPriority(int32_t priority);
    virtual bool setFixedTransformHint(ui::Transform::RotationFlags fixedTransformHint);
    //  If the variable is not set on the layer, it traverses up the tree to inherit the frame
    //  rate priority from its parent.
    virtual int32_t getFrameRateSelectionPriority() const;
    static bool isLayerFocusedBasedOnPriority(int32_t priority);

    virtual ui::Dataspace getDataSpace() const { return ui::Dataspace::UNKNOWN; }

    // Before color management is introduced, contents on Android have to be
    // desaturated in order to match what they appears like visually.
    // With color management, these contents will appear desaturated, thus
    // needed to be saturated so that they match what they are designed for
    // visually.
    bool isLegacyDataSpace() const;

    virtual sp<compositionengine::LayerFE> getCompositionEngineLayerFE() const;
    virtual compositionengine::LayerFECompositionState* editCompositionState();

    // If we have received a new buffer this frame, we will pass its surface
    // damage down to hardware composer. Otherwise, we must send a region with
    // one empty rect.
    virtual void useSurfaceDamage() {}
    virtual void useEmptyDamage() {}

    uint32_t getTransactionFlags() const { return mTransactionFlags; }
    uint32_t getTransactionFlags(uint32_t flags);
    uint32_t setTransactionFlags(uint32_t flags);

    // Deprecated, please use compositionengine::Output::belongsInOutput()
    // instead.
    // TODO(lpique): Move the remaining callers (screencap) to the new function.
    bool belongsToDisplay(uint32_t layerStack, bool isPrimaryDisplay) const {
        return getLayerStack() == layerStack && (!mPrimaryDisplayOnly || isPrimaryDisplay);
    }

    FloatRect getBounds(const Region& activeTransparentRegion) const;
    FloatRect getBounds() const;

    // Compute bounds for the layer and cache the results.
    void computeBounds(FloatRect parentBounds, ui::Transform parentTransform, float shadowRadius);

    // Returns the buffer scale transform if a scaling mode is set.
    ui::Transform getBufferScaleTransform() const;

    // Get effective layer transform, taking into account all its parent transform with any
    // scaling if the parent scaling more is not NATIVE_WINDOW_SCALING_MODE_FREEZE.
    ui::Transform getTransformWithScale(const ui::Transform& bufferScaleTransform) const;

    // Returns the bounds of the layer without any buffer scaling.
    FloatRect getBoundsPreScaling(const ui::Transform& bufferScaleTransform) const;

    int32_t getSequence() const { return sequence; }

    // For tracing.
    // TODO: Replace with raw buffer id from buffer metadata when that becomes available.
    // GraphicBuffer::getId() does not provide a reliable global identifier. Since the traces
    // creates its tracks by buffer id and has no way of associating a buffer back to the process
    // that created it, the current implementation is only sufficient for cases where a buffer is
    // only used within a single layer.
    uint64_t getCurrentBufferId() const { return getBuffer() ? getBuffer()->getId() : 0; }

    // -----------------------------------------------------------------------
    // Virtuals

    // Provide unique string for each class type in the Layer hierarchy
    virtual const char* getType() const = 0;

    /*
     * isOpaque - true if this surface is opaque
     *
     * This takes into account the buffer format (i.e. whether or not the
     * pixel format includes an alpha channel) and the "opaque" flag set
     * on the layer.  It does not examine the current plane alpha value.
     */
    virtual bool isOpaque(const Layer::State&) const { return false; }

    /*
     * isSecure - true if this surface is secure, that is if it prevents
     * screenshots or VNC servers.
     */
    bool isSecure() const;

    /*
     * isVisible - true if this layer is visible, false otherwise
     */
    virtual bool isVisible() const = 0;

    /*
     * isHiddenByPolicy - true if this layer has been forced invisible.
     * just because this is false, doesn't mean isVisible() is true.
     * For example if this layer has no active buffer, it may not be hidden by
     * policy, but it still can not be visible.
     */
    bool isHiddenByPolicy() const;

    /*
     * Returns whether this layer can receive input.
     */
    virtual bool canReceiveInput() const;

    /*
     * isProtected - true if the layer may contain protected content in the
     * GRALLOC_USAGE_PROTECTED sense.
     */
    virtual bool isProtected() const { return false; }

    /*
     * isFixedSize - true if content has a fixed size
     */
    virtual bool isFixedSize() const { return true; }

    /*
     * usesSourceCrop - true if content should use a source crop
     */
    virtual bool usesSourceCrop() const { return false; }

    // Most layers aren't created from the main thread, and therefore need to
    // grab the SF state lock to access HWC, but ContainerLayer does, so we need
    // to avoid grabbing the lock again to avoid deadlock
    virtual bool isCreatedFromMainThread() const { return false; }

    bool isRemovedFromCurrentState() const;

    LayerProto* writeToProto(LayersProto& layersProto, uint32_t traceFlags,
                             const DisplayDevice*) const;

    // Write states that are modified by the main thread. This includes drawing
    // state as well as buffer data. This should be called in the main or tracing
    // thread.
    void writeToProtoDrawingState(LayerProto* layerInfo, uint32_t traceFlags,
                                  const DisplayDevice*) const;
    // Write drawing or current state. If writing current state, the caller should hold the
    // external mStateLock. If writing drawing state, this function should be called on the
    // main or tracing thread.
    void writeToProtoCommonState(LayerProto* layerInfo, LayerVector::StateSet stateSet,
                                 uint32_t traceFlags = SurfaceTracing::TRACE_ALL) const;

    virtual Geometry getActiveGeometry(const Layer::State& s) const { return s.active_legacy; }
    virtual uint32_t getActiveWidth(const Layer::State& s) const { return s.active_legacy.w; }
    virtual uint32_t getActiveHeight(const Layer::State& s) const { return s.active_legacy.h; }
    virtual ui::Transform getActiveTransform(const Layer::State& s) const {
        return s.active_legacy.transform;
    }
    virtual Region getActiveTransparentRegion(const Layer::State& s) const {
        return s.activeTransparentRegion_legacy;
    }
    virtual Rect getCrop(const Layer::State& s) const { return s.crop_legacy; }
    virtual bool needsFiltering(const DisplayDevice*) const { return false; }
    // True if this layer requires filtering
    // This method is distinct from needsFiltering() in how the filter
    // requirement is computed. needsFiltering() compares displayFrame and crop,
    // where as this method transforms the displayFrame to layer-stack space
    // first. This method should be used if there is no physical display to
    // project onto when taking screenshots, as the filtering requirements are
    // different.
    // If the parent transform needs to be undone when capturing the layer, then
    // the inverse parent transform is also required.
    virtual bool needsFilteringForScreenshots(const DisplayDevice*, const ui::Transform&) const {
        return false;
    }

    // This layer is not a clone, but it's the parent to the cloned hierarchy. The
    // variable mClonedChild represents the top layer that will be cloned so this
    // layer will be the parent of mClonedChild.
    // The layers in the cloned hierarchy will match the lifetime of the real layers. That is
    // if the real layer is destroyed, then the clone layer will also be destroyed.
    sp<Layer> mClonedChild;

    virtual sp<Layer> createClone() = 0;
    void updateMirrorInfo();
    virtual void updateCloneBufferInfo(){};

protected:
    sp<compositionengine::LayerFE> asLayerFE() const;
    sp<Layer> getClonedFrom() { return mClonedFrom != nullptr ? mClonedFrom.promote() : nullptr; }
    bool isClone() { return mClonedFrom != nullptr; }
    bool isClonedFromAlive() { return getClonedFrom() != nullptr; }

    virtual void setInitialValuesForClone(const sp<Layer>& clonedFrom);

    void updateClonedDrawingState(std::map<sp<Layer>, sp<Layer>>& clonedLayersMap);
    void updateClonedChildren(const sp<Layer>& mirrorRoot,
                              std::map<sp<Layer>, sp<Layer>>& clonedLayersMap);
    void updateClonedRelatives(const std::map<sp<Layer>, sp<Layer>>& clonedLayersMap);
    void addChildToDrawing(const sp<Layer>& layer);
    void updateClonedInputInfo(const std::map<sp<Layer>, sp<Layer>>& clonedLayersMap);
    virtual std::optional<compositionengine::LayerFE::LayerSettings> prepareClientComposition(
            compositionengine::LayerFE::ClientCompositionTargetSettings&);
    virtual std::optional<compositionengine::LayerFE::LayerSettings> prepareShadowClientComposition(
            const LayerFE::LayerSettings& layerSettings, const Rect& displayViewport,
            ui::Dataspace outputDataspace);
    // Modifies the passed in layer settings to clear the contents. If the blackout flag is set,
    // the settings clears the content with a solid black fill.
    void prepareClearClientComposition(LayerFE::LayerSettings& layerSettings, bool blackout) const;

public:
    /*
     * compositionengine::LayerFE overrides
     */
    const compositionengine::LayerFECompositionState* getCompositionState() const override;
    bool onPreComposition(nsecs_t) override;
    void prepareCompositionState(compositionengine::LayerFE::StateSubset subset) override;
    std::vector<compositionengine::LayerFE::LayerSettings> prepareClientCompositionList(
            compositionengine::LayerFE::ClientCompositionTargetSettings&) override;
    void onLayerDisplayed(const sp<Fence>& releaseFence) override;
    const char* getDebugName() const override;

protected:
    void prepareBasicGeometryCompositionState();
    void prepareGeometryCompositionState();
    virtual void preparePerFrameCompositionState();
    void prepareCursorCompositionState();

public:
    virtual void setDefaultBufferSize(uint32_t /*w*/, uint32_t /*h*/) {}

    virtual bool isHdrY410() const { return false; }

    virtual bool shouldPresentNow(nsecs_t /*expectedPresentTime*/) const { return false; }

    /*
     * called after composition.
     * returns true if the layer latched a new buffer this frame.
     */
    virtual bool onPostComposition(const DisplayDevice*,
                                   const std::shared_ptr<FenceTime>& /*glDoneFence*/,
                                   const std::shared_ptr<FenceTime>& /*presentFence*/,
                                   const CompositorTiming&) {
        return false;
    }

    // If a buffer was replaced this frame, release the former buffer
    virtual void releasePendingBuffer(nsecs_t /*dequeueReadyTime*/) { }

    virtual void finalizeFrameEventHistory(const std::shared_ptr<FenceTime>& /*glDoneFence*/,
                                           const CompositorTiming& /*compositorTiming*/) {}
    /*
     * doTransaction - process the transaction. This is a good place to figure
     * out which attributes of the surface have changed.
     */
    uint32_t doTransaction(uint32_t transactionFlags);

    /*
     * latchBuffer - called each time the screen is redrawn and returns whether
     * the visible regions need to be recomputed (this is a fairly heavy
     * operation, so this should be set only if needed). Typically this is used
     * to figure out if the content or size of a surface has changed.
     */
    virtual bool latchBuffer(bool& /*recomputeVisibleRegions*/, nsecs_t /*latchTime*/,
                             nsecs_t /*expectedPresentTime*/) {
        return false;
    }

    virtual bool isBufferLatched() const { return false; }

    virtual void latchAndReleaseBuffer() {}

    /*
     * Remove relative z for the layer if its relative parent is not part of the
     * provided layer tree.
     */
    void removeRelativeZ(const std::vector<Layer*>& layersInTree);

    /*
     * Remove from current state and mark for removal.
     */
    void removeFromCurrentState();

    /*
     * called with the state lock from a binder thread when the layer is
     * removed from the current list to the pending removal list
     */
    void onRemovedFromCurrentState();

    /*
     * Called when the layer is added back to the current state list.
     */
    void addToCurrentState();

    /*
     * Sets display transform hint on BufferLayerConsumer.
     */
    void updateTransformHint(ui::Transform::RotationFlags);

    /*
     * returns the rectangle that crops the content of the layer and scales it
     * to the layer's size.
     */
    virtual Rect getBufferCrop() const { return Rect(); }

    /*
     * Returns the transform applied to the buffer.
     */
    virtual uint32_t getBufferTransform() const { return 0; }

    virtual sp<GraphicBuffer> getBuffer() const { return nullptr; }

    virtual ui::Transform::RotationFlags getTransformHint() const { return ui::Transform::ROT_0; }

    /*
     * Returns if a frame is ready
     */
    virtual bool hasReadyFrame() const { return false; }

    virtual int32_t getQueuedFrameCount() const { return 0; }

    // -----------------------------------------------------------------------
    inline const State& getDrawingState() const { return mDrawingState; }
    inline const State& getCurrentState() const { return mCurrentState; }
    inline State& getCurrentState() { return mCurrentState; }

    LayerDebugInfo getLayerDebugInfo(const DisplayDevice*) const;

    static void miniDumpHeader(std::string& result);
    void miniDump(std::string& result, const DisplayDevice&) const;
    void dumpFrameStats(std::string& result) const;
    void dumpFrameEvents(std::string& result);
    void dumpCallingUidPid(std::string& result) const;
    void clearFrameStats();
    void logFrameStats();
    void getFrameStats(FrameStats* outStats) const;

    virtual std::vector<OccupancyTracker::Segment> getOccupancyHistory(bool /*forceFlush*/) {
        return {};
    }

    void onDisconnect();
    void addAndGetFrameTimestamps(const NewFrameEventsEntry* newEntry,
                                  FrameEventHistoryDelta* outDelta);

    virtual bool getTransformToDisplayInverse() const { return false; }

    ui::Transform getTransform() const;

    // Returns the Alpha of the Surface, accounting for the Alpha
    // of parent Surfaces in the hierarchy (alpha's will be multiplied
    // down the hierarchy).
    half getAlpha() const;
    half4 getColor() const;
    int32_t getBackgroundBlurRadius() const;
    bool drawShadows() const { return mEffectiveShadowRadius > 0.f; };

    // Returns the transform hint set by Window Manager on the layer or one of its parents.
    // This traverses the current state because the data is needed when creating
    // the layer(off drawing thread) and the hint should be available before the producer
    // is ready to acquire a buffer.
    ui::Transform::RotationFlags getFixedTransformHint() const;

    // Returns how rounded corners should be drawn for this layer.
    // This will traverse the hierarchy until it reaches its root, finding topmost rounded
    // corner definition and converting it into current layer's coordinates.
    // As of now, only 1 corner radius per display list is supported. Subsequent ones will be
    // ignored.
    virtual RoundedCornerState getRoundedCornerState() const;

    renderengine::ShadowSettings getShadowSettings(const Rect& viewport) const;

    /**
     * Traverse this layer and it's hierarchy of children directly. Unlike traverseInZOrder
     * which will not emit children who have relativeZOrder to another layer, this method
     * just directly emits all children. It also emits them in no particular order.
     * So this method is not suitable for graphical operations, as it doesn't represent
     * the scene state, but it's also more efficient than traverseInZOrder and so useful for
     * book-keeping.
     */
    void traverse(LayerVector::StateSet stateSet, const LayerVector::Visitor& visitor);
    void traverseInReverseZOrder(LayerVector::StateSet stateSet,
                                 const LayerVector::Visitor& visitor);
    void traverseInZOrder(LayerVector::StateSet stateSet, const LayerVector::Visitor& visitor);

    /**
     * Traverse only children in z order, ignoring relative layers that are not children of the
     * parent.
     */
    void traverseChildrenInZOrder(LayerVector::StateSet stateSet,
                                  const LayerVector::Visitor& visitor);

    size_t getChildrenCount() const;

    // ONLY CALL THIS FROM THE LAYER DTOR!
    // See b/141111965.  We need to add current children to offscreen layers in
    // the layer dtor so as not to dangle layers.  Since the layer has not
    // committed its transaction when the layer is destroyed, we must add
    // current children.  This is safe in the dtor as we will no longer update
    // the current state, but should not be called anywhere else!
    LayerVector& getCurrentChildren() { return mCurrentChildren; }

    void addChild(const sp<Layer>& layer);
    // Returns index if removed, or negative value otherwise
    // for symmetry with Vector::remove
    ssize_t removeChild(const sp<Layer>& layer);
    sp<Layer> getParent() const { return mCurrentParent.promote(); }
    bool hasParent() const { return getParent() != nullptr; }
    Rect getScreenBounds(bool reduceTransparentRegion = true) const;
    bool setChildLayer(const sp<Layer>& childLayer, int32_t z);
    bool setChildRelativeLayer(const sp<Layer>& childLayer,
            const sp<IBinder>& relativeToHandle, int32_t relativeZ);

    // Copy the current list of children to the drawing state. Called by
    // SurfaceFlinger to complete a transaction.
    void commitChildList();
    int32_t getZ(LayerVector::StateSet stateSet) const;
    virtual void pushPendingState();

    /**
     * Returns active buffer size in the correct orientation. Buffer size is determined by undoing
     * any buffer transformations. If the layer has no buffer then return INVALID_RECT.
     */
    virtual Rect getBufferSize(const Layer::State&) const { return Rect::INVALID_RECT; }

    /**
     * Returns the source bounds. If the bounds are not defined, it is inferred from the
     * buffer size. Failing that, the bounds are determined from the passed in parent bounds.
     * For the root layer, this is the display viewport size.
     */
    virtual FloatRect computeSourceBounds(const FloatRect& parentBounds) const {
        return parentBounds;
    }

    /**
     * Returns the cropped buffer size or the layer crop if the layer has no buffer. Return
     * INVALID_RECT if the layer has no buffer and no crop.
     * A layer with an invalid buffer size and no crop is considered to be boundless. The layer
     * bounds are constrained by its parent bounds.
     */
    Rect getCroppedBufferSize(const Layer::State& s) const;

    bool setFrameRate(FrameRate frameRate);
    virtual FrameRate getFrameRateForLayerTree() const;
    static std::string frameRateCompatibilityString(FrameRateCompatibility compatibility);

protected:
    // constant
    sp<SurfaceFlinger> mFlinger;
    /*
     * Trivial class, used to ensure that mFlinger->onLayerDestroyed(mLayer)
     * is called.
     */
    class LayerCleaner {
        sp<SurfaceFlinger> mFlinger;
        sp<Layer> mLayer;

    protected:
        ~LayerCleaner() {
            // destroy client resources
            mFlinger->onHandleDestroyed(mLayer);
        }

    public:
        LayerCleaner(const sp<SurfaceFlinger>& flinger, const sp<Layer>& layer)
              : mFlinger(flinger), mLayer(layer) {}
    };

    friend class impl::SurfaceInterceptor;

    // For unit tests
    friend class TestableSurfaceFlinger;
    friend class RefreshRateSelectionTest;
    friend class SetFrameRateTest;

    virtual void commitTransaction(const State& stateToCommit);

    uint32_t getEffectiveUsage(uint32_t usage) const;

    /**
     * Setup rounded corners coordinates of this layer, taking into account the layer bounds and
     * crop coordinates, transforming them into layer space.
     */
    void setupRoundedCornersCropCoordinates(Rect win, const FloatRect& roundedCornersCrop) const;
    void setParent(const sp<Layer>& layer);
    LayerVector makeTraversalList(LayerVector::StateSet stateSet, bool* outSkipRelativeZUsers);
    void addZOrderRelative(const wp<Layer>& relative);
    void removeZOrderRelative(const wp<Layer>& relative);

    class SyncPoint {
    public:
        explicit SyncPoint(uint64_t frameNumber,
                           wp<Layer> requestedSyncLayer,
                           wp<Layer> barrierLayer_legacy)
              : mFrameNumber(frameNumber),
                mFrameIsAvailable(false),
                mTransactionIsApplied(false),
                mRequestedSyncLayer(requestedSyncLayer),
                mBarrierLayer_legacy(barrierLayer_legacy) {}
        uint64_t getFrameNumber() const { return mFrameNumber; }

        bool frameIsAvailable() const { return mFrameIsAvailable; }

        void setFrameAvailable() { mFrameIsAvailable = true; }

        bool transactionIsApplied() const { return mTransactionIsApplied; }

        void setTransactionApplied() { mTransactionIsApplied = true; }

        sp<Layer> getRequestedSyncLayer() { return mRequestedSyncLayer.promote(); }

        sp<Layer> getBarrierLayer() const { return mBarrierLayer_legacy.promote(); }

        bool isTimeout() const {
            using namespace std::chrono_literals;
            static constexpr std::chrono::nanoseconds TIMEOUT_THRESHOLD = 1s;

            return std::chrono::steady_clock::now() - mCreateTimeStamp > TIMEOUT_THRESHOLD;
        }

        void checkTimeoutAndLog() {
            using namespace std::chrono_literals;
            static constexpr std::chrono::nanoseconds LOG_PERIOD = 1s;

            if (!frameIsAvailable() && isTimeout()) {
                const auto now = std::chrono::steady_clock::now();
                if (now - mLastLogTime > LOG_PERIOD) {
                    mLastLogTime = now;
                    sp<Layer> requestedSyncLayer = getRequestedSyncLayer();
                    sp<Layer> barrierLayer = getBarrierLayer();
                    ALOGW("[%s] sync point %" PRIu64 " wait timeout %lld for %s",
                          requestedSyncLayer ? requestedSyncLayer->getDebugName() : "Removed",
                          mFrameNumber, (now - mCreateTimeStamp).count(),
                          barrierLayer ? barrierLayer->getDebugName() : "Removed");
                }
            }
        }
    private:
        const uint64_t mFrameNumber;
        std::atomic<bool> mFrameIsAvailable;
        std::atomic<bool> mTransactionIsApplied;
        wp<Layer> mRequestedSyncLayer;
        wp<Layer> mBarrierLayer_legacy;
        const std::chrono::time_point<std::chrono::steady_clock> mCreateTimeStamp =
            std::chrono::steady_clock::now();
        std::chrono::time_point<std::chrono::steady_clock> mLastLogTime;
    };

    // SyncPoints which will be signaled when the correct frame is at the head
    // of the queue and dropped after the frame has been latched. Protected by
    // mLocalSyncPointMutex.
    Mutex mLocalSyncPointMutex;
    std::list<std::shared_ptr<SyncPoint>> mLocalSyncPoints;

    // SyncPoints which will be signaled and then dropped when the transaction
    // is applied
    std::list<std::shared_ptr<SyncPoint>> mRemoteSyncPoints;

    // Returns false if the relevant frame has already been latched
    bool addSyncPoint(const std::shared_ptr<SyncPoint>& point);

    void popPendingState(State* stateToCommit);
    virtual bool applyPendingStates(State* stateToCommit);
    virtual uint32_t doTransactionResize(uint32_t flags, Layer::State* stateToCommit);

    // Returns mCurrentScaling mode (originating from the
    // Client) or mOverrideScalingMode mode (originating from
    // the Surface Controller) if set.
    virtual uint32_t getEffectiveScalingMode() const { return 0; }

public:
    /*
     * The layer handle is just a BBinder object passed to the client
     * (remote process) -- we don't keep any reference on our side such that
     * the dtor is called when the remote side let go of its reference.
     *
     * LayerCleaner ensures that mFlinger->onLayerDestroyed() is called for
     * this layer when the handle is destroyed.
     */
    class Handle : public BBinder, public LayerCleaner {
    public:
        Handle(const sp<SurfaceFlinger>& flinger, const sp<Layer>& layer)
              : LayerCleaner(flinger, layer), owner(layer) {}

        wp<Layer> owner;
    };

    // Creates a new handle each time, so we only expect
    // this to be called once.
    sp<IBinder> getHandle();
    const std::string& getName() const { return mName; }
    virtual void notifyAvailableFrames(nsecs_t /*expectedPresentTime*/) {}
    virtual PixelFormat getPixelFormat() const { return PIXEL_FORMAT_NONE; }
    bool getPremultipledAlpha() const;

    bool mPendingHWCDestroy{false};
    void setInputInfo(const InputWindowInfo& info);

    InputWindowInfo fillInputInfo();
    /**
     * Returns whether this layer has an explicitly set input-info.
     */
    bool hasInputInfo() const;
    /**
     * Return whether this layer needs an input info. For most layer types
     * this is only true if they explicitly set an input-info but BufferLayer
     * overrides this so we can generate input-info for Buffered layers that don't
     * have them (for input occlusion detection checks).
     */
    virtual bool needsInputInfo() const { return hasInputInfo(); }

protected:
    compositionengine::OutputLayer* findOutputLayerForDisplay(const DisplayDevice*) const;

    bool usingRelativeZ(LayerVector::StateSet stateSet) const;

    bool mPremultipliedAlpha{true};
    const std::string mName;
    const std::string mTransactionName{"TX - " + mName};

    bool mPrimaryDisplayOnly = false;

    // These are only accessed by the main thread or the tracing thread.
    State mDrawingState;
    // Store a copy of the pending state so that the drawing thread can access the
    // states without a lock.
    std::deque<State> mPendingStatesSnapshot;

    // these are protected by an external lock (mStateLock)
    State mCurrentState;
    std::atomic<uint32_t> mTransactionFlags{0};
    std::deque<State> mPendingStates;

    // Timestamp history for UIAutomation. Thread safe.
    FrameTracker mFrameTracker;

    // Timestamp history for the consumer to query.
    // Accessed by both consumer and producer on main and binder threads.
    Mutex mFrameEventHistoryMutex;
    ConsumerFrameEventHistory mFrameEventHistory;
    FenceTimeline mAcquireTimeline;
    FenceTimeline mReleaseTimeline;

    // main thread
    sp<NativeHandle> mSidebandStream;
    // False if the buffer and its contents have been previously used for GPU
    // composition, true otherwise.
    bool mIsActiveBufferUpdatedForGpu = true;

    // We encode unset as -1.
    int32_t mOverrideScalingMode{-1};
    std::atomic<uint64_t> mCurrentFrameNumber{0};
    // Whether filtering is needed b/c of the drawingstate
    bool mNeedsFiltering{false};

    std::atomic<bool> mRemovedFromCurrentState{false};

    // page-flip thread (currently main thread)
    bool mProtectedByApp{false}; // application requires protected path to external sink

    // protected by mLock
    mutable Mutex mLock;

    const wp<Client> mClientRef;

    // This layer can be a cursor on some displays.
    bool mPotentialCursor{false};

    // Child list about to be committed/used for editing.
    LayerVector mCurrentChildren{LayerVector::StateSet::Current};
    // Child list used for rendering.
    LayerVector mDrawingChildren{LayerVector::StateSet::Drawing};

    wp<Layer> mCurrentParent;
    wp<Layer> mDrawingParent;

    // Can only be accessed with the SF state lock held.
    bool mLayerDetached{false};
    // Can only be accessed with the SF state lock held.
    bool mChildrenChanged{false};

    // Window types from WindowManager.LayoutParams
    const int mWindowType;

private:
    virtual void setTransformHint(ui::Transform::RotationFlags) {}

    Hwc2::IComposerClient::Composition getCompositionType(const DisplayDevice&) const;
    Region getVisibleRegion(const DisplayDevice*) const;

    /**
     * Returns an unsorted vector of all layers that are part of this tree.
     * That includes the current layer and all its descendants.
     */
    std::vector<Layer*> getLayersInTree(LayerVector::StateSet stateSet);
    /**
     * Traverses layers that are part of this tree in the correct z order.
     * layersInTree must be sorted before calling this method.
     */
    void traverseChildrenInZOrderInner(const std::vector<Layer*>& layersInTree,
                                       LayerVector::StateSet stateSet,
                                       const LayerVector::Visitor& visitor);
    LayerVector makeChildrenTraversalList(LayerVector::StateSet stateSet,
                                          const std::vector<Layer*>& layersInTree);

    void updateTreeHasFrameRateVote();

    // Cached properties computed from drawing state
    // Effective transform taking into account parent transforms and any parent scaling.
    ui::Transform mEffectiveTransform;

    // Bounds of the layer before any transformation is applied and before it has been cropped
    // by its parents.
    FloatRect mSourceBounds;

    // Bounds of the layer in layer space. This is the mSourceBounds cropped by its layer crop and
    // its parent bounds.
    FloatRect mBounds;

    // Layer bounds in screen space.
    FloatRect mScreenBounds;

    void setZOrderRelativeOf(const wp<Layer>& relativeOf);

    bool mGetHandleCalled = false;

    void removeRemoteSyncPoints();

    // Tracks the process and user id of the caller when creating this layer
    // to help debugging.
    pid_t mCallingPid;
    uid_t mCallingUid;

    // The current layer is a clone of mClonedFrom. This means that this layer will update it's
    // properties based on mClonedFrom. When mClonedFrom latches a new buffer for BufferLayers,
    // this layer will update it's buffer. When mClonedFrom updates it's drawing state, children,
    // and relatives, this layer will update as well.
    wp<Layer> mClonedFrom;

    // The inherited shadow radius after taking into account the layer hierarchy. This is the
    // final shadow radius for this layer. If a shadow is specified for a layer, then effective
    // shadow radius is the set shadow radius, otherwise its the parent's shadow radius.
    float mEffectiveShadowRadius = 0.f;

    // Returns true if the layer can draw shadows on its border.
    virtual bool canDrawShadows() const { return true; }

    // Find the root of the cloned hierarchy, this means the first non cloned parent.
    // This will return null if first non cloned parent is not found.
    sp<Layer> getClonedRoot();

    // Finds the top most layer in the hierarchy. This will find the root Layer where the parent is
    // null.
    sp<Layer> getRootLayer();
};

} // namespace android
