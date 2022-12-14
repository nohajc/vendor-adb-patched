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

#include <android/gui/DropInputMode.h>
#include <gui/BufferQueue.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
#include <gui/WindowInfo.h>
#include <layerproto/LayerProtoHeader.h>
#include <math/vec4.h>
#include <renderengine/Mesh.h>
#include <renderengine/Texture.h>
#include <sys/types.h>
#include <ui/BlurRegion.h>
#include <ui/FloatRect.h>
#include <ui/FrameStats.h>
#include <ui/GraphicBuffer.h>
#include <ui/PixelFormat.h>
#include <ui/Region.h>
#include <ui/StretchEffect.h>
#include <ui/Transform.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include <compositionengine/LayerFE.h>
#include <scheduler/Fps.h>
#include <scheduler/Seamlessness.h>

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
#include "Scheduler/LayerInfo.h"
#include "SurfaceFlinger.h"
#include "Tracing/LayerTracing.h"
#include "TransactionCallbackInvoker.h"

using namespace android::surfaceflinger;

namespace android {

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

namespace frametimeline {
class SurfaceFrame;
} // namespace frametimeline

struct LayerCreationArgs {
    LayerCreationArgs(SurfaceFlinger*, sp<Client>, std::string name, uint32_t flags, LayerMetadata);

    SurfaceFlinger* flinger;
    const sp<Client> client;
    std::string name;
    uint32_t flags;
    LayerMetadata metadata;

    pid_t callingPid;
    uid_t callingUid;
    uint32_t textureName;
    std::optional<uint32_t> sequence = std::nullopt;
    bool addToRoot = true;
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
        RoundedCornerState(const FloatRect& cropRect, const vec2& radius)
              : cropRect(cropRect), radius(radius) {}

        // Rounded rectangle in local layer coordinate space.
        FloatRect cropRect = FloatRect();
        // Radius of the rounded rectangle.
        vec2 radius;
        bool hasRoundedCorners() const { return radius.x > 0.0f && radius.y > 0.0f; }
    };

    using FrameRate = scheduler::LayerInfo::FrameRate;
    using FrameRateCompatibility = scheduler::LayerInfo::FrameRateCompatibility;

    struct State {
        Geometry active_legacy;
        Geometry requested_legacy;
        int32_t z;

        ui::LayerStack layerStack;

        uint32_t flags;
        uint8_t reserved[2];
        int32_t sequence; // changes when visible regions can change
        bool modified;

        // Crop is expressed in layer space coordinate.
        Rect crop;
        Rect requestedCrop;

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

        gui::WindowInfo inputInfo;
        wp<Layer> touchableRegionCrop;

        // dataspace is only used by BufferStateLayer and EffectLayer
        ui::Dataspace dataspace;

        // The fields below this point are only used by BufferStateLayer
        uint64_t frameNumber;
        uint32_t width;
        uint32_t height;
        ui::Transform transform;

        uint32_t bufferTransform;
        bool transformToDisplayInverse;

        Region transparentRegionHint;

        std::shared_ptr<renderengine::ExternalTexture> buffer;
        client_cache_t clientCacheId;
        sp<Fence> acquireFence;
        std::shared_ptr<FenceTime> acquireFenceTime;
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
        nsecs_t desiredPresentTime = 0;
        bool isAutoTimestamp = true;

        // Length of the cast shadow. If the radius is > 0, a shadow of length shadowRadius will
        // be rendered around the layer.
        float shadowRadius;

        // Layer regions that are made of custom materials, like frosted glass
        std::vector<BlurRegion> blurRegions;

        // Priority of the layer assigned by Window Manager.
        int32_t frameRateSelectionPriority;

        FrameRate frameRate;

        // The combined frame rate of parents / children of this layer
        FrameRate frameRateForLayerTree;

        // Set by window manager indicating the layer and all its children are
        // in a different orientation than the display. The hint suggests that
        // the graphic producers should receive a transform hint as if the
        // display was in this orientation. When the display changes to match
        // the layer orientation, the graphic producer may not need to allocate
        // a buffer of a different size. ui::Transform::ROT_INVALID means the
        // a fixed transform hint is not set.
        ui::Transform::RotationFlags fixedTransformHint;

        // The vsync info that was used to start the transaction
        FrameTimelineInfo frameTimelineInfo;

        // When the transaction was posted
        nsecs_t postTime;

        sp<ITransactionCompletedListener> releaseBufferListener;
        // SurfaceFrame that tracks the timeline of Transactions that contain a Buffer. Only one
        // such SurfaceFrame exists because only one buffer can be presented on the layer per vsync.
        // If multiple buffers are queued, the prior ones will be dropped, along with the
        // SurfaceFrame that's tracking them.
        std::shared_ptr<frametimeline::SurfaceFrame> bufferSurfaceFrameTX;
        // A map of token(frametimelineVsyncId) to the SurfaceFrame that's tracking a transaction
        // that contains the token. Only one SurfaceFrame exisits for transactions that share the
        // same token, unless they are presented in different vsyncs.
        std::unordered_map<int64_t, std::shared_ptr<frametimeline::SurfaceFrame>>
                bufferlessSurfaceFramesTX;
        // An arbitrary threshold for the number of BufferlessSurfaceFrames in the state. Used to
        // trigger a warning if the number of SurfaceFrames crosses the threshold.
        static constexpr uint32_t kStateSurfaceFramesThreshold = 25;

        // Stretch effect to apply to this layer
        StretchEffect stretchEffect;

        // Whether or not this layer is a trusted overlay for input
        bool isTrustedOverlay;

        Rect bufferCrop;
        Rect destinationFrame;

        sp<IBinder> releaseBufferEndpoint;

        gui::DropInputMode dropInputMode;

        bool autoRefresh = false;

        bool dimmingEnabled = true;
    };

    /*
     * Trivial class, used to ensure that mFlinger->onLayerDestroyed(mLayer)
     * is called.
     */
    class LayerCleaner {
        sp<SurfaceFlinger> mFlinger;
        sp<Layer> mLayer;
        BBinder* mHandle;

    protected:
        ~LayerCleaner() {
            // destroy client resources
            mFlinger->onHandleDestroyed(mHandle, mLayer);
        }

    public:
        LayerCleaner(const sp<SurfaceFlinger>& flinger, const sp<Layer>& layer, BBinder* handle)
              : mFlinger(flinger), mLayer(layer), mHandle(handle) {}
    };

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
              : LayerCleaner(flinger, layer, this), owner(layer) {}
        const String16& getInterfaceDescriptor() const override { return kDescriptor; }

        static const String16 kDescriptor;
        wp<Layer> owner;
    };

    static wp<Layer> fromHandle(const sp<IBinder>& handle);

    explicit Layer(const LayerCreationArgs& args);
    virtual ~Layer();

    static bool isLayerFocusedBasedOnPriority(int32_t priority);
    static void miniDumpHeader(std::string& result);

    // Provide unique string for each class type in the Layer hierarchy
    virtual const char* getType() const = 0;

    // true if this layer is visible, false otherwise
    virtual bool isVisible() const = 0;

    virtual sp<Layer> createClone() = 0;

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
    virtual bool setMatrix(const layer_state_t::matrix22_t& matrix);

    // This second set of geometry attributes are controlled by
    // setGeometryAppliesWithResize, and their default mode is to be
    // immediate. If setGeometryAppliesWithResize is specified
    // while a resize is pending, then update of these attributes will
    // be delayed until the resize completes.

    // setPosition operates in parent buffer space (pre parent-transform) or display
    // space for top-level layers.
    virtual bool setPosition(float x, float y);
    // Buffer space
    virtual bool setCrop(const Rect& crop);

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
    virtual bool setBlurRegions(const std::vector<BlurRegion>& effectRegions);
    virtual bool setTransparentRegionHint(const Region& transparent);
    virtual bool setTrustedOverlay(bool);
    virtual bool setFlags(uint32_t flags, uint32_t mask);
    virtual bool setLayerStack(ui::LayerStack);
    virtual ui::LayerStack getLayerStack() const;
    virtual bool setMetadata(const LayerMetadata& data);
    virtual void setChildrenDrawingParent(const sp<Layer>&);
    virtual bool reparent(const sp<IBinder>& newParentHandle) REQUIRES(mFlinger->mStateLock);
    virtual bool setColorTransform(const mat4& matrix);
    virtual mat4 getColorTransform() const;
    virtual bool hasColorTransform() const;
    virtual bool isColorSpaceAgnostic() const { return mDrawingState.colorSpaceAgnostic; }
    virtual bool isDimmingEnabled() const { return getDrawingState().dimmingEnabled; };

    // Used only to set BufferStateLayer state
    virtual bool setTransform(uint32_t /*transform*/) { return false; };
    virtual bool setTransformToDisplayInverse(bool /*transformToDisplayInverse*/) { return false; };
    virtual bool setBuffer(std::shared_ptr<renderengine::ExternalTexture>& /* buffer */,
                           const BufferData& /* bufferData */, nsecs_t /* postTime */,
                           nsecs_t /*desiredPresentTime*/, bool /*isAutoTimestamp*/,
                           std::optional<nsecs_t> /* dequeueTime */,
                           const FrameTimelineInfo& /*info*/) {
        return false;
    };
    virtual bool setDataspace(ui::Dataspace /*dataspace*/) { return false; };
    virtual bool setHdrMetadata(const HdrMetadata& /*hdrMetadata*/) { return false; };
    virtual bool setSurfaceDamageRegion(const Region& /*surfaceDamage*/) { return false; };
    virtual bool setApi(int32_t /*api*/) { return false; };
    virtual bool setSidebandStream(const sp<NativeHandle>& /*sidebandStream*/) { return false; };
    virtual bool setTransactionCompletedListeners(
            const std::vector<sp<CallbackHandle>>& /*handles*/);
    virtual bool setBackgroundColor(const half3& color, float alpha, ui::Dataspace dataspace)
            REQUIRES(mFlinger->mStateLock);
    virtual bool setColorSpaceAgnostic(const bool agnostic);
    virtual bool setDimmingEnabled(const bool dimmingEnabled);
    virtual bool setFrameRateSelectionPriority(int32_t priority);
    virtual bool setFixedTransformHint(ui::Transform::RotationFlags fixedTransformHint);
    virtual void setAutoRefresh(bool /* autoRefresh */) {}
    bool setDropInputMode(gui::DropInputMode);

    //  If the variable is not set on the layer, it traverses up the tree to inherit the frame
    //  rate priority from its parent.
    virtual int32_t getFrameRateSelectionPriority() const;
    virtual ui::Dataspace getDataSpace() const { return ui::Dataspace::UNKNOWN; }

    virtual sp<compositionengine::LayerFE> getCompositionEngineLayerFE() const;
    virtual compositionengine::LayerFECompositionState* editCompositionState();

    // If we have received a new buffer this frame, we will pass its surface
    // damage down to hardware composer. Otherwise, we must send a region with
    // one empty rect.
    virtual void useSurfaceDamage() {}
    virtual void useEmptyDamage() {}
    Region getVisibleRegion(const DisplayDevice*) const;

    /*
     * isOpaque - true if this surface is opaque
     *
     * This takes into account the buffer format (i.e. whether or not the
     * pixel format includes an alpha channel) and the "opaque" flag set
     * on the layer.  It does not examine the current plane alpha value.
     */
    virtual bool isOpaque(const Layer::State&) const { return false; }

    /*
     * Returns whether this layer can receive input.
     */
    virtual bool canReceiveInput() const;

    /*
     * Whether or not the layer should be considered visible for input calculations.
     */
    virtual bool isVisibleForInput() const {
        // For compatibility reasons we let layers which can receive input
        // receive input before they have actually submitted a buffer. Because
        // of this we use canReceiveInput instead of isVisible to check the
        // policy-visibility, ignoring the buffer state. However for layers with
        // hasInputInfo()==false we can use the real visibility state.
        // We are just using these layers for occlusion detection in
        // InputDispatcher, and obviously if they aren't visible they can't occlude
        // anything.
        return hasInputInfo() ? canReceiveInput() : isVisible();
    }

    /*
     * isProtected - true if the layer may contain protected contents in the
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

    uint32_t getActiveWidth(const Layer::State& s) const { return s.width; }
    uint32_t getActiveHeight(const Layer::State& s) const { return s.height; }
    ui::Transform getActiveTransform(const Layer::State& s) const { return s.transform; }
    virtual Region getActiveTransparentRegion(const Layer::State& s) const {
        return s.activeTransparentRegion_legacy;
    }
    virtual Rect getCrop(const Layer::State& s) const { return s.crop; }
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

    virtual void updateCloneBufferInfo(){};

    virtual void setDefaultBufferSize(uint32_t /*w*/, uint32_t /*h*/) {}

    virtual bool isHdrY410() const { return false; }

    virtual bool shouldPresentNow(nsecs_t /*expectedPresentTime*/) const { return false; }

    /*
     * called after composition.
     * returns true if the layer latched a new buffer this frame.
     */
    virtual void onPostComposition(const DisplayDevice*,
                                   const std::shared_ptr<FenceTime>& /*glDoneFence*/,
                                   const std::shared_ptr<FenceTime>& /*presentFence*/,
                                   const CompositorTiming&) {}

    // If a buffer was replaced this frame, release the former buffer
    virtual void releasePendingBuffer(nsecs_t /*dequeueReadyTime*/) { }

    virtual void finalizeFrameEventHistory(const std::shared_ptr<FenceTime>& /*glDoneFence*/,
                                           const CompositorTiming& /*compositorTiming*/) {}

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

    virtual void latchAndReleaseBuffer() {}

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
    virtual const std::shared_ptr<renderengine::ExternalTexture>& getExternalTexture() const {
        return mDrawingState.buffer;
    };

    virtual ui::Transform::RotationFlags getTransformHint() const { return ui::Transform::ROT_0; }

    /*
     * Returns if a frame is ready
     */
    virtual bool hasReadyFrame() const { return false; }

    virtual int32_t getQueuedFrameCount() const { return 0; }

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
    virtual FrameRate getFrameRateForLayerTree() const;

    virtual bool getTransformToDisplayInverse() const { return false; }

    // Returns how rounded corners should be drawn for this layer.
    // A layer can override its parent's rounded corner settings if the parent's rounded
    // corner crop does not intersect with its own rounded corner crop.
    virtual RoundedCornerState getRoundedCornerState() const;

    bool hasRoundedCorners() const override { return getRoundedCornerState().hasRoundedCorners(); }

    virtual PixelFormat getPixelFormat() const { return PIXEL_FORMAT_NONE; }
    /**
     * Return whether this layer needs an input info. For most layer types
     * this is only true if they explicitly set an input-info but BufferLayer
     * overrides this so we can generate input-info for Buffered layers that don't
     * have them (for input occlusion detection checks).
     */
    virtual bool needsInputInfo() const { return hasInputInfo(); }

    // Implements RefBase.
    void onFirstRef() override;

    // implements compositionengine::LayerFE
    const compositionengine::LayerFECompositionState* getCompositionState() const override;
    bool onPreComposition(nsecs_t) override;
    void prepareCompositionState(compositionengine::LayerFE::StateSubset subset) override;
    std::vector<compositionengine::LayerFE::LayerSettings> prepareClientCompositionList(
            compositionengine::LayerFE::ClientCompositionTargetSettings&) override;
    void onLayerDisplayed(ftl::SharedFuture<FenceResult>) override;

    void setWasClientComposed(const sp<Fence>& fence) override {
        mLastClientCompositionFence = fence;
        mClearClientCompositionFenceOnLayerDisplayed = false;
    }

    const char* getDebugName() const override;

    bool setShadowRadius(float shadowRadius);

    // Before color management is introduced, contents on Android have to be
    // desaturated in order to match what they appears like visually.
    // With color management, these contents will appear desaturated, thus
    // needed to be saturated so that they match what they are designed for
    // visually.
    bool isLegacyDataSpace() const;

    uint32_t getTransactionFlags() const { return mTransactionFlags; }

    // Sets the masked bits.
    void setTransactionFlags(uint32_t mask);

    // Clears and returns the masked bits.
    uint32_t clearTransactionFlags(uint32_t mask);

    FloatRect getBounds(const Region& activeTransparentRegion) const;
    FloatRect getBounds() const;

    // Compute bounds for the layer and cache the results.
    void computeBounds(FloatRect parentBounds, ui::Transform parentTransform, float shadowRadius);

    int32_t getSequence() const override { return sequence; }

    // For tracing.
    // TODO: Replace with raw buffer id from buffer metadata when that becomes available.
    // GraphicBuffer::getId() does not provide a reliable global identifier. Since the traces
    // creates its tracks by buffer id and has no way of associating a buffer back to the process
    // that created it, the current implementation is only sufficient for cases where a buffer is
    // only used within a single layer.
    uint64_t getCurrentBufferId() const { return getBuffer() ? getBuffer()->getId() : 0; }

    /*
     * isSecure - true if this surface is secure, that is if it prevents
     * screenshots or VNC servers. A surface can be set to be secure by the
     * application, being secure doesn't mean the surface has DRM contents.
     */
    bool isSecure() const;

    /*
     * isHiddenByPolicy - true if this layer has been forced invisible.
     * just because this is false, doesn't mean isVisible() is true.
     * For example if this layer has no active buffer, it may not be hidden by
     * policy, but it still can not be visible.
     */
    bool isHiddenByPolicy() const;

    // True if the layer should be skipped in screenshots, screen recordings,
    // and mirroring to external or virtual displays.
    bool isInternalDisplayOverlay() const;

    ui::LayerFilter getOutputFilter() const {
        return {getLayerStack(), isInternalDisplayOverlay()};
    }

    bool isRemovedFromCurrentState() const;

    LayerProto* writeToProto(LayersProto& layersProto, uint32_t traceFlags);

    // Write states that are modified by the main thread. This includes drawing
    // state as well as buffer data. This should be called in the main or tracing
    // thread.
    void writeToProtoDrawingState(LayerProto* layerInfo);
    // Write drawing or current state. If writing current state, the caller should hold the
    // external mStateLock. If writing drawing state, this function should be called on the
    // main or tracing thread.
    void writeToProtoCommonState(LayerProto* layerInfo, LayerVector::StateSet,
                                 uint32_t traceFlags = LayerTracing::TRACE_ALL);

    gui::WindowInfo::Type getWindowType() const { return mWindowType; }

    void updateMirrorInfo();

    /*
     * doTransaction - process the transaction. This is a good place to figure
     * out which attributes of the surface have changed.
     */
    virtual uint32_t doTransaction(uint32_t transactionFlags);

    /*
     * Remove relative z for the layer if its relative parent is not part of the
     * provided layer tree.
     */
    void removeRelativeZ(const std::vector<Layer*>& layersInTree);

    /*
     * Remove from current state and mark for removal.
     */
    void removeFromCurrentState() REQUIRES(mFlinger->mStateLock);

    /*
     * called with the state lock from a binder thread when the layer is
     * removed from the current list to the pending removal list
     */
    void onRemovedFromCurrentState() REQUIRES(mFlinger->mStateLock);

    /*
     * Called when the layer is added back to the current state list.
     */
    void addToCurrentState();

    /*
     * Sets display transform hint on BufferLayerConsumer.
     */
    void updateTransformHint(ui::Transform::RotationFlags);

    inline const State& getDrawingState() const { return mDrawingState; }
    inline State& getDrawingState() { return mDrawingState; }

    LayerDebugInfo getLayerDebugInfo(const DisplayDevice*) const;

    void miniDump(std::string& result, const DisplayDevice&) const;
    void dumpFrameStats(std::string& result) const;
    void dumpCallingUidPid(std::string& result) const;
    void clearFrameStats();
    void logFrameStats();
    void getFrameStats(FrameStats* outStats) const;
    void onDisconnect();

    ui::Transform getTransform() const;
    bool isTransformValid() const;

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

    /**
     * Traverse this layer and it's hierarchy of children directly. Unlike traverseInZOrder
     * which will not emit children who have relativeZOrder to another layer, this method
     * just directly emits all children. It also emits them in no particular order.
     * So this method is not suitable for graphical operations, as it doesn't represent
     * the scene state, but it's also more efficient than traverseInZOrder and so useful for
     * book-keeping.
     */
    void traverse(LayerVector::StateSet, const LayerVector::Visitor&);
    void traverseInReverseZOrder(LayerVector::StateSet, const LayerVector::Visitor&);
    void traverseInZOrder(LayerVector::StateSet, const LayerVector::Visitor&);

    /**
     * Traverse only children in z order, ignoring relative layers that are not children of the
     * parent.
     */
    void traverseChildrenInZOrder(LayerVector::StateSet, const LayerVector::Visitor&);

    size_t getChildrenCount() const;

    // ONLY CALL THIS FROM THE LAYER DTOR!
    // See b/141111965.  We need to add current children to offscreen layers in
    // the layer dtor so as not to dangle layers.  Since the layer has not
    // committed its transaction when the layer is destroyed, we must add
    // current children.  This is safe in the dtor as we will no longer update
    // the current state, but should not be called anywhere else!
    LayerVector& getCurrentChildren() { return mCurrentChildren; }

    void addChild(const sp<Layer>&);
    // Returns index if removed, or negative value otherwise
    // for symmetry with Vector::remove
    ssize_t removeChild(const sp<Layer>& layer);
    sp<Layer> getParent() const { return mCurrentParent.promote(); }

    // Should be called with the surfaceflinger statelock held
    bool isAtRoot() const { return mIsAtRoot; }
    void setIsAtRoot(bool isAtRoot) { mIsAtRoot = isAtRoot; }

    bool hasParent() const { return getParent() != nullptr; }
    Rect getScreenBounds(bool reduceTransparentRegion = true) const;
    bool setChildLayer(const sp<Layer>& childLayer, int32_t z);
    bool setChildRelativeLayer(const sp<Layer>& childLayer,
            const sp<IBinder>& relativeToHandle, int32_t relativeZ);

    // Copy the current list of children to the drawing state. Called by
    // SurfaceFlinger to complete a transaction.
    void commitChildList();
    int32_t getZ(LayerVector::StateSet) const;

    /**
     * Returns the cropped buffer size or the layer crop if the layer has no buffer. Return
     * INVALID_RECT if the layer has no buffer and no crop.
     * A layer with an invalid buffer size and no crop is considered to be boundless. The layer
     * bounds are constrained by its parent bounds.
     */
    Rect getCroppedBufferSize(const Layer::State& s) const;

    bool setFrameRate(FrameRate);

    virtual void setFrameTimelineInfoForBuffer(const FrameTimelineInfo& /*info*/) {}
    void setFrameTimelineVsyncForBufferTransaction(const FrameTimelineInfo& info, nsecs_t postTime);
    void setFrameTimelineVsyncForBufferlessTransaction(const FrameTimelineInfo& info,
                                                       nsecs_t postTime);

    void addSurfaceFrameDroppedForBuffer(
            std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame);
    void addSurfaceFramePresentedForBuffer(
            std::shared_ptr<frametimeline::SurfaceFrame>& surfaceFrame, nsecs_t acquireFenceTime,
            nsecs_t currentLatchTime);

    std::shared_ptr<frametimeline::SurfaceFrame> createSurfaceFrameForTransaction(
            const FrameTimelineInfo& info, nsecs_t postTime);
    std::shared_ptr<frametimeline::SurfaceFrame> createSurfaceFrameForBuffer(
            const FrameTimelineInfo& info, nsecs_t queueTime, std::string debugName);

    // Creates a new handle each time, so we only expect
    // this to be called once.
    sp<IBinder> getHandle();
    const std::string& getName() const { return mName; }
    bool getPremultipledAlpha() const;
    void setInputInfo(const gui::WindowInfo& info);

    struct InputDisplayArgs {
        const ui::Transform* transform = nullptr;
        bool isSecure = false;
    };
    gui::WindowInfo fillInputInfo(const InputDisplayArgs& displayArgs);

    /**
     * Returns whether this layer has an explicitly set input-info.
     */
    bool hasInputInfo() const;

    // Sets the GameMode for the tree rooted at this layer. A layer in the tree inherits this
    // GameMode unless it (or an ancestor) has GAME_MODE_METADATA.
    void setGameModeForTree(GameMode);

    void setGameMode(GameMode gameMode) { mGameMode = gameMode; }
    GameMode getGameMode() const { return mGameMode; }

    virtual uid_t getOwnerUid() const { return mOwnerUid; }

    pid_t getOwnerPid() { return mOwnerPid; }

    // This layer is not a clone, but it's the parent to the cloned hierarchy. The
    // variable mClonedChild represents the top layer that will be cloned so this
    // layer will be the parent of mClonedChild.
    // The layers in the cloned hierarchy will match the lifetime of the real layers. That is
    // if the real layer is destroyed, then the clone layer will also be destroyed.
    sp<Layer> mClonedChild;
    bool mHadClonedChild = false;
    void setClonedChild(const sp<Layer>& mClonedChild);

    mutable bool contentDirty{false};
    Region surfaceDamageRegion;

    // Layer serial number.  This gives layers an explicit ordering, so we
    // have a stable sort order when their layer stack and Z-order are
    // the same.
    const int32_t sequence;

    bool mPendingHWCDestroy{false};

    bool backpressureEnabled() { return mDrawingState.flags & layer_state_t::eEnableBackpressure; }

    bool setStretchEffect(const StretchEffect& effect);
    StretchEffect getStretchEffect() const;

    virtual bool setBufferCrop(const Rect& /* bufferCrop */) { return false; }
    virtual bool setDestinationFrame(const Rect& /* destinationFrame */) { return false; }
    virtual std::atomic<int32_t>* getPendingBufferCounter() { return nullptr; }
    virtual std::string getPendingBufferCounterName() { return ""; }
    virtual bool updateGeometry() { return false; }

    virtual bool simpleBufferUpdate(const layer_state_t&) const { return false; }

    // Exposed so SurfaceFlinger can assert that it's held
    const sp<SurfaceFlinger> mFlinger;

protected:
    friend class impl::SurfaceInterceptor;

    // For unit tests
    friend class TestableSurfaceFlinger;
    friend class FpsReporterTest;
    friend class RefreshRateSelectionTest;
    friend class SetFrameRateTest;
    friend class TransactionFrameTracerTest;
    friend class TransactionSurfaceFrameTest;

    virtual void setInitialValuesForClone(const sp<Layer>& clonedFrom);
    virtual std::optional<compositionengine::LayerFE::LayerSettings> prepareClientComposition(
            compositionengine::LayerFE::ClientCompositionTargetSettings&);
    virtual void preparePerFrameCompositionState();
    virtual void commitTransaction(State& stateToCommit);
    virtual void onSurfaceFrameCreated(const std::shared_ptr<frametimeline::SurfaceFrame>&) {}

    // Returns mCurrentScaling mode (originating from the
    // Client) or mOverrideScalingMode mode (originating from
    // the Surface Controller) if set.
    virtual uint32_t getEffectiveScalingMode() const { return 0; }

    sp<compositionengine::LayerFE> asLayerFE() const;
    sp<Layer> getClonedFrom() { return mClonedFrom != nullptr ? mClonedFrom.promote() : nullptr; }
    bool isClone() { return mClonedFrom != nullptr; }
    bool isClonedFromAlive() { return getClonedFrom() != nullptr; }

    void cloneDrawingState(const Layer* from);
    void updateClonedDrawingState(std::map<sp<Layer>, sp<Layer>>& clonedLayersMap);
    void updateClonedChildren(const sp<Layer>& mirrorRoot,
                              std::map<sp<Layer>, sp<Layer>>& clonedLayersMap);
    void updateClonedRelatives(const std::map<sp<Layer>, sp<Layer>>& clonedLayersMap);
    void addChildToDrawing(const sp<Layer>&);
    void updateClonedInputInfo(const std::map<sp<Layer>, sp<Layer>>& clonedLayersMap);

    // Modifies the passed in layer settings to clear the contents. If the blackout flag is set,
    // the settings clears the content with a solid black fill.
    void prepareClearClientComposition(LayerFE::LayerSettings&, bool blackout) const;
    void prepareShadowClientComposition(LayerFE::LayerSettings& caster, const Rect& layerStackRect);

    void prepareBasicGeometryCompositionState();
    void prepareGeometryCompositionState();
    void prepareCursorCompositionState();

    uint32_t getEffectiveUsage(uint32_t usage) const;

    /**
     * Setup rounded corners coordinates of this layer, taking into account the layer bounds and
     * crop coordinates, transforming them into layer space.
     */
    void setupRoundedCornersCropCoordinates(Rect win, const FloatRect& roundedCornersCrop) const;
    void setParent(const sp<Layer>&);
    LayerVector makeTraversalList(LayerVector::StateSet, bool* outSkipRelativeZUsers);
    void addZOrderRelative(const wp<Layer>& relative);
    void removeZOrderRelative(const wp<Layer>& relative);
    compositionengine::OutputLayer* findOutputLayerForDisplay(const DisplayDevice*) const;
    bool usingRelativeZ(LayerVector::StateSet) const;

    virtual ui::Transform getInputTransform() const;
    /**
     * Get the bounds in layer space within which this layer can receive input.
     *
     * These bounds are used to:
     * - Determine the input frame for the layer to be used for occlusion detection; and
     * - Determine the coordinate space within which the layer will receive input. The top-left of
     *   this rect will be the origin of the coordinate space that the input events sent to the
     *   layer will be in (prior to accounting for surface insets).
     *
     * The layer can still receive touch input if these bounds are invalid if
     * "replaceTouchableRegionWithCrop" is specified. In this case, the layer will receive input
     * in this layer's space, regardless of the specified crop layer.
     */
    virtual Rect getInputBounds() const;

    bool mPremultipliedAlpha{true};
    const std::string mName;
    const std::string mTransactionName{"TX - " + mName};

    // These are only accessed by the main thread or the tracing thread.
    State mDrawingState;

    uint32_t mTransactionFlags{0};
    // Updated in doTransaction, used to track the last sequence number we
    // committed. Currently this is really only used for updating visible
    // regions.
    int32_t mLastCommittedTxSequence = -1;

    // Timestamp history for UIAutomation. Thread safe.
    FrameTracker mFrameTracker;

    // main thread
    sp<NativeHandle> mSidebandStream;
    // False if the buffer and its contents have been previously used for GPU
    // composition, true otherwise.
    bool mIsActiveBufferUpdatedForGpu = true;

    // We encode unset as -1.
    std::atomic<uint64_t> mCurrentFrameNumber{0};
    // Whether filtering is needed b/c of the drawingstate
    bool mNeedsFiltering{false};

    std::atomic<bool> mRemovedFromDrawingState{false};

    // page-flip thread (currently main thread)
    bool mProtectedByApp{false}; // application requires protected path to external sink

    // protected by mLock
    mutable Mutex mLock;

    const wp<Client> mClientRef;

    // This layer can be a cursor on some displays.
    bool mPotentialCursor{false};

    LayerVector mCurrentChildren{LayerVector::StateSet::Current};
    LayerVector mDrawingChildren{LayerVector::StateSet::Drawing};

    wp<Layer> mCurrentParent;
    wp<Layer> mDrawingParent;

    // Window types from WindowManager.LayoutParams
    const gui::WindowInfo::Type mWindowType;

    // The owner of the layer. If created from a non system process, it will be the calling uid.
    // If created from a system process, the value can be passed in.
    uid_t mOwnerUid;

    // The owner pid of the layer. If created from a non system process, it will be the calling pid.
    // If created from a system process, the value can be passed in.
    pid_t mOwnerPid;

    // Keeps track of the time SF latched the last buffer from this layer.
    // Used in buffer stuffing analysis in FrameTimeline.
    nsecs_t mLastLatchTime = 0;

    mutable bool mDrawingStateModified = false;

    sp<Fence> mLastClientCompositionFence;
    bool mClearClientCompositionFenceOnLayerDisplayed = false;
private:
    virtual void setTransformHint(ui::Transform::RotationFlags) {}

    // Returns true if the layer can draw shadows on its border.
    virtual bool canDrawShadows() const { return true; }

    aidl::android::hardware::graphics::composer3::Composition getCompositionType(
            const DisplayDevice&) const;

    /**
     * Returns an unsorted vector of all layers that are part of this tree.
     * That includes the current layer and all its descendants.
     */
    std::vector<Layer*> getLayersInTree(LayerVector::StateSet);
    /**
     * Traverses layers that are part of this tree in the correct z order.
     * layersInTree must be sorted before calling this method.
     */
    void traverseChildrenInZOrderInner(const std::vector<Layer*>& layersInTree,
                                       LayerVector::StateSet, const LayerVector::Visitor&);
    LayerVector makeChildrenTraversalList(LayerVector::StateSet,
                                          const std::vector<Layer*>& layersInTree);

    void updateTreeHasFrameRateVote();
    bool propagateFrameRateForLayerTree(FrameRate parentFrameRate, bool* transactionNeeded);
    bool setFrameRateForLayerTree(FrameRate);
    void setZOrderRelativeOf(const wp<Layer>& relativeOf);
    bool isTrustedOverlay() const;
    gui::DropInputMode getDropInputMode() const;
    void handleDropInputMode(gui::WindowInfo& info) const;

    // Find the root of the cloned hierarchy, this means the first non cloned parent.
    // This will return null if first non cloned parent is not found.
    sp<Layer> getClonedRoot();

    // Finds the top most layer in the hierarchy. This will find the root Layer where the parent is
    // null.
    sp<Layer> getRootLayer();

    // Fills in the touch occlusion mode of the first parent (including this layer) that
    // hasInputInfo() or no-op if no such parent is found.
    void fillTouchOcclusionMode(gui::WindowInfo& info);

    // Fills in the frame and transform info for the gui::WindowInfo.
    void fillInputFrameInfo(gui::WindowInfo&, const ui::Transform& screenToDisplay);

    // Cached properties computed from drawing state
    // Effective transform taking into account parent transforms and any parent scaling, which is
    // a transform from the current layer coordinate space to display(screen) coordinate space.
    ui::Transform mEffectiveTransform;

    // Bounds of the layer before any transformation is applied and before it has been cropped
    // by its parents.
    FloatRect mSourceBounds;

    // Bounds of the layer in layer space. This is the mSourceBounds cropped by its layer crop and
    // its parent bounds.
    FloatRect mBounds;

    // Layer bounds in screen space.
    FloatRect mScreenBounds;

    bool mGetHandleCalled = false;

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

    // Game mode for the layer. Set by WindowManagerShell and recorded by SurfaceFlingerStats.
    GameMode mGameMode = GameMode::Unsupported;

    // A list of regions on this layer that should have blurs.
    const std::vector<BlurRegion> getBlurRegions() const;

    bool mIsAtRoot = false;

    uint32_t mLayerCreationFlags;
    bool findInHierarchy(const sp<Layer>&);
};

std::ostream& operator<<(std::ostream& stream, const Layer::FrameRate& rate);

} // namespace android
