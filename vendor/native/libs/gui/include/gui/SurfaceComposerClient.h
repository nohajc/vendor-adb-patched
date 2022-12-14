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

#include <stdint.h>
#include <sys/types.h>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include <binder/IBinder.h>

#include <utils/RefBase.h>
#include <utils/Singleton.h>
#include <utils/SortedVector.h>
#include <utils/threads.h>

#include <ui/BlurRegion.h>
#include <ui/ConfigStoreTypes.h>
#include <ui/DisplayedFrameStats.h>
#include <ui/FrameStats.h>
#include <ui/GraphicTypes.h>
#include <ui/PixelFormat.h>
#include <ui/Rotation.h>

#include <gui/CpuConsumer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ITransactionCompletedListener.h>
#include <gui/LayerState.h>
#include <gui/SurfaceControl.h>
#include <gui/WindowInfosListenerReporter.h>
#include <math/vec3.h>

namespace android {

class HdrCapabilities;
class ISurfaceComposerClient;
class IGraphicBufferProducer;
class IRegionSamplingListener;
class ITunnelModeEnabledListener;
class Region;

struct SurfaceControlStats {
    SurfaceControlStats(const sp<SurfaceControl>& sc, nsecs_t latchTime, nsecs_t acquireTime,
                        const sp<Fence>& presentFence, const sp<Fence>& prevReleaseFence,
                        uint32_t hint, FrameEventHistoryStats eventStats, uint32_t currentMaxAcquiredBufferCount)
          : surfaceControl(sc),
            latchTime(latchTime),
            acquireTime(acquireTime),
            presentFence(presentFence),
            previousReleaseFence(prevReleaseFence),
            transformHint(hint),
            frameEventStats(eventStats),
            currentMaxAcquiredBufferCount(currentMaxAcquiredBufferCount) {}

    sp<SurfaceControl> surfaceControl;
    nsecs_t latchTime = -1;
    nsecs_t acquireTime = -1;
    sp<Fence> presentFence;
    sp<Fence> previousReleaseFence;
    uint32_t transformHint = 0;
    FrameEventHistoryStats frameEventStats;
    uint32_t currentMaxAcquiredBufferCount = 0;
};

using TransactionCompletedCallbackTakesContext =
        std::function<void(void* /*context*/, nsecs_t /*latchTime*/,
                           const sp<Fence>& /*presentFence*/,
                           const std::vector<SurfaceControlStats>& /*stats*/)>;
using TransactionCompletedCallback =
        std::function<void(nsecs_t /*latchTime*/, const sp<Fence>& /*presentFence*/,
                           const std::vector<SurfaceControlStats>& /*stats*/)>;
using ReleaseBufferCallback =
        std::function<void(const ReleaseCallbackId&, const sp<Fence>& /*releaseFence*/,
                           uint32_t transformHint, uint32_t currentMaxAcquiredBufferCount)>;

using SurfaceStatsCallback =
        std::function<void(void* /*context*/, nsecs_t /*latchTime*/,
                           const sp<Fence>& /*presentFence*/,
                           const SurfaceStats& /*stats*/)>;

// ---------------------------------------------------------------------------

class SurfaceComposerClient : public RefBase
{
    friend class Composer;
public:
                SurfaceComposerClient();
                SurfaceComposerClient(const sp<ISurfaceComposerClient>& client);
    virtual     ~SurfaceComposerClient();

    // Always make sure we could initialize
    status_t    initCheck() const;

    // Return the connection of this client
    sp<IBinder> connection() const;

    // Forcibly remove connection before all references have gone away.
    void        dispose();

    // callback when the composer is dies
    status_t linkToComposerDeath(const sp<IBinder::DeathRecipient>& recipient,
            void* cookie = nullptr, uint32_t flags = 0);

    // Get transactional state of given display.
    static status_t getDisplayState(const sp<IBinder>& display, ui::DisplayState*);

    // Get immutable information about given physical display.
    static status_t getStaticDisplayInfo(const sp<IBinder>& display, ui::StaticDisplayInfo*);

    // Get dynamic information about given physical display.
    static status_t getDynamicDisplayInfo(const sp<IBinder>& display, ui::DynamicDisplayInfo*);

    // Shorthand for the active display mode from getDynamicDisplayInfo().
    // TODO(b/180391891): Update clients to use getDynamicDisplayInfo and remove this function.
    static status_t getActiveDisplayMode(const sp<IBinder>& display, ui::DisplayMode*);

    // Sets the refresh rate boundaries for the display.
    static status_t setDesiredDisplayModeSpecs(
            const sp<IBinder>& displayToken, ui::DisplayModeId defaultMode,
            bool allowGroupSwitching, float primaryRefreshRateMin, float primaryRefreshRateMax,
            float appRequestRefreshRateMin, float appRequestRefreshRateMax);
    // Gets the refresh rate boundaries for the display.
    static status_t getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                               ui::DisplayModeId* outDefaultMode,
                                               bool* outAllowGroupSwitching,
                                               float* outPrimaryRefreshRateMin,
                                               float* outPrimaryRefreshRateMax,
                                               float* outAppRequestRefreshRateMin,
                                               float* outAppRequestRefreshRateMax);

    // Get the coordinates of the display's native color primaries
    static status_t getDisplayNativePrimaries(const sp<IBinder>& display,
            ui::DisplayPrimaries& outPrimaries);

    // Sets the active color mode for the given display
    static status_t setActiveColorMode(const sp<IBinder>& display,
            ui::ColorMode colorMode);

    // Switches on/off Auto Low Latency Mode on the connected display. This should only be
    // called if the connected display supports Auto Low Latency Mode as reported by
    // #getAutoLowLatencyModeSupport
    static void setAutoLowLatencyMode(const sp<IBinder>& display, bool on);

    // Turns Game mode on/off on the connected display. This should only be called
    // if the display supports Game content type, as reported by #getGameContentTypeSupport
    static void setGameContentType(const sp<IBinder>& display, bool on);

    /* Triggers screen on/off or low power mode and waits for it to complete */
    static void setDisplayPowerMode(const sp<IBinder>& display, int mode);

    /* Returns the composition preference of the default data space and default pixel format,
     * as well as the wide color gamut data space and wide color gamut pixel format.
     * If the wide color gamut data space is V0_SRGB, then it implies that the platform
     * has no wide color gamut support.
     */
    static status_t getCompositionPreference(ui::Dataspace* defaultDataspace,
                                             ui::PixelFormat* defaultPixelFormat,
                                             ui::Dataspace* wideColorGamutDataspace,
                                             ui::PixelFormat* wideColorGamutPixelFormat);

    /*
     * Gets whether SurfaceFlinger can support protected content in GPU composition.
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    static bool getProtectedContentSupport();

    /**
     * Gets the context priority of surface flinger's render engine.
     */
    static int getGPUContextPriority();

    /**
     * Uncaches a buffer in ISurfaceComposer. It must be uncached via a transaction so that it is
     * in order with other transactions that use buffers.
     */
    static void doUncacheBufferTransaction(uint64_t cacheId);

    // Queries whether a given display is wide color display.
    static status_t isWideColorDisplay(const sp<IBinder>& display, bool* outIsWideColorDisplay);

    /*
     * Returns whether brightness operations are supported on a display.
     *
     * displayToken
     *      The token of the display.
     *
     * Returns whether brightness operations are supported on a display or not.
     */
    static bool getDisplayBrightnessSupport(const sp<IBinder>& displayToken);

    /*
     * Sets the brightness of a display.
     *
     * displayToken
     *      The token of the display whose brightness is set.
     * brightness
     *      A number between 0.0 (minimum brightness) and 1.0 (maximum brightness), or -1.0f to
     *      turn the backlight off.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND    if the display handle is invalid, or
     *      BAD_VALUE         if the brightness value is invalid, or
     *      INVALID_OPERATION if brightness operaetions are not supported.
     */
    static status_t setDisplayBrightness(const sp<IBinder>& displayToken,
                                         const gui::DisplayBrightness& brightness);

    static status_t addHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                            const sp<gui::IHdrLayerInfoListener>& listener);
    static status_t removeHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                               const sp<gui::IHdrLayerInfoListener>& listener);

    /*
     * Sends a power boost to the composer. This function is asynchronous.
     *
     * boostId
     *      boost id according to android::hardware::power::Boost
     *
     * Returns NO_ERROR upon success.
     */
    static status_t notifyPowerBoost(int32_t boostId);

    /*
     * Sets the global configuration for all the shadows drawn by SurfaceFlinger. Shadow follows
     * material design guidelines.
     *
     * ambientColor
     *      Color to the ambient shadow. The alpha is premultiplied.
     *
     * spotColor
     *      Color to the spot shadow. The alpha is premultiplied. The position of the spot shadow
     *      depends on the light position.
     *
     * lightPosY/lightPosZ
     *      Position of the light used to cast the spot shadow. The X value is always the display
     *      width / 2.
     *
     * lightRadius
     *      Radius of the light casting the shadow.
     */
    static status_t setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                            float lightPosY, float lightPosZ, float lightRadius);

    // ------------------------------------------------------------------------
    // surface creation / destruction

    static sp<SurfaceComposerClient> getDefault();

    //! Create a surface
    sp<SurfaceControl> createSurface(const String8& name, // name of the surface
                                     uint32_t w,          // width in pixel
                                     uint32_t h,          // height in pixel
                                     PixelFormat format,  // pixel-format desired
                                     uint32_t flags = 0,  // usage flags
                                     const sp<IBinder>& parentHandle = nullptr, // parentHandle
                                     LayerMetadata metadata = LayerMetadata(),  // metadata
                                     uint32_t* outTransformHint = nullptr);

    status_t createSurfaceChecked(const String8& name, // name of the surface
                                  uint32_t w,          // width in pixel
                                  uint32_t h,          // height in pixel
                                  PixelFormat format,  // pixel-format desired
                                  sp<SurfaceControl>* outSurface,
                                  uint32_t flags = 0,                        // usage flags
                                  const sp<IBinder>& parentHandle = nullptr, // parentHandle
                                  LayerMetadata metadata = LayerMetadata(),  // metadata
                                  uint32_t* outTransformHint = nullptr);

    //! Create a surface
    sp<SurfaceControl> createWithSurfaceParent(const String8& name,       // name of the surface
                                               uint32_t w,                // width in pixel
                                               uint32_t h,                // height in pixel
                                               PixelFormat format,        // pixel-format desired
                                               uint32_t flags = 0,        // usage flags
                                               Surface* parent = nullptr, // parent
                                               LayerMetadata metadata = LayerMetadata(), // metadata
                                               uint32_t* outTransformHint = nullptr);

    // Creates a mirrored hierarchy for the mirrorFromSurface. This returns a SurfaceControl
    // which is a parent of the root of the mirrored hierarchy.
    //
    //  Real Hierarchy    Mirror
    //                      SC (value that's returned)
    //                      |
    //      A               A'
    //      |               |
    //      B               B'
    sp<SurfaceControl> mirrorSurface(SurfaceControl* mirrorFromSurface);

    //! Create a virtual display
    static sp<IBinder> createDisplay(const String8& displayName, bool secure);

    //! Destroy a virtual display
    static void destroyDisplay(const sp<IBinder>& display);

    //! Get stable IDs for connected physical displays
    static std::vector<PhysicalDisplayId> getPhysicalDisplayIds();
    static status_t getPrimaryPhysicalDisplayId(PhysicalDisplayId*);
    static std::optional<PhysicalDisplayId> getInternalDisplayId();

    //! Get token for a physical display given its stable ID
    static sp<IBinder> getPhysicalDisplayToken(PhysicalDisplayId displayId);
    static sp<IBinder> getInternalDisplayToken();

    static status_t enableVSyncInjections(bool enable);

    static status_t injectVSync(nsecs_t when);

    struct SCHash {
        std::size_t operator()(const sp<SurfaceControl>& sc) const {
            return std::hash<SurfaceControl *>{}(sc.get());
        }
    };

    struct IBinderHash {
        std::size_t operator()(const sp<IBinder>& iBinder) const {
            return std::hash<IBinder*>{}(iBinder.get());
        }
    };

    struct TCLHash {
        std::size_t operator()(const sp<ITransactionCompletedListener>& tcl) const {
            return std::hash<IBinder*>{}((tcl) ? IInterface::asBinder(tcl).get() : nullptr);
        }
    };

    struct CallbackInfo {
        // All the callbacks that have been requested for a TransactionCompletedListener in the
        // Transaction
        std::unordered_set<CallbackId, CallbackIdHash> callbackIds;
        // All the SurfaceControls that have been modified in this TransactionCompletedListener's
        // process that require a callback if there is one or more callbackIds set.
        std::unordered_set<sp<SurfaceControl>, SCHash> surfaceControls;
    };

    class Transaction : public Parcelable {
    private:
        static std::atomic<uint32_t> idCounter;
        int64_t generateId();

    protected:
        std::unordered_map<sp<IBinder>, ComposerState, IBinderHash> mComposerStates;
        SortedVector<DisplayState> mDisplayStates;
        std::unordered_map<sp<ITransactionCompletedListener>, CallbackInfo, TCLHash>
                mListenerCallbacks;

        uint64_t mId;

        uint32_t mForceSynchronous = 0;
        uint32_t mTransactionNestCount = 0;
        bool mAnimation = false;
        bool mEarlyWakeupStart = false;
        bool mEarlyWakeupEnd = false;

        // Indicates that the Transaction contains a buffer that should be cached
        bool mContainsBuffer = false;

        // mDesiredPresentTime is the time in nanoseconds that the client would like the transaction
        // to be presented. When it is not possible to present at exactly that time, it will be
        // presented after the time has passed.
        //
        // If the client didn't pass a desired presentation time, mDesiredPresentTime will be
        // populated to the time setBuffer was called, and mIsAutoTimestamp will be set to true.
        //
        // Desired present times that are more than 1 second in the future may be ignored.
        // When a desired present time has already passed, the transaction will be presented as soon
        // as possible.
        //
        // Transactions from the same process are presented in the same order that they are applied.
        // The desired present time does not affect this ordering.
        int64_t mDesiredPresentTime = 0;
        bool mIsAutoTimestamp = true;

        // The vsync id provided by Choreographer.getVsyncId and the input event id
        FrameTimelineInfo mFrameTimelineInfo;

        // If not null, transactions will be queued up using this token otherwise a common token
        // per process will be used.
        sp<IBinder> mApplyToken = nullptr;

        InputWindowCommands mInputWindowCommands;
        int mStatus = NO_ERROR;

        layer_state_t* getLayerState(const sp<SurfaceControl>& sc);
        DisplayState& getDisplayState(const sp<IBinder>& token);

        void cacheBuffers();
        void registerSurfaceControlForCallback(const sp<SurfaceControl>& sc);
        void setReleaseBufferCallback(layer_state_t*, const ReleaseCallbackId&,
                                      ReleaseBufferCallback);
        void removeReleaseBufferCallback(layer_state_t*);

    public:
        Transaction();
        virtual ~Transaction() = default;
        Transaction(Transaction const& other);

        // Factory method that creates a new Transaction instance from the parcel.
        static std::unique_ptr<Transaction> createFromParcel(const Parcel* parcel);

        status_t writeToParcel(Parcel* parcel) const override;
        status_t readFromParcel(const Parcel* parcel) override;

        // Clears the contents of the transaction without applying it.
        void clear();

        status_t apply(bool synchronous = false);
        // Merge another transaction in to this one, clearing other
        // as if it had been applied.
        Transaction& merge(Transaction&& other);
        Transaction& show(const sp<SurfaceControl>& sc);
        Transaction& hide(const sp<SurfaceControl>& sc);
        Transaction& setPosition(const sp<SurfaceControl>& sc,
                float x, float y);
        Transaction& setSize(const sp<SurfaceControl>& sc,
                uint32_t w, uint32_t h);
        Transaction& setLayer(const sp<SurfaceControl>& sc,
                int32_t z);

        // Sets a Z order relative to the Surface specified by "relativeTo" but
        // without becoming a full child of the relative. Z-ordering works exactly
        // as if it were a child however.
        //
        // As a nod to sanity, only non-child surfaces may have a relative Z-order.
        //
        // This overrides any previous call and is overriden by any future calls
        // to setLayer.
        //
        // If the relative is removed, the Surface will have no layer and be
        // invisible, until the next time set(Relative)Layer is called.
        Transaction& setRelativeLayer(const sp<SurfaceControl>& sc,
                                      const sp<SurfaceControl>& relativeTo, int32_t z);
        Transaction& setFlags(const sp<SurfaceControl>& sc,
                uint32_t flags, uint32_t mask);
        Transaction& setTransparentRegionHint(const sp<SurfaceControl>& sc,
                const Region& transparentRegion);
        Transaction& setAlpha(const sp<SurfaceControl>& sc,
                float alpha);
        Transaction& setMatrix(const sp<SurfaceControl>& sc,
                float dsdx, float dtdx, float dtdy, float dsdy);
        Transaction& setCrop(const sp<SurfaceControl>& sc, const Rect& crop);
        Transaction& setCornerRadius(const sp<SurfaceControl>& sc, float cornerRadius);
        Transaction& setBackgroundBlurRadius(const sp<SurfaceControl>& sc,
                                             int backgroundBlurRadius);
        Transaction& setBlurRegions(const sp<SurfaceControl>& sc,
                                    const std::vector<BlurRegion>& regions);
        Transaction& setLayerStack(const sp<SurfaceControl>& sc, uint32_t layerStack);
        Transaction& setMetadata(const sp<SurfaceControl>& sc, uint32_t key, const Parcel& p);

        /// Reparents the current layer to the new parent handle. The new parent must not be null.
        Transaction& reparent(const sp<SurfaceControl>& sc, const sp<SurfaceControl>& newParent);

        Transaction& setColor(const sp<SurfaceControl>& sc, const half3& color);

        // Sets the background color of a layer with the specified color, alpha, and dataspace
        Transaction& setBackgroundColor(const sp<SurfaceControl>& sc, const half3& color,
                                        float alpha, ui::Dataspace dataspace);

        Transaction& setTransform(const sp<SurfaceControl>& sc, uint32_t transform);
        Transaction& setTransformToDisplayInverse(const sp<SurfaceControl>& sc,
                                                  bool transformToDisplayInverse);
        Transaction& setBuffer(const sp<SurfaceControl>& sc, const sp<GraphicBuffer>& buffer,
                               const ReleaseCallbackId& id = ReleaseCallbackId::INVALID_ID,
                               ReleaseBufferCallback callback = nullptr);
        Transaction& setCachedBuffer(const sp<SurfaceControl>& sc, int32_t bufferId);
        Transaction& setAcquireFence(const sp<SurfaceControl>& sc, const sp<Fence>& fence);
        Transaction& setDataspace(const sp<SurfaceControl>& sc, ui::Dataspace dataspace);
        Transaction& setHdrMetadata(const sp<SurfaceControl>& sc, const HdrMetadata& hdrMetadata);
        Transaction& setSurfaceDamageRegion(const sp<SurfaceControl>& sc,
                                            const Region& surfaceDamageRegion);
        Transaction& setApi(const sp<SurfaceControl>& sc, int32_t api);
        Transaction& setSidebandStream(const sp<SurfaceControl>& sc,
                                       const sp<NativeHandle>& sidebandStream);
        Transaction& setDesiredPresentTime(nsecs_t desiredPresentTime);
        Transaction& setColorSpaceAgnostic(const sp<SurfaceControl>& sc, const bool agnostic);

        // Sets information about the priority of the frame.
        Transaction& setFrameRateSelectionPriority(const sp<SurfaceControl>& sc, int32_t priority);

        Transaction& addTransactionCallback(TransactionCompletedCallbackTakesContext callback,
                                            void* callbackContext, CallbackId::Type callbackType);

        Transaction& addTransactionCompletedCallback(
                TransactionCompletedCallbackTakesContext callback, void* callbackContext);

        Transaction& addTransactionCommittedCallback(
                TransactionCompletedCallbackTakesContext callback, void* callbackContext);

        // ONLY FOR BLAST ADAPTER
        Transaction& notifyProducerDisconnect(const sp<SurfaceControl>& sc);
        // Set the framenumber generated by the graphics producer to mimic BufferQueue behaviour.
        Transaction& setFrameNumber(const sp<SurfaceControl>& sc, uint64_t frameNumber);

        Transaction& setInputWindowInfo(const sp<SurfaceControl>& sc, const gui::WindowInfo& info);
        Transaction& setFocusedWindow(const gui::FocusRequest& request);
        Transaction& syncInputWindows();

        // Set a color transform matrix on the given layer on the built-in display.
        Transaction& setColorTransform(const sp<SurfaceControl>& sc, const mat3& matrix,
                                       const vec3& translation);

        Transaction& setGeometry(const sp<SurfaceControl>& sc,
                const Rect& source, const Rect& dst, int transform);
        Transaction& setShadowRadius(const sp<SurfaceControl>& sc, float cornerRadius);

        Transaction& setFrameRate(const sp<SurfaceControl>& sc, float frameRate,
                                  int8_t compatibility, int8_t changeFrameRateStrategy);

        // Set by window manager indicating the layer and all its children are
        // in a different orientation than the display. The hint suggests that
        // the graphic producers should receive a transform hint as if the
        // display was in this orientation. When the display changes to match
        // the layer orientation, the graphic producer may not need to allocate
        // a buffer of a different size.
        Transaction& setFixedTransformHint(const sp<SurfaceControl>& sc, int32_t transformHint);

        // Sets the frame timeline vsync id received from choreographer that corresponds
        // to the transaction, and the input event id that identifies the input event that caused
        // the current frame.
        Transaction& setFrameTimelineInfo(const FrameTimelineInfo& frameTimelineInfo);

        // Indicates that the consumer should acquire the next frame as soon as it
        // can and not wait for a frame to become available. This is only relevant
        // in shared buffer mode.
        Transaction& setAutoRefresh(const sp<SurfaceControl>& sc, bool autoRefresh);

        // Sets that this surface control and its children are trusted overlays for input
        Transaction& setTrustedOverlay(const sp<SurfaceControl>& sc, bool isTrustedOverlay);

        // Queues up transactions using this token in SurfaceFlinger.  By default, all transactions
        // from a client are placed on the same queue. This can be used to prevent multiple
        // transactions from blocking each other.
        Transaction& setApplyToken(const sp<IBinder>& token);

        /**
         * Provides the stretch effect configured on a container that the
         * surface is rendered within.
         * @param sc target surface the stretch should be applied to
         * @param stretchEffect the corresponding stretch effect to be applied
         *    to the surface. This can be directly on the surface itself or
         *    configured from a parent of the surface in which case the
         *    StretchEffect provided has parameters mapping the position of
         *    the surface within the container that has the stretch configured
         *    on it
         * @return The transaction being constructed
         */
        Transaction& setStretchEffect(const sp<SurfaceControl>& sc,
                                      const StretchEffect& stretchEffect);

        Transaction& setBufferCrop(const sp<SurfaceControl>& sc, const Rect& bufferCrop);
        Transaction& setDestinationFrame(const sp<SurfaceControl>& sc,
                                         const Rect& destinationFrame);
        Transaction& setDropInputMode(const sp<SurfaceControl>& sc, gui::DropInputMode mode);

        status_t setDisplaySurface(const sp<IBinder>& token,
                const sp<IGraphicBufferProducer>& bufferProducer);

        void setDisplayLayerStack(const sp<IBinder>& token, uint32_t layerStack);

        void setDisplayFlags(const sp<IBinder>& token, uint32_t flags);

        /* setDisplayProjection() defines the projection of layer stacks
         * to a given display.
         *
         * - orientation defines the display's orientation.
         * - layerStackRect defines which area of the window manager coordinate
         * space will be used.
         * - displayRect defines where on the display will layerStackRect be
         * mapped to. displayRect is specified post-orientation, that is
         * it uses the orientation seen by the end-user.
         */
        void setDisplayProjection(const sp<IBinder>& token, ui::Rotation orientation,
                                  const Rect& layerStackRect, const Rect& displayRect);
        void setDisplaySize(const sp<IBinder>& token, uint32_t width, uint32_t height);
        void setAnimationTransaction();
        void setEarlyWakeupStart();
        void setEarlyWakeupEnd();

        /**
         * Strip the transaction of all permissioned requests, required when
         * accepting transactions across process boundaries.
         *
         * TODO (b/213644870): Remove all permissioned things from Transaction
         */
        void sanitize();
    };

    status_t clearLayerFrameStats(const sp<IBinder>& token) const;
    status_t getLayerFrameStats(const sp<IBinder>& token, FrameStats* outStats) const;
    static status_t clearAnimationFrameStats();
    static status_t getAnimationFrameStats(FrameStats* outStats);

    static status_t overrideHdrTypes(const sp<IBinder>& display,
                                     const std::vector<ui::Hdr>& hdrTypes);

    static status_t onPullAtom(const int32_t atomId, std::string* outData, bool* success);

    static void setDisplayProjection(const sp<IBinder>& token, ui::Rotation orientation,
                                     const Rect& layerStackRect, const Rect& displayRect);

    inline sp<ISurfaceComposerClient> getClient() { return mClient; }

    static status_t getDisplayedContentSamplingAttributes(const sp<IBinder>& display,
                                                          ui::PixelFormat* outFormat,
                                                          ui::Dataspace* outDataspace,
                                                          uint8_t* outComponentMask);
    static status_t setDisplayContentSamplingEnabled(const sp<IBinder>& display, bool enable,
                                                     uint8_t componentMask, uint64_t maxFrames);

    static status_t getDisplayedContentSample(const sp<IBinder>& display, uint64_t maxFrames,
                                              uint64_t timestamp, DisplayedFrameStats* outStats);
    static status_t addRegionSamplingListener(const Rect& samplingArea,
                                              const sp<IBinder>& stopLayerHandle,
                                              const sp<IRegionSamplingListener>& listener);
    static status_t removeRegionSamplingListener(const sp<IRegionSamplingListener>& listener);
    static status_t addFpsListener(int32_t taskId, const sp<gui::IFpsListener>& listener);
    static status_t removeFpsListener(const sp<gui::IFpsListener>& listener);
    static status_t addTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& listener);
    static status_t removeTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& listener);

    status_t addWindowInfosListener(const sp<gui::WindowInfosListener>& windowInfosListener);
    status_t removeWindowInfosListener(const sp<gui::WindowInfosListener>& windowInfosListener);

private:
    virtual void onFirstRef();

    mutable     Mutex                       mLock;
                status_t                    mStatus;
                sp<ISurfaceComposerClient>  mClient;
};

// ---------------------------------------------------------------------------

class ScreenshotClient {
public:
    static status_t captureDisplay(const DisplayCaptureArgs& captureArgs,
                                   const sp<IScreenCaptureListener>& captureListener);
    static status_t captureDisplay(uint64_t displayOrLayerStack,
                                   const sp<IScreenCaptureListener>& captureListener);
    static status_t captureLayers(const LayerCaptureArgs& captureArgs,
                                  const sp<IScreenCaptureListener>& captureListener);
};

// ---------------------------------------------------------------------------

class JankDataListener : public VirtualLightRefBase {
public:
    virtual ~JankDataListener() = 0;
    virtual void onJankDataAvailable(const std::vector<JankData>& jankData) = 0;
};

class TransactionCompletedListener : public BnTransactionCompletedListener {
public:
    TransactionCompletedListener();

protected:
    int64_t getNextIdLocked() REQUIRES(mMutex);

    std::mutex mMutex;

    // This lock needs to be recursive so we can unregister a callback from within that callback.
    std::recursive_mutex mSurfaceStatsListenerMutex;

    bool mListening GUARDED_BY(mMutex) = false;

    int64_t mCallbackIdCounter GUARDED_BY(mMutex) = 1;
    struct CallbackTranslation {
        TransactionCompletedCallback callbackFunction;
        std::unordered_map<sp<IBinder>, sp<SurfaceControl>, SurfaceComposerClient::IBinderHash>
                surfaceControls;
    };

    struct SurfaceStatsCallbackEntry {
        SurfaceStatsCallbackEntry(void* context, void* cookie, SurfaceStatsCallback callback)
                : context(context),
                cookie(cookie),
                callback(callback) {}

        void* context;
        void* cookie;
        SurfaceStatsCallback callback;
    };

    std::unordered_map<CallbackId, CallbackTranslation, CallbackIdHash> mCallbacks
            GUARDED_BY(mMutex);
    std::multimap<int32_t, sp<JankDataListener>> mJankListeners GUARDED_BY(mMutex);
    std::unordered_map<ReleaseCallbackId, ReleaseBufferCallback, ReleaseBufferCallbackIdHash>
            mReleaseBufferCallbacks GUARDED_BY(mMutex);

    // This is protected by mSurfaceStatsListenerMutex, but GUARDED_BY isn't supported for
    // std::recursive_mutex
    std::multimap<int32_t, SurfaceStatsCallbackEntry> mSurfaceStatsListeners;

public:
    static sp<TransactionCompletedListener> getInstance();
    static sp<ITransactionCompletedListener> getIInstance();

    void startListeningLocked() REQUIRES(mMutex);

    CallbackId addCallbackFunction(
            const TransactionCompletedCallback& callbackFunction,
            const std::unordered_set<sp<SurfaceControl>, SurfaceComposerClient::SCHash>&
                    surfaceControls,
            CallbackId::Type callbackType);

    void addSurfaceControlToCallbacks(
            const sp<SurfaceControl>& surfaceControl,
            const std::unordered_set<CallbackId, CallbackIdHash>& callbackIds);

    /*
     * Adds a jank listener to be informed about SurfaceFlinger's jank classification for a specific
     * surface. Jank classifications arrive as part of the transaction callbacks about previous
     * frames submitted to this Surface.
     */
    void addJankListener(const sp<JankDataListener>& listener, sp<SurfaceControl> surfaceControl);

    /**
     * Removes a jank listener previously added to addJankCallback.
     */
    void removeJankListener(const sp<JankDataListener>& listener);

    void addSurfaceStatsListener(void* context, void* cookie, sp<SurfaceControl> surfaceControl,
                SurfaceStatsCallback listener);
    void removeSurfaceStatsListener(void* context, void* cookie);

    void setReleaseBufferCallback(const ReleaseCallbackId&, ReleaseBufferCallback);
    void removeReleaseBufferCallback(const ReleaseCallbackId&);

    // BnTransactionCompletedListener overrides
    void onTransactionCompleted(ListenerStats stats) override;
    void onReleaseBuffer(ReleaseCallbackId, sp<Fence> releaseFence, uint32_t transformHint,
                         uint32_t currentMaxAcquiredBufferCount) override;

    // For Testing Only
    static void setInstance(const sp<TransactionCompletedListener>&);

private:
    ReleaseBufferCallback popReleaseBufferCallbackLocked(const ReleaseCallbackId&);
    static sp<TransactionCompletedListener> sInstance;
};

} // namespace android
