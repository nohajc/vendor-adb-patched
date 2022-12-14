/*
 * Copyright (C) 2006 The Android Open Source Project
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

#include <android/gui/DisplayBrightness.h>
#include <android/gui/IFpsListener.h>
#include <android/gui/IHdrLayerInfoListener.h>
#include <android/gui/IScreenCaptureListener.h>
#include <android/gui/ITransactionTraceListener.h>
#include <android/gui/ITunnelModeEnabledListener.h>
#include <android/gui/IWindowInfosListener.h>
#include <binder/IBinder.h>
#include <binder/IInterface.h>
#include <ftl/Flags.h>
#include <gui/FrameTimelineInfo.h>
#include <gui/ITransactionCompletedListener.h>
#include <math/vec4.h>
#include <stdint.h>
#include <sys/types.h>
#include <ui/ConfigStoreTypes.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMode.h>
#include <ui/DisplayedFrameStats.h>
#include <ui/FrameStats.h>
#include <ui/GraphicBuffer.h>
#include <ui/GraphicTypes.h>
#include <ui/PixelFormat.h>
#include <ui/Rotation.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>
#include <utils/Vector.h>

#include <optional>
#include <unordered_set>
#include <vector>

namespace android {

struct client_cache_t;
struct ComposerState;
struct DisplayCaptureArgs;
struct DisplayStatInfo;
struct DisplayState;
struct InputWindowCommands;
struct LayerCaptureArgs;
class LayerDebugInfo;
class HdrCapabilities;
class IDisplayEventConnection;
class IGraphicBufferProducer;
class ISurfaceComposerClient;
class IRegionSamplingListener;
class Rect;
enum class FrameEvent;

using gui::IScreenCaptureListener;

namespace ui {

struct DisplayMode;
struct DisplayState;
struct DynamicDisplayInfo;
struct StaticDisplayInfo;

} // namespace ui

/*
 * This class defines the Binder IPC interface for accessing various
 * SurfaceFlinger features.
 */
class ISurfaceComposer: public IInterface {
public:
    DECLARE_META_INTERFACE(SurfaceComposer)

    static constexpr size_t MAX_LAYERS = 4096;

    // flags for setTransactionState()
    enum {
        eSynchronous = 0x01,
        eAnimation = 0x02,

        // Explicit indication that this transaction and others to follow will likely result in a
        // lot of layers being composed, and thus, SurfaceFlinger should wake-up earlier to avoid
        // missing frame deadlines. In this case SurfaceFlinger will wake up at
        // (sf vsync offset - debug.sf.early_phase_offset_ns). SurfaceFlinger will continue to be
        // in the early configuration until it receives eEarlyWakeupEnd. These flags are
        // expected to be used by WindowManager only and are guarded by
        // android.permission.ACCESS_SURFACE_FLINGER
        eEarlyWakeupStart = 0x08,
        eEarlyWakeupEnd = 0x10,
    };

    enum VsyncSource {
        eVsyncSourceApp = 0,
        eVsyncSourceSurfaceFlinger = 1
    };

    enum class EventRegistration {
        modeChanged = 1 << 0,
        frameRateOverride = 1 << 1,
    };

    using EventRegistrationFlags = Flags<EventRegistration>;

    /*
     * Create a connection with SurfaceFlinger.
     */
    virtual sp<ISurfaceComposerClient> createConnection() = 0;

    /* return an IDisplayEventConnection */
    virtual sp<IDisplayEventConnection> createDisplayEventConnection(
            VsyncSource vsyncSource = eVsyncSourceApp,
            EventRegistrationFlags eventRegistration = {}) = 0;

    /* create a virtual display
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    virtual sp<IBinder> createDisplay(const String8& displayName,
            bool secure) = 0;

    /* destroy a virtual display
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    virtual void destroyDisplay(const sp<IBinder>& display) = 0;

    /* get stable IDs for connected physical displays.
     */
    virtual std::vector<PhysicalDisplayId> getPhysicalDisplayIds() const = 0;

    virtual status_t getPrimaryPhysicalDisplayId(PhysicalDisplayId*) const = 0;

    // TODO(b/74619554): Remove this stopgap once the framework is display-agnostic.
    std::optional<PhysicalDisplayId> getInternalDisplayId() const {
        const auto displayIds = getPhysicalDisplayIds();
        return displayIds.empty() ? std::nullopt : std::make_optional(displayIds.front());
    }

    /* get token for a physical display given its stable ID obtained via getPhysicalDisplayIds or a
     * DisplayEventReceiver hotplug event.
     */
    virtual sp<IBinder> getPhysicalDisplayToken(PhysicalDisplayId displayId) const = 0;

    // TODO(b/74619554): Remove this stopgap once the framework is display-agnostic.
    sp<IBinder> getInternalDisplayToken() const {
        const auto displayId = getInternalDisplayId();
        return displayId ? getPhysicalDisplayToken(*displayId) : nullptr;
    }

    /* open/close transactions. requires ACCESS_SURFACE_FLINGER permission */
    virtual status_t setTransactionState(
            const FrameTimelineInfo& frameTimelineInfo, const Vector<ComposerState>& state,
            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
            const InputWindowCommands& inputWindowCommands, int64_t desiredPresentTime,
            bool isAutoTimestamp, const client_cache_t& uncacheBuffer, bool hasListenerCallbacks,
            const std::vector<ListenerCallbacks>& listenerCallbacks, uint64_t transactionId) = 0;

    /* signal that we're done booting.
     * Requires ACCESS_SURFACE_FLINGER permission
     */
    virtual void bootFinished() = 0;

    /* verify that an IGraphicBufferProducer was created by SurfaceFlinger.
     */
    virtual bool authenticateSurfaceTexture(
            const sp<IGraphicBufferProducer>& surface) const = 0;

    /* Returns the frame timestamps supported by SurfaceFlinger.
     */
    virtual status_t getSupportedFrameTimestamps(
            std::vector<FrameEvent>* outSupported) const = 0;

    /* set display power mode. depending on the mode, it can either trigger
     * screen on, off or low power mode and wait for it to complete.
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    virtual void setPowerMode(const sp<IBinder>& display, int mode) = 0;


    /* returns display statistics for a given display
     * intended to be used by the media framework to properly schedule
     * video frames */
    virtual status_t getDisplayStats(const sp<IBinder>& display,
            DisplayStatInfo* stats) = 0;

    /**
     * Get transactional state of given display.
     */
    virtual status_t getDisplayState(const sp<IBinder>& display, ui::DisplayState*) = 0;

    /**
     * Gets immutable information about given physical display.
     */
    virtual status_t getStaticDisplayInfo(const sp<IBinder>& display, ui::StaticDisplayInfo*) = 0;

    /**
     * Gets dynamic information about given physical display.
     */
    virtual status_t getDynamicDisplayInfo(const sp<IBinder>& display, ui::DynamicDisplayInfo*) = 0;

    virtual status_t getDisplayNativePrimaries(const sp<IBinder>& display,
            ui::DisplayPrimaries& primaries) = 0;
    virtual status_t setActiveColorMode(const sp<IBinder>& display,
            ui::ColorMode colorMode) = 0;

    /**
     * Switches Auto Low Latency Mode on/off on the connected display, if it is
     * available. This should only be called if the display supports Auto Low
     * Latency Mode as reported in #getDynamicDisplayInfo.
     * For more information, see the HDMI 2.1 specification.
     */
    virtual void setAutoLowLatencyMode(const sp<IBinder>& display, bool on) = 0;

    /**
     * This will start sending infoframes to the connected display with
     * ContentType=Game (if on=true). This should only be called if the display
     * Game Content Type as reported in #getDynamicDisplayInfo.
     * For more information, see the HDMI 1.4 specification.
     */
    virtual void setGameContentType(const sp<IBinder>& display, bool on) = 0;

    /**
     * Capture the specified screen. This requires READ_FRAME_BUFFER
     * permission.  This function will fail if there is a secure window on
     * screen and DisplayCaptureArgs.captureSecureLayers is false.
     *
     * This function can capture a subregion (the source crop) of the screen.
     * The subregion can be optionally rotated.  It will also be scaled to
     * match the size of the output buffer.
     */
    virtual status_t captureDisplay(const DisplayCaptureArgs& args,
                                    const sp<IScreenCaptureListener>& captureListener) = 0;

    virtual status_t captureDisplay(uint64_t displayOrLayerStack,
                                    const sp<IScreenCaptureListener>& captureListener) = 0;

    template <class AA>
    struct SpHash {
        size_t operator()(const sp<AA>& k) const { return std::hash<AA*>()(k.get()); }
    };

    /**
     * Capture a subtree of the layer hierarchy, potentially ignoring the root node.
     * This requires READ_FRAME_BUFFER permission. This function will fail if there
     * is a secure window on screen
     */
    virtual status_t captureLayers(const LayerCaptureArgs& args,
                                   const sp<IScreenCaptureListener>& captureListener) = 0;

    /* Clears the frame statistics for animations.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t clearAnimationFrameStats() = 0;

    /* Gets the frame statistics for animations.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t getAnimationFrameStats(FrameStats* outStats) const = 0;

    /* Overrides the supported HDR modes for the given display device.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t overrideHdrTypes(const sp<IBinder>& display,
                                      const std::vector<ui::Hdr>& hdrTypes) = 0;

    /* Pulls surfaceflinger atoms global stats and layer stats to pipe to statsd.
     *
     * Requires the calling uid be from system server.
     */
    virtual status_t onPullAtom(const int32_t atomId, std::string* outData, bool* success) = 0;

    virtual status_t enableVSyncInjections(bool enable) = 0;

    virtual status_t injectVSync(nsecs_t when) = 0;

    /* Gets the list of active layers in Z order for debugging purposes
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t getLayerDebugInfo(std::vector<LayerDebugInfo>* outLayers) = 0;

    virtual status_t getColorManagement(bool* outGetColorManagement) const = 0;

    /* Gets the composition preference of the default data space and default pixel format,
     * as well as the wide color gamut data space and wide color gamut pixel format.
     * If the wide color gamut data space is V0_SRGB, then it implies that the platform
     * has no wide color gamut support.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t getCompositionPreference(ui::Dataspace* defaultDataspace,
                                              ui::PixelFormat* defaultPixelFormat,
                                              ui::Dataspace* wideColorGamutDataspace,
                                              ui::PixelFormat* wideColorGamutPixelFormat) const = 0;
    /*
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t getDisplayedContentSamplingAttributes(const sp<IBinder>& display,
                                                           ui::PixelFormat* outFormat,
                                                           ui::Dataspace* outDataspace,
                                                           uint8_t* outComponentMask) const = 0;

    /* Turns on the color sampling engine on the display.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t setDisplayContentSamplingEnabled(const sp<IBinder>& display, bool enable,
                                                      uint8_t componentMask,
                                                      uint64_t maxFrames) = 0;

    /* Returns statistics on the color profile of the last frame displayed for a given display
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t getDisplayedContentSample(const sp<IBinder>& display, uint64_t maxFrames,
                                               uint64_t timestamp,
                                               DisplayedFrameStats* outStats) const = 0;

    /*
     * Gets whether SurfaceFlinger can support protected content in GPU composition.
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t getProtectedContentSupport(bool* outSupported) const = 0;

    /*
     * Queries whether the given display is a wide color display.
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t isWideColorDisplay(const sp<IBinder>& token,
                                        bool* outIsWideColorDisplay) const = 0;

    /* Registers a listener to stream median luma updates from SurfaceFlinger.
     *
     * The sampling area is bounded by both samplingArea and the given stopLayerHandle
     * (i.e., only layers behind the stop layer will be captured and sampled).
     *
     * Multiple listeners may be provided so long as they have independent listeners.
     * If multiple listeners are provided, the effective sampling region for each listener will
     * be bounded by whichever stop layer has a lower Z value.
     *
     * Requires the same permissions as captureLayers and captureScreen.
     */
    virtual status_t addRegionSamplingListener(const Rect& samplingArea,
                                               const sp<IBinder>& stopLayerHandle,
                                               const sp<IRegionSamplingListener>& listener) = 0;

    /*
     * Removes a listener that was streaming median luma updates from SurfaceFlinger.
     */
    virtual status_t removeRegionSamplingListener(const sp<IRegionSamplingListener>& listener) = 0;

    /* Registers a listener that streams fps updates from SurfaceFlinger.
     *
     * The listener will stream fps updates for the layer tree rooted at the layer denoted by the
     * task ID, i.e., the layer must have the task ID as part of its layer metadata with key
     * METADATA_TASK_ID. If there is no such layer, then no fps is expected to be reported.
     *
     * Multiple listeners may be supported.
     *
     * Requires the READ_FRAME_BUFFER permission.
     */
    virtual status_t addFpsListener(int32_t taskId, const sp<gui::IFpsListener>& listener) = 0;
    /*
     * Removes a listener that was streaming fps updates from SurfaceFlinger.
     */
    virtual status_t removeFpsListener(const sp<gui::IFpsListener>& listener) = 0;

    /* Registers a listener to receive tunnel mode enabled updates from SurfaceFlinger.
     *
     * Requires ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t addTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& listener) = 0;

    /*
     * Removes a listener that was receiving tunnel mode enabled updates from SurfaceFlinger.
     *
     * Requires ACCESS_SURFACE_FLINGER permission.
     */
    virtual status_t removeTunnelModeEnabledListener(
            const sp<gui::ITunnelModeEnabledListener>& listener) = 0;

    /* Sets the refresh rate boundaries for the display.
     *
     * The primary refresh rate range represents display manager's general guidance on the display
     * modes we'll consider when switching refresh rates. Unless we get an explicit signal from an
     * app, we should stay within this range.
     *
     * The app request refresh rate range allows us to consider more display modes when switching
     * refresh rates. Although we should generally stay within the primary range, specific
     * considerations, such as layer frame rate settings specified via the setFrameRate() api, may
     * cause us to go outside the primary range. We never go outside the app request range. The app
     * request range will be greater than or equal to the primary refresh rate range, never smaller.
     *
     * defaultMode is used to narrow the list of display modes SurfaceFlinger will consider
     * switching between. Only modes with a mode group and resolution matching defaultMode
     * will be considered for switching. The defaultMode corresponds to an ID of mode in the list
     * of supported modes returned from getDynamicDisplayInfo().
     */
    virtual status_t setDesiredDisplayModeSpecs(
            const sp<IBinder>& displayToken, ui::DisplayModeId defaultMode,
            bool allowGroupSwitching, float primaryRefreshRateMin, float primaryRefreshRateMax,
            float appRequestRefreshRateMin, float appRequestRefreshRateMax) = 0;

    virtual status_t getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                                ui::DisplayModeId* outDefaultMode,
                                                bool* outAllowGroupSwitching,
                                                float* outPrimaryRefreshRateMin,
                                                float* outPrimaryRefreshRateMax,
                                                float* outAppRequestRefreshRateMin,
                                                float* outAppRequestRefreshRateMax) = 0;
    /*
     * Gets whether brightness operations are supported on a display.
     *
     * displayToken
     *      The token of the display.
     * outSupport
     *      An output parameter for whether brightness operations are supported.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND if the display is invalid, or
     *      BAD_VALUE      if the output parameter is invalid.
     */
    virtual status_t getDisplayBrightnessSupport(const sp<IBinder>& displayToken,
                                                 bool* outSupport) const = 0;

    /*
     * Sets the brightness of a display.
     *
     * displayToken
     *      The token of the display whose brightness is set.
     * brightness
     *      The DisplayBrightness info to set on the desired display.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND    if the display is invalid, or
     *      BAD_VALUE         if the brightness is invalid, or
     *      INVALID_OPERATION if brightness operations are not supported.
     */
    virtual status_t setDisplayBrightness(const sp<IBinder>& displayToken,
                                          const gui::DisplayBrightness& brightness) = 0;

    /*
     * Adds a listener that receives HDR layer information. This is used in combination
     * with setDisplayBrightness to adjust the display brightness depending on factors such
     * as whether or not HDR is in use.
     *
     * Returns NO_ERROR upon success or NAME_NOT_FOUND if the display is invalid.
     */
    virtual status_t addHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                             const sp<gui::IHdrLayerInfoListener>& listener) = 0;
    /*
     * Removes a listener that was added with addHdrLayerInfoListener.
     *
     * Returns NO_ERROR upon success, NAME_NOT_FOUND if the display is invalid, and BAD_VALUE if
     *     the listener wasn't registered.
     *
     */
    virtual status_t removeHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                                const sp<gui::IHdrLayerInfoListener>& listener) = 0;

    /*
     * Sends a power boost to the composer. This function is asynchronous.
     *
     * boostId
     *      boost id according to android::hardware::power::Boost
     *
     * Returns NO_ERROR upon success.
     */
    virtual status_t notifyPowerBoost(int32_t boostId) = 0;

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
    virtual status_t setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                             float lightPosY, float lightPosZ,
                                             float lightRadius) = 0;

    /*
     * Sets the intended frame rate for a surface. See ANativeWindow_setFrameRate() for more info.
     */
    virtual status_t setFrameRate(const sp<IGraphicBufferProducer>& surface, float frameRate,
                                  int8_t compatibility, int8_t changeFrameRateStrategy) = 0;

    /*
     * Acquire a frame rate flexibility token from SurfaceFlinger. While this token is acquired,
     * surface flinger will freely switch between frame rates in any way it sees fit, regardless of
     * the current restrictions applied by DisplayManager. This is useful to get consistent behavior
     * for tests. Release the token by releasing the returned IBinder reference.
     */
    virtual status_t acquireFrameRateFlexibilityToken(sp<IBinder>* outToken) = 0;

    /*
     * Sets the frame timeline vsync info received from choreographer that corresponds to next
     * buffer submitted on that surface.
     */
    virtual status_t setFrameTimelineInfo(const sp<IGraphicBufferProducer>& surface,
                                          const FrameTimelineInfo& frameTimelineInfo) = 0;

    /*
     * Adds a TransactionTraceListener to listen for transaction tracing state updates.
     */
    virtual status_t addTransactionTraceListener(
            const sp<gui::ITransactionTraceListener>& listener) = 0;

    /**
     * Gets priority of the RenderEngine in SurfaceFlinger.
     */
    virtual int getGPUContextPriority() = 0;

    /**
     * Gets the number of buffers SurfaceFlinger would need acquire. This number
     * would be propagated to the client via MIN_UNDEQUEUED_BUFFERS so that the
     * client could allocate enough buffers to match SF expectations of the
     * pipeline depth. SurfaceFlinger will make sure that it will give the app at
     * least the time configured as the 'appDuration' before trying to latch
     * the buffer.
     *
     * The total buffers needed for a given configuration is basically the
     * numbers of vsyncs a single buffer is used across the stack. For the default
     * configuration a buffer is held ~1 vsync by the app, ~1 vsync by SurfaceFlinger
     * and 1 vsync by the display. The extra buffers are calculated as the
     * number of additional buffers on top of the 2 buffers already present
     * in MIN_UNDEQUEUED_BUFFERS.
     */
    virtual status_t getMaxAcquiredBufferCount(int* buffers) const = 0;

    virtual status_t addWindowInfosListener(
            const sp<gui::IWindowInfosListener>& windowInfosListener) const = 0;
    virtual status_t removeWindowInfosListener(
            const sp<gui::IWindowInfosListener>& windowInfosListener) const = 0;
};

// ----------------------------------------------------------------------------

class BnSurfaceComposer: public BnInterface<ISurfaceComposer> {
public:
    enum ISurfaceComposerTag {
        // Note: BOOT_FINISHED must remain this value, it is called from
        // Java by ActivityManagerService.
        BOOT_FINISHED = IBinder::FIRST_CALL_TRANSACTION,
        CREATE_CONNECTION,
        GET_STATIC_DISPLAY_INFO,
        CREATE_DISPLAY_EVENT_CONNECTION,
        CREATE_DISPLAY,
        DESTROY_DISPLAY,
        GET_PHYSICAL_DISPLAY_TOKEN,
        SET_TRANSACTION_STATE,
        AUTHENTICATE_SURFACE,
        GET_SUPPORTED_FRAME_TIMESTAMPS,
        GET_DISPLAY_MODES,       // Deprecated. Use GET_DYNAMIC_DISPLAY_INFO instead.
        GET_ACTIVE_DISPLAY_MODE, // Deprecated. Use GET_DYNAMIC_DISPLAY_INFO instead.
        GET_DISPLAY_STATE,
        CAPTURE_DISPLAY,
        CAPTURE_LAYERS,
        CLEAR_ANIMATION_FRAME_STATS,
        GET_ANIMATION_FRAME_STATS,
        SET_POWER_MODE,
        GET_DISPLAY_STATS,
        GET_HDR_CAPABILITIES,    // Deprecated. Use GET_DYNAMIC_DISPLAY_INFO instead.
        GET_DISPLAY_COLOR_MODES, // Deprecated. Use GET_DYNAMIC_DISPLAY_INFO instead.
        GET_ACTIVE_COLOR_MODE,   // Deprecated. Use GET_DYNAMIC_DISPLAY_INFO instead.
        SET_ACTIVE_COLOR_MODE,
        ENABLE_VSYNC_INJECTIONS,
        INJECT_VSYNC,
        GET_LAYER_DEBUG_INFO,
        GET_COMPOSITION_PREFERENCE,
        GET_COLOR_MANAGEMENT,
        GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES,
        SET_DISPLAY_CONTENT_SAMPLING_ENABLED,
        GET_DISPLAYED_CONTENT_SAMPLE,
        GET_PROTECTED_CONTENT_SUPPORT,
        IS_WIDE_COLOR_DISPLAY,
        GET_DISPLAY_NATIVE_PRIMARIES,
        GET_PHYSICAL_DISPLAY_IDS,
        ADD_REGION_SAMPLING_LISTENER,
        REMOVE_REGION_SAMPLING_LISTENER,
        SET_DESIRED_DISPLAY_MODE_SPECS,
        GET_DESIRED_DISPLAY_MODE_SPECS,
        GET_DISPLAY_BRIGHTNESS_SUPPORT,
        SET_DISPLAY_BRIGHTNESS,
        CAPTURE_DISPLAY_BY_ID,
        NOTIFY_POWER_BOOST,
        SET_GLOBAL_SHADOW_SETTINGS,
        GET_AUTO_LOW_LATENCY_MODE_SUPPORT, // Deprecated. Use GET_DYNAMIC_DISPLAY_INFO instead.
        SET_AUTO_LOW_LATENCY_MODE,
        GET_GAME_CONTENT_TYPE_SUPPORT, // Deprecated. Use GET_DYNAMIC_DISPLAY_INFO instead.
        SET_GAME_CONTENT_TYPE,
        SET_FRAME_RATE,
        ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN,
        SET_FRAME_TIMELINE_INFO,
        ADD_TRANSACTION_TRACE_LISTENER,
        GET_GPU_CONTEXT_PRIORITY,
        GET_MAX_ACQUIRED_BUFFER_COUNT,
        GET_DYNAMIC_DISPLAY_INFO,
        ADD_FPS_LISTENER,
        REMOVE_FPS_LISTENER,
        OVERRIDE_HDR_TYPES,
        ADD_HDR_LAYER_INFO_LISTENER,
        REMOVE_HDR_LAYER_INFO_LISTENER,
        ON_PULL_ATOM,
        ADD_TUNNEL_MODE_ENABLED_LISTENER,
        REMOVE_TUNNEL_MODE_ENABLED_LISTENER,
        ADD_WINDOW_INFOS_LISTENER,
        REMOVE_WINDOW_INFOS_LISTENER,
        GET_PRIMARY_PHYSICAL_DISPLAY_ID,
        // Always append new enum to the end.
    };

    virtual status_t onTransact(uint32_t code, const Parcel& data,
            Parcel* reply, uint32_t flags = 0);
};

} // namespace android
