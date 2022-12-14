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

#include <sys/types.h>

/*
 * NOTE: Make sure this file doesn't include  anything from <gl/ > or <gl2/ >
 */

#include <android-base/thread_annotations.h>
#include <compositionengine/OutputColorSetting.h>
#include <cutils/atomic.h>
#include <cutils/compiler.h>
#include <gui/BufferQueue.h>
#include <gui/FrameTimestamps.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/ITransactionCompletedListener.h>
#include <gui/LayerState.h>
#include <gui/OccupancyTracker.h>
#include <input/ISetInputWindowsListener.h>
#include <layerproto/LayerProtoHeader.h>
#include <math/mat4.h>
#include <renderengine/LayerSettings.h>
#include <serviceutils/PriorityDumper.h>
#include <system/graphics.h>
#include <ui/FenceTime.h>
#include <ui/PixelFormat.h>
#include <ui/Size.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/RefBase.h>
#include <utils/SortedVector.h>
#include <utils/Trace.h>
#include <utils/threads.h>

#include "ClientCache.h"
#include "DisplayDevice.h"
#include "DisplayHardware/HWC2.h"
#include "DisplayHardware/PowerAdvisor.h"
#include "Effects/Daltonizer.h"
#include "FrameTracker.h"
#include "LayerVector.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "Scheduler/RefreshRateStats.h"
#include "Scheduler/Scheduler.h"
#include "Scheduler/VSyncModulator.h"
#include "SurfaceFlingerFactory.h"
#include "SurfaceTracing.h"
#include "TracedOrdinal.h"
#include "TransactionCompletedThread.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

using namespace android::surfaceflinger;

namespace android {

class Client;
class EventThread;
class HWComposer;
class IGraphicBufferProducer;
class IInputFlinger;
class Layer;
class MessageBase;
class RefreshRateOverlay;
class RegionSamplingThread;
class TimeStats;
class FrameTracer;

namespace compositionengine {
class DisplaySurface;
class OutputLayer;

struct CompositionRefreshArgs;
} // namespace compositionengine

namespace renderengine {
class RenderEngine;
} // namespace renderengine

enum {
    eTransactionNeeded = 0x01,
    eTraversalNeeded = 0x02,
    eDisplayTransactionNeeded = 0x04,
    eTransformHintUpdateNeeded = 0x08,
    eTransactionFlushNeeded = 0x10,
    eTransactionMask = 0x1f,
};

using DisplayColorSetting = compositionengine::OutputColorSetting;

class SurfaceFlingerBE
{
public:
    SurfaceFlingerBE();

    const std::string mHwcServiceName; // "default" for real use, something else for testing.

    FenceTimeline mGlCompositionDoneTimeline;
    FenceTimeline mDisplayTimeline;

    // protected by mCompositorTimingLock;
    mutable std::mutex mCompositorTimingLock;
    CompositorTiming mCompositorTiming;

    // Only accessed from the main thread.
    struct CompositePresentTime {
        nsecs_t composite = -1;
        std::shared_ptr<FenceTime> display = FenceTime::NO_FENCE;
    };
    std::queue<CompositePresentTime> mCompositePresentTimes;

    static const size_t NUM_BUCKETS = 8; // < 1-7, 7+
    nsecs_t mFrameBuckets[NUM_BUCKETS] = {};
    nsecs_t mTotalTime = 0;
    std::atomic<nsecs_t> mLastSwapTime = 0;

    // Double- vs. triple-buffering stats
    struct BufferingStats {
        size_t numSegments = 0;
        nsecs_t totalTime = 0;

        // "Two buffer" means that a third buffer was never used, whereas
        // "double-buffered" means that on average the segment only used two
        // buffers (though it may have used a third for some part of the
        // segment)
        nsecs_t twoBufferTime = 0;
        nsecs_t doubleBufferedTime = 0;
        nsecs_t tripleBufferedTime = 0;
    };
    mutable Mutex mBufferingStatsMutex;
    std::unordered_map<std::string, BufferingStats> mBufferingStats;

    // The composer sequence id is a monotonically increasing integer that we
    // use to differentiate callbacks from different hardware composer
    // instances. Each hardware composer instance gets a different sequence id.
    int32_t mComposerSequenceId = 0;
};

class SurfaceFlinger : public BnSurfaceComposer,
                       public PriorityDumper,
                       public ClientCache::ErasedRecipient,
                       private IBinder::DeathRecipient,
                       private HWC2::ComposerCallback,
                       private ISchedulerCallback {
public:
    SurfaceFlingerBE& getBE() { return mBE; }
    const SurfaceFlingerBE& getBE() const { return mBE; }

    // This is the phase offset in nanoseconds of the software vsync event
    // relative to the vsync event reported by HWComposer.  The software vsync
    // event is when SurfaceFlinger and Choreographer-based applications run each
    // frame.
    //
    // This phase offset allows adjustment of the minimum latency from application
    // wake-up time (by Choreographer) to the time at which the resulting window
    // image is displayed.  This value may be either positive (after the HW vsync)
    // or negative (before the HW vsync). Setting it to 0 will result in a lower
    // latency bound of two vsync periods because the app and SurfaceFlinger
    // will run just after the HW vsync.  Setting it to a positive number will
    // result in the minimum latency being:
    //
    //     (2 * VSYNC_PERIOD - (vsyncPhaseOffsetNs % VSYNC_PERIOD))
    //
    // Note that reducing this latency makes it more likely for the applications
    // to not have their window content image ready in time.  When this happens
    // the latency will end up being an additional vsync period, and animations
    // will hiccup.  Therefore, this latency should be tuned somewhat
    // conservatively (or at least with awareness of the trade-off being made).
    static int64_t vsyncPhaseOffsetNs;
    static int64_t sfVsyncPhaseOffsetNs;

    // If fences from sync Framework are supported.
    static bool hasSyncFramework;

    // The offset in nanoseconds to use when DispSync timestamps present fence
    // signaling time.
    static int64_t dispSyncPresentTimeOffset;

    // Some hardware can do RGB->YUV conversion more efficiently in hardware
    // controlled by HWC than in hardware controlled by the video encoder.
    // This instruct VirtualDisplaySurface to use HWC for such conversion on
    // GL composition.
    static bool useHwcForRgbToYuv;

    // Maximum dimension supported by HWC for virtual display.
    // Equal to min(max_height, max_width).
    static uint64_t maxVirtualDisplaySize;

    // Controls the number of buffers SurfaceFlinger will allocate for use in
    // FramebufferSurface
    static int64_t maxFrameBufferAcquiredBuffers;

    // Controls the maximum width and height in pixels that the graphics pipeline can support for
    // GPU fallback composition. For example, 8k devices with 4k GPUs, or 4k devices with 2k GPUs.
    static uint32_t maxGraphicsWidth;
    static uint32_t maxGraphicsHeight;

    // Indicate if a device has wide color gamut display. This is typically
    // found on devices with wide color gamut (e.g. Display-P3) display.
    static bool hasWideColorDisplay;

    static ui::Rotation internalDisplayOrientation;

    // Indicate if device wants color management on its display.
    static bool useColorManagement;

    static bool useContextPriority;

    // The data space and pixel format that SurfaceFlinger expects hardware composer
    // to composite efficiently. Meaning under most scenarios, hardware composer
    // will accept layers with the data space and pixel format.
    static ui::Dataspace defaultCompositionDataspace;
    static ui::PixelFormat defaultCompositionPixelFormat;

    // The data space and pixel format that SurfaceFlinger expects hardware composer
    // to composite efficiently for wide color gamut surfaces. Meaning under most scenarios,
    // hardware composer will accept layers with the data space and pixel format.
    static ui::Dataspace wideColorGamutCompositionDataspace;
    static ui::PixelFormat wideColorGamutCompositionPixelFormat;

    // Whether to use frame rate API when deciding about the refresh rate of the display. This
    // variable is caches in SF, so that we can check it with each layer creation, and a void the
    // overhead that is caused by reading from sysprop.
    static bool useFrameRateApi;

    // set main thread scheduling policy
    static status_t setSchedFifo(bool enabled) ANDROID_API;

    static char const* getServiceName() ANDROID_API {
        return "SurfaceFlinger";
    }

    struct SkipInitializationTag {};
    static constexpr SkipInitializationTag SkipInitialization;
    SurfaceFlinger(surfaceflinger::Factory&, SkipInitializationTag) ANDROID_API;
    explicit SurfaceFlinger(surfaceflinger::Factory&) ANDROID_API;

    // must be called before clients can connect
    void init() ANDROID_API;

    // starts SurfaceFlinger main loop in the current thread
    void run() ANDROID_API;

    // Schedule an asynchronous or synchronous task on the main thread.
    template <typename F, typename T = std::invoke_result_t<F>>
    [[nodiscard]] std::future<T> schedule(F&&);

    // force full composition on all displays
    void repaintEverything();

    surfaceflinger::Factory& getFactory() { return mFactory; }

    // The CompositionEngine encapsulates all composition related interfaces and actions.
    compositionengine::CompositionEngine& getCompositionEngine() const;

    // Obtains a name from the texture pool, or, if the pool is empty, posts a
    // synchronous message to the main thread to obtain one on the fly
    uint32_t getNewTexture();

    // utility function to delete a texture on the main thread
    void deleteTextureAsync(uint32_t texture);

    // enable/disable h/w composer event
    // TODO: this should be made accessible only to EventThread
    void setPrimaryVsyncEnabled(bool enabled);

    // main thread function to enable/disable h/w composer event
    void setPrimaryVsyncEnabledInternal(bool enabled) REQUIRES(mStateLock);

    // called on the main thread by MessageQueue when an internal message
    // is received
    // TODO: this should be made accessible only to MessageQueue
    void onMessageReceived(int32_t what, nsecs_t expectedVSyncTime);

    renderengine::RenderEngine& getRenderEngine() const;

    bool authenticateSurfaceTextureLocked(
        const sp<IGraphicBufferProducer>& bufferProducer) const;

    void onLayerFirstRef(Layer*);
    void onLayerDestroyed(Layer*);

    void removeFromOffscreenLayers(Layer* layer);

    TransactionCompletedThread& getTransactionCompletedThread() {
        return mTransactionCompletedThread;
    }

    // Converts from a binder handle to a Layer
    // Returns nullptr if the handle does not point to an existing layer.
    // Otherwise, returns a weak reference so that callers off the main-thread
    // won't accidentally hold onto the last strong reference.
    wp<Layer> fromHandle(const sp<IBinder>& handle);
    wp<Layer> fromHandleLocked(const sp<IBinder>& handle) REQUIRES(mStateLock);

    // Inherit from ClientCache::ErasedRecipient
    void bufferErased(const client_cache_t& clientCacheId) override;

    // If set, disables reusing client composition buffers. This can be set by
    // debug.sf.disable_client_composition_cache
    bool mDisableClientCompositionCache = false;

private:
    friend class BufferLayer;
    friend class BufferQueueLayer;
    friend class BufferStateLayer;
    friend class Client;
    friend class Layer;
    friend class MonitoredProducer;
    friend class RefreshRateOverlay;
    friend class RegionSamplingThread;
    friend class SurfaceTracing;

    // For unit tests
    friend class TestableSurfaceFlinger;
    friend class TransactionApplicationTest;

    // This value is specified in number of frames.  Log frame stats at most
    // every half hour.
    enum { LOG_FRAME_STATS_PERIOD =  30*60*60 };

    static const int MAX_TRACING_MEMORY = 100 * 1024 * 1024; // 100MB

protected:
    // We're reference counted, never destroy SurfaceFlinger directly
    virtual ~SurfaceFlinger();

private:
    /* ------------------------------------------------------------------------
     * Internal data structures
     */

    class State {
    public:
        explicit State(LayerVector::StateSet set) : stateSet(set), layersSortedByZ(set) {}
        State& operator=(const State& other) {
            // We explicitly don't copy stateSet so that, e.g., mDrawingState
            // always uses the Drawing StateSet.
            layersSortedByZ = other.layersSortedByZ;
            displays = other.displays;
            colorMatrixChanged = other.colorMatrixChanged;
            if (colorMatrixChanged) {
                colorMatrix = other.colorMatrix;
            }
            globalShadowSettings = other.globalShadowSettings;

            return *this;
        }

        const LayerVector::StateSet stateSet = LayerVector::StateSet::Invalid;
        LayerVector layersSortedByZ;
        DefaultKeyedVector< wp<IBinder>, DisplayDeviceState> displays;

        bool colorMatrixChanged = true;
        mat4 colorMatrix;

        renderengine::ShadowSettings globalShadowSettings;

        void traverse(const LayerVector::Visitor& visitor) const;
        void traverseInZOrder(const LayerVector::Visitor& visitor) const;
        void traverseInReverseZOrder(const LayerVector::Visitor& visitor) const;
    };

    /* ------------------------------------------------------------------------
     * IBinder interface
     */
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override;
    status_t dump(int fd, const Vector<String16>& args) override { return priorityDump(fd, args); }
    bool callingThreadHasUnscopedSurfaceFlingerAccess(bool usePermissionCache = true)
            EXCLUDES(mStateLock);

    /* ------------------------------------------------------------------------
     * ISurfaceComposer interface
     */
    sp<ISurfaceComposerClient> createConnection() override;
    sp<IBinder> createDisplay(const String8& displayName, bool secure) override;
    void destroyDisplay(const sp<IBinder>& displayToken) override;
    std::vector<PhysicalDisplayId> getPhysicalDisplayIds() const override;
    sp<IBinder> getPhysicalDisplayToken(PhysicalDisplayId displayId) const override;
    void setTransactionState(const Vector<ComposerState>& state,
                             const Vector<DisplayState>& displays, uint32_t flags,
                             const sp<IBinder>& applyToken,
                             const InputWindowCommands& inputWindowCommands,
                             int64_t desiredPresentTime, const client_cache_t& uncacheBuffer,
                             bool hasListenerCallbacks,
                             const std::vector<ListenerCallbacks>& listenerCallbacks) override;
    void bootFinished() override;
    bool authenticateSurfaceTexture(
            const sp<IGraphicBufferProducer>& bufferProducer) const override;
    status_t getSupportedFrameTimestamps(std::vector<FrameEvent>* outSupported) const override;
    sp<IDisplayEventConnection> createDisplayEventConnection(
            ISurfaceComposer::VsyncSource vsyncSource = eVsyncSourceApp,
            ISurfaceComposer::ConfigChanged configChanged =
                    ISurfaceComposer::eConfigChangedSuppress) override;
    status_t captureScreen(const sp<IBinder>& displayToken, sp<GraphicBuffer>* outBuffer,
                           bool& outCapturedSecureLayers, ui::Dataspace reqDataspace,
                           ui::PixelFormat reqPixelFormat, const Rect& sourceCrop,
                           uint32_t reqWidth, uint32_t reqHeight, bool useIdentityTransform,
                           ui::Rotation rotation, bool captureSecureLayers) override;
    status_t captureScreen(uint64_t displayOrLayerStack, ui::Dataspace* outDataspace,
                           sp<GraphicBuffer>* outBuffer) override;
    status_t captureLayers(
            const sp<IBinder>& parentHandle, sp<GraphicBuffer>* outBuffer,
            const ui::Dataspace reqDataspace, const ui::PixelFormat reqPixelFormat,
            const Rect& sourceCrop,
            const std::unordered_set<sp<IBinder>, ISurfaceComposer::SpHash<IBinder>>& exclude,
            float frameScale, bool childrenOnly) override;

    status_t getDisplayStats(const sp<IBinder>& displayToken, DisplayStatInfo* stats) override;
    status_t getDisplayState(const sp<IBinder>& displayToken, ui::DisplayState*) override;
    status_t getDisplayInfo(const sp<IBinder>& displayToken, DisplayInfo*) override;
    status_t getDisplayConfigs(const sp<IBinder>& displayToken, Vector<DisplayConfig>*) override;
    int getActiveConfig(const sp<IBinder>& displayToken) override;
    status_t getDisplayColorModes(const sp<IBinder>& displayToken, Vector<ui::ColorMode>*) override;
    status_t getDisplayNativePrimaries(const sp<IBinder>& displayToken,
                                       ui::DisplayPrimaries&) override;
    ui::ColorMode getActiveColorMode(const sp<IBinder>& displayToken) override;
    status_t setActiveColorMode(const sp<IBinder>& displayToken, ui::ColorMode colorMode) override;
    status_t getAutoLowLatencyModeSupport(const sp<IBinder>& displayToken,
                                          bool* outSupported) const override;
    void setAutoLowLatencyMode(const sp<IBinder>& displayToken, bool on) override;
    status_t getGameContentTypeSupport(const sp<IBinder>& displayToken,
                                       bool* outSupported) const override;
    void setGameContentType(const sp<IBinder>& displayToken, bool on) override;
    void setPowerMode(const sp<IBinder>& displayToken, int mode) override;
    status_t clearAnimationFrameStats() override;
    status_t getAnimationFrameStats(FrameStats* outStats) const override;
    status_t getHdrCapabilities(const sp<IBinder>& displayToken,
                                HdrCapabilities* outCapabilities) const override;
    status_t enableVSyncInjections(bool enable) override;
    status_t injectVSync(nsecs_t when) override;
    status_t getLayerDebugInfo(std::vector<LayerDebugInfo>* outLayers) override;
    status_t getColorManagement(bool* outGetColorManagement) const override;
    status_t getCompositionPreference(ui::Dataspace* outDataspace, ui::PixelFormat* outPixelFormat,
                                      ui::Dataspace* outWideColorGamutDataspace,
                                      ui::PixelFormat* outWideColorGamutPixelFormat) const override;
    status_t getDisplayedContentSamplingAttributes(const sp<IBinder>& displayToken,
                                                   ui::PixelFormat* outFormat,
                                                   ui::Dataspace* outDataspace,
                                                   uint8_t* outComponentMask) const override;
    status_t setDisplayContentSamplingEnabled(const sp<IBinder>& displayToken, bool enable,
                                              uint8_t componentMask, uint64_t maxFrames) override;
    status_t getDisplayedContentSample(const sp<IBinder>& displayToken, uint64_t maxFrames,
                                       uint64_t timestamp,
                                       DisplayedFrameStats* outStats) const override;
    status_t getProtectedContentSupport(bool* outSupported) const override;
    status_t isWideColorDisplay(const sp<IBinder>& displayToken,
                                bool* outIsWideColorDisplay) const override;
    status_t addRegionSamplingListener(const Rect& samplingArea, const sp<IBinder>& stopLayerHandle,
                                       const sp<IRegionSamplingListener>& listener) override;
    status_t removeRegionSamplingListener(const sp<IRegionSamplingListener>& listener) override;
    status_t setDesiredDisplayConfigSpecs(const sp<IBinder>& displayToken, int32_t displayModeId,
                                          float primaryRefreshRateMin, float primaryRefreshRateMax,
                                          float appRequestRefreshRateMin,
                                          float appRequestRefreshRateMax) override;
    status_t getDesiredDisplayConfigSpecs(const sp<IBinder>& displayToken,
                                          int32_t* outDefaultConfig,
                                          float* outPrimaryRefreshRateMin,
                                          float* outPrimaryRefreshRateMax,
                                          float* outAppRequestRefreshRateMin,
                                          float* outAppRequestRefreshRateMax) override;
    status_t getDisplayBrightnessSupport(const sp<IBinder>& displayToken,
                                         bool* outSupport) const override;
    status_t setDisplayBrightness(const sp<IBinder>& displayToken, float brightness) override;
    status_t notifyPowerHint(int32_t hintId) override;
    status_t setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                     float lightPosY, float lightPosZ, float lightRadius) override;
    status_t setFrameRate(const sp<IGraphicBufferProducer>& surface, float frameRate,
                          int8_t compatibility) override;
    status_t acquireFrameRateFlexibilityToken(sp<IBinder>* outToken) override;
    /* ------------------------------------------------------------------------
     * DeathRecipient interface
     */
    void binderDied(const wp<IBinder>& who) override;

    /* ------------------------------------------------------------------------
     * RefBase interface
     */
    void onFirstRef() override;

    /* ------------------------------------------------------------------------
     * HWC2::ComposerCallback / HWComposer::EventHandler interface
     */
    void onVsyncReceived(int32_t sequenceId, hal::HWDisplayId hwcDisplayId, int64_t timestamp,
                         std::optional<hal::VsyncPeriodNanos> vsyncPeriod) override;
    void onHotplugReceived(int32_t sequenceId, hal::HWDisplayId hwcDisplayId,
                           hal::Connection connection) override;
    void onRefreshReceived(int32_t sequenceId, hal::HWDisplayId hwcDisplayId) override;
    void onVsyncPeriodTimingChangedReceived(
            int32_t sequenceId, hal::HWDisplayId display,
            const hal::VsyncPeriodChangeTimeline& updatedTimeline) override;
    void onSeamlessPossible(int32_t sequenceId, hal::HWDisplayId display) override;

    /* ------------------------------------------------------------------------
     * ISchedulerCallback
     */
    void changeRefreshRate(const Scheduler::RefreshRate&, Scheduler::ConfigEvent) override;
    // force full composition on all displays without resetting the scheduler idle timer.
    void repaintEverythingForHWC() override;
    // Called when kernel idle timer has expired. Used to update the refresh rate overlay.
    void kernelTimerChanged(bool expired) override;
    // Toggles the kernel idle timer on or off depending the policy decisions around refresh rates.
    void toggleKernelIdleTimer();
    // Keeps track of whether the kernel idle timer is currently enabled, so we don't have to
    // make calls to sys prop each time.
    bool mKernelIdleTimerEnabled = false;
    // Keeps track of whether the kernel timer is supported on the SF side.
    bool mSupportKernelIdleTimer = false;
    /* ------------------------------------------------------------------------
     * Message handling
     */
    // Can only be called from the main thread or with mStateLock held
    void signalTransaction();
    // Can only be called from the main thread or with mStateLock held
    void signalLayerUpdate();
    void signalRefresh();

    using RefreshRate = scheduler::RefreshRateConfigs::RefreshRate;

    struct ActiveConfigInfo {
        HwcConfigIndexType configId;
        Scheduler::ConfigEvent event = Scheduler::ConfigEvent::None;

        bool operator!=(const ActiveConfigInfo& other) const {
            return configId != other.configId || event != other.event;
        }
    };

    // called on the main thread in response to initializeDisplays()
    void onInitializeDisplays() REQUIRES(mStateLock);
    // Sets the desired active config bit. It obtains the lock, and sets mDesiredActiveConfig.
    void setDesiredActiveConfig(const ActiveConfigInfo& info) REQUIRES(mStateLock);
    status_t setActiveConfig(const sp<IBinder>& displayToken, int id);
    // Once HWC has returned the present fence, this sets the active config and a new refresh
    // rate in SF.
    void setActiveConfigInternal() REQUIRES(mStateLock);
    // Calls to setActiveConfig on the main thread if there is a pending config
    // that needs to be applied.
    void performSetActiveConfig() REQUIRES(mStateLock);
    // Called when active config is no longer is progress
    void desiredActiveConfigChangeDone() REQUIRES(mStateLock);
    // called on the main thread in response to setPowerMode()
    void setPowerModeInternal(const sp<DisplayDevice>& display, hal::PowerMode mode)
            REQUIRES(mStateLock);

    // Sets the desired display configs.
    status_t setDesiredDisplayConfigSpecsInternal(
            const sp<DisplayDevice>& display,
            const std::optional<scheduler::RefreshRateConfigs::Policy>& policy, bool overridePolicy)
            EXCLUDES(mStateLock);

    // Handle the INVALIDATE message queue event, latching new buffers and applying
    // incoming transactions
    void onMessageInvalidate(nsecs_t expectedVSyncTime);

    // Returns whether the transaction actually modified any state
    bool handleMessageTransaction();

    // Handle the REFRESH message queue event, sending the current frame down to RenderEngine and
    // the Composer HAL for presentation
    void onMessageRefresh();

    // Returns whether a new buffer has been latched (see handlePageFlip())
    bool handleMessageInvalidate();

    void handleTransaction(uint32_t transactionFlags);
    void handleTransactionLocked(uint32_t transactionFlags) REQUIRES(mStateLock);

    void updateInputFlinger();
    void updateInputWindowInfo();
    void commitInputWindowCommands() REQUIRES(mStateLock);
    void setInputWindowsFinished();
    void updateCursorAsync();
    void initScheduler(DisplayId primaryDisplayId);

    /* handlePageFlip - latch a new buffer if available and compute the dirty
     * region. Returns whether a new buffer has been latched, i.e., whether it
     * is necessary to perform a refresh during this vsync.
     */
    bool handlePageFlip();

    /* ------------------------------------------------------------------------
     * Transactions
     */
    void applyTransactionState(const Vector<ComposerState>& state,
                               const Vector<DisplayState>& displays, uint32_t flags,
                               const InputWindowCommands& inputWindowCommands,
                               const int64_t desiredPresentTime,
                               const client_cache_t& uncacheBuffer, const int64_t postTime,
                               bool privileged, bool hasListenerCallbacks,
                               const std::vector<ListenerCallbacks>& listenerCallbacks,
                               bool isMainThread = false) REQUIRES(mStateLock);
    // Returns true if at least one transaction was flushed
    bool flushTransactionQueues();
    // Returns true if there is at least one transaction that needs to be flushed
    bool transactionFlushNeeded();
    uint32_t getTransactionFlags(uint32_t flags);
    uint32_t peekTransactionFlags();
    // Can only be called from the main thread or with mStateLock held
    uint32_t setTransactionFlags(uint32_t flags);
    // Indicate SF should call doTraversal on layers, but don't trigger a wakeup! We use this cases
    // where there are still pending transactions but we know they won't be ready until a frame
    // arrives from a different layer. So we need to ensure we performTransaction from invalidate
    // but there is no need to try and wake up immediately to do it. Rather we rely on
    // onFrameAvailable or another layer update to wake us up.
    void setTraversalNeeded();
    uint32_t setTransactionFlags(uint32_t flags, Scheduler::TransactionStart transactionStart);
    void commitTransaction() REQUIRES(mStateLock);
    void commitOffscreenLayers();
    bool transactionIsReadyToBeApplied(int64_t desiredPresentTime,
                                       const Vector<ComposerState>& states);
    uint32_t setDisplayStateLocked(const DisplayState& s) REQUIRES(mStateLock);
    uint32_t addInputWindowCommands(const InputWindowCommands& inputWindowCommands)
            REQUIRES(mStateLock);

protected:
    virtual uint32_t setClientStateLocked(
            const ComposerState& composerState, int64_t desiredPresentTime, int64_t postTime,
            bool privileged,
            std::unordered_set<ListenerCallbacks, ListenerCallbacksHash>& listenerCallbacks)
            REQUIRES(mStateLock);
    virtual void commitTransactionLocked();

    // Used internally by computeLayerBounds() to gets the clip rectangle to use for the
    // root layers on a particular display in layer-coordinate space. The
    // layers (and effectively their children) will be clipped against this
    // rectangle. The base behavior is to clip to the visible region of the
    // display.
    virtual FloatRect getLayerClipBoundsForDisplay(const DisplayDevice&) const;

private:
    /* ------------------------------------------------------------------------
     * Layer management
     */
    status_t createLayer(const String8& name, const sp<Client>& client, uint32_t w, uint32_t h,
                         PixelFormat format, uint32_t flags, LayerMetadata metadata,
                         sp<IBinder>* handle, sp<IGraphicBufferProducer>* gbp,
                         const sp<IBinder>& parentHandle, const sp<Layer>& parentLayer = nullptr,
                         uint32_t* outTransformHint = nullptr);

    status_t createBufferQueueLayer(const sp<Client>& client, std::string name, uint32_t w,
                                    uint32_t h, uint32_t flags, LayerMetadata metadata,
                                    PixelFormat& format, sp<IBinder>* outHandle,
                                    sp<IGraphicBufferProducer>* outGbp, sp<Layer>* outLayer);

    status_t createBufferStateLayer(const sp<Client>& client, std::string name, uint32_t w,
                                    uint32_t h, uint32_t flags, LayerMetadata metadata,
                                    sp<IBinder>* outHandle, sp<Layer>* outLayer);

    status_t createEffectLayer(const sp<Client>& client, std::string name, uint32_t w, uint32_t h,
                               uint32_t flags, LayerMetadata metadata, sp<IBinder>* outHandle,
                               sp<Layer>* outLayer);

    status_t createContainerLayer(const sp<Client>& client, std::string name, uint32_t w,
                                  uint32_t h, uint32_t flags, LayerMetadata metadata,
                                  sp<IBinder>* outHandle, sp<Layer>* outLayer);

    status_t mirrorLayer(const sp<Client>& client, const sp<IBinder>& mirrorFromHandle,
                         sp<IBinder>* outHandle);

    std::string getUniqueLayerName(const char* name);

    // called when all clients have released all their references to
    // this layer meaning it is entirely safe to destroy all
    // resources associated to this layer.
    void onHandleDestroyed(sp<Layer>& layer);
    void markLayerPendingRemovalLocked(const sp<Layer>& layer);

    // add a layer to SurfaceFlinger
    status_t addClientLayer(const sp<Client>& client, const sp<IBinder>& handle,
                            const sp<IGraphicBufferProducer>& gbc, const sp<Layer>& lbc,
                            const sp<IBinder>& parentHandle, const sp<Layer>& parentLayer,
                            bool addToCurrentState, uint32_t* outTransformHint);

    // Traverse through all the layers and compute and cache its bounds.
    void computeLayerBounds();

    /* ------------------------------------------------------------------------
     * Boot animation, on/off animations and screen capture
     */

    void startBootAnim();

    using TraverseLayersFunction = std::function<void(const LayerVector::Visitor&)>;

    void renderScreenImplLocked(const RenderArea& renderArea, TraverseLayersFunction traverseLayers,
                                ANativeWindowBuffer* buffer, bool useIdentityTransform,
                                bool regionSampling, int* outSyncFd);
    status_t captureScreenCommon(RenderArea& renderArea, TraverseLayersFunction traverseLayers,
                                 sp<GraphicBuffer>* outBuffer, const ui::PixelFormat reqPixelFormat,
                                 bool useIdentityTransform, bool& outCapturedSecureLayers);
    status_t captureScreenCommon(RenderArea& renderArea, TraverseLayersFunction traverseLayers,
                                 const sp<GraphicBuffer>& buffer, bool useIdentityTransform,
                                 bool regionSampling, bool& outCapturedSecureLayers);
    sp<DisplayDevice> getDisplayByIdOrLayerStack(uint64_t displayOrLayerStack) REQUIRES(mStateLock);
    sp<DisplayDevice> getDisplayByLayerStack(uint64_t layerStack) REQUIRES(mStateLock);
    status_t captureScreenImplLocked(const RenderArea& renderArea,
                                     TraverseLayersFunction traverseLayers,
                                     ANativeWindowBuffer* buffer, bool useIdentityTransform,
                                     bool forSystem, int* outSyncFd, bool regionSampling,
                                     bool& outCapturedSecureLayers);
    void traverseLayersInDisplay(const sp<const DisplayDevice>& display,
                                 const LayerVector::Visitor& visitor);

    sp<StartPropertySetThread> mStartPropertySetThread;

    /* ------------------------------------------------------------------------
     * Properties
     */
    void readPersistentProperties();

    /* ------------------------------------------------------------------------
     * EGL
     */
    size_t getMaxTextureSize() const;
    size_t getMaxViewportDims() const;

    /* ------------------------------------------------------------------------
     * Display and layer stack management
     */
    // called when starting, or restarting after system_server death
    void initializeDisplays();

    sp<const DisplayDevice> getDisplayDeviceLocked(const wp<IBinder>& displayToken) const
            REQUIRES(mStateLock) {
        return const_cast<SurfaceFlinger*>(this)->getDisplayDeviceLocked(displayToken);
    }

    sp<DisplayDevice> getDisplayDeviceLocked(const wp<IBinder>& displayToken) REQUIRES(mStateLock) {
        const auto it = mDisplays.find(displayToken);
        return it == mDisplays.end() ? nullptr : it->second;
    }

    sp<const DisplayDevice> getDefaultDisplayDeviceLocked() const REQUIRES(mStateLock) {
        return const_cast<SurfaceFlinger*>(this)->getDefaultDisplayDeviceLocked();
    }

    sp<DisplayDevice> getDefaultDisplayDeviceLocked() REQUIRES(mStateLock) {
        if (const auto token = getInternalDisplayTokenLocked()) {
            return getDisplayDeviceLocked(token);
        }
        return nullptr;
    }

    sp<const DisplayDevice> getDefaultDisplayDevice() EXCLUDES(mStateLock) {
        Mutex::Autolock lock(mStateLock);
        return getDefaultDisplayDeviceLocked();
    }

    std::optional<DeviceProductInfo> getDeviceProductInfoLocked(const DisplayDevice&) const;

    // mark a region of a layer stack dirty. this updates the dirty
    // region of all screens presenting this layer stack.
    void invalidateLayerStack(const sp<const Layer>& layer, const Region& dirty);

    /* ------------------------------------------------------------------------
     * H/W composer
     */

    // The current hardware composer interface.
    //
    // The following thread safety rules apply when accessing mHwc, either
    // directly or via getHwComposer():
    //
    // 1. When recreating mHwc, acquire mStateLock. Recreating mHwc must only be
    //    done on the main thread.
    //
    // 2. When accessing mHwc on the main thread, it's not necessary to acquire
    //    mStateLock.
    //
    // 3. When accessing mHwc on a thread other than the main thread, we always
    //    need to acquire mStateLock. This is because the main thread could be
    //    in the process of destroying the current mHwc instance.
    //
    // The above thread safety rules only apply to SurfaceFlinger.cpp. In
    // SurfaceFlinger_hwc1.cpp we create mHwc at surface flinger init and never
    // destroy it, so it's always safe to access mHwc from any thread without
    // acquiring mStateLock.
    HWComposer& getHwComposer() const;

    /* ------------------------------------------------------------------------
     * Compositing
     */
    void invalidateHwcGeometry();

    void postComposition();
    void getCompositorTiming(CompositorTiming* compositorTiming);
    void updateCompositorTiming(const DisplayStatInfo& stats, nsecs_t compositeTime,
                                std::shared_ptr<FenceTime>& presentFenceTime);
    void setCompositorTimingSnapped(const DisplayStatInfo& stats,
                                    nsecs_t compositeToPresentLatency);

    void postFrame();

    /* ------------------------------------------------------------------------
     * Display management
     */
    sp<DisplayDevice> setupNewDisplayDeviceInternal(
            const wp<IBinder>& displayToken,
            std::shared_ptr<compositionengine::Display> compositionDisplay,
            const DisplayDeviceState& state,
            const sp<compositionengine::DisplaySurface>& displaySurface,
            const sp<IGraphicBufferProducer>& producer) REQUIRES(mStateLock);
    void processDisplayChangesLocked() REQUIRES(mStateLock);
    void processDisplayAdded(const wp<IBinder>& displayToken, const DisplayDeviceState&)
            REQUIRES(mStateLock);
    void processDisplayRemoved(const wp<IBinder>& displayToken) REQUIRES(mStateLock);
    void processDisplayChanged(const wp<IBinder>& displayToken,
                               const DisplayDeviceState& currentState,
                               const DisplayDeviceState& drawingState) REQUIRES(mStateLock);
    void processDisplayHotplugEventsLocked() REQUIRES(mStateLock);

    void dispatchDisplayHotplugEvent(PhysicalDisplayId displayId, bool connected);

    /* ------------------------------------------------------------------------
     * VSync
     */
    nsecs_t getVsyncPeriodFromHWC() const REQUIRES(mStateLock);

    // Sets the refresh rate by switching active configs, if they are available for
    // the desired refresh rate.
    void changeRefreshRateLocked(const RefreshRate&, Scheduler::ConfigEvent event)
            REQUIRES(mStateLock);

    bool isDisplayConfigAllowed(HwcConfigIndexType configId) const REQUIRES(mStateLock);

    // Gets the fence for the previous frame.
    // Must be called on the main thread.
    sp<Fence> previousFrameFence();

    // Whether the previous frame has not yet been presented to the display.
    // If graceTimeMs is positive, this method waits for at most the provided
    // grace period before reporting if the frame missed.
    // Must be called on the main thread.
    bool previousFramePending(int graceTimeMs = 0);

    // Returns the previous time that the frame was presented. If the frame has
    // not been presented yet, then returns Fence::SIGNAL_TIME_PENDING. If there
    // is no pending frame, then returns Fence::SIGNAL_TIME_INVALID.
    // Must be called on the main thread.
    nsecs_t previousFramePresentTime();

    // Calculates the expected present time for this frame. For negative offsets, performs a
    // correction using the predicted vsync for the next frame instead.
    nsecs_t calculateExpectedPresentTime(nsecs_t now) const;

    /*
     * Display identification
     */
    sp<IBinder> getPhysicalDisplayTokenLocked(DisplayId displayId) const REQUIRES(mStateLock) {
        const auto it = mPhysicalDisplayTokens.find(displayId);
        return it != mPhysicalDisplayTokens.end() ? it->second : nullptr;
    }

    std::optional<DisplayId> getPhysicalDisplayIdLocked(const sp<IBinder>& displayToken) const
            REQUIRES(mStateLock) {
        for (const auto& [id, token] : mPhysicalDisplayTokens) {
            if (token == displayToken) {
                return id;
            }
        }
        return {};
    }

    // TODO(b/74619554): Remove special cases for primary display.
    sp<IBinder> getInternalDisplayTokenLocked() const REQUIRES(mStateLock) {
        const auto displayId = getInternalDisplayIdLocked();
        return displayId ? getPhysicalDisplayTokenLocked(*displayId) : nullptr;
    }

    std::optional<DisplayId> getInternalDisplayIdLocked() const REQUIRES(mStateLock) {
        const auto hwcDisplayId = getHwComposer().getInternalHwcDisplayId();
        return hwcDisplayId ? getHwComposer().toPhysicalDisplayId(*hwcDisplayId) : std::nullopt;
    }

    /*
     * Debugging & dumpsys
     */
    using DumpArgs = Vector<String16>;
    using Dumper = std::function<void(const DumpArgs&, bool asProto, std::string&)>;

    template <typename F, std::enable_if_t<!std::is_member_function_pointer_v<F>>* = nullptr>
    static Dumper dumper(F&& dump) {
        using namespace std::placeholders;
        return std::bind(std::forward<F>(dump), _3);
    }

    template <typename F, std::enable_if_t<std::is_member_function_pointer_v<F>>* = nullptr>
    Dumper dumper(F dump) {
        using namespace std::placeholders;
        return std::bind(dump, this, _3);
    }

    template <typename F>
    Dumper argsDumper(F dump) {
        using namespace std::placeholders;
        return std::bind(dump, this, _1, _3);
    }

    template <typename F>
    Dumper protoDumper(F dump) {
        using namespace std::placeholders;
        return std::bind(dump, this, _1, _2, _3);
    }

    void dumpAllLocked(const DumpArgs& args, std::string& result) const REQUIRES(mStateLock);

    void appendSfConfigString(std::string& result) const;
    void listLayersLocked(std::string& result) const;
    void dumpStatsLocked(const DumpArgs& args, std::string& result) const REQUIRES(mStateLock);
    void clearStatsLocked(const DumpArgs& args, std::string& result);
    void dumpTimeStats(const DumpArgs& args, bool asProto, std::string& result) const;
    void logFrameStats();

    void dumpVSync(std::string& result) const REQUIRES(mStateLock);
    void dumpStaticScreenStats(std::string& result) const;
    // Not const because each Layer needs to query Fences and cache timestamps.
    void dumpFrameEventsLocked(std::string& result);

    void recordBufferingStats(const std::string& layerName,
                              std::vector<OccupancyTracker::Segment>&& history);
    void dumpBufferingStats(std::string& result) const;
    void dumpDisplayIdentificationData(std::string& result) const REQUIRES(mStateLock);
    void dumpRawDisplayIdentificationData(const DumpArgs&, std::string& result) const;
    void dumpWideColorInfo(std::string& result) const REQUIRES(mStateLock);
    LayersProto dumpDrawingStateProto(uint32_t traceFlags) const;
    void dumpOffscreenLayersProto(LayersProto& layersProto,
                                  uint32_t traceFlags = SurfaceTracing::TRACE_ALL) const;
    // Dumps state from HW Composer
    void dumpHwc(std::string& result) const;
    LayersProto dumpProtoFromMainThread(uint32_t traceFlags = SurfaceTracing::TRACE_ALL)
            EXCLUDES(mStateLock);
    void dumpOffscreenLayers(std::string& result) EXCLUDES(mStateLock);

    bool isLayerTripleBufferingDisabled() const {
        return this->mLayerTripleBufferingDisabled;
    }

    status_t doDump(int fd, const DumpArgs& args, bool asProto);

    status_t dumpCritical(int fd, const DumpArgs&, bool asProto);

    status_t dumpAll(int fd, const DumpArgs& args, bool asProto) override {
        return doDump(fd, args, asProto);
    }

    void onFrameRateFlexibilityTokenReleased();

    void updateColorMatrixLocked();

    /* ------------------------------------------------------------------------
     * Attributes
     */

    surfaceflinger::Factory& mFactory;

    // access must be protected by mStateLock
    mutable Mutex mStateLock;
    State mCurrentState{LayerVector::StateSet::Current};
    std::atomic<int32_t> mTransactionFlags = 0;
    Condition mTransactionCV;
    bool mTransactionPending = false;
    bool mAnimTransactionPending = false;
    SortedVector<sp<Layer>> mLayersPendingRemoval;
    bool mForceTraversal = false;

    // global color transform states
    Daltonizer mDaltonizer;
    float mGlobalSaturationFactor = 1.0f;
    mat4 mClientColorMatrix;

    // Can't be unordered_set because wp<> isn't hashable
    std::set<wp<IBinder>> mGraphicBufferProducerList;
    size_t mMaxGraphicBufferProducerListSize = ISurfaceComposer::MAX_LAYERS;

    void removeGraphicBufferProducerAsync(const wp<IBinder>&);

    // protected by mStateLock (but we could use another lock)
    bool mLayersRemoved = false;
    bool mLayersAdded = false;

    std::atomic<bool> mRepaintEverything = false;

    // constant members (no synchronization needed for access)
    const nsecs_t mBootTime = systemTime();
    bool mGpuToCpuSupported = false;
    bool mIsUserBuild = true;

    // Can only accessed from the main thread, these members
    // don't need synchronization
    State mDrawingState{LayerVector::StateSet::Drawing};
    bool mVisibleRegionsDirty = false;
    // Set during transaction commit stage to track if the input info for a layer has changed.
    bool mInputInfoChanged = false;
    bool mGeometryInvalid = false;
    bool mAnimCompositionPending = false;
    std::vector<sp<Layer>> mLayersWithQueuedFrames;
    // Tracks layers that need to update a display's dirty region.
    std::vector<sp<Layer>> mLayersPendingRefresh;
    std::array<sp<Fence>, 2> mPreviousPresentFences = {Fence::NO_FENCE, Fence::NO_FENCE};
    // True if in the previous frame at least one layer was composed via the GPU.
    bool mHadClientComposition = false;
    // True if in the previous frame at least one layer was composed via HW Composer.
    // Note that it is possible for a frame to be composed via both client and device
    // composition, for example in the case of overlays.
    bool mHadDeviceComposition = false;
    // True if in the previous frame, the client composition was skipped by reusing the buffer
    // used in a previous composition. This can happed if the client composition requests
    // did not change.
    bool mReusedClientComposition = false;

    enum class BootStage {
        BOOTLOADER,
        BOOTANIMATION,
        FINISHED,
    };
    BootStage mBootStage = BootStage::BOOTLOADER;

    struct HotplugEvent {
        hal::HWDisplayId hwcDisplayId;
        hal::Connection connection = hal::Connection::INVALID;
    };
    std::vector<HotplugEvent> mPendingHotplugEvents GUARDED_BY(mStateLock);

    // this may only be written from the main thread with mStateLock held
    // it may be read from other threads with mStateLock held
    std::map<wp<IBinder>, sp<DisplayDevice>> mDisplays GUARDED_BY(mStateLock);
    std::unordered_map<DisplayId, sp<IBinder>> mPhysicalDisplayTokens GUARDED_BY(mStateLock);

    std::unordered_map<BBinder*, wp<Layer>> mLayersByLocalBinderToken GUARDED_BY(mStateLock);

    // don't use a lock for these, we don't care
    int mDebugRegion = 0;
    bool mDebugDisableHWC = false;
    bool mDebugDisableTransformHint = false;
    volatile nsecs_t mDebugInTransaction = 0;
    bool mForceFullDamage = false;
    bool mPropagateBackpressure = true;
    bool mPropagateBackpressureClientComposition = false;
    std::unique_ptr<SurfaceInterceptor> mInterceptor;

    SurfaceTracing mTracing{*this};
    std::mutex mTracingLock;
    bool mTracingEnabled = false;
    bool mAddCompositionStateToTrace = false;
    std::atomic<bool> mTracingEnabledChanged = false;

    const std::shared_ptr<TimeStats> mTimeStats;
    const std::unique_ptr<FrameTracer> mFrameTracer;
    bool mUseHwcVirtualDisplays = false;
    // If blurs should be enabled on this device.
    bool mSupportsBlur = false;
    // Disable blurs, for debugging
    std::atomic<bool> mDisableBlurs = false;
    // If blurs are considered expensive and should require high GPU frequency.
    bool mBlursAreExpensive = false;
    std::atomic<uint32_t> mFrameMissedCount = 0;
    std::atomic<uint32_t> mHwcFrameMissedCount = 0;
    std::atomic<uint32_t> mGpuFrameMissedCount = 0;

    TransactionCompletedThread mTransactionCompletedThread;

    // Restrict layers to use two buffers in their bufferqueues.
    bool mLayerTripleBufferingDisabled = false;

    // these are thread safe
    std::unique_ptr<MessageQueue> mEventQueue;
    FrameTracker mAnimFrameTracker;

    // protected by mDestroyedLayerLock;
    mutable Mutex mDestroyedLayerLock;
    Vector<Layer const *> mDestroyedLayers;

    nsecs_t mRefreshStartTime = 0;

    std::atomic<bool> mRefreshPending = false;

    // We maintain a pool of pre-generated texture names to hand out to avoid
    // layer creation needing to run on the main thread (which it would
    // otherwise need to do to access RenderEngine).
    std::mutex mTexturePoolMutex;
    uint32_t mTexturePoolSize = 0;
    std::vector<uint32_t> mTexturePool;

    struct TransactionState {
        TransactionState(const Vector<ComposerState>& composerStates,
                         const Vector<DisplayState>& displayStates, uint32_t transactionFlags,
                         int64_t desiredPresentTime, const client_cache_t& uncacheBuffer,
                         int64_t postTime, bool privileged, bool hasListenerCallbacks,
                         std::vector<ListenerCallbacks> listenerCallbacks)
              : states(composerStates),
                displays(displayStates),
                flags(transactionFlags),
                desiredPresentTime(desiredPresentTime),
                buffer(uncacheBuffer),
                postTime(postTime),
                privileged(privileged),
                hasListenerCallbacks(hasListenerCallbacks),
                listenerCallbacks(listenerCallbacks) {}

        Vector<ComposerState> states;
        Vector<DisplayState> displays;
        uint32_t flags;
        const int64_t desiredPresentTime;
        client_cache_t buffer;
        const int64_t postTime;
        bool privileged;
        bool hasListenerCallbacks;
        std::vector<ListenerCallbacks> listenerCallbacks;
    };
    std::unordered_map<sp<IBinder>, std::queue<TransactionState>, IListenerHash> mTransactionQueues;

    /* ------------------------------------------------------------------------
     * Feature prototyping
     */

    // Static screen stats
    bool mHasPoweredOff = false;

    std::atomic<size_t> mNumLayers = 0;

    // Verify that transaction is being called by an approved process:
    // either AID_GRAPHICS or AID_SYSTEM.
    status_t CheckTransactCodeCredentials(uint32_t code);

    // to linkToDeath
    sp<IBinder> mWindowManager;
    // We want to avoid multiple calls to BOOT_FINISHED as they come in on
    // different threads without a lock and could trigger unsynchronized writes to
    // to mWindowManager or mInputFlinger
    std::atomic<bool> mBootFinished = false;

    std::thread::id mMainThreadId = std::this_thread::get_id();

    DisplayColorSetting mDisplayColorSetting = DisplayColorSetting::kEnhanced;

    // Color mode forced by setting persist.sys.sf.color_mode, it must:
    //     1. not be NATIVE color mode, NATIVE color mode means no forced color mode;
    //     2. be one of the supported color modes returned by hardware composer, otherwise
    //        it will not be respected.
    // persist.sys.sf.color_mode will only take effect when persist.sys.sf.native_mode
    // is not set to 1.
    // This property can be used to force SurfaceFlinger to always pick a certain color mode.
    ui::ColorMode mForceColorMode = ui::ColorMode::NATIVE;

    ui::Dataspace mDefaultCompositionDataspace;
    ui::Dataspace mWideColorGamutCompositionDataspace;
    ui::Dataspace mColorSpaceAgnosticDataspace;

    SurfaceFlingerBE mBE;
    std::unique_ptr<compositionengine::CompositionEngine> mCompositionEngine;

    /* ------------------------------------------------------------------------
     * Scheduler
     */
    std::unique_ptr<Scheduler> mScheduler;
    scheduler::ConnectionHandle mAppConnectionHandle;
    scheduler::ConnectionHandle mSfConnectionHandle;

    // Stores phase offsets configured per refresh rate.
    std::unique_ptr<scheduler::PhaseConfiguration> mPhaseConfiguration;

    // Optional to defer construction until scheduler connections are created.
    std::optional<scheduler::VSyncModulator> mVSyncModulator;

    std::unique_ptr<scheduler::RefreshRateConfigs> mRefreshRateConfigs;
    std::unique_ptr<scheduler::RefreshRateStats> mRefreshRateStats;

    std::atomic<nsecs_t> mExpectedPresentTime = 0;
    nsecs_t mScheduledPresentTime = 0;
    hal::Vsync mHWCVsyncPendingState = hal::Vsync::DISABLE;

    /* ------------------------------------------------------------------------
     * Generic Layer Metadata
     */
    const std::unordered_map<std::string, uint32_t>& getGenericLayerMetadataKeyMap() const;

    /* ------------------------------------------------------------------------
     * Misc
     */

    std::optional<ActiveConfigInfo> getDesiredActiveConfig() EXCLUDES(mActiveConfigLock) {
        std::lock_guard<std::mutex> lock(mActiveConfigLock);
        if (mDesiredActiveConfigChanged) return mDesiredActiveConfig;
        return std::nullopt;
    }

    std::mutex mActiveConfigLock;
    // This bit is set once we start setting the config. We read from this bit during the
    // process. If at the end, this bit is different than mDesiredActiveConfig, we restart
    // the process.
    ActiveConfigInfo mUpcomingActiveConfig; // Always read and written on the main thread.
    // This bit can be set at any point in time when the system wants the new config.
    ActiveConfigInfo mDesiredActiveConfig GUARDED_BY(mActiveConfigLock);

    // below flags are set by main thread only
    TracedOrdinal<bool> mDesiredActiveConfigChanged
            GUARDED_BY(mActiveConfigLock) = {"DesiredActiveConfigChanged", false};
    bool mSetActiveConfigPending = false;

    bool mLumaSampling = true;
    sp<RegionSamplingThread> mRegionSamplingThread;
    ui::DisplayPrimaries mInternalDisplayPrimaries;

    const float mInternalDisplayDensity;
    const float mEmulatedDisplayDensity;

    sp<IInputFlinger> mInputFlinger;
    InputWindowCommands mPendingInputWindowCommands GUARDED_BY(mStateLock);
    // Should only be accessed by the main thread.
    InputWindowCommands mInputWindowCommands;

    struct SetInputWindowsListener : BnSetInputWindowsListener {
        explicit SetInputWindowsListener(sp<SurfaceFlinger> flinger)
              : mFlinger(std::move(flinger)) {}

        void onSetInputWindowsFinished() override;

        const sp<SurfaceFlinger> mFlinger;
    };

    const sp<SetInputWindowsListener> mSetInputWindowsListener = new SetInputWindowsListener(this);

    bool mPendingSyncInputWindows GUARDED_BY(mStateLock) = false;
    Hwc2::impl::PowerAdvisor mPowerAdvisor;

    // This should only be accessed on the main thread.
    nsecs_t mFrameStartTime = 0;

    void enableRefreshRateOverlay(bool enable);
    std::unique_ptr<RefreshRateOverlay> mRefreshRateOverlay GUARDED_BY(mStateLock);

    // Flag used to set override allowed display configs from backdoor
    bool mDebugDisplayConfigSetByBackdoor = false;

    // A set of layers that have no parent so they are not drawn on screen.
    // Should only be accessed by the main thread.
    // The Layer pointer is removed from the set when the destructor is called so there shouldn't
    // be any issues with a raw pointer referencing an invalid object.
    std::unordered_set<Layer*> mOffscreenLayers;

    // Fields tracking the current jank event: when it started and how many
    // janky frames there are.
    nsecs_t mMissedFrameJankStart = 0;
    int32_t mMissedFrameJankCount = 0;
    // Positive if jank should be uploaded in postComposition
    nsecs_t mLastJankDuration = -1;

    int mFrameRateFlexibilityTokenCount = 0;

    sp<IBinder> mDebugFrameRateFlexibilityToken;
};

} // namespace android
