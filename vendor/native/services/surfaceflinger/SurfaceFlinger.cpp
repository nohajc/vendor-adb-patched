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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

//#define LOG_NDEBUG 0
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "SurfaceFlinger.h"

#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android/configuration.h>
#include <android/gui/IDisplayEventConnection.h>
#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/types.h>
#include <android/hardware/power/Boost.h>
#include <android/native_window.h>
#include <android/os/IInputFlinger.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/CompositionRefreshArgs.h>
#include <compositionengine/Display.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/RenderSurface.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <configstore/Utils.h>
#include <cutils/compiler.h>
#include <cutils/properties.h>
#include <ftl/fake_guard.h>
#include <ftl/future.h>
#include <ftl/small_map.h>
#include <gui/BufferQueue.h>
#include <gui/DebugEGLImageTracker.h>
#include <gui/IProducerListener.h>
#include <gui/LayerDebugInfo.h>
#include <gui/LayerMetadata.h>
#include <gui/LayerState.h>
#include <gui/Surface.h>
#include <gui/TraceUtils.h>
#include <hidl/ServiceManagement.h>
#include <layerproto/LayerProtoParser.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <private/gui/SyncFeatures.h>
#include <processgroup/processgroup.h>
#include <renderengine/RenderEngine.h>
#include <renderengine/impl/ExternalTexture.h>
#include <sys/types.h>
#include <ui/ColorSpace.h>
#include <ui/DataspaceUtils.h>
#include <ui/DebugUtils.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMode.h>
#include <ui/DisplayStatInfo.h>
#include <ui/DisplayState.h>
#include <ui/DynamicDisplayInfo.h>
#include <ui/GraphicBufferAllocator.h>
#include <ui/PixelFormat.h>
#include <ui/StaticDisplayInfo.h>
#include <utils/StopWatch.h>
#include <utils/String16.h>
#include <utils/String8.h>
#include <utils/Timers.h>
#include <utils/misc.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <unordered_map>

#include <ui/DisplayIdentification.h>
#include "BackgroundExecutor.h"
#include "BufferLayer.h"
#include "BufferQueueLayer.h"
#include "BufferStateLayer.h"
#include "Client.h"
#include "Colorizer.h"
#include "ContainerLayer.h"
#include "DisplayDevice.h"
#include "DisplayHardware/ComposerHal.h"
#include "DisplayHardware/FramebufferSurface.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/Hal.h"
#include "DisplayHardware/PowerAdvisor.h"
#include "DisplayHardware/VirtualDisplaySurface.h"
#include "DisplayRenderArea.h"
#include "EffectLayer.h"
#include "Effects/Daltonizer.h"
#include "FlagManager.h"
#include "FpsReporter.h"
#include "FrameTimeline/FrameTimeline.h"
#include "FrameTracer/FrameTracer.h"
#include "HdrLayerInfoReporter.h"
#include "Layer.h"
#include "LayerProtoHelper.h"
#include "LayerRenderArea.h"
#include "LayerVector.h"
#include "MonitoredProducer.h"
#include "MutexUtils.h"
#include "NativeWindowSurface.h"
#include "RefreshRateOverlay.h"
#include "RegionSamplingThread.h"
#include "Scheduler/DispSyncSource.h"
#include "Scheduler/EventThread.h"
#include "Scheduler/LayerHistory.h"
#include "Scheduler/Scheduler.h"
#include "Scheduler/VsyncConfiguration.h"
#include "Scheduler/VsyncController.h"
#include "StartPropertySetThread.h"
#include "SurfaceFlingerProperties.h"
#include "SurfaceInterceptor.h"
#include "TimeStats/TimeStats.h"
#include "TunnelModeEnabledReporter.h"
#include "WindowInfosListenerInvoker.h"

#include <aidl/android/hardware/graphics/common/DisplayDecorationSupport.h>
#include <aidl/android/hardware/graphics/composer3/DisplayCapability.h>
#include <aidl/android/hardware/graphics/composer3/RenderIntent.h>

#undef NO_THREAD_SAFETY_ANALYSIS
#define NO_THREAD_SAFETY_ANALYSIS \
    _Pragma("GCC error \"Prefer <ftl/fake_guard.h> or MutexUtils.h helpers.\"")

namespace android {

using namespace std::string_literals;

using namespace hardware::configstore;
using namespace hardware::configstore::V1_0;
using namespace sysprop;

using aidl::android::hardware::graphics::common::DisplayDecorationSupport;
using aidl::android::hardware::graphics::composer3::Capability;
using aidl::android::hardware::graphics::composer3::DisplayCapability;
using CompositionStrategyPredictionState = android::compositionengine::impl::
        OutputCompositionState::CompositionStrategyPredictionState;

using base::StringAppendF;
using gui::DisplayInfo;
using gui::IDisplayEventConnection;
using gui::IWindowInfosListener;
using gui::WindowInfo;
using ui::ColorMode;
using ui::Dataspace;
using ui::DisplayPrimaries;
using ui::RenderIntent;

using KernelIdleTimerController = scheduler::RefreshRateConfigs::KernelIdleTimerController;

namespace hal = android::hardware::graphics::composer::hal;

namespace {

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wswitch-enum"

bool isWideColorMode(const ColorMode colorMode) {
    switch (colorMode) {
        case ColorMode::DISPLAY_P3:
        case ColorMode::ADOBE_RGB:
        case ColorMode::DCI_P3:
        case ColorMode::BT2020:
        case ColorMode::DISPLAY_BT2020:
        case ColorMode::BT2100_PQ:
        case ColorMode::BT2100_HLG:
            return true;
        case ColorMode::NATIVE:
        case ColorMode::STANDARD_BT601_625:
        case ColorMode::STANDARD_BT601_625_UNADJUSTED:
        case ColorMode::STANDARD_BT601_525:
        case ColorMode::STANDARD_BT601_525_UNADJUSTED:
        case ColorMode::STANDARD_BT709:
        case ColorMode::SRGB:
            return false;
    }
    return false;
}

#pragma clang diagnostic pop

// TODO(b/141333600): Consolidate with DisplayMode::Builder::getDefaultDensity.
constexpr float FALLBACK_DENSITY = ACONFIGURATION_DENSITY_TV;

float getDensityFromProperty(const char* property, bool required) {
    char value[PROPERTY_VALUE_MAX];
    const float density = property_get(property, value, nullptr) > 0 ? std::atof(value) : 0.f;
    if (!density && required) {
        ALOGE("%s must be defined as a build property", property);
        return FALLBACK_DENSITY;
    }
    return density;
}

// Currently we only support V0_SRGB and DISPLAY_P3 as composition preference.
bool validateCompositionDataspace(Dataspace dataspace) {
    return dataspace == Dataspace::V0_SRGB || dataspace == Dataspace::DISPLAY_P3;
}

std::chrono::milliseconds getIdleTimerTimeout(DisplayId displayId) {
    const auto displayIdleTimerMsKey = [displayId] {
        std::stringstream ss;
        ss << "debug.sf.set_idle_timer_ms_" << displayId.value;
        return ss.str();
    }();

    const int32_t displayIdleTimerMs = base::GetIntProperty(displayIdleTimerMsKey, 0);
    if (displayIdleTimerMs > 0) {
        return std::chrono::milliseconds(displayIdleTimerMs);
    }

    const int32_t setIdleTimerMs = base::GetIntProperty("debug.sf.set_idle_timer_ms", 0);
    const int32_t millis = setIdleTimerMs ? setIdleTimerMs : sysprop::set_idle_timer_ms(0);
    return std::chrono::milliseconds(millis);
}

bool getKernelIdleTimerSyspropConfig(DisplayId displayId) {
    const auto displaySupportKernelIdleTimerKey = [displayId] {
        std::stringstream ss;
        ss << "debug.sf.support_kernel_idle_timer_" << displayId.value;
        return ss.str();
    }();

    const auto displaySupportKernelIdleTimer =
            base::GetBoolProperty(displaySupportKernelIdleTimerKey, false);
    return displaySupportKernelIdleTimer || sysprop::support_kernel_idle_timer(false);
}

}  // namespace anonymous

// ---------------------------------------------------------------------------

const String16 sHardwareTest("android.permission.HARDWARE_TEST");
const String16 sAccessSurfaceFlinger("android.permission.ACCESS_SURFACE_FLINGER");
const String16 sRotateSurfaceFlinger("android.permission.ROTATE_SURFACE_FLINGER");
const String16 sReadFramebuffer("android.permission.READ_FRAME_BUFFER");
const String16 sControlDisplayBrightness("android.permission.CONTROL_DISPLAY_BRIGHTNESS");
const String16 sDump("android.permission.DUMP");
const String16 sCaptureBlackoutContent("android.permission.CAPTURE_BLACKOUT_CONTENT");
const String16 sInternalSystemWindow("android.permission.INTERNAL_SYSTEM_WINDOW");

const char* KERNEL_IDLE_TIMER_PROP = "graphics.display.kernel_idle_timer.enabled";

// ---------------------------------------------------------------------------
int64_t SurfaceFlinger::dispSyncPresentTimeOffset;
bool SurfaceFlinger::useHwcForRgbToYuv;
bool SurfaceFlinger::hasSyncFramework;
int64_t SurfaceFlinger::maxFrameBufferAcquiredBuffers;
uint32_t SurfaceFlinger::maxGraphicsWidth;
uint32_t SurfaceFlinger::maxGraphicsHeight;
bool SurfaceFlinger::hasWideColorDisplay;
bool SurfaceFlinger::useContextPriority;
Dataspace SurfaceFlinger::defaultCompositionDataspace = Dataspace::V0_SRGB;
ui::PixelFormat SurfaceFlinger::defaultCompositionPixelFormat = ui::PixelFormat::RGBA_8888;
Dataspace SurfaceFlinger::wideColorGamutCompositionDataspace = Dataspace::V0_SRGB;
ui::PixelFormat SurfaceFlinger::wideColorGamutCompositionPixelFormat = ui::PixelFormat::RGBA_8888;
LatchUnsignaledConfig SurfaceFlinger::enableLatchUnsignaledConfig;

std::string decodeDisplayColorSetting(DisplayColorSetting displayColorSetting) {
    switch(displayColorSetting) {
        case DisplayColorSetting::kManaged:
            return std::string("Managed");
        case DisplayColorSetting::kUnmanaged:
            return std::string("Unmanaged");
        case DisplayColorSetting::kEnhanced:
            return std::string("Enhanced");
        default:
            return std::string("Unknown ") +
                std::to_string(static_cast<int>(displayColorSetting));
    }
}

bool callingThreadHasRotateSurfaceFlingerAccess() {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    return uid == AID_GRAPHICS || uid == AID_SYSTEM ||
            PermissionCache::checkPermission(sRotateSurfaceFlinger, pid, uid);
}

bool callingThreadHasInternalSystemWindowAccess() {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    return uid == AID_GRAPHICS || uid == AID_SYSTEM ||
        PermissionCache::checkPermission(sInternalSystemWindow, pid, uid);
}

SurfaceFlinger::SurfaceFlinger(Factory& factory, SkipInitializationTag)
      : mFactory(factory),
        mPid(getpid()),
        mInterceptor(mFactory.createSurfaceInterceptor()),
        mTimeStats(std::make_shared<impl::TimeStats>()),
        mFrameTracer(mFactory.createFrameTracer()),
        mFrameTimeline(mFactory.createFrameTimeline(mTimeStats, mPid)),
        mCompositionEngine(mFactory.createCompositionEngine()),
        mHwcServiceName(base::GetProperty("debug.sf.hwc_service_name"s, "default"s)),
        mTunnelModeEnabledReporter(new TunnelModeEnabledReporter()),
        mEmulatedDisplayDensity(getDensityFromProperty("qemu.sf.lcd_density", false)),
        mInternalDisplayDensity(
                getDensityFromProperty("ro.sf.lcd_density", !mEmulatedDisplayDensity)),
        mPowerAdvisor(std::make_unique<Hwc2::impl::PowerAdvisor>(*this)),
        mWindowInfosListenerInvoker(sp<WindowInfosListenerInvoker>::make(*this)) {
    ALOGI("Using HWComposer service: %s", mHwcServiceName.c_str());
}

SurfaceFlinger::SurfaceFlinger(Factory& factory) : SurfaceFlinger(factory, SkipInitialization) {
    ALOGI("SurfaceFlinger is starting");

    hasSyncFramework = running_without_sync_framework(true);

    dispSyncPresentTimeOffset = present_time_offset_from_vsync_ns(0);

    useHwcForRgbToYuv = force_hwc_copy_for_virtual_displays(false);

    maxFrameBufferAcquiredBuffers = max_frame_buffer_acquired_buffers(2);

    maxGraphicsWidth = std::max(max_graphics_width(0), 0);
    maxGraphicsHeight = std::max(max_graphics_height(0), 0);

    hasWideColorDisplay = has_wide_color_display(false);
    mDefaultCompositionDataspace =
            static_cast<ui::Dataspace>(default_composition_dataspace(Dataspace::V0_SRGB));
    mWideColorGamutCompositionDataspace = static_cast<ui::Dataspace>(wcg_composition_dataspace(
            hasWideColorDisplay ? Dataspace::DISPLAY_P3 : Dataspace::V0_SRGB));
    defaultCompositionDataspace = mDefaultCompositionDataspace;
    wideColorGamutCompositionDataspace = mWideColorGamutCompositionDataspace;
    defaultCompositionPixelFormat = static_cast<ui::PixelFormat>(
            default_composition_pixel_format(ui::PixelFormat::RGBA_8888));
    wideColorGamutCompositionPixelFormat =
            static_cast<ui::PixelFormat>(wcg_composition_pixel_format(ui::PixelFormat::RGBA_8888));

    mColorSpaceAgnosticDataspace =
            static_cast<ui::Dataspace>(color_space_agnostic_dataspace(Dataspace::UNKNOWN));

    mLayerCachingEnabled = [] {
        const bool enable =
                android::sysprop::SurfaceFlingerProperties::enable_layer_caching().value_or(false);
        return base::GetBoolProperty(std::string("debug.sf.enable_layer_caching"), enable);
    }();

    useContextPriority = use_context_priority(true);

    mInternalDisplayPrimaries = sysprop::getDisplayNativePrimaries();

    // debugging stuff...
    char value[PROPERTY_VALUE_MAX];

    property_get("ro.bq.gpu_to_cpu_unsupported", value, "0");
    mGpuToCpuSupported = !atoi(value);

    property_get("ro.build.type", value, "user");
    mIsUserBuild = strcmp(value, "user") == 0;

    mDebugFlashDelay = base::GetUintProperty("debug.sf.showupdates"s, 0u);

    // DDMS debugging deprecated (b/120782499)
    property_get("debug.sf.ddms", value, "0");
    int debugDdms = atoi(value);
    ALOGI_IF(debugDdms, "DDMS debugging not supported");

    property_get("debug.sf.enable_gl_backpressure", value, "0");
    mPropagateBackpressureClientComposition = atoi(value);
    ALOGI_IF(mPropagateBackpressureClientComposition,
             "Enabling backpressure propagation for Client Composition");

    property_get("ro.surface_flinger.supports_background_blur", value, "0");
    bool supportsBlurs = atoi(value);
    mSupportsBlur = supportsBlurs;
    ALOGI_IF(!mSupportsBlur, "Disabling blur effects, they are not supported.");
    property_get("ro.sf.blurs_are_expensive", value, "0");
    mBlursAreExpensive = atoi(value);

    const size_t defaultListSize = ISurfaceComposer::MAX_LAYERS;
    auto listSize = property_get_int32("debug.sf.max_igbp_list_size", int32_t(defaultListSize));
    mMaxGraphicBufferProducerListSize = (listSize > 0) ? size_t(listSize) : defaultListSize;
    mGraphicBufferProducerListSizeLogThreshold =
            std::max(static_cast<int>(0.95 *
                                      static_cast<double>(mMaxGraphicBufferProducerListSize)),
                     1);

    property_get("debug.sf.luma_sampling", value, "1");
    mLumaSampling = atoi(value);

    property_get("debug.sf.disable_client_composition_cache", value, "0");
    mDisableClientCompositionCache = atoi(value);

    property_get("debug.sf.predict_hwc_composition_strategy", value, "1");
    mPredictCompositionStrategy = atoi(value);

    property_get("debug.sf.treat_170m_as_sRGB", value, "0");
    mTreat170mAsSrgb = atoi(value);

    // We should be reading 'persist.sys.sf.color_saturation' here
    // but since /data may be encrypted, we need to wait until after vold
    // comes online to attempt to read the property. The property is
    // instead read after the boot animation

    if (base::GetBoolProperty("debug.sf.treble_testing_override"s, false)) {
        // Without the override SurfaceFlinger cannot connect to HIDL
        // services that are not listed in the manifests.  Considered
        // deriving the setting from the set service name, but it
        // would be brittle if the name that's not 'default' is used
        // for production purposes later on.
        ALOGI("Enabling Treble testing override");
        android::hardware::details::setTrebleTestingOverride(true);
    }

    mRefreshRateOverlaySpinner = property_get_bool("sf.debug.show_refresh_rate_overlay_spinner", 0);

    if (!mIsUserBuild && base::GetBoolProperty("debug.sf.enable_transaction_tracing"s, true)) {
        mTransactionTracing.emplace();
    }

    mIgnoreHdrCameraLayers = ignore_hdr_camera_layers(false);

    // Power hint session mode, representing which hint(s) to send: early, late, or both)
    mPowerHintSessionMode =
            {.late = base::GetBoolProperty("debug.sf.send_late_power_session_hint"s, true),
             .early = base::GetBoolProperty("debug.sf.send_early_power_session_hint"s, false)};
}

LatchUnsignaledConfig SurfaceFlinger::getLatchUnsignaledConfig() {
    if (base::GetBoolProperty("debug.sf.latch_unsignaled"s, false)) {
        return LatchUnsignaledConfig::Always;
    }

    if (base::GetBoolProperty("debug.sf.auto_latch_unsignaled"s, true)) {
        return LatchUnsignaledConfig::AutoSingleLayer;
    }

    return LatchUnsignaledConfig::Disabled;
}

SurfaceFlinger::~SurfaceFlinger() = default;

void SurfaceFlinger::binderDied(const wp<IBinder>&) {
    // the window manager died on us. prepare its eulogy.
    mBootFinished = false;

    // Sever the link to inputflinger since it's gone as well.
    static_cast<void>(mScheduler->schedule([=] { mInputFlinger = nullptr; }));

    // restore initial conditions (default device unblank, etc)
    initializeDisplays();

    // restart the boot-animation
    startBootAnim();
}

void SurfaceFlinger::run() {
    mScheduler->run();
}

sp<ISurfaceComposerClient> SurfaceFlinger::createConnection() {
    const sp<Client> client = new Client(this);
    return client->initCheck() == NO_ERROR ? client : nullptr;
}

sp<IBinder> SurfaceFlinger::createDisplay(const String8& displayName, bool secure) {
    // onTransact already checks for some permissions, but adding an additional check here.
    // This is to ensure that only system and graphics can request to create a secure
    // display. Secure displays can show secure content so we add an additional restriction on it.
    const int uid = IPCThreadState::self()->getCallingUid();
    if (secure && uid != AID_GRAPHICS && uid != AID_SYSTEM) {
        ALOGE("Only privileged processes can create a secure display");
        return nullptr;
    }

    class DisplayToken : public BBinder {
        sp<SurfaceFlinger> flinger;
        virtual ~DisplayToken() {
             // no more references, this display must be terminated
             Mutex::Autolock _l(flinger->mStateLock);
             flinger->mCurrentState.displays.removeItem(this);
             flinger->setTransactionFlags(eDisplayTransactionNeeded);
         }
     public:
        explicit DisplayToken(const sp<SurfaceFlinger>& flinger)
            : flinger(flinger) {
        }
    };

    sp<BBinder> token = new DisplayToken(this);

    Mutex::Autolock _l(mStateLock);
    // Display ID is assigned when virtual display is allocated by HWC.
    DisplayDeviceState state;
    state.isSecure = secure;
    state.displayName = displayName;
    mCurrentState.displays.add(token, state);
    mInterceptor->saveDisplayCreation(state);
    return token;
}

void SurfaceFlinger::destroyDisplay(const sp<IBinder>& displayToken) {
    Mutex::Autolock lock(mStateLock);

    const ssize_t index = mCurrentState.displays.indexOfKey(displayToken);
    if (index < 0) {
        ALOGE("%s: Invalid display token %p", __func__, displayToken.get());
        return;
    }

    const DisplayDeviceState& state = mCurrentState.displays.valueAt(index);
    if (state.physical) {
        ALOGE("%s: Invalid operation on physical display", __func__);
        return;
    }
    mInterceptor->saveDisplayDeletion(state.sequenceId);
    mCurrentState.displays.removeItemsAt(index);
    setTransactionFlags(eDisplayTransactionNeeded);
}

void SurfaceFlinger::enableHalVirtualDisplays(bool enable) {
    auto& generator = mVirtualDisplayIdGenerators.hal;
    if (!generator && enable) {
        ALOGI("Enabling HAL virtual displays");
        generator.emplace(getHwComposer().getMaxVirtualDisplayCount());
    } else if (generator && !enable) {
        ALOGW_IF(generator->inUse(), "Disabling HAL virtual displays while in use");
        generator.reset();
    }
}

VirtualDisplayId SurfaceFlinger::acquireVirtualDisplay(ui::Size resolution,
                                                       ui::PixelFormat format) {
    if (auto& generator = mVirtualDisplayIdGenerators.hal) {
        if (const auto id = generator->generateId()) {
            if (getHwComposer().allocateVirtualDisplay(*id, resolution, &format)) {
                return *id;
            }

            generator->releaseId(*id);
        } else {
            ALOGW("%s: Exhausted HAL virtual displays", __func__);
        }

        ALOGW("%s: Falling back to GPU virtual display", __func__);
    }

    const auto id = mVirtualDisplayIdGenerators.gpu.generateId();
    LOG_ALWAYS_FATAL_IF(!id, "Failed to generate ID for GPU virtual display");
    return *id;
}

void SurfaceFlinger::releaseVirtualDisplay(VirtualDisplayId displayId) {
    if (const auto id = HalVirtualDisplayId::tryCast(displayId)) {
        if (auto& generator = mVirtualDisplayIdGenerators.hal) {
            generator->releaseId(*id);
        }
        return;
    }

    const auto id = GpuVirtualDisplayId::tryCast(displayId);
    LOG_ALWAYS_FATAL_IF(!id);
    mVirtualDisplayIdGenerators.gpu.releaseId(*id);
}

std::vector<PhysicalDisplayId> SurfaceFlinger::getPhysicalDisplayIdsLocked() const {
    std::vector<PhysicalDisplayId> displayIds;
    displayIds.reserve(mPhysicalDisplayTokens.size());

    const auto defaultDisplayId = getDefaultDisplayDeviceLocked()->getPhysicalId();
    displayIds.push_back(defaultDisplayId);

    for (const auto& [id, token] : mPhysicalDisplayTokens) {
        if (id != defaultDisplayId) {
            displayIds.push_back(id);
        }
    }

    return displayIds;
}

status_t SurfaceFlinger::getPrimaryPhysicalDisplayId(PhysicalDisplayId* id) const {
    Mutex::Autolock lock(mStateLock);
    *id = getPrimaryDisplayIdLocked();
    return NO_ERROR;
}

sp<IBinder> SurfaceFlinger::getPhysicalDisplayToken(PhysicalDisplayId displayId) const {
    Mutex::Autolock lock(mStateLock);
    return getPhysicalDisplayTokenLocked(displayId);
}

status_t SurfaceFlinger::getColorManagement(bool* outGetColorManagement) const {
    if (!outGetColorManagement) {
        return BAD_VALUE;
    }
    *outGetColorManagement = useColorManagement;
    return NO_ERROR;
}

HWComposer& SurfaceFlinger::getHwComposer() const {
    return mCompositionEngine->getHwComposer();
}

renderengine::RenderEngine& SurfaceFlinger::getRenderEngine() const {
    return mCompositionEngine->getRenderEngine();
}

compositionengine::CompositionEngine& SurfaceFlinger::getCompositionEngine() const {
    return *mCompositionEngine.get();
}

void SurfaceFlinger::bootFinished() {
    if (mBootFinished == true) {
        ALOGE("Extra call to bootFinished");
        return;
    }
    mBootFinished = true;
    if (mStartPropertySetThread->join() != NO_ERROR) {
        ALOGE("Join StartPropertySetThread failed!");
    }

    if (mRenderEnginePrimeCacheFuture.valid()) {
        mRenderEnginePrimeCacheFuture.get();
    }
    const nsecs_t now = systemTime();
    const nsecs_t duration = now - mBootTime;
    ALOGI("Boot is finished (%ld ms)", long(ns2ms(duration)) );

    mFrameTracer->initialize();
    mFrameTimeline->onBootFinished();
    getRenderEngine().setEnableTracing(mFlagManager.use_skia_tracing());

    // wait patiently for the window manager death
    const String16 name("window");
    mWindowManager = defaultServiceManager()->getService(name);
    if (mWindowManager != 0) {
        mWindowManager->linkToDeath(static_cast<IBinder::DeathRecipient*>(this));
    }

    // stop boot animation
    // formerly we would just kill the process, but we now ask it to exit so it
    // can choose where to stop the animation.
    property_set("service.bootanim.exit", "1");

    const int LOGTAG_SF_STOP_BOOTANIM = 60110;
    LOG_EVENT_LONG(LOGTAG_SF_STOP_BOOTANIM,
                   ns2ms(systemTime(SYSTEM_TIME_MONOTONIC)));

    sp<IBinder> input(defaultServiceManager()->getService(String16("inputflinger")));

    static_cast<void>(mScheduler->schedule([=] {
        if (input == nullptr) {
            ALOGE("Failed to link to input service");
        } else {
            mInputFlinger = interface_cast<os::IInputFlinger>(input);
        }

        readPersistentProperties();
        mPowerAdvisor->onBootFinished();
        const bool powerHintEnabled = mFlagManager.use_adpf_cpu_hint();
        mPowerAdvisor->enablePowerHint(powerHintEnabled);
        const bool powerHintUsed = mPowerAdvisor->usePowerHintSession();
        ALOGD("Power hint is %s",
              powerHintUsed ? "supported" : (powerHintEnabled ? "unsupported" : "disabled"));
        if (powerHintUsed) {
            std::optional<pid_t> renderEngineTid = getRenderEngine().getRenderEngineTid();
            std::vector<int32_t> tidList;
            tidList.emplace_back(gettid());
            if (renderEngineTid.has_value()) {
                tidList.emplace_back(*renderEngineTid);
            }
            if (!mPowerAdvisor->startPowerHintSession(tidList)) {
                ALOGW("Cannot start power hint session");
            }
        }

        mBootStage = BootStage::FINISHED;

        if (property_get_bool("sf.debug.show_refresh_rate_overlay", false)) {
            FTL_FAKE_GUARD(mStateLock, enableRefreshRateOverlay(true));
        }
    }));
}

uint32_t SurfaceFlinger::getNewTexture() {
    {
        std::lock_guard lock(mTexturePoolMutex);
        if (!mTexturePool.empty()) {
            uint32_t name = mTexturePool.back();
            mTexturePool.pop_back();
            ATRACE_INT("TexturePoolSize", mTexturePool.size());
            return name;
        }

        // The pool was too small, so increase it for the future
        ++mTexturePoolSize;
    }

    // The pool was empty, so we need to get a new texture name directly using a
    // blocking call to the main thread
    auto genTextures = [this] {
               uint32_t name = 0;
               getRenderEngine().genTextures(1, &name);
               return name;
    };
    if (std::this_thread::get_id() == mMainThreadId) {
        return genTextures();
    } else {
        return mScheduler->schedule(genTextures).get();
    }
}

void SurfaceFlinger::deleteTextureAsync(uint32_t texture) {
    std::lock_guard lock(mTexturePoolMutex);
    // We don't change the pool size, so the fix-up logic in postComposition will decide whether
    // to actually delete this or not based on mTexturePoolSize
    mTexturePool.push_back(texture);
    ATRACE_INT("TexturePoolSize", mTexturePool.size());
}

static std::optional<renderengine::RenderEngine::RenderEngineType>
chooseRenderEngineTypeViaSysProp() {
    char prop[PROPERTY_VALUE_MAX];
    property_get(PROPERTY_DEBUG_RENDERENGINE_BACKEND, prop, "");

    if (strcmp(prop, "gles") == 0) {
        return renderengine::RenderEngine::RenderEngineType::GLES;
    } else if (strcmp(prop, "threaded") == 0) {
        return renderengine::RenderEngine::RenderEngineType::THREADED;
    } else if (strcmp(prop, "skiagl") == 0) {
        return renderengine::RenderEngine::RenderEngineType::SKIA_GL;
    } else if (strcmp(prop, "skiaglthreaded") == 0) {
        return renderengine::RenderEngine::RenderEngineType::SKIA_GL_THREADED;
    } else {
        ALOGE("Unrecognized RenderEngineType %s; ignoring!", prop);
        return {};
    }
}

// Do not call property_set on main thread which will be blocked by init
// Use StartPropertySetThread instead.
void SurfaceFlinger::init() {
    ALOGI(  "SurfaceFlinger's main thread ready to run. "
            "Initializing graphics H/W...");
    Mutex::Autolock _l(mStateLock);

    // Get a RenderEngine for the given display / config (can't fail)
    // TODO(b/77156734): We need to stop casting and use HAL types when possible.
    // Sending maxFrameBufferAcquiredBuffers as the cache size is tightly tuned to single-display.
    auto builder = renderengine::RenderEngineCreationArgs::Builder()
                           .setPixelFormat(static_cast<int32_t>(defaultCompositionPixelFormat))
                           .setImageCacheSize(maxFrameBufferAcquiredBuffers)
                           .setUseColorManagerment(useColorManagement)
                           .setEnableProtectedContext(enable_protected_contents(false))
                           .setPrecacheToneMapperShaderOnly(false)
                           .setSupportsBackgroundBlur(mSupportsBlur)
                           .setContextPriority(
                                   useContextPriority
                                           ? renderengine::RenderEngine::ContextPriority::REALTIME
                                           : renderengine::RenderEngine::ContextPriority::MEDIUM);
    if (auto type = chooseRenderEngineTypeViaSysProp()) {
        builder.setRenderEngineType(type.value());
    }
    mCompositionEngine->setRenderEngine(renderengine::RenderEngine::create(builder.build()));
    mMaxRenderTargetSize =
            std::min(getRenderEngine().getMaxTextureSize(), getRenderEngine().getMaxViewportDims());

    // Set SF main policy after initializing RenderEngine which has its own policy.
    if (!SetTaskProfiles(0, {"SFMainPolicy"})) {
        ALOGW("Failed to set main task profile");
    }

    mCompositionEngine->setTimeStats(mTimeStats);
    mCompositionEngine->setHwComposer(getFactory().createHWComposer(mHwcServiceName));
    mCompositionEngine->getHwComposer().setCallback(*this);
    ClientCache::getInstance().setRenderEngine(&getRenderEngine());

    enableLatchUnsignaledConfig = getLatchUnsignaledConfig();

    if (base::GetBoolProperty("debug.sf.enable_hwc_vds"s, false)) {
        enableHalVirtualDisplays(true);
    }

    // Process any initial hotplug and resulting display changes.
    processDisplayHotplugEventsLocked();
    const auto display = getDefaultDisplayDeviceLocked();
    LOG_ALWAYS_FATAL_IF(!display, "Missing primary display after registering composer callback.");
    const auto displayId = display->getPhysicalId();
    LOG_ALWAYS_FATAL_IF(!getHwComposer().isConnected(displayId),
                        "Primary display is disconnected.");

    // initialize our drawing state
    mDrawingState = mCurrentState;

    // set initial conditions (e.g. unblank default device)
    initializeDisplays();

    mPowerAdvisor->init();

    char primeShaderCache[PROPERTY_VALUE_MAX];
    property_get("service.sf.prime_shader_cache", primeShaderCache, "1");
    if (atoi(primeShaderCache)) {
        if (setSchedFifo(false) != NO_ERROR) {
            ALOGW("Can't set SCHED_OTHER for primeCache");
        }

        mRenderEnginePrimeCacheFuture = getRenderEngine().primeCache();

        if (setSchedFifo(true) != NO_ERROR) {
            ALOGW("Can't set SCHED_OTHER for primeCache");
        }
    }

    onActiveDisplaySizeChanged(display);

    // Inform native graphics APIs whether the present timestamp is supported:

    const bool presentFenceReliable =
            !getHwComposer().hasCapability(Capability::PRESENT_FENCE_IS_NOT_RELIABLE);
    mStartPropertySetThread = getFactory().createStartPropertySetThread(presentFenceReliable);

    if (mStartPropertySetThread->Start() != NO_ERROR) {
        ALOGE("Run StartPropertySetThread failed!");
    }

    ALOGV("Done initializing");
}

void SurfaceFlinger::readPersistentProperties() {
    Mutex::Autolock _l(mStateLock);

    char value[PROPERTY_VALUE_MAX];

    property_get("persist.sys.sf.color_saturation", value, "1.0");
    mGlobalSaturationFactor = atof(value);
    updateColorMatrixLocked();
    ALOGV("Saturation is set to %.2f", mGlobalSaturationFactor);

    property_get("persist.sys.sf.native_mode", value, "0");
    mDisplayColorSetting = static_cast<DisplayColorSetting>(atoi(value));

    property_get("persist.sys.sf.color_mode", value, "0");
    mForceColorMode = static_cast<ColorMode>(atoi(value));
}

void SurfaceFlinger::startBootAnim() {
    // Start boot animation service by setting a property mailbox
    // if property setting thread is already running, Start() will be just a NOP
    mStartPropertySetThread->Start();
    // Wait until property was set
    if (mStartPropertySetThread->join() != NO_ERROR) {
        ALOGE("Join StartPropertySetThread failed!");
    }
}

// ----------------------------------------------------------------------------

bool SurfaceFlinger::authenticateSurfaceTexture(
        const sp<IGraphicBufferProducer>& bufferProducer) const {
    Mutex::Autolock _l(mStateLock);
    return authenticateSurfaceTextureLocked(bufferProducer);
}

bool SurfaceFlinger::authenticateSurfaceTextureLocked(
        const sp<IGraphicBufferProducer>& /* bufferProducer */) const {
    return false;
}

status_t SurfaceFlinger::getSupportedFrameTimestamps(
        std::vector<FrameEvent>* outSupported) const {
    *outSupported = {
        FrameEvent::REQUESTED_PRESENT,
        FrameEvent::ACQUIRE,
        FrameEvent::LATCH,
        FrameEvent::FIRST_REFRESH_START,
        FrameEvent::LAST_REFRESH_START,
        FrameEvent::GPU_COMPOSITION_DONE,
        FrameEvent::DEQUEUE_READY,
        FrameEvent::RELEASE,
    };

    ConditionalLock lock(mStateLock, std::this_thread::get_id() != mMainThreadId);

    if (!getHwComposer().hasCapability(Capability::PRESENT_FENCE_IS_NOT_RELIABLE)) {
        outSupported->push_back(FrameEvent::DISPLAY_PRESENT);
    }
    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayState(const sp<IBinder>& displayToken, ui::DisplayState* state) {
    if (!displayToken || !state) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    state->layerStack = display->getLayerStack();
    state->orientation = display->getOrientation();

    const Rect layerStackRect = display->getLayerStackSpaceRect();
    state->layerStackSpaceRect =
            layerStackRect.isValid() ? layerStackRect.getSize() : display->getSize();

    return NO_ERROR;
}

status_t SurfaceFlinger::getStaticDisplayInfo(const sp<IBinder>& displayToken,
                                              ui::StaticDisplayInfo* info) {
    if (!displayToken || !info) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    if (const auto connectionType = display->getConnectionType())
        info->connectionType = *connectionType;
    else {
        return INVALID_OPERATION;
    }

    if (mEmulatedDisplayDensity) {
        info->density = mEmulatedDisplayDensity;
    } else {
        info->density = info->connectionType == ui::DisplayConnectionType::Internal
                ? mInternalDisplayDensity
                : FALLBACK_DENSITY;
    }
    info->density /= ACONFIGURATION_DENSITY_MEDIUM;

    info->secure = display->isSecure();
    info->deviceProductInfo = display->getDeviceProductInfo();
    info->installOrientation = display->getPhysicalOrientation();

    return NO_ERROR;
}

status_t SurfaceFlinger::getDynamicDisplayInfo(const sp<IBinder>& displayToken,
                                               ui::DynamicDisplayInfo* info) {
    if (!displayToken || !info) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    const auto displayId = PhysicalDisplayId::tryCast(display->getId());
    if (!displayId) {
        return INVALID_OPERATION;
    }

    info->activeDisplayModeId = display->getActiveMode()->getId().value();

    const auto& supportedModes = display->getSupportedModes();
    info->supportedDisplayModes.clear();
    info->supportedDisplayModes.reserve(supportedModes.size());

    for (const auto& [id, mode] : supportedModes) {
        ui::DisplayMode outMode;
        outMode.id = static_cast<int32_t>(id.value());

        auto [width, height] = mode->getResolution();
        auto [xDpi, yDpi] = mode->getDpi();

        if (const auto physicalOrientation = display->getPhysicalOrientation();
            physicalOrientation == ui::ROTATION_90 || physicalOrientation == ui::ROTATION_270) {
            std::swap(width, height);
            std::swap(xDpi, yDpi);
        }

        outMode.resolution = ui::Size(width, height);

        outMode.xDpi = xDpi;
        outMode.yDpi = yDpi;

        const nsecs_t period = mode->getVsyncPeriod();
        outMode.refreshRate = Fps::fromPeriodNsecs(period).getValue();

        const auto vsyncConfigSet =
                mVsyncConfiguration->getConfigsForRefreshRate(Fps::fromValue(outMode.refreshRate));
        outMode.appVsyncOffset = vsyncConfigSet.late.appOffset;
        outMode.sfVsyncOffset = vsyncConfigSet.late.sfOffset;
        outMode.group = mode->getGroup();

        // This is how far in advance a buffer must be queued for
        // presentation at a given time.  If you want a buffer to appear
        // on the screen at time N, you must submit the buffer before
        // (N - presentationDeadline).
        //
        // Normally it's one full refresh period (to give SF a chance to
        // latch the buffer), but this can be reduced by configuring a
        // VsyncController offset.  Any additional delays introduced by the hardware
        // composer or panel must be accounted for here.
        //
        // We add an additional 1ms to allow for processing time and
        // differences between the ideal and actual refresh rate.
        outMode.presentationDeadline = period - outMode.sfVsyncOffset + 1000000;

        info->supportedDisplayModes.push_back(outMode);
    }

    info->activeColorMode = display->getCompositionDisplay()->getState().colorMode;
    info->supportedColorModes = getDisplayColorModes(*display);
    info->hdrCapabilities = display->getHdrCapabilities();

    info->autoLowLatencyModeSupported =
            getHwComposer().hasDisplayCapability(*displayId,
                                                 DisplayCapability::AUTO_LOW_LATENCY_MODE);
    info->gameContentTypeSupported =
            getHwComposer().supportsContentType(*displayId, hal::ContentType::GAME);

    info->preferredBootDisplayMode = static_cast<ui::DisplayModeId>(-1);

    if (getHwComposer().hasCapability(Capability::BOOT_DISPLAY_CONFIG)) {
        if (const auto hwcId = getHwComposer().getPreferredBootDisplayMode(*displayId)) {
            if (const auto modeId = display->translateModeId(*hwcId)) {
                info->preferredBootDisplayMode = modeId->value();
            }
        }
    }

    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayStats(const sp<IBinder>&, DisplayStatInfo* stats) {
    if (!stats) {
        return BAD_VALUE;
    }

    *stats = mScheduler->getDisplayStatInfo(systemTime());
    return NO_ERROR;
}

void SurfaceFlinger::setDesiredActiveMode(const ActiveModeInfo& info, bool force) {
    ATRACE_CALL();

    if (!info.mode) {
        ALOGW("requested display mode is null");
        return;
    }
    auto display = getDisplayDeviceLocked(info.mode->getPhysicalDisplayId());
    if (!display) {
        ALOGW("%s: display is no longer valid", __func__);
        return;
    }

    if (display->setDesiredActiveMode(info, force)) {
        scheduleComposite(FrameHint::kNone);

        // Start receiving vsync samples now, so that we can detect a period
        // switch.
        mScheduler->resyncToHardwareVsync(true, info.mode->getFps());
        // As we called to set period, we will call to onRefreshRateChangeCompleted once
        // VsyncController model is locked.
        modulateVsync(&VsyncModulator::onRefreshRateChangeInitiated);

        updatePhaseConfiguration(info.mode->getFps());
        mScheduler->setModeChangePending(true);
    }
}

status_t SurfaceFlinger::setActiveModeFromBackdoor(const sp<IBinder>& displayToken, int modeId) {
    ATRACE_CALL();

    if (!displayToken) {
        return BAD_VALUE;
    }

    auto future = mScheduler->schedule([=]() -> status_t {
        const auto display = FTL_FAKE_GUARD(mStateLock, getDisplayDeviceLocked(displayToken));
        if (!display) {
            ALOGE("Attempt to set allowed display modes for invalid display token %p",
                  displayToken.get());
            return NAME_NOT_FOUND;
        }

        if (display->isVirtual()) {
            ALOGW("Attempt to set allowed display modes for virtual display");
            return INVALID_OPERATION;
        }

        const auto mode = display->getMode(DisplayModeId{modeId});
        if (!mode) {
            ALOGW("Attempt to switch to an unsupported mode %d.", modeId);
            return BAD_VALUE;
        }

        const auto fps = mode->getFps();
        // Keep the old switching type.
        const auto allowGroupSwitching =
                display->refreshRateConfigs().getCurrentPolicy().allowGroupSwitching;
        const scheduler::RefreshRateConfigs::Policy policy{mode->getId(),
                                                           allowGroupSwitching,
                                                           {fps, fps}};
        constexpr bool kOverridePolicy = false;

        return setDesiredDisplayModeSpecsInternal(display, policy, kOverridePolicy);
    });

    return future.get();
}

void SurfaceFlinger::updateInternalStateWithChangedMode() {
    ATRACE_CALL();

    const auto display = getDefaultDisplayDeviceLocked();
    if (!display) {
        return;
    }

    const auto upcomingModeInfo =
            FTL_FAKE_GUARD(kMainThreadContext, display->getUpcomingActiveMode());

    if (!upcomingModeInfo.mode) {
        // There is no pending mode change. This can happen if the active
        // display changed and the mode change happened on a different display.
        return;
    }

    if (display->getActiveMode()->getResolution() != upcomingModeInfo.mode->getResolution()) {
        auto& state = mCurrentState.displays.editValueFor(display->getDisplayToken());
        // We need to generate new sequenceId in order to recreate the display (and this
        // way the framebuffer).
        state.sequenceId = DisplayDeviceState{}.sequenceId;
        state.physical->activeMode = upcomingModeInfo.mode;
        processDisplayChangesLocked();

        // processDisplayChangesLocked will update all necessary components so we're done here.
        return;
    }

    // We just created this display so we can call even if we are not on the main thread.
    ftl::FakeGuard guard(kMainThreadContext);
    display->setActiveMode(upcomingModeInfo.mode->getId());

    const Fps refreshRate = upcomingModeInfo.mode->getFps();
    mRefreshRateStats->setRefreshRate(refreshRate);
    updatePhaseConfiguration(refreshRate);

    if (upcomingModeInfo.event != DisplayModeEvent::None) {
        mScheduler->onPrimaryDisplayModeChanged(mAppConnectionHandle, upcomingModeInfo.mode);
    }
}

void SurfaceFlinger::clearDesiredActiveModeState(const sp<DisplayDevice>& display) {
    display->clearDesiredActiveModeState();
    if (isDisplayActiveLocked(display)) {
        mScheduler->setModeChangePending(false);
    }
}

void SurfaceFlinger::desiredActiveModeChangeDone(const sp<DisplayDevice>& display) {
    const auto refreshRate = display->getDesiredActiveMode()->mode->getFps();
    clearDesiredActiveModeState(display);
    mScheduler->resyncToHardwareVsync(true, refreshRate);
    updatePhaseConfiguration(refreshRate);
}

void SurfaceFlinger::setActiveModeInHwcIfNeeded() {
    ATRACE_CALL();

    std::optional<PhysicalDisplayId> displayToUpdateImmediately;

    for (const auto& iter : mDisplays) {
        const auto& display = iter.second;
        if (!display || !display->isInternal()) {
            continue;
        }

        // Store the local variable to release the lock.
        const auto desiredActiveMode = display->getDesiredActiveMode();
        if (!desiredActiveMode) {
            // No desired active mode pending to be applied
            continue;
        }

        if (!isDisplayActiveLocked(display)) {
            // display is no longer the active display, so abort the mode change
            clearDesiredActiveModeState(display);
            continue;
        }

        const auto desiredMode = display->getMode(desiredActiveMode->mode->getId());
        if (!desiredMode) {
            ALOGW("Desired display mode is no longer supported. Mode ID = %d",
                  desiredActiveMode->mode->getId().value());
            clearDesiredActiveModeState(display);
            continue;
        }

        const auto refreshRate = desiredMode->getFps();
        ALOGV("%s changing active mode to %d(%s) for display %s", __func__,
              desiredMode->getId().value(), to_string(refreshRate).c_str(),
              to_string(display->getId()).c_str());

        if (display->getActiveMode()->getId() == desiredActiveMode->mode->getId()) {
            // we are already in the requested mode, there is nothing left to do
            desiredActiveModeChangeDone(display);
            continue;
        }

        // Desired active mode was set, it is different than the mode currently in use, however
        // allowed modes might have changed by the time we process the refresh.
        // Make sure the desired mode is still allowed
        const auto displayModeAllowed =
                display->refreshRateConfigs().isModeAllowed(desiredActiveMode->mode->getId());
        if (!displayModeAllowed) {
            clearDesiredActiveModeState(display);
            continue;
        }

        // TODO(b/142753666) use constrains
        hal::VsyncPeriodChangeConstraints constraints;
        constraints.desiredTimeNanos = systemTime();
        constraints.seamlessRequired = false;
        hal::VsyncPeriodChangeTimeline outTimeline;

        const auto status = FTL_FAKE_GUARD(kMainThreadContext,
                                           display->initiateModeChange(*desiredActiveMode,
                                                                       constraints, &outTimeline));

        if (status != NO_ERROR) {
            // initiateModeChange may fail if a hotplug event is just about
            // to be sent. We just log the error in this case.
            ALOGW("initiateModeChange failed: %d", status);
            continue;
        }
        mScheduler->onNewVsyncPeriodChangeTimeline(outTimeline);

        if (outTimeline.refreshRequired) {
            scheduleComposite(FrameHint::kNone);
            mSetActiveModePending = true;
        } else {
            // Updating the internal state should be done outside the loop,
            // because it can recreate a DisplayDevice and modify mDisplays
            // which will invalidate the iterator.
            displayToUpdateImmediately = display->getPhysicalId();
        }
    }

    if (displayToUpdateImmediately) {
        updateInternalStateWithChangedMode();

        const auto display = getDisplayDeviceLocked(*displayToUpdateImmediately);
        const auto desiredActiveMode = display->getDesiredActiveMode();
        if (desiredActiveMode &&
            display->getActiveMode()->getId() == desiredActiveMode->mode->getId()) {
            desiredActiveModeChangeDone(display);
        }
    }
}

void SurfaceFlinger::disableExpensiveRendering() {
    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
        ATRACE_NAME(whence);
        if (mPowerAdvisor->isUsingExpensiveRendering()) {
            for (const auto& [_, display] : mDisplays) {
                constexpr bool kDisable = false;
                mPowerAdvisor->setExpensiveRenderingExpected(display->getId(), kDisable);
            }
        }
    });

    future.wait();
}

std::vector<ColorMode> SurfaceFlinger::getDisplayColorModes(const DisplayDevice& display) {
    auto modes = getHwComposer().getColorModes(display.getPhysicalId());

    // If the display is internal and the configuration claims it's not wide color capable,
    // filter out all wide color modes. The typical reason why this happens is that the
    // hardware is not good enough to support GPU composition of wide color, and thus the
    // OEMs choose to disable this capability.
    if (display.getConnectionType() == ui::DisplayConnectionType::Internal &&
        !hasWideColorDisplay) {
        const auto newEnd = std::remove_if(modes.begin(), modes.end(), isWideColorMode);
        modes.erase(newEnd, modes.end());
    }

    return modes;
}

status_t SurfaceFlinger::getDisplayNativePrimaries(const sp<IBinder>& displayToken,
                                                   ui::DisplayPrimaries& primaries) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    const auto connectionType = display->getConnectionType();
    if (connectionType != ui::DisplayConnectionType::Internal) {
        return INVALID_OPERATION;
    }

    // TODO(b/229846990): For now, assume that all internal displays have the same primaries.
    primaries = mInternalDisplayPrimaries;
    return NO_ERROR;
}

status_t SurfaceFlinger::setActiveColorMode(const sp<IBinder>& displayToken, ColorMode mode) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) -> status_t {
        const auto display = getDisplayDeviceLocked(displayToken);
        if (!display) {
            ALOGE("Attempt to set active color mode %s (%d) for invalid display token %p",
                  decodeColorMode(mode).c_str(), mode, displayToken.get());
            return NAME_NOT_FOUND;
        }

        if (display->isVirtual()) {
            ALOGW("Attempt to set active color mode %s (%d) for virtual display",
                  decodeColorMode(mode).c_str(), mode);
            return INVALID_OPERATION;
        }

        const auto modes = getDisplayColorModes(*display);
        const bool exists = std::find(modes.begin(), modes.end(), mode) != modes.end();

        if (mode < ColorMode::NATIVE || !exists) {
            ALOGE("Attempt to set invalid active color mode %s (%d) for display token %p",
                  decodeColorMode(mode).c_str(), mode, displayToken.get());
            return BAD_VALUE;
        }

        display->getCompositionDisplay()->setColorProfile(
                {mode, Dataspace::UNKNOWN, RenderIntent::COLORIMETRIC, Dataspace::UNKNOWN});

        return NO_ERROR;
    });

    // TODO(b/195698395): Propagate error.
    future.wait();
    return NO_ERROR;
}

status_t SurfaceFlinger::getBootDisplayModeSupport(bool* outSupport) const {
    auto future = mScheduler->schedule(
            [this] { return getHwComposer().hasCapability(Capability::BOOT_DISPLAY_CONFIG); });

    *outSupport = future.get();
    return NO_ERROR;
}

status_t SurfaceFlinger::setBootDisplayMode(const sp<IBinder>& displayToken,
                                            ui::DisplayModeId modeId) {
    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) -> status_t {
        const auto display = getDisplayDeviceLocked(displayToken);
        if (!display) {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
            return NAME_NOT_FOUND;
        }

        if (display->isVirtual()) {
            ALOGE("%s: Invalid operation on virtual display", whence);
            return INVALID_OPERATION;
        }

        const auto displayId = display->getPhysicalId();
        const auto mode = display->getMode(DisplayModeId{modeId});
        if (!mode) {
            ALOGE("%s: Invalid mode %d for display %s", whence, modeId,
                  to_string(displayId).c_str());
            return BAD_VALUE;
        }

        return getHwComposer().setBootDisplayMode(displayId, mode->getHwcId());
    });
    return future.get();
}

status_t SurfaceFlinger::clearBootDisplayMode(const sp<IBinder>& displayToken) {
    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) -> status_t {
        if (const auto displayId = getPhysicalDisplayIdLocked(displayToken)) {
            return getHwComposer().clearBootDisplayMode(*displayId);
        } else {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
            return BAD_VALUE;
        }
    });
    return future.get();
}

void SurfaceFlinger::setAutoLowLatencyMode(const sp<IBinder>& displayToken, bool on) {
    const char* const whence = __func__;
    static_cast<void>(mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
        if (const auto displayId = getPhysicalDisplayIdLocked(displayToken)) {
            getHwComposer().setAutoLowLatencyMode(*displayId, on);
        } else {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
        }
    }));
}

void SurfaceFlinger::setGameContentType(const sp<IBinder>& displayToken, bool on) {
    const char* const whence = __func__;
    static_cast<void>(mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
        if (const auto displayId = getPhysicalDisplayIdLocked(displayToken)) {
            const auto type = on ? hal::ContentType::GAME : hal::ContentType::NONE;
            getHwComposer().setContentType(*displayId, type);
        } else {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
        }
    }));
}

status_t SurfaceFlinger::clearAnimationFrameStats() {
    Mutex::Autolock _l(mStateLock);
    mAnimFrameTracker.clearStats();
    return NO_ERROR;
}

status_t SurfaceFlinger::getAnimationFrameStats(FrameStats* outStats) const {
    Mutex::Autolock _l(mStateLock);
    mAnimFrameTracker.getStats(outStats);
    return NO_ERROR;
}

status_t SurfaceFlinger::overrideHdrTypes(const sp<IBinder>& displayToken,
                                          const std::vector<ui::Hdr>& hdrTypes) {
    Mutex::Autolock lock(mStateLock);

    auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        ALOGE("%s: Invalid display token %p", __func__, displayToken.get());
        return NAME_NOT_FOUND;
    }

    display->overrideHdrTypes(hdrTypes);
    dispatchDisplayHotplugEvent(display->getPhysicalId(), true /* connected */);
    return NO_ERROR;
}

status_t SurfaceFlinger::onPullAtom(const int32_t atomId, std::string* pulledData, bool* success) {
    *success = mTimeStats->onPullAtom(atomId, pulledData);
    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayedContentSamplingAttributes(const sp<IBinder>& displayToken,
                                                               ui::PixelFormat* outFormat,
                                                               ui::Dataspace* outDataspace,
                                                               uint8_t* outComponentMask) const {
    if (!outFormat || !outDataspace || !outComponentMask) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto displayId = getPhysicalDisplayIdLocked(displayToken);
    if (!displayId) {
        return NAME_NOT_FOUND;
    }

    return getHwComposer().getDisplayedContentSamplingAttributes(*displayId, outFormat,
                                                                 outDataspace, outComponentMask);
}

status_t SurfaceFlinger::setDisplayContentSamplingEnabled(const sp<IBinder>& displayToken,
                                                          bool enable, uint8_t componentMask,
                                                          uint64_t maxFrames) {
    const char* const whence = __func__;
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) -> status_t {
        if (const auto displayId = getPhysicalDisplayIdLocked(displayToken)) {
            return getHwComposer().setDisplayContentSamplingEnabled(*displayId, enable,
                                                                    componentMask, maxFrames);
        } else {
            ALOGE("%s: Invalid display token %p", whence, displayToken.get());
            return NAME_NOT_FOUND;
        }
    });

    return future.get();
}

status_t SurfaceFlinger::getDisplayedContentSample(const sp<IBinder>& displayToken,
                                                   uint64_t maxFrames, uint64_t timestamp,
                                                   DisplayedFrameStats* outStats) const {
    Mutex::Autolock lock(mStateLock);

    const auto displayId = getPhysicalDisplayIdLocked(displayToken);
    if (!displayId) {
        return NAME_NOT_FOUND;
    }

    return getHwComposer().getDisplayedContentSample(*displayId, maxFrames, timestamp, outStats);
}

status_t SurfaceFlinger::getProtectedContentSupport(bool* outSupported) const {
    if (!outSupported) {
        return BAD_VALUE;
    }
    *outSupported = getRenderEngine().supportsProtectedContent();
    return NO_ERROR;
}

status_t SurfaceFlinger::isWideColorDisplay(const sp<IBinder>& displayToken,
                                            bool* outIsWideColorDisplay) const {
    if (!displayToken || !outIsWideColorDisplay) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);
    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    *outIsWideColorDisplay =
            display->isPrimary() ? hasWideColorDisplay : display->hasWideColorGamut();
    return NO_ERROR;
}

status_t SurfaceFlinger::enableVSyncInjections(bool enable) {
    auto future = mScheduler->schedule([=] {
        Mutex::Autolock lock(mStateLock);

        if (const auto handle = mScheduler->enableVSyncInjection(enable)) {
            mScheduler->setInjector(enable ? mScheduler->getEventConnection(handle) : nullptr);
        }
    });

    future.wait();
    return NO_ERROR;
}

status_t SurfaceFlinger::injectVSync(nsecs_t when) {
    Mutex::Autolock lock(mStateLock);
    const DisplayStatInfo stats = mScheduler->getDisplayStatInfo(when);
    const auto expectedPresent = calculateExpectedPresentTime(stats);
    return mScheduler->injectVSync(when, /*expectedVSyncTime=*/expectedPresent,
                                   /*deadlineTimestamp=*/expectedPresent)
            ? NO_ERROR
            : BAD_VALUE;
}

status_t SurfaceFlinger::getLayerDebugInfo(std::vector<LayerDebugInfo>* outLayers) {
    outLayers->clear();
    auto future = mScheduler->schedule([=] {
        const auto display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());
        mDrawingState.traverseInZOrder([&](Layer* layer) {
            outLayers->push_back(layer->getLayerDebugInfo(display.get()));
        });
    });

    future.wait();
    return NO_ERROR;
}

status_t SurfaceFlinger::getCompositionPreference(
        Dataspace* outDataspace, ui::PixelFormat* outPixelFormat,
        Dataspace* outWideColorGamutDataspace,
        ui::PixelFormat* outWideColorGamutPixelFormat) const {
    *outDataspace = mDefaultCompositionDataspace;
    *outPixelFormat = defaultCompositionPixelFormat;
    *outWideColorGamutDataspace = mWideColorGamutCompositionDataspace;
    *outWideColorGamutPixelFormat = wideColorGamutCompositionPixelFormat;
    return NO_ERROR;
}

status_t SurfaceFlinger::addRegionSamplingListener(const Rect& samplingArea,
                                                   const sp<IBinder>& stopLayerHandle,
                                                   const sp<IRegionSamplingListener>& listener) {
    if (!listener || samplingArea == Rect::INVALID_RECT || samplingArea.isEmpty()) {
        return BAD_VALUE;
    }

    const wp<Layer> stopLayer = fromHandle(stopLayerHandle);
    mRegionSamplingThread->addListener(samplingArea, stopLayer, listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::removeRegionSamplingListener(const sp<IRegionSamplingListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }
    mRegionSamplingThread->removeListener(listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::addFpsListener(int32_t taskId, const sp<gui::IFpsListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }

    mFpsReporter->addListener(listener, taskId);
    return NO_ERROR;
}

status_t SurfaceFlinger::removeFpsListener(const sp<gui::IFpsListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }
    mFpsReporter->removeListener(listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::addTunnelModeEnabledListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }

    mTunnelModeEnabledReporter->addListener(listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::removeTunnelModeEnabledListener(
        const sp<gui::ITunnelModeEnabledListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }

    mTunnelModeEnabledReporter->removeListener(listener);
    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayBrightnessSupport(const sp<IBinder>& displayToken,
                                                     bool* outSupport) const {
    if (!displayToken || !outSupport) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto displayId = getPhysicalDisplayIdLocked(displayToken);
    if (!displayId) {
        return NAME_NOT_FOUND;
    }
    *outSupport = getHwComposer().hasDisplayCapability(*displayId, DisplayCapability::BRIGHTNESS);
    return NO_ERROR;
}

bool SurfaceFlinger::hasVisibleHdrLayer(const sp<DisplayDevice>& display) {
    bool hasHdrLayers = false;
    mDrawingState.traverse([&,
                            compositionDisplay = display->getCompositionDisplay()](Layer* layer) {
        hasHdrLayers |= (layer->isVisible() &&
                         compositionDisplay->includesLayer(layer->getCompositionEngineLayerFE()) &&
                         isHdrDataspace(layer->getDataSpace()));
    });
    return hasHdrLayers;
}

status_t SurfaceFlinger::setDisplayBrightness(const sp<IBinder>& displayToken,
                                              const gui::DisplayBrightness& brightness) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    const char* const whence = __func__;
    return ftl::Future(mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
               if (const auto display = getDisplayDeviceLocked(displayToken)) {
                   const bool supportsDisplayBrightnessCommand =
                           getHwComposer().getComposer()->isSupported(
                                   Hwc2::Composer::OptionalFeature::DisplayBrightnessCommand);
                   // If we support applying display brightness as a command, then we also support
                   // dimming SDR layers.
                   if (supportsDisplayBrightnessCommand) {
                       auto compositionDisplay = display->getCompositionDisplay();
                       float currentDimmingRatio =
                               compositionDisplay->editState().sdrWhitePointNits /
                               compositionDisplay->editState().displayBrightnessNits;
                       compositionDisplay->setDisplayBrightness(brightness.sdrWhitePointNits,
                                                                brightness.displayBrightnessNits);
                       FTL_FAKE_GUARD(kMainThreadContext,
                                      display->stageBrightness(brightness.displayBrightness));

                       if (brightness.sdrWhitePointNits / brightness.displayBrightnessNits !=
                           currentDimmingRatio) {
                           scheduleComposite(FrameHint::kNone);
                       } else {
                           scheduleCommit(FrameHint::kNone);
                       }
                       return ftl::yield<status_t>(OK);
                   } else {
                       return getHwComposer()
                               .setDisplayBrightness(display->getPhysicalId(),
                                                     brightness.displayBrightness,
                                                     brightness.displayBrightnessNits,
                                                     Hwc2::Composer::DisplayBrightnessOptions{
                                                             .applyImmediately = true});
                   }

               } else {
                   ALOGE("%s: Invalid display token %p", whence, displayToken.get());
                   return ftl::yield<status_t>(NAME_NOT_FOUND);
               }
           }))
            .then([](ftl::Future<status_t> task) { return task; })
            .get();
}

status_t SurfaceFlinger::addHdrLayerInfoListener(const sp<IBinder>& displayToken,
                                                 const sp<gui::IHdrLayerInfoListener>& listener) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }
    const auto displayId = display->getId();
    sp<HdrLayerInfoReporter>& hdrInfoReporter = mHdrLayerInfoListeners[displayId];
    if (!hdrInfoReporter) {
        hdrInfoReporter = sp<HdrLayerInfoReporter>::make();
    }
    hdrInfoReporter->addListener(listener);


    mAddingHDRLayerInfoListener = true;
    return OK;
}

status_t SurfaceFlinger::removeHdrLayerInfoListener(
        const sp<IBinder>& displayToken, const sp<gui::IHdrLayerInfoListener>& listener) {
    if (!displayToken) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }
    const auto displayId = display->getId();
    sp<HdrLayerInfoReporter>& hdrInfoReporter = mHdrLayerInfoListeners[displayId];
    if (hdrInfoReporter) {
        hdrInfoReporter->removeListener(listener);
    }
    return OK;
}

status_t SurfaceFlinger::notifyPowerBoost(int32_t boostId) {
    using hardware::power::Boost;
    Boost powerBoost = static_cast<Boost>(boostId);

    if (powerBoost == Boost::INTERACTION) {
        mScheduler->onTouchHint();
    }

    return NO_ERROR;
}

status_t SurfaceFlinger::getDisplayDecorationSupport(
        const sp<IBinder>& displayToken,
        std::optional<DisplayDecorationSupport>* outSupport) const {
    if (!displayToken || !outSupport) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);

    const auto displayId = getPhysicalDisplayIdLocked(displayToken);
    if (!displayId) {
        return NAME_NOT_FOUND;
    }
    getHwComposer().getDisplayDecorationSupport(*displayId, outSupport);
    return NO_ERROR;
}

// ----------------------------------------------------------------------------

sp<IDisplayEventConnection> SurfaceFlinger::createDisplayEventConnection(
        ISurfaceComposer::VsyncSource vsyncSource,
        ISurfaceComposer::EventRegistrationFlags eventRegistration) {
    const auto& handle =
            vsyncSource == eVsyncSourceSurfaceFlinger ? mSfConnectionHandle : mAppConnectionHandle;

    return mScheduler->createDisplayEventConnection(handle, eventRegistration);
}

void SurfaceFlinger::scheduleCommit(FrameHint hint) {
    if (hint == FrameHint::kActive) {
        mScheduler->resetIdleTimer();
    }
    mPowerAdvisor->notifyDisplayUpdateImminent();
    mScheduler->scheduleFrame();
}

void SurfaceFlinger::scheduleComposite(FrameHint hint) {
    mMustComposite = true;
    scheduleCommit(hint);
}

void SurfaceFlinger::scheduleRepaint() {
    mGeometryDirty = true;
    scheduleComposite(FrameHint::kActive);
}

void SurfaceFlinger::scheduleSample() {
    static_cast<void>(mScheduler->schedule([this] { sample(); }));
}

nsecs_t SurfaceFlinger::getVsyncPeriodFromHWC() const {
    if (const auto display = getDefaultDisplayDeviceLocked()) {
        return display->getVsyncPeriodFromHWC();
    }

    return 0;
}

void SurfaceFlinger::onComposerHalVsync(hal::HWDisplayId hwcDisplayId, int64_t timestamp,
                                        std::optional<hal::VsyncPeriodNanos> vsyncPeriod) {
    const std::string tracePeriod = [vsyncPeriod]() {
        if (ATRACE_ENABLED() && vsyncPeriod) {
            std::stringstream ss;
            ss << "(" << *vsyncPeriod << ")";
            return ss.str();
        }
        return std::string();
    }();
    ATRACE_FORMAT("onComposerHalVsync%s", tracePeriod.c_str());

    Mutex::Autolock lock(mStateLock);
    const auto displayId = getHwComposer().toPhysicalDisplayId(hwcDisplayId);
    if (displayId) {
        const auto token = getPhysicalDisplayTokenLocked(*displayId);
        const auto display = getDisplayDeviceLocked(token);
        display->onVsync(timestamp);
    }

    if (!getHwComposer().onVsync(hwcDisplayId, timestamp)) {
        return;
    }

    const bool isActiveDisplay =
            displayId && getPhysicalDisplayTokenLocked(*displayId) == mActiveDisplayToken;
    if (!isActiveDisplay) {
        // For now, we don't do anything with non active display vsyncs.
        return;
    }

    bool periodFlushed = false;
    mScheduler->addResyncSample(timestamp, vsyncPeriod, &periodFlushed);
    if (periodFlushed) {
        modulateVsync(&VsyncModulator::onRefreshRateChangeCompleted);
    }
}

void SurfaceFlinger::getCompositorTiming(CompositorTiming* compositorTiming) {
    std::lock_guard<std::mutex> lock(getBE().mCompositorTimingLock);
    *compositorTiming = getBE().mCompositorTiming;
}

void SurfaceFlinger::onComposerHalHotplug(hal::HWDisplayId hwcDisplayId,
                                          hal::Connection connection) {
    const bool connected = connection == hal::Connection::CONNECTED;
    ALOGI("%s HAL display %" PRIu64, connected ? "Connecting" : "Disconnecting", hwcDisplayId);

    // Only lock if we're not on the main thread. This function is normally
    // called on a hwbinder thread, but for the primary display it's called on
    // the main thread with the state lock already held, so don't attempt to
    // acquire it here.
    ConditionalLock lock(mStateLock, std::this_thread::get_id() != mMainThreadId);

    mPendingHotplugEvents.emplace_back(HotplugEvent{hwcDisplayId, connection});

    if (std::this_thread::get_id() == mMainThreadId) {
        // Process all pending hot plug events immediately if we are on the main thread.
        processDisplayHotplugEventsLocked();
    }

    setTransactionFlags(eDisplayTransactionNeeded);
}

void SurfaceFlinger::onComposerHalVsyncPeriodTimingChanged(
        hal::HWDisplayId, const hal::VsyncPeriodChangeTimeline& timeline) {
    Mutex::Autolock lock(mStateLock);
    mScheduler->onNewVsyncPeriodChangeTimeline(timeline);

    if (timeline.refreshRequired) {
        scheduleComposite(FrameHint::kNone);
    }
}

void SurfaceFlinger::onComposerHalSeamlessPossible(hal::HWDisplayId) {
    // TODO(b/142753666): use constraints when calling to setActiveModeWithConstraints and
    // use this callback to know when to retry in case of SEAMLESS_NOT_POSSIBLE.
}

void SurfaceFlinger::onComposerHalRefresh(hal::HWDisplayId) {
    Mutex::Autolock lock(mStateLock);
    scheduleComposite(FrameHint::kNone);
}

void SurfaceFlinger::onComposerHalVsyncIdle(hal::HWDisplayId) {
    ATRACE_CALL();
    mScheduler->forceNextResync();
}

void SurfaceFlinger::setVsyncEnabled(bool enabled) {
    ATRACE_CALL();

    // On main thread to avoid race conditions with display power state.
    static_cast<void>(mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
        mHWCVsyncPendingState = enabled ? hal::Vsync::ENABLE : hal::Vsync::DISABLE;

        if (const auto display = getDefaultDisplayDeviceLocked();
            display && display->isPoweredOn()) {
            setHWCVsyncEnabled(display->getPhysicalId(), mHWCVsyncPendingState);
        }
    }));
}

SurfaceFlinger::FenceWithFenceTime SurfaceFlinger::previousFrameFence() {
    const auto now = systemTime();
    const auto vsyncPeriod = mScheduler->getDisplayStatInfo(now).vsyncPeriod;
    const bool expectedPresentTimeIsTheNextVsync = mExpectedPresentTime - now <= vsyncPeriod;

    size_t shift = 0;
    if (!expectedPresentTimeIsTheNextVsync) {
        shift = static_cast<size_t>((mExpectedPresentTime - now) / vsyncPeriod);
        if (shift >= mPreviousPresentFences.size()) {
            shift = mPreviousPresentFences.size() - 1;
        }
    }
    ATRACE_FORMAT("previousFrameFence shift=%zu", shift);
    return mPreviousPresentFences[shift];
}

bool SurfaceFlinger::previousFramePending(int graceTimeMs) {
    ATRACE_CALL();
    const std::shared_ptr<FenceTime>& fence = previousFrameFence().fenceTime;

    if (fence == FenceTime::NO_FENCE) {
        return false;
    }

    const status_t status = fence->wait(graceTimeMs);
    // This is the same as Fence::Status::Unsignaled, but it saves a getStatus() call,
    // which calls wait(0) again internally
    return status == -ETIME;
}

nsecs_t SurfaceFlinger::previousFramePresentTime() {
    const std::shared_ptr<FenceTime>& fence = previousFrameFence().fenceTime;

    if (fence == FenceTime::NO_FENCE) {
        return Fence::SIGNAL_TIME_INVALID;
    }

    return fence->getSignalTime();
}

nsecs_t SurfaceFlinger::calculateExpectedPresentTime(DisplayStatInfo stats) const {
    // Inflate the expected present time if we're targetting the next vsync.
    return mVsyncModulator->getVsyncConfig().sfOffset > 0 ? stats.vsyncTime
                                                          : stats.vsyncTime + stats.vsyncPeriod;
}

bool SurfaceFlinger::commit(nsecs_t frameTime, int64_t vsyncId, nsecs_t expectedVsyncTime)
        FTL_FAKE_GUARD(kMainThreadContext) {
    // calculate the expected present time once and use the cached
    // value throughout this frame to make sure all layers are
    // seeing this same value.
    if (expectedVsyncTime >= frameTime) {
        mExpectedPresentTime = expectedVsyncTime;
    } else {
        const DisplayStatInfo stats = mScheduler->getDisplayStatInfo(frameTime);
        mExpectedPresentTime = calculateExpectedPresentTime(stats);
    }

    const nsecs_t lastScheduledPresentTime = mScheduledPresentTime;
    mScheduledPresentTime = expectedVsyncTime;

    const auto vsyncIn = [&] {
        if (!ATRACE_ENABLED()) return 0.f;
        return (mExpectedPresentTime - systemTime()) / 1e6f;
    }();
    ATRACE_FORMAT("%s %" PRId64 " vsyncIn %.2fms%s", __func__, vsyncId, vsyncIn,
                  mExpectedPresentTime == expectedVsyncTime ? "" : " (adjusted)");

    // When Backpressure propagation is enabled we want to give a small grace period
    // for the present fence to fire instead of just giving up on this frame to handle cases
    // where present fence is just about to get signaled.
    const int graceTimeForPresentFenceMs =
            (mPropagateBackpressureClientComposition || !mHadClientComposition) ? 1 : 0;

    // Pending frames may trigger backpressure propagation.
    const TracedOrdinal<bool> framePending = {"PrevFramePending",
                                              previousFramePending(graceTimeForPresentFenceMs)};

    // Frame missed counts for metrics tracking.
    // A frame is missed if the prior frame is still pending. If no longer pending,
    // then we still count the frame as missed if the predicted present time
    // was further in the past than when the fence actually fired.

    // Add some slop to correct for drift. This should generally be
    // smaller than a typical frame duration, but should not be so small
    // that it reports reasonable drift as a missed frame.
    const DisplayStatInfo stats = mScheduler->getDisplayStatInfo(systemTime());
    const nsecs_t frameMissedSlop = stats.vsyncPeriod / 2;
    const nsecs_t previousPresentTime = previousFramePresentTime();
    const TracedOrdinal<bool> frameMissed = {"PrevFrameMissed",
                                             framePending ||
                                                     (previousPresentTime >= 0 &&
                                                      (lastScheduledPresentTime <
                                                       previousPresentTime - frameMissedSlop))};
    const TracedOrdinal<bool> hwcFrameMissed = {"PrevHwcFrameMissed",
                                                mHadDeviceComposition && frameMissed};
    const TracedOrdinal<bool> gpuFrameMissed = {"PrevGpuFrameMissed",
                                                mHadClientComposition && frameMissed};

    if (frameMissed) {
        mFrameMissedCount++;
        mTimeStats->incrementMissedFrames();
    }

    if (hwcFrameMissed) {
        mHwcFrameMissedCount++;
    }

    if (gpuFrameMissed) {
        mGpuFrameMissedCount++;
    }

    // If we are in the middle of a mode change and the fence hasn't
    // fired yet just wait for the next commit.
    if (mSetActiveModePending) {
        if (framePending) {
            mScheduler->scheduleFrame();
            return false;
        }

        // We received the present fence from the HWC, so we assume it successfully updated
        // the mode, hence we update SF.
        mSetActiveModePending = false;
        {
            Mutex::Autolock lock(mStateLock);
            updateInternalStateWithChangedMode();
        }
    }

    if (framePending) {
        if ((hwcFrameMissed && !gpuFrameMissed) || mPropagateBackpressureClientComposition) {
            scheduleCommit(FrameHint::kNone);
            return false;
        }
    }

    // Save this once per commit + composite to ensure consistency
    // TODO (b/240619471): consider removing active display check once AOD is fixed
    const auto activeDisplay =
            FTL_FAKE_GUARD(mStateLock, getDisplayDeviceLocked(mActiveDisplayToken));
    mPowerHintSessionEnabled = mPowerAdvisor->usePowerHintSession() && activeDisplay &&
            activeDisplay->getPowerMode() == hal::PowerMode::ON;
    if (mPowerHintSessionEnabled) {
        const auto& display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked()).get();
        // get stable vsync period from display mode
        const nsecs_t vsyncPeriod = display->getActiveMode()->getVsyncPeriod();
        mPowerAdvisor->setCommitStart(frameTime);
        mPowerAdvisor->setExpectedPresentTime(mExpectedPresentTime);
        const nsecs_t idealSfWorkDuration =
                mVsyncModulator->getVsyncConfig().sfWorkDuration.count();
        // Frame delay is how long we should have minus how long we actually have
        mPowerAdvisor->setFrameDelay(idealSfWorkDuration - (mExpectedPresentTime - frameTime));
        mPowerAdvisor->setTotalFrameTargetWorkDuration(idealSfWorkDuration);
        mPowerAdvisor->setTargetWorkDuration(vsyncPeriod);

        // Send early hint here to make sure there's not another frame pending
        if (mPowerHintSessionMode.early) {
            // Send a rough prediction for this frame based on last frame's timing info
            mPowerAdvisor->sendPredictedWorkDuration();
        }
    }

    if (mTracingEnabledChanged) {
        mLayerTracingEnabled = mLayerTracing.isEnabled();
        mTracingEnabledChanged = false;
    }

    if (mRefreshRateOverlaySpinner) {
        Mutex::Autolock lock(mStateLock);
        if (const auto display = getDefaultDisplayDeviceLocked()) {
            display->animateRefreshRateOverlay();
        }
    }

    // Composite if transactions were committed, or if requested by HWC.
    bool mustComposite = mMustComposite.exchange(false);
    {
        mFrameTimeline->setSfWakeUp(vsyncId, frameTime, Fps::fromPeriodNsecs(stats.vsyncPeriod));

        bool needsTraversal = false;
        if (clearTransactionFlags(eTransactionFlushNeeded)) {
            // Locking:
            // 1. to prevent onHandleDestroyed from being called while the state lock is held,
            // we must keep a copy of the transactions (specifically the composer
            // states) around outside the scope of the lock
            // 2. Transactions and created layers do not share a lock. To prevent applying
            // transactions with layers still in the createdLayer queue, flush the transactions
            // before committing the created layers.
            std::vector<TransactionState> transactions = flushTransactions();
            needsTraversal |= commitCreatedLayers();
            needsTraversal |= applyTransactions(transactions, vsyncId);
        }

        const bool shouldCommit =
                (getTransactionFlags() & ~eTransactionFlushNeeded) || needsTraversal;
        if (shouldCommit) {
            commitTransactions();
        }

        if (transactionFlushNeeded()) {
            setTransactionFlags(eTransactionFlushNeeded);
        }

        mustComposite |= shouldCommit;
        mustComposite |= latchBuffers();

        // This has to be called after latchBuffers because we want to include the layers that have
        // been latched in the commit callback
        if (!needsTraversal) {
            // Invoke empty transaction callbacks early.
            mTransactionCallbackInvoker.sendCallbacks(false /* onCommitOnly */);
        } else {
            // Invoke OnCommit callbacks.
            mTransactionCallbackInvoker.sendCallbacks(true /* onCommitOnly */);
        }

        updateLayerGeometry();
    }

    // Layers need to get updated (in the previous line) before we can use them for
    // choosing the refresh rate.
    // Hold mStateLock as chooseRefreshRateForContent promotes wp<Layer> to sp<Layer>
    // and may eventually call to ~Layer() if it holds the last reference
    {
        Mutex::Autolock _l(mStateLock);
        mScheduler->chooseRefreshRateForContent();
        setActiveModeInHwcIfNeeded();
    }

    updateCursorAsync();
    updateInputFlinger();

    if (mLayerTracingEnabled && !mLayerTracing.flagIsSet(LayerTracing::TRACE_COMPOSITION)) {
        // This will block and tracing should only be enabled for debugging.
        mLayerTracing.notify(mVisibleRegionsDirty, frameTime);
    }

    persistDisplayBrightness(mustComposite);

    return mustComposite && CC_LIKELY(mBootStage != BootStage::BOOTLOADER);
}

void SurfaceFlinger::composite(nsecs_t frameTime, int64_t vsyncId)
        FTL_FAKE_GUARD(kMainThreadContext) {
    ATRACE_FORMAT("%s %" PRId64, __func__, vsyncId);

    compositionengine::CompositionRefreshArgs refreshArgs;
    const auto& displays = FTL_FAKE_GUARD(mStateLock, mDisplays);
    refreshArgs.outputs.reserve(displays.size());
    std::vector<DisplayId> displayIds;
    for (const auto& [_, display] : displays) {
        refreshArgs.outputs.push_back(display->getCompositionDisplay());
        displayIds.push_back(display->getId());
    }
    mPowerAdvisor->setDisplays(displayIds);
    mDrawingState.traverseInZOrder([&refreshArgs](Layer* layer) {
        if (auto layerFE = layer->getCompositionEngineLayerFE())
            refreshArgs.layers.push_back(layerFE);
    });
    refreshArgs.layersWithQueuedFrames.reserve(mLayersWithQueuedFrames.size());
    for (auto layer : mLayersWithQueuedFrames) {
        if (auto layerFE = layer->getCompositionEngineLayerFE())
            refreshArgs.layersWithQueuedFrames.push_back(layerFE);
    }

    refreshArgs.outputColorSetting = useColorManagement
            ? mDisplayColorSetting
            : compositionengine::OutputColorSetting::kUnmanaged;
    refreshArgs.colorSpaceAgnosticDataspace = mColorSpaceAgnosticDataspace;
    refreshArgs.forceOutputColorMode = mForceColorMode;

    refreshArgs.updatingOutputGeometryThisFrame = mVisibleRegionsDirty;
    refreshArgs.updatingGeometryThisFrame = mGeometryDirty.exchange(false) || mVisibleRegionsDirty;
    refreshArgs.blursAreExpensive = mBlursAreExpensive;
    refreshArgs.internalDisplayRotationFlags = DisplayDevice::getPrimaryDisplayRotationFlags();

    if (CC_UNLIKELY(mDrawingState.colorMatrixChanged)) {
        refreshArgs.colorTransformMatrix = mDrawingState.colorMatrix;
        mDrawingState.colorMatrixChanged = false;
    }

    refreshArgs.devOptForceClientComposition = mDebugDisableHWC;

    if (mDebugFlashDelay != 0) {
        refreshArgs.devOptForceClientComposition = true;
        refreshArgs.devOptFlashDirtyRegionsDelay = std::chrono::milliseconds(mDebugFlashDelay);
    }

    const auto expectedPresentTime = mExpectedPresentTime.load();
    const auto prevVsyncTime = mScheduler->getPreviousVsyncFrom(expectedPresentTime);
    const auto hwcMinWorkDuration = mVsyncConfiguration->getCurrentConfigs().hwcMinWorkDuration;
    refreshArgs.earliestPresentTime = prevVsyncTime - hwcMinWorkDuration;
    refreshArgs.previousPresentFence = mPreviousPresentFences[0].fenceTime;
    refreshArgs.scheduledFrameTime = mScheduler->getScheduledFrameTime();
    refreshArgs.expectedPresentTime = expectedPresentTime;

    // Store the present time just before calling to the composition engine so we could notify
    // the scheduler.
    const auto presentTime = systemTime();

    mCompositionEngine->present(refreshArgs);

    mTimeStats->recordFrameDuration(frameTime, systemTime());

    // Send a power hint hint after presentation is finished
    if (mPowerHintSessionEnabled) {
        mPowerAdvisor->setSfPresentTiming(mPreviousPresentFences[0].fenceTime->getSignalTime(),
                                          systemTime());
        if (mPowerHintSessionMode.late) {
            mPowerAdvisor->sendActualWorkDuration();
        }
    }

    if (mScheduler->onPostComposition(presentTime)) {
        scheduleComposite(FrameHint::kNone);
    }

    postFrame();
    postComposition();

    const bool prevFrameHadClientComposition = mHadClientComposition;

    mHadClientComposition = mHadDeviceComposition = mReusedClientComposition = false;
    TimeStats::ClientCompositionRecord clientCompositionRecord;
    for (const auto& [_, display] : displays) {
        const auto& state = display->getCompositionDisplay()->getState();
        mHadClientComposition |= state.usesClientComposition && !state.reusedClientComposition;
        mHadDeviceComposition |= state.usesDeviceComposition;
        mReusedClientComposition |= state.reusedClientComposition;
        clientCompositionRecord.predicted |=
                (state.strategyPrediction != CompositionStrategyPredictionState::DISABLED);
        clientCompositionRecord.predictionSucceeded |=
                (state.strategyPrediction == CompositionStrategyPredictionState::SUCCESS);
    }

    clientCompositionRecord.hadClientComposition = mHadClientComposition;
    clientCompositionRecord.reused = mReusedClientComposition;
    clientCompositionRecord.changed = prevFrameHadClientComposition != mHadClientComposition;
    mTimeStats->pushCompositionStrategyState(clientCompositionRecord);

    // TODO: b/160583065 Enable skip validation when SF caches all client composition layers
    const bool usedGpuComposition = mHadClientComposition || mReusedClientComposition;
    modulateVsync(&VsyncModulator::onDisplayRefresh, usedGpuComposition);

    mLayersWithQueuedFrames.clear();
    if (mLayerTracingEnabled && mLayerTracing.flagIsSet(LayerTracing::TRACE_COMPOSITION)) {
        // This will block and should only be used for debugging.
        mLayerTracing.notify(mVisibleRegionsDirty, frameTime);
    }

    mVisibleRegionsWereDirtyThisFrame = mVisibleRegionsDirty; // Cache value for use in post-comp
    mVisibleRegionsDirty = false;

    if (mCompositionEngine->needsAnotherUpdate()) {
        scheduleCommit(FrameHint::kNone);
    }

    if (mPowerHintSessionEnabled) {
        mPowerAdvisor->setCompositeEnd(systemTime());
    }
}

void SurfaceFlinger::updateLayerGeometry() {
    ATRACE_CALL();

    if (mVisibleRegionsDirty) {
        computeLayerBounds();
    }

    for (auto& layer : mLayersPendingRefresh) {
        Region visibleReg;
        visibleReg.set(layer->getScreenBounds());
        invalidateLayerStack(layer, visibleReg);
    }
    mLayersPendingRefresh.clear();
}

void SurfaceFlinger::updateCompositorTiming(const DisplayStatInfo& stats, nsecs_t compositeTime,
                                            std::shared_ptr<FenceTime>& presentFenceTime) {
    // Update queue of past composite+present times and determine the
    // most recently known composite to present latency.
    getBE().mCompositePresentTimes.push({compositeTime, presentFenceTime});
    nsecs_t compositeToPresentLatency = -1;
    while (!getBE().mCompositePresentTimes.empty()) {
        SurfaceFlingerBE::CompositePresentTime& cpt = getBE().mCompositePresentTimes.front();
        // Cached values should have been updated before calling this method,
        // which helps avoid duplicate syscalls.
        nsecs_t displayTime = cpt.display->getCachedSignalTime();
        if (displayTime == Fence::SIGNAL_TIME_PENDING) {
            break;
        }
        compositeToPresentLatency = displayTime - cpt.composite;
        getBE().mCompositePresentTimes.pop();
    }

    // Don't let mCompositePresentTimes grow unbounded, just in case.
    while (getBE().mCompositePresentTimes.size() > 16) {
        getBE().mCompositePresentTimes.pop();
    }

    setCompositorTimingSnapped(stats, compositeToPresentLatency);
}

void SurfaceFlinger::setCompositorTimingSnapped(const DisplayStatInfo& stats,
                                                nsecs_t compositeToPresentLatency) {
    // Avoid division by 0 by defaulting to 60Hz
    const auto vsyncPeriod = stats.vsyncPeriod ?: (60_Hz).getPeriodNsecs();

    // Integer division and modulo round toward 0 not -inf, so we need to
    // treat negative and positive offsets differently.
    nsecs_t idealLatency = (mVsyncConfiguration->getCurrentConfigs().late.sfOffset > 0)
            ? (vsyncPeriod -
               (mVsyncConfiguration->getCurrentConfigs().late.sfOffset % vsyncPeriod))
            : ((-mVsyncConfiguration->getCurrentConfigs().late.sfOffset) % vsyncPeriod);

    // Just in case mVsyncConfiguration->getCurrentConfigs().late.sf == -vsyncInterval.
    if (idealLatency <= 0) {
        idealLatency = vsyncPeriod;
    }

    // Snap the latency to a value that removes scheduling jitter from the
    // composition and present times, which often have >1ms of jitter.
    // Reducing jitter is important if an app attempts to extrapolate
    // something (such as user input) to an accurate diasplay time.
    // Snapping also allows an app to precisely calculate
    // mVsyncConfiguration->getCurrentConfigs().late.sf with (presentLatency % interval).
    const nsecs_t bias = vsyncPeriod / 2;
    const int64_t extraVsyncs = ((compositeToPresentLatency - idealLatency + bias) / vsyncPeriod);
    const nsecs_t snappedCompositeToPresentLatency =
            (extraVsyncs > 0) ? idealLatency + (extraVsyncs * vsyncPeriod) : idealLatency;

    std::lock_guard<std::mutex> lock(getBE().mCompositorTimingLock);
    getBE().mCompositorTiming.deadline = stats.vsyncTime - idealLatency;
    getBE().mCompositorTiming.interval = vsyncPeriod;
    getBE().mCompositorTiming.presentLatency = snappedCompositeToPresentLatency;
}

bool SurfaceFlinger::isHdrLayer(Layer* layer) const {
    // Treat all layers as non-HDR if:
    // 1. They do not have a valid HDR dataspace. Currently we treat those as PQ or HLG. and
    // 2. The layer is allowed to be dimmed. WindowManager may disable dimming in order to
    // keep animations invoking SDR screenshots of HDR layers seamless. Treat such tagged
    // layers as HDR so that DisplayManagerService does not try to change the screen brightness
    if (!isHdrDataspace(layer->getDataSpace()) && layer->isDimmingEnabled()) {
        return false;
    }
    if (mIgnoreHdrCameraLayers) {
        auto buffer = layer->getBuffer();
        if (buffer && (buffer->getUsage() & GRALLOC_USAGE_HW_CAMERA_WRITE) != 0) {
            return false;
        }
    }
    return true;
}

ui::Rotation SurfaceFlinger::getPhysicalDisplayOrientation(DisplayId displayId,
                                                           bool isPrimary) const {
    const auto id = PhysicalDisplayId::tryCast(displayId);
    if (!id) {
        return ui::ROTATION_0;
    }
    if (getHwComposer().getComposer()->isSupported(
                Hwc2::Composer::OptionalFeature::PhysicalDisplayOrientation)) {
        switch (getHwComposer().getPhysicalDisplayOrientation(*id)) {
            case Hwc2::AidlTransform::ROT_90:
                return ui::ROTATION_90;
            case Hwc2::AidlTransform::ROT_180:
                return ui::ROTATION_180;
            case Hwc2::AidlTransform::ROT_270:
                return ui::ROTATION_270;
            default:
                return ui::ROTATION_0;
        }
    }

    if (isPrimary) {
        using Values = SurfaceFlingerProperties::primary_display_orientation_values;
        switch (primary_display_orientation(Values::ORIENTATION_0)) {
            case Values::ORIENTATION_90:
                return ui::ROTATION_90;
            case Values::ORIENTATION_180:
                return ui::ROTATION_180;
            case Values::ORIENTATION_270:
                return ui::ROTATION_270;
            default:
                break;
        }
    }
    return ui::ROTATION_0;
}

void SurfaceFlinger::postComposition() {
    ATRACE_CALL();
    ALOGV("postComposition");

    const auto* display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked()).get();

    std::shared_ptr<FenceTime> glCompositionDoneFenceTime;
    if (display && display->getCompositionDisplay()->getState().usesClientComposition) {
        glCompositionDoneFenceTime =
                std::make_shared<FenceTime>(display->getCompositionDisplay()
                                                    ->getRenderSurface()
                                                    ->getClientTargetAcquireFence());
    } else {
        glCompositionDoneFenceTime = FenceTime::NO_FENCE;
    }

    for (size_t i = mPreviousPresentFences.size()-1; i >= 1; i--) {
        mPreviousPresentFences[i] = mPreviousPresentFences[i-1];
    }

    mPreviousPresentFences[0].fence =
            display ? getHwComposer().getPresentFence(display->getPhysicalId()) : Fence::NO_FENCE;
    mPreviousPresentFences[0].fenceTime =
            std::make_shared<FenceTime>(mPreviousPresentFences[0].fence);

    nsecs_t now = systemTime();

    // Set presentation information before calling Layer::releasePendingBuffer, such that jank
    // information from previous' frame classification is already available when sending jank info
    // to clients, so they get jank classification as early as possible.
    mFrameTimeline->setSfPresent(/* sfPresentTime */ now, mPreviousPresentFences[0].fenceTime,
                                 glCompositionDoneFenceTime);

    const DisplayStatInfo stats = mScheduler->getDisplayStatInfo(now);

    // We use the CompositionEngine::getLastFrameRefreshTimestamp() which might
    // be sampled a little later than when we started doing work for this frame,
    // but that should be okay since updateCompositorTiming has snapping logic.
    updateCompositorTiming(stats, mCompositionEngine->getLastFrameRefreshTimestamp(),
                           mPreviousPresentFences[0].fenceTime);
    CompositorTiming compositorTiming;
    {
        std::lock_guard<std::mutex> lock(getBE().mCompositorTimingLock);
        compositorTiming = getBE().mCompositorTiming;
    }

    for (const auto& layer: mLayersWithQueuedFrames) {
        layer->onPostComposition(display, glCompositionDoneFenceTime,
                                 mPreviousPresentFences[0].fenceTime, compositorTiming);
        layer->releasePendingBuffer(/*dequeueReadyTime*/ now);
    }

    std::vector<std::pair<std::shared_ptr<compositionengine::Display>, sp<HdrLayerInfoReporter>>>
            hdrInfoListeners;
    bool haveNewListeners = false;
    {
        Mutex::Autolock lock(mStateLock);
        if (mFpsReporter) {
            mFpsReporter->dispatchLayerFps();
        }

        if (mTunnelModeEnabledReporter) {
            mTunnelModeEnabledReporter->updateTunnelModeStatus();
        }
        hdrInfoListeners.reserve(mHdrLayerInfoListeners.size());
        for (const auto& [displayId, reporter] : mHdrLayerInfoListeners) {
            if (reporter && reporter->hasListeners()) {
                if (const auto display = getDisplayDeviceLocked(displayId)) {
                    hdrInfoListeners.emplace_back(display->getCompositionDisplay(), reporter);
                }
            }
        }
        haveNewListeners = mAddingHDRLayerInfoListener; // grab this with state lock
        mAddingHDRLayerInfoListener = false;
    }

    if (haveNewListeners || mSomeDataspaceChanged || mVisibleRegionsWereDirtyThisFrame) {
        for (auto& [compositionDisplay, listener] : hdrInfoListeners) {
            HdrLayerInfoReporter::HdrLayerInfo info;
            int32_t maxArea = 0;
            mDrawingState.traverse([&, compositionDisplay = compositionDisplay](Layer* layer) {
                const auto layerFe = layer->getCompositionEngineLayerFE();
                if (layer->isVisible() && compositionDisplay->includesLayer(layerFe)) {
                    if (isHdrLayer(layer)) {
                        const auto* outputLayer =
                            compositionDisplay->getOutputLayerForLayer(layerFe);
                        if (outputLayer) {
                            info.numberOfHdrLayers++;
                            const auto displayFrame = outputLayer->getState().displayFrame;
                            const int32_t area = displayFrame.width() * displayFrame.height();
                            if (area > maxArea) {
                                maxArea = area;
                                info.maxW = displayFrame.width();
                                info.maxH = displayFrame.height();
                            }
                        }
                    }
                }
            });
            listener->dispatchHdrLayerInfo(info);
        }
    }

    mSomeDataspaceChanged = false;
    mVisibleRegionsWereDirtyThisFrame = false;

    mTransactionCallbackInvoker.addPresentFence(mPreviousPresentFences[0].fence);
    mTransactionCallbackInvoker.sendCallbacks(false /* onCommitOnly */);
    mTransactionCallbackInvoker.clearCompletedTransactions();

    if (display && display->isInternal() && display->getPowerMode() == hal::PowerMode::ON &&
        mPreviousPresentFences[0].fenceTime->isValid()) {
        mScheduler->addPresentFence(mPreviousPresentFences[0].fenceTime);
    }

    const bool isDisplayConnected =
            display && getHwComposer().isConnected(display->getPhysicalId());

    if (!hasSyncFramework) {
        if (isDisplayConnected && display->isPoweredOn()) {
            mScheduler->enableHardwareVsync();
        }
    }

    if (mAnimCompositionPending) {
        mAnimCompositionPending = false;

        if (mPreviousPresentFences[0].fenceTime->isValid()) {
            mAnimFrameTracker.setActualPresentFence(mPreviousPresentFences[0].fenceTime);
        } else if (isDisplayConnected) {
            // The HWC doesn't support present fences, so use the refresh
            // timestamp instead.
            const nsecs_t presentTime = display->getRefreshTimestamp();
            mAnimFrameTracker.setActualPresentTime(presentTime);
        }
        mAnimFrameTracker.advanceFrame();
    }

    mTimeStats->incrementTotalFrames();

    mTimeStats->setPresentFenceGlobal(mPreviousPresentFences[0].fenceTime);

    const size_t sfConnections = mScheduler->getEventThreadConnectionCount(mSfConnectionHandle);
    const size_t appConnections = mScheduler->getEventThreadConnectionCount(mAppConnectionHandle);
    mTimeStats->recordDisplayEventConnectionCount(sfConnections + appConnections);

    if (isDisplayConnected && !display->isPoweredOn()) {
        getRenderEngine().cleanupPostRender();
        return;
    }

    nsecs_t currentTime = systemTime();
    if (mHasPoweredOff) {
        mHasPoweredOff = false;
    } else {
        nsecs_t elapsedTime = currentTime - getBE().mLastSwapTime;
        size_t numPeriods = static_cast<size_t>(elapsedTime / stats.vsyncPeriod);
        if (numPeriods < SurfaceFlingerBE::NUM_BUCKETS - 1) {
            getBE().mFrameBuckets[numPeriods] += elapsedTime;
        } else {
            getBE().mFrameBuckets[SurfaceFlingerBE::NUM_BUCKETS - 1] += elapsedTime;
        }
        getBE().mTotalTime += elapsedTime;
    }
    getBE().mLastSwapTime = currentTime;

    // Cleanup any outstanding resources due to rendering a prior frame.
    getRenderEngine().cleanupPostRender();

    {
        std::lock_guard lock(mTexturePoolMutex);
        if (mTexturePool.size() < mTexturePoolSize) {
            const size_t refillCount = mTexturePoolSize - mTexturePool.size();
            const size_t offset = mTexturePool.size();
            mTexturePool.resize(mTexturePoolSize);
            getRenderEngine().genTextures(refillCount, mTexturePool.data() + offset);
            ATRACE_INT("TexturePoolSize", mTexturePool.size());
        } else if (mTexturePool.size() > mTexturePoolSize) {
            const size_t deleteCount = mTexturePool.size() - mTexturePoolSize;
            const size_t offset = mTexturePoolSize;
            getRenderEngine().deleteTextures(deleteCount, mTexturePool.data() + offset);
            mTexturePool.resize(mTexturePoolSize);
            ATRACE_INT("TexturePoolSize", mTexturePool.size());
        }
    }

    // Even though ATRACE_INT64 already checks if tracing is enabled, it doesn't prevent the
    // side-effect of getTotalSize(), so we check that again here
    if (ATRACE_ENABLED()) {
        // getTotalSize returns the total number of buffers that were allocated by SurfaceFlinger
        ATRACE_INT64("Total Buffer Size", GraphicBufferAllocator::get().getTotalSize());
    }
}

FloatRect SurfaceFlinger::getMaxDisplayBounds() {
    const ui::Size maxSize = [this] {
        ftl::FakeGuard guard(mStateLock);

        // The LayerTraceGenerator tool runs without displays.
        if (mDisplays.empty()) return ui::Size{5000, 5000};

        return std::accumulate(mDisplays.begin(), mDisplays.end(), ui::kEmptySize,
                               [](ui::Size size, const auto& pair) -> ui::Size {
                                   const auto& display = pair.second;
                                   return {std::max(size.getWidth(), display->getWidth()),
                                           std::max(size.getHeight(), display->getHeight())};
                               });
    }();

    // Ignore display bounds for now since they will be computed later. Use a large Rect bound
    // to ensure it's bigger than an actual display will be.
    const float xMax = maxSize.getWidth() * 10.f;
    const float yMax = maxSize.getHeight() * 10.f;

    return {-xMax, -yMax, xMax, yMax};
}

void SurfaceFlinger::computeLayerBounds() {
    const FloatRect maxBounds = getMaxDisplayBounds();
    for (const auto& layer : mDrawingState.layersSortedByZ) {
        layer->computeBounds(maxBounds, ui::Transform(), 0.f /* shadowRadius */);
    }
}

void SurfaceFlinger::postFrame() {
    const auto display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());
    if (display && getHwComposer().isConnected(display->getPhysicalId())) {
        uint32_t flipCount = display->getPageFlipCount();
        if (flipCount % LOG_FRAME_STATS_PERIOD == 0) {
            logFrameStats();
        }
    }
}

void SurfaceFlinger::commitTransactions() {
    ATRACE_CALL();

    // Keep a copy of the drawing state (that is going to be overwritten
    // by commitTransactionsLocked) outside of mStateLock so that the side
    // effects of the State assignment don't happen with mStateLock held,
    // which can cause deadlocks.
    State drawingState(mDrawingState);

    Mutex::Autolock lock(mStateLock);
    mDebugInTransaction = systemTime();

    // Here we're guaranteed that some transaction flags are set
    // so we can call commitTransactionsLocked unconditionally.
    // We clear the flags with mStateLock held to guarantee that
    // mCurrentState won't change until the transaction is committed.
    modulateVsync(&VsyncModulator::onTransactionCommit);
    commitTransactionsLocked(clearTransactionFlags(eTransactionMask));

    mDebugInTransaction = 0;
}

std::pair<DisplayModes, DisplayModePtr> SurfaceFlinger::loadDisplayModes(
        PhysicalDisplayId displayId) const {
    std::vector<HWComposer::HWCDisplayMode> hwcModes;
    std::optional<hal::HWDisplayId> activeModeHwcId;

    int attempt = 0;
    constexpr int kMaxAttempts = 3;
    do {
        hwcModes = getHwComposer().getModes(displayId);
        activeModeHwcId = getHwComposer().getActiveMode(displayId);
        LOG_ALWAYS_FATAL_IF(!activeModeHwcId, "HWC returned no active mode");

        const auto isActiveMode = [activeModeHwcId](const HWComposer::HWCDisplayMode& mode) {
            return mode.hwcId == *activeModeHwcId;
        };

        if (std::any_of(hwcModes.begin(), hwcModes.end(), isActiveMode)) {
            break;
        }
    } while (++attempt < kMaxAttempts);

    LOG_ALWAYS_FATAL_IF(attempt == kMaxAttempts,
                        "After %d attempts HWC still returns an active mode which is not"
                        " supported. Active mode ID = %" PRIu64 ". Supported modes = %s",
                        kMaxAttempts, *activeModeHwcId, base::Join(hwcModes, ", ").c_str());

    DisplayModes oldModes;
    if (const auto token = getPhysicalDisplayTokenLocked(displayId)) {
        oldModes = getDisplayDeviceLocked(token)->getSupportedModes();
    }

    ui::DisplayModeId nextModeId = 1 +
            std::accumulate(oldModes.begin(), oldModes.end(), static_cast<ui::DisplayModeId>(-1),
                            [](ui::DisplayModeId max, const auto& pair) {
                                return std::max(max, pair.first.value());
                            });

    DisplayModes newModes;
    for (const auto& hwcMode : hwcModes) {
        const DisplayModeId id{nextModeId++};
        newModes.try_emplace(id,
                             DisplayMode::Builder(hwcMode.hwcId)
                                     .setId(id)
                                     .setPhysicalDisplayId(displayId)
                                     .setResolution({hwcMode.width, hwcMode.height})
                                     .setVsyncPeriod(hwcMode.vsyncPeriod)
                                     .setDpiX(hwcMode.dpiX)
                                     .setDpiY(hwcMode.dpiY)
                                     .setGroup(hwcMode.configGroup)
                                     .build());
    }

    const bool sameModes =
            std::equal(newModes.begin(), newModes.end(), oldModes.begin(), oldModes.end(),
                       [](const auto& lhs, const auto& rhs) {
                           return equalsExceptDisplayModeId(*lhs.second, *rhs.second);
                       });

    // Keep IDs if modes have not changed.
    const auto& modes = sameModes ? oldModes : newModes;
    const DisplayModePtr activeMode =
            std::find_if(modes.begin(), modes.end(), [activeModeHwcId](const auto& pair) {
                return pair.second->getHwcId() == activeModeHwcId;
            })->second;

    return {modes, activeMode};
}

void SurfaceFlinger::processDisplayHotplugEventsLocked() {
    for (const auto& event : mPendingHotplugEvents) {
        std::optional<DisplayIdentificationInfo> info =
                getHwComposer().onHotplug(event.hwcDisplayId, event.connection);

        if (!info) {
            continue;
        }

        const auto displayId = info->id;
        const auto token = mPhysicalDisplayTokens.get(displayId);

        if (event.connection == hal::Connection::CONNECTED) {
            auto [supportedModes, activeMode] = loadDisplayModes(displayId);

            if (!token) {
                ALOGV("Creating display %s", to_string(displayId).c_str());

                DisplayDeviceState state;
                state.physical = {.id = displayId,
                                  .type = getHwComposer().getDisplayConnectionType(displayId),
                                  .hwcDisplayId = event.hwcDisplayId,
                                  .deviceProductInfo = std::move(info->deviceProductInfo),
                                  .supportedModes = std::move(supportedModes),
                                  .activeMode = std::move(activeMode)};
                state.isSecure = true; // All physical displays are currently considered secure.
                state.displayName = std::move(info->name);

                sp<IBinder> token = new BBinder();
                mCurrentState.displays.add(token, state);
                mPhysicalDisplayTokens.try_emplace(displayId, std::move(token));
                mInterceptor->saveDisplayCreation(state);
            } else {
                ALOGV("Recreating display %s", to_string(displayId).c_str());

                auto& state = mCurrentState.displays.editValueFor(token->get());
                state.sequenceId = DisplayDeviceState{}.sequenceId; // Generate new sequenceId.
                state.physical->supportedModes = std::move(supportedModes);
                state.physical->activeMode = std::move(activeMode);
                if (getHwComposer().updatesDeviceProductInfoOnHotplugReconnect()) {
                    state.physical->deviceProductInfo = std::move(info->deviceProductInfo);
                }
            }
        } else {
            ALOGV("Removing display %s", to_string(displayId).c_str());

            if (const ssize_t index = mCurrentState.displays.indexOfKey(token->get()); index >= 0) {
                const DisplayDeviceState& state = mCurrentState.displays.valueAt(index);
                mInterceptor->saveDisplayDeletion(state.sequenceId);
                mCurrentState.displays.removeItemsAt(index);
            }

            mPhysicalDisplayTokens.erase(displayId);
        }

        processDisplayChangesLocked();
    }

    mPendingHotplugEvents.clear();
}

void SurfaceFlinger::dispatchDisplayHotplugEvent(PhysicalDisplayId displayId, bool connected) {
    ALOGI("Dispatching display hotplug event displayId=%s, connected=%d",
          to_string(displayId).c_str(), connected);
    mScheduler->onHotplugReceived(mAppConnectionHandle, displayId, connected);
    mScheduler->onHotplugReceived(mSfConnectionHandle, displayId, connected);
}

sp<DisplayDevice> SurfaceFlinger::setupNewDisplayDeviceInternal(
        const wp<IBinder>& displayToken,
        std::shared_ptr<compositionengine::Display> compositionDisplay,
        const DisplayDeviceState& state,
        const sp<compositionengine::DisplaySurface>& displaySurface,
        const sp<IGraphicBufferProducer>& producer) {
    DisplayDeviceCreationArgs creationArgs(this, getHwComposer(), displayToken, compositionDisplay);
    creationArgs.sequenceId = state.sequenceId;
    creationArgs.isSecure = state.isSecure;
    creationArgs.displaySurface = displaySurface;
    creationArgs.hasWideColorGamut = false;
    creationArgs.supportedPerFrameMetadata = 0;

    if (const auto& physical = state.physical) {
        creationArgs.connectionType = physical->type;
        creationArgs.supportedModes = physical->supportedModes;
        creationArgs.activeModeId = physical->activeMode->getId();
        const auto [kernelIdleTimerController, idleTimerTimeoutMs] =
                getKernelIdleTimerProperties(compositionDisplay->getId());

        scheduler::RefreshRateConfigs::Config config =
                {.enableFrameRateOverride = android::sysprop::enable_frame_rate_override(false),
                 .frameRateMultipleThreshold =
                         base::GetIntProperty("debug.sf.frame_rate_multiple_threshold", 0),
                 .idleTimerTimeout = idleTimerTimeoutMs,
                 .kernelIdleTimerController = kernelIdleTimerController};
        creationArgs.refreshRateConfigs =
                std::make_shared<scheduler::RefreshRateConfigs>(creationArgs.supportedModes,
                                                                creationArgs.activeModeId, config);
    }

    if (const auto id = PhysicalDisplayId::tryCast(compositionDisplay->getId())) {
        creationArgs.isPrimary = id == getPrimaryDisplayIdLocked();

        if (useColorManagement) {
            std::vector<ColorMode> modes = getHwComposer().getColorModes(*id);
            for (ColorMode colorMode : modes) {
                if (isWideColorMode(colorMode)) {
                    creationArgs.hasWideColorGamut = true;
                }

                std::vector<RenderIntent> renderIntents =
                        getHwComposer().getRenderIntents(*id, colorMode);
                creationArgs.hwcColorModes.emplace(colorMode, renderIntents);
            }
        }
    }

    if (const auto id = HalDisplayId::tryCast(compositionDisplay->getId())) {
        getHwComposer().getHdrCapabilities(*id, &creationArgs.hdrCapabilities);
        creationArgs.supportedPerFrameMetadata = getHwComposer().getSupportedPerFrameMetadata(*id);
    }

    auto nativeWindowSurface = getFactory().createNativeWindowSurface(producer);
    auto nativeWindow = nativeWindowSurface->getNativeWindow();
    creationArgs.nativeWindow = nativeWindow;

    // Make sure that composition can never be stalled by a virtual display
    // consumer that isn't processing buffers fast enough. We have to do this
    // here, in case the display is composed entirely by HWC.
    if (state.isVirtual()) {
        nativeWindow->setSwapInterval(nativeWindow.get(), 0);
    }

    creationArgs.physicalOrientation =
            getPhysicalDisplayOrientation(compositionDisplay->getId(), creationArgs.isPrimary);
    ALOGV("Display Orientation: %s", toCString(creationArgs.physicalOrientation));

    // virtual displays are always considered enabled
    creationArgs.initialPowerMode =
            state.isVirtual() ? std::make_optional(hal::PowerMode::ON) : std::nullopt;

    sp<DisplayDevice> display = getFactory().createDisplayDevice(creationArgs);

    nativeWindowSurface->preallocateBuffers();

    ColorMode defaultColorMode = ColorMode::NATIVE;
    Dataspace defaultDataSpace = Dataspace::UNKNOWN;
    if (display->hasWideColorGamut()) {
        defaultColorMode = ColorMode::SRGB;
        defaultDataSpace = Dataspace::V0_SRGB;
    }
    display->getCompositionDisplay()->setColorProfile(
            compositionengine::Output::ColorProfile{defaultColorMode, defaultDataSpace,
                                                    RenderIntent::COLORIMETRIC,
                                                    Dataspace::UNKNOWN});
    if (!state.isVirtual()) {
        FTL_FAKE_GUARD(kMainThreadContext,
                       display->setActiveMode(state.physical->activeMode->getId()));
        display->setDeviceProductInfo(state.physical->deviceProductInfo);
    }

    display->setLayerStack(state.layerStack);
    display->setProjection(state.orientation, state.layerStackSpaceRect,
                           state.orientedDisplaySpaceRect);
    display->setDisplayName(state.displayName);
    display->setFlags(state.flags);

    return display;
}

void SurfaceFlinger::processDisplayAdded(const wp<IBinder>& displayToken,
                                         const DisplayDeviceState& state) {
    ui::Size resolution(0, 0);
    ui::PixelFormat pixelFormat = static_cast<ui::PixelFormat>(PIXEL_FORMAT_UNKNOWN);
    if (state.physical) {
        resolution = state.physical->activeMode->getResolution();
        pixelFormat = static_cast<ui::PixelFormat>(PIXEL_FORMAT_RGBA_8888);
    } else if (state.surface != nullptr) {
        int status = state.surface->query(NATIVE_WINDOW_WIDTH, &resolution.width);
        ALOGE_IF(status != NO_ERROR, "Unable to query width (%d)", status);
        status = state.surface->query(NATIVE_WINDOW_HEIGHT, &resolution.height);
        ALOGE_IF(status != NO_ERROR, "Unable to query height (%d)", status);
        int format;
        status = state.surface->query(NATIVE_WINDOW_FORMAT, &format);
        ALOGE_IF(status != NO_ERROR, "Unable to query format (%d)", status);
        pixelFormat = static_cast<ui::PixelFormat>(format);
    } else {
        // Virtual displays without a surface are dormant:
        // they have external state (layer stack, projection,
        // etc.) but no internal state (i.e. a DisplayDevice).
        return;
    }

    compositionengine::DisplayCreationArgsBuilder builder;
    if (const auto& physical = state.physical) {
        builder.setId(physical->id);
    } else {
        builder.setId(acquireVirtualDisplay(resolution, pixelFormat));
    }

    builder.setPixels(resolution);
    builder.setIsSecure(state.isSecure);
    builder.setPowerAdvisor(mPowerAdvisor.get());
    builder.setName(state.displayName);
    auto compositionDisplay = getCompositionEngine().createDisplay(builder.build());
    compositionDisplay->setLayerCachingEnabled(mLayerCachingEnabled);

    sp<compositionengine::DisplaySurface> displaySurface;
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferProducer> bqProducer;
    sp<IGraphicBufferConsumer> bqConsumer;
    getFactory().createBufferQueue(&bqProducer, &bqConsumer, /*consumerIsSurfaceFlinger =*/false);

    if (state.isVirtual()) {
        const auto displayId = VirtualDisplayId::tryCast(compositionDisplay->getId());
        LOG_FATAL_IF(!displayId);
        auto surface = sp<VirtualDisplaySurface>::make(getHwComposer(), *displayId, state.surface,
                                                       bqProducer, bqConsumer, state.displayName);
        displaySurface = surface;
        producer = std::move(surface);
    } else {
        ALOGE_IF(state.surface != nullptr,
                 "adding a supported display, but rendering "
                 "surface is provided (%p), ignoring it",
                 state.surface.get());
        const auto displayId = PhysicalDisplayId::tryCast(compositionDisplay->getId());
        LOG_FATAL_IF(!displayId);
        displaySurface =
                sp<FramebufferSurface>::make(getHwComposer(), *displayId, bqConsumer,
                                             state.physical->activeMode->getResolution(),
                                             ui::Size(maxGraphicsWidth, maxGraphicsHeight));
        producer = bqProducer;
    }

    LOG_FATAL_IF(!displaySurface);
    auto display = setupNewDisplayDeviceInternal(displayToken, std::move(compositionDisplay), state,
                                                 displaySurface, producer);
    if (display->isPrimary()) {
        initScheduler(display);
    }
    if (!state.isVirtual()) {
        dispatchDisplayHotplugEvent(display->getPhysicalId(), true);
    }

    mDisplays.try_emplace(displayToken, std::move(display));
}

void SurfaceFlinger::processDisplayRemoved(const wp<IBinder>& displayToken) {
    auto display = getDisplayDeviceLocked(displayToken);
    if (display) {
        display->disconnect();

        if (display->isVirtual()) {
            releaseVirtualDisplay(display->getVirtualId());
        } else {
            dispatchDisplayHotplugEvent(display->getPhysicalId(), false);
        }
    }

    mDisplays.erase(displayToken);

    if (display && display->isVirtual()) {
        static_cast<void>(mScheduler->schedule([display = std::move(display)] {
            // Destroy the display without holding the mStateLock.
            // This is a temporary solution until we can manage transaction queues without
            // holding the mStateLock.
            // With blast, the IGBP that is passed to the VirtualDisplaySurface is owned by the
            // client. When the IGBP is disconnected, its buffer cache in SF will be cleared
            // via SurfaceComposerClient::doUncacheBufferTransaction. This call from the client
            // ends up running on the main thread causing a deadlock since setTransactionstate
            // will try to acquire the mStateLock. Instead we extend the lifetime of
            // DisplayDevice and destroy it in the main thread without holding the mStateLock.
            // The display will be disconnected and removed from the mDisplays list so it will
            // not be accessible.
        }));
    }
}

void SurfaceFlinger::processDisplayChanged(const wp<IBinder>& displayToken,
                                           const DisplayDeviceState& currentState,
                                           const DisplayDeviceState& drawingState) {
    const sp<IBinder> currentBinder = IInterface::asBinder(currentState.surface);
    const sp<IBinder> drawingBinder = IInterface::asBinder(drawingState.surface);

    // Recreate the DisplayDevice if the surface or sequence ID changed.
    if (currentBinder != drawingBinder || currentState.sequenceId != drawingState.sequenceId) {
        getRenderEngine().cleanFramebufferCache();

        if (const auto display = getDisplayDeviceLocked(displayToken)) {
            display->disconnect();
            if (display->isVirtual()) {
                releaseVirtualDisplay(display->getVirtualId());
            }
        }

        mDisplays.erase(displayToken);

        if (const auto& physical = currentState.physical) {
            getHwComposer().allocatePhysicalDisplay(physical->hwcDisplayId, physical->id);
        }

        processDisplayAdded(displayToken, currentState);

        if (currentState.physical) {
            const auto display = getDisplayDeviceLocked(displayToken);
            setPowerModeInternal(display, hal::PowerMode::ON);

            // TODO(b/175678251) Call a listener instead.
            if (currentState.physical->hwcDisplayId == getHwComposer().getPrimaryHwcDisplayId()) {
                updateInternalDisplayVsyncLocked(display);
            }
        }
        return;
    }

    if (const auto display = getDisplayDeviceLocked(displayToken)) {
        if (currentState.layerStack != drawingState.layerStack) {
            display->setLayerStack(currentState.layerStack);
        }
        if (currentState.flags != drawingState.flags) {
            display->setFlags(currentState.flags);
        }
        if ((currentState.orientation != drawingState.orientation) ||
            (currentState.layerStackSpaceRect != drawingState.layerStackSpaceRect) ||
            (currentState.orientedDisplaySpaceRect != drawingState.orientedDisplaySpaceRect)) {
            display->setProjection(currentState.orientation, currentState.layerStackSpaceRect,
                                   currentState.orientedDisplaySpaceRect);
            if (isDisplayActiveLocked(display)) {
                mActiveDisplayTransformHint = display->getTransformHint();
            }
        }
        if (currentState.width != drawingState.width ||
            currentState.height != drawingState.height) {
            display->setDisplaySize(currentState.width, currentState.height);

            if (isDisplayActiveLocked(display)) {
                onActiveDisplaySizeChanged(display);
            }
        }
    }
}
void SurfaceFlinger::updateInternalDisplayVsyncLocked(const sp<DisplayDevice>& activeDisplay) {
    mVsyncConfiguration->reset();
    const Fps refreshRate = activeDisplay->refreshRateConfigs().getActiveMode()->getFps();
    updatePhaseConfiguration(refreshRate);
    mRefreshRateStats->setRefreshRate(refreshRate);
}

void SurfaceFlinger::processDisplayChangesLocked() {
    // here we take advantage of Vector's copy-on-write semantics to
    // improve performance by skipping the transaction entirely when
    // know that the lists are identical
    const KeyedVector<wp<IBinder>, DisplayDeviceState>& curr(mCurrentState.displays);
    const KeyedVector<wp<IBinder>, DisplayDeviceState>& draw(mDrawingState.displays);
    if (!curr.isIdenticalTo(draw)) {
        mVisibleRegionsDirty = true;

        // find the displays that were removed
        // (ie: in drawing state but not in current state)
        // also handle displays that changed
        // (ie: displays that are in both lists)
        for (size_t i = 0; i < draw.size(); i++) {
            const wp<IBinder>& displayToken = draw.keyAt(i);
            const ssize_t j = curr.indexOfKey(displayToken);
            if (j < 0) {
                // in drawing state but not in current state
                processDisplayRemoved(displayToken);
            } else {
                // this display is in both lists. see if something changed.
                const DisplayDeviceState& currentState = curr[j];
                const DisplayDeviceState& drawingState = draw[i];
                processDisplayChanged(displayToken, currentState, drawingState);
            }
        }

        // find displays that were added
        // (ie: in current state but not in drawing state)
        for (size_t i = 0; i < curr.size(); i++) {
            const wp<IBinder>& displayToken = curr.keyAt(i);
            if (draw.indexOfKey(displayToken) < 0) {
                processDisplayAdded(displayToken, curr[i]);
            }
        }
    }

    mDrawingState.displays = mCurrentState.displays;
}

void SurfaceFlinger::commitTransactionsLocked(uint32_t transactionFlags) {
    // Commit display transactions.
    const bool displayTransactionNeeded = transactionFlags & eDisplayTransactionNeeded;
    if (displayTransactionNeeded) {
        processDisplayChangesLocked();
        processDisplayHotplugEventsLocked();
    }
    mForceTransactionDisplayChange = displayTransactionNeeded;

    if (mSomeChildrenChanged) {
        mVisibleRegionsDirty = true;
        mSomeChildrenChanged = false;
    }

    // Update transform hint.
    if (transactionFlags & (eTransformHintUpdateNeeded | eDisplayTransactionNeeded)) {
        // Layers and/or displays have changed, so update the transform hint for each layer.
        //
        // NOTE: we do this here, rather than when presenting the display so that
        // the hint is set before we acquire a buffer from the surface texture.
        //
        // NOTE: layer transactions have taken place already, so we use their
        // drawing state. However, SurfaceFlinger's own transaction has not
        // happened yet, so we must use the current state layer list
        // (soon to become the drawing state list).
        //
        sp<const DisplayDevice> hintDisplay;
        ui::LayerStack layerStack;

        mCurrentState.traverse([&](Layer* layer) REQUIRES(mStateLock) {
            // NOTE: we rely on the fact that layers are sorted by
            // layerStack first (so we don't have to traverse the list
            // of displays for every layer).
            if (const auto filter = layer->getOutputFilter(); layerStack != filter.layerStack) {
                layerStack = filter.layerStack;
                hintDisplay = nullptr;

                // Find the display that includes the layer.
                for (const auto& [token, display] : mDisplays) {
                    if (!display->getCompositionDisplay()->includesLayer(filter)) {
                        continue;
                    }

                    // Pick the primary display if another display mirrors the layer.
                    if (hintDisplay) {
                        hintDisplay = nullptr;
                        break;
                    }

                    hintDisplay = display;
                }
            }

            if (!hintDisplay) {
                // NOTE: TEMPORARY FIX ONLY. Real fix should cause layers to
                // redraw after transform hint changes. See bug 8508397.

                // could be null when this layer is using a layerStack
                // that is not visible on any display. Also can occur at
                // screen off/on times.
                hintDisplay = getDefaultDisplayDeviceLocked();
            }

            layer->updateTransformHint(hintDisplay->getTransformHint());
        });
    }

    if (mLayersAdded) {
        mLayersAdded = false;
        // Layers have been added.
        mVisibleRegionsDirty = true;
    }

    // some layers might have been removed, so
    // we need to update the regions they're exposing.
    if (mLayersRemoved) {
        mLayersRemoved = false;
        mVisibleRegionsDirty = true;
        mDrawingState.traverseInZOrder([&](Layer* layer) {
            if (mLayersPendingRemoval.indexOf(layer) >= 0) {
                // this layer is not visible anymore
                Region visibleReg;
                visibleReg.set(layer->getScreenBounds());
                invalidateLayerStack(layer, visibleReg);
            }
        });
    }

    doCommitTransactions();
    signalSynchronousTransactions(CountDownLatch::eSyncTransaction);
    mAnimTransactionPending = false;
}

void SurfaceFlinger::updateInputFlinger() {
    ATRACE_CALL();
    if (!mInputFlinger) {
        return;
    }

    std::vector<WindowInfo> windowInfos;
    std::vector<DisplayInfo> displayInfos;
    bool updateWindowInfo = false;
    if (mVisibleRegionsDirty || mInputInfoChanged) {
        mInputInfoChanged = false;
        updateWindowInfo = true;
        buildWindowInfos(windowInfos, displayInfos);
    }
    if (!updateWindowInfo && mInputWindowCommands.empty()) {
        return;
    }

    std::unordered_set<Layer*> visibleLayers;
    mDrawingState.traverse([&visibleLayers](Layer* layer) {
        if (layer->isVisibleForInput()) {
            visibleLayers.insert(layer);
        }
    });
    bool visibleLayersChanged = false;
    if (visibleLayers != mVisibleLayers) {
        visibleLayersChanged = true;
        mVisibleLayers = std::move(visibleLayers);
    }

    BackgroundExecutor::getInstance().sendCallbacks({[updateWindowInfo,
                                                      windowInfos = std::move(windowInfos),
                                                      displayInfos = std::move(displayInfos),
                                                      inputWindowCommands =
                                                              std::move(mInputWindowCommands),
                                                      inputFlinger = mInputFlinger, this,
                                                      visibleLayersChanged]() {
        ATRACE_NAME("BackgroundExecutor::updateInputFlinger");
        if (updateWindowInfo) {
            mWindowInfosListenerInvoker
                    ->windowInfosChanged(std::move(windowInfos), std::move(displayInfos),
                                         /* shouldSync= */ inputWindowCommands.syncInputWindows,
                                         /* forceImmediateCall= */
                                         visibleLayersChanged ||
                                                 !inputWindowCommands.focusRequests.empty());
        } else if (inputWindowCommands.syncInputWindows) {
            // If the caller requested to sync input windows, but there are no
            // changes to input windows, notify immediately.
            windowInfosReported();
        }
        for (const auto& focusRequest : inputWindowCommands.focusRequests) {
            inputFlinger->setFocusedWindow(focusRequest);
        }
    }});

    mInputWindowCommands.clear();
}

void SurfaceFlinger::persistDisplayBrightness(bool needsComposite) {
    const bool supportsDisplayBrightnessCommand = getHwComposer().getComposer()->isSupported(
            Hwc2::Composer::OptionalFeature::DisplayBrightnessCommand);
    if (!supportsDisplayBrightnessCommand) {
        return;
    }

    for (const auto& [_, display] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        if (const auto brightness = display->getStagedBrightness(); brightness) {
            if (!needsComposite) {
                const status_t error =
                        getHwComposer()
                                .setDisplayBrightness(display->getPhysicalId(), *brightness,
                                                      display->getCompositionDisplay()
                                                              ->getState()
                                                              .displayBrightnessNits,
                                                      Hwc2::Composer::DisplayBrightnessOptions{
                                                              .applyImmediately = true})
                                .get();

                ALOGE_IF(error != NO_ERROR,
                         "Error setting display brightness for display %s: %d (%s)",
                         display->getDebugName().c_str(), error, strerror(error));
            }
            display->persistBrightness(needsComposite);
        }
    }
}

void SurfaceFlinger::buildWindowInfos(std::vector<WindowInfo>& outWindowInfos,
                                      std::vector<DisplayInfo>& outDisplayInfos) {
    ftl::SmallMap<ui::LayerStack, DisplayDevice::InputInfo, 4> displayInputInfos;

    for (const auto& [_, display] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        const auto layerStack = display->getLayerStack();
        const auto info = display->getInputInfo();

        const auto [it, emplaced] = displayInputInfos.try_emplace(layerStack, info);
        if (emplaced) {
            continue;
        }

        // If the layer stack is mirrored on multiple displays, the first display that is configured
        // to receive input takes precedence.
        auto& otherInfo = it->second;
        if (otherInfo.receivesInput) {
            ALOGW_IF(display->receivesInput(),
                     "Multiple displays claim to accept input for the same layer stack: %u",
                     layerStack.id);
        } else {
            otherInfo = info;
        }
    }

    static size_t sNumWindowInfos = 0;
    outWindowInfos.reserve(sNumWindowInfos);
    sNumWindowInfos = 0;

    mDrawingState.traverseInReverseZOrder([&](Layer* layer) {
        if (!layer->needsInputInfo()) return;

        const auto opt = displayInputInfos.get(layer->getLayerStack(),
                                               [](const auto& info) -> Layer::InputDisplayArgs {
                                                   return {&info.transform, info.isSecure};
                                               });
        outWindowInfos.push_back(layer->fillInputInfo(opt.value_or(Layer::InputDisplayArgs{})));
    });

    sNumWindowInfos = outWindowInfos.size();

    outDisplayInfos.reserve(displayInputInfos.size());
    for (const auto& [_, info] : displayInputInfos) {
        outDisplayInfos.push_back(info.info);
    }
}

void SurfaceFlinger::updateCursorAsync() {
    compositionengine::CompositionRefreshArgs refreshArgs;
    for (const auto& [_, display] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        if (HalDisplayId::tryCast(display->getId())) {
            refreshArgs.outputs.push_back(display->getCompositionDisplay());
        }
    }

    mCompositionEngine->updateCursorAsync(refreshArgs);
}

void SurfaceFlinger::requestDisplayMode(DisplayModePtr mode, DisplayModeEvent event) {
    // If this is called from the main thread mStateLock must be locked before
    // Currently the only way to call this function from the main thread is from
    // Scheduler::chooseRefreshRateForContent

    ConditionalLock lock(mStateLock, std::this_thread::get_id() != mMainThreadId);

    const auto display = getDefaultDisplayDeviceLocked();
    if (!display || mBootStage != BootStage::FINISHED) {
        return;
    }
    ATRACE_CALL();

    if (display->isInternal() && !isDisplayActiveLocked(display)) {
        ALOGV("%s(%s): Inactive display", __func__, to_string(display->getId()).c_str());
        return;
    }

    if (!display->refreshRateConfigs().isModeAllowed(mode->getId())) {
        ALOGV("%s(%s): Disallowed mode %d", __func__, to_string(display->getId()).c_str(),
              mode->getId().value());
        return;
    }

    setDesiredActiveMode({std::move(mode), event});
}

void SurfaceFlinger::triggerOnFrameRateOverridesChanged() {
    PhysicalDisplayId displayId = [&]() {
        ConditionalLock lock(mStateLock, std::this_thread::get_id() != mMainThreadId);
        return getDefaultDisplayDeviceLocked()->getPhysicalId();
    }();

    mScheduler->onFrameRateOverridesChanged(mAppConnectionHandle, displayId);
}

void SurfaceFlinger::initScheduler(const sp<DisplayDevice>& display) {
    if (mScheduler) {
        // If the scheduler is already initialized, this means that we received
        // a hotplug(connected) on the primary display. In that case we should
        // update the scheduler with the most recent display information.
        ALOGW("Scheduler already initialized, updating instead");
        mScheduler->setRefreshRateConfigs(display->holdRefreshRateConfigs());
        return;
    }
    const auto currRefreshRate = display->getActiveMode()->getFps();
    mRefreshRateStats = std::make_unique<scheduler::RefreshRateStats>(*mTimeStats, currRefreshRate,
                                                                      hal::PowerMode::OFF);

    mVsyncConfiguration = getFactory().createVsyncConfiguration(currRefreshRate);
    mVsyncModulator = sp<VsyncModulator>::make(mVsyncConfiguration->getCurrentConfigs());

    using Feature = scheduler::Feature;
    scheduler::FeatureFlags features;

    if (sysprop::use_content_detection_for_refresh_rate(false)) {
        features |= Feature::kContentDetection;
    }
    if (base::GetBoolProperty("debug.sf.show_predicted_vsync"s, false)) {
        features |= Feature::kTracePredictedVsync;
    }
    if (!base::GetBoolProperty("debug.sf.vsync_reactor_ignore_present_fences"s, false) &&
        !getHwComposer().hasCapability(Capability::PRESENT_FENCE_IS_NOT_RELIABLE)) {
        features |= Feature::kPresentFences;
    }

    mScheduler = std::make_unique<scheduler::Scheduler>(static_cast<ICompositor&>(*this),
                                                        static_cast<ISchedulerCallback&>(*this),
                                                        features);
    {
        auto configs = display->holdRefreshRateConfigs();
        if (configs->kernelIdleTimerController().has_value()) {
            features |= Feature::kKernelIdleTimer;
        }

        mScheduler->createVsyncSchedule(features);
        mScheduler->setRefreshRateConfigs(std::move(configs));
    }
    setVsyncEnabled(false);
    mScheduler->startTimers();

    const auto configs = mVsyncConfiguration->getCurrentConfigs();
    const nsecs_t vsyncPeriod = currRefreshRate.getPeriodNsecs();
    mAppConnectionHandle =
            mScheduler->createConnection("app", mFrameTimeline->getTokenManager(),
                                         /*workDuration=*/configs.late.appWorkDuration,
                                         /*readyDuration=*/configs.late.sfWorkDuration,
                                         impl::EventThread::InterceptVSyncsCallback());
    mSfConnectionHandle =
            mScheduler->createConnection("appSf", mFrameTimeline->getTokenManager(),
                                         /*workDuration=*/std::chrono::nanoseconds(vsyncPeriod),
                                         /*readyDuration=*/configs.late.sfWorkDuration,
                                         [this](nsecs_t timestamp) {
                                             mInterceptor->saveVSyncEvent(timestamp);
                                         });

    mScheduler->initVsync(mScheduler->getVsyncDispatch(), *mFrameTimeline->getTokenManager(),
                          configs.late.sfWorkDuration);

    mRegionSamplingThread =
            new RegionSamplingThread(*this, RegionSamplingThread::EnvironmentTimingTunables());
    mFpsReporter = new FpsReporter(*mFrameTimeline, *this);
    // Dispatch a mode change request for the primary display on scheduler
    // initialization, so that the EventThreads always contain a reference to a
    // prior configuration.
    //
    // This is a bit hacky, but this avoids a back-pointer into the main SF
    // classes from EventThread, and there should be no run-time binder cost
    // anyway since there are no connected apps at this point.
    mScheduler->onPrimaryDisplayModeChanged(mAppConnectionHandle, display->getActiveMode());
}

void SurfaceFlinger::updatePhaseConfiguration(const Fps& refreshRate) {
    mVsyncConfiguration->setRefreshRateFps(refreshRate);
    setVsyncConfig(mVsyncModulator->setVsyncConfigSet(mVsyncConfiguration->getCurrentConfigs()),
                   refreshRate.getPeriodNsecs());
}

void SurfaceFlinger::setVsyncConfig(const VsyncModulator::VsyncConfig& config,
                                    nsecs_t vsyncPeriod) {
    mScheduler->setDuration(mAppConnectionHandle,
                            /*workDuration=*/config.appWorkDuration,
                            /*readyDuration=*/config.sfWorkDuration);
    mScheduler->setDuration(mSfConnectionHandle,
                            /*workDuration=*/std::chrono::nanoseconds(vsyncPeriod),
                            /*readyDuration=*/config.sfWorkDuration);
    mScheduler->setDuration(config.sfWorkDuration);
}

void SurfaceFlinger::doCommitTransactions() {
    ATRACE_CALL();

    if (!mLayersPendingRemoval.isEmpty()) {
        // Notify removed layers now that they can't be drawn from
        for (const auto& l : mLayersPendingRemoval) {
            // Ensure any buffers set to display on any children are released.
            if (l->isRemovedFromCurrentState()) {
                l->latchAndReleaseBuffer();
            }

            // If a layer has a parent, we allow it to out-live it's handle
            // with the idea that the parent holds a reference and will eventually
            // be cleaned up. However no one cleans up the top-level so we do so
            // here.
            if (l->isAtRoot()) {
                l->setIsAtRoot(false);
                mCurrentState.layersSortedByZ.remove(l);
            }

            // If the layer has been removed and has no parent, then it will not be reachable
            // when traversing layers on screen. Add the layer to the offscreenLayers set to
            // ensure we can copy its current to drawing state.
            if (!l->getParent()) {
                mOffscreenLayers.emplace(l.get());
            }
        }
        mLayersPendingRemoval.clear();
    }

    // If this transaction is part of a window animation then the next frame
    // we composite should be considered an animation as well.
    mAnimCompositionPending = mAnimTransactionPending;

    mDrawingState = mCurrentState;
    // clear the "changed" flags in current state
    mCurrentState.colorMatrixChanged = false;

    if (mVisibleRegionsDirty) {
        for (const auto& rootLayer : mDrawingState.layersSortedByZ) {
            rootLayer->commitChildList();
        }
    }

    commitOffscreenLayers();
    if (mNumClones > 0) {
        mDrawingState.traverse([&](Layer* layer) { layer->updateMirrorInfo(); });
    }
}

void SurfaceFlinger::commitOffscreenLayers() {
    for (Layer* offscreenLayer : mOffscreenLayers) {
        offscreenLayer->traverse(LayerVector::StateSet::Drawing, [](Layer* layer) {
            if (layer->clearTransactionFlags(eTransactionNeeded)) {
                layer->doTransaction(0);
                layer->commitChildList();
            }
        });
    }
}

void SurfaceFlinger::invalidateLayerStack(const sp<const Layer>& layer, const Region& dirty) {
    for (const auto& [token, displayDevice] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        auto display = displayDevice->getCompositionDisplay();
        if (display->includesLayer(layer->getOutputFilter())) {
            display->editState().dirtyRegion.orSelf(dirty);
        }
    }
}

bool SurfaceFlinger::latchBuffers() {
    ATRACE_CALL();

    const nsecs_t latchTime = systemTime();

    bool visibleRegions = false;
    bool frameQueued = false;
    bool newDataLatched = false;

    const nsecs_t expectedPresentTime = mExpectedPresentTime.load();

    // Store the set of layers that need updates. This set must not change as
    // buffers are being latched, as this could result in a deadlock.
    // Example: Two producers share the same command stream and:
    // 1.) Layer 0 is latched
    // 2.) Layer 0 gets a new frame
    // 2.) Layer 1 gets a new frame
    // 3.) Layer 1 is latched.
    // Display is now waiting on Layer 1's frame, which is behind layer 0's
    // second frame. But layer 0's second frame could be waiting on display.
    mDrawingState.traverse([&](Layer* layer) {
        if (layer->clearTransactionFlags(eTransactionNeeded) || mForceTransactionDisplayChange) {
            const uint32_t flags = layer->doTransaction(0);
            if (flags & Layer::eVisibleRegion) {
                mVisibleRegionsDirty = true;
            }
        }

        if (layer->hasReadyFrame()) {
            frameQueued = true;
            if (layer->shouldPresentNow(expectedPresentTime)) {
                mLayersWithQueuedFrames.emplace(layer);
            } else {
                ATRACE_NAME("!layer->shouldPresentNow()");
                layer->useEmptyDamage();
            }
        } else {
            layer->useEmptyDamage();
        }
    });
    mForceTransactionDisplayChange = false;

    // The client can continue submitting buffers for offscreen layers, but they will not
    // be shown on screen. Therefore, we need to latch and release buffers of offscreen
    // layers to ensure dequeueBuffer doesn't block indefinitely.
    for (Layer* offscreenLayer : mOffscreenLayers) {
        offscreenLayer->traverse(LayerVector::StateSet::Drawing,
                                         [&](Layer* l) { l->latchAndReleaseBuffer(); });
    }

    if (!mLayersWithQueuedFrames.empty()) {
        // mStateLock is needed for latchBuffer as LayerRejecter::reject()
        // writes to Layer current state. See also b/119481871
        Mutex::Autolock lock(mStateLock);

        for (const auto& layer : mLayersWithQueuedFrames) {
            if (layer->latchBuffer(visibleRegions, latchTime, expectedPresentTime)) {
                mLayersPendingRefresh.push_back(layer);
                newDataLatched = true;
            }
            layer->useSurfaceDamage();
        }
    }

    mVisibleRegionsDirty |= visibleRegions;

    // If we will need to wake up at some time in the future to deal with a
    // queued frame that shouldn't be displayed during this vsync period, wake
    // up during the next vsync period to check again.
    if (frameQueued && (mLayersWithQueuedFrames.empty() || !newDataLatched)) {
        scheduleCommit(FrameHint::kNone);
    }

    // enter boot animation on first buffer latch
    if (CC_UNLIKELY(mBootStage == BootStage::BOOTLOADER && newDataLatched)) {
        ALOGI("Enter boot animation");
        mBootStage = BootStage::BOOTANIMATION;
    }

    if (mNumClones > 0) {
        mDrawingState.traverse([&](Layer* layer) { layer->updateCloneBufferInfo(); });
    }

    // Only continue with the refresh if there is actually new work to do
    return !mLayersWithQueuedFrames.empty() && newDataLatched;
}

status_t SurfaceFlinger::addClientLayer(const sp<Client>& client, const sp<IBinder>& handle,
                                        const sp<Layer>& layer, const wp<Layer>& parent,
                                        bool addToRoot, uint32_t* outTransformHint) {
    if (mNumLayers >= ISurfaceComposer::MAX_LAYERS) {
        ALOGE("AddClientLayer failed, mNumLayers (%zu) >= MAX_LAYERS (%zu)", mNumLayers.load(),
              ISurfaceComposer::MAX_LAYERS);
        static_cast<void>(mScheduler->schedule([=] {
            ALOGE("Dumping random sampling of on-screen layers: ");
            mDrawingState.traverse([&](Layer *layer) {
                // Aim to dump about 200 layers to avoid totally trashing
                // logcat. On the other hand, if there really are 4096 layers
                // something has gone totally wrong its probably the most
                // useful information in logcat.
                if (rand() % 20 == 13) {
                    ALOGE("Layer: %s", layer->getName().c_str());
                }
            });
            for (Layer* offscreenLayer : mOffscreenLayers) {
                if (rand() % 20 == 13) {
                    ALOGE("Offscreen-layer: %s", offscreenLayer->getName().c_str());
                }
            }
        }));
        return NO_MEMORY;
    }

    {
        std::scoped_lock<std::mutex> lock(mCreatedLayersLock);
        mCreatedLayers.emplace_back(layer, parent, addToRoot);
    }

    layer->updateTransformHint(mActiveDisplayTransformHint);
    if (outTransformHint) {
        *outTransformHint = mActiveDisplayTransformHint;
    }
    // attach this layer to the client
    if (client != nullptr) {
        client->attachLayer(handle, layer);
    }

    setTransactionFlags(eTransactionNeeded);
    return NO_ERROR;
}

uint32_t SurfaceFlinger::getTransactionFlags() const {
    return mTransactionFlags;
}

uint32_t SurfaceFlinger::clearTransactionFlags(uint32_t mask) {
    return mTransactionFlags.fetch_and(~mask) & mask;
}

void SurfaceFlinger::setTransactionFlags(uint32_t mask, TransactionSchedule schedule,
                                         const sp<IBinder>& applyToken, FrameHint frameHint) {
    modulateVsync(&VsyncModulator::setTransactionSchedule, schedule, applyToken);

    if (const bool scheduled = mTransactionFlags.fetch_or(mask) & mask; !scheduled) {
        scheduleCommit(frameHint);
    }
}

bool SurfaceFlinger::stopTransactionProcessing(
        const std::unordered_set<sp<IBinder>, SpHash<IBinder>>&
                applyTokensWithUnsignaledTransactions) const {
    if (enableLatchUnsignaledConfig == LatchUnsignaledConfig::AutoSingleLayer) {
        // if we are in LatchUnsignaledConfig::AutoSingleLayer
        // then we should have only one applyToken for processing.
        // so we can stop further transactions on this applyToken.
        return !applyTokensWithUnsignaledTransactions.empty();
    }

    return false;
}

int SurfaceFlinger::flushUnsignaledPendingTransactionQueues(
        std::vector<TransactionState>& transactions,
        std::unordered_map<sp<IBinder>, uint64_t, SpHash<IBinder>>& bufferLayersReadyToPresent,
        std::unordered_set<sp<IBinder>, SpHash<IBinder>>& applyTokensWithUnsignaledTransactions) {
    return flushPendingTransactionQueues(transactions, bufferLayersReadyToPresent,
                                         applyTokensWithUnsignaledTransactions,
                                         /*tryApplyUnsignaled*/ true);
}

int SurfaceFlinger::flushPendingTransactionQueues(
        std::vector<TransactionState>& transactions,
        std::unordered_map<sp<IBinder>, uint64_t, SpHash<IBinder>>& bufferLayersReadyToPresent,
        std::unordered_set<sp<IBinder>, SpHash<IBinder>>& applyTokensWithUnsignaledTransactions,
        bool tryApplyUnsignaled) {
    int transactionsPendingBarrier = 0;
    auto it = mPendingTransactionQueues.begin();
    while (it != mPendingTransactionQueues.end()) {
        auto& [applyToken, transactionQueue] = *it;
        while (!transactionQueue.empty()) {
            if (stopTransactionProcessing(applyTokensWithUnsignaledTransactions)) {
                ATRACE_NAME("stopTransactionProcessing");
                break;
            }

            auto& transaction = transactionQueue.front();
            const auto ready =
                transactionIsReadyToBeApplied(transaction,
                                              transaction.frameTimelineInfo,
                                              transaction.isAutoTimestamp,
                                              transaction.desiredPresentTime,
                                              transaction.originUid, transaction.states,
                                              bufferLayersReadyToPresent, transactions.size(),
                                              tryApplyUnsignaled);
            ATRACE_INT("TransactionReadiness", static_cast<int>(ready));
            if (ready == TransactionReadiness::NotReady) {
                setTransactionFlags(eTransactionFlushNeeded);
                break;
            }
            if (ready == TransactionReadiness::NotReadyBarrier) {
                transactionsPendingBarrier++;
                setTransactionFlags(eTransactionFlushNeeded);
                break;
            }
            transaction.traverseStatesWithBuffers([&](const layer_state_t& state) {
                const bool frameNumberChanged = state.bufferData->flags.test(
                        BufferData::BufferDataChange::frameNumberChanged);
                if (frameNumberChanged) {
                    bufferLayersReadyToPresent[state.surface] = state.bufferData->frameNumber;
                } else {
                    // Barrier function only used for BBQ which always includes a frame number
                    bufferLayersReadyToPresent[state.surface] =
                        std::numeric_limits<uint64_t>::max();
                }
            });
            const bool appliedUnsignaled = (ready == TransactionReadiness::ReadyUnsignaled);
            if (appliedUnsignaled) {
                applyTokensWithUnsignaledTransactions.insert(transaction.applyToken);
            }

            transactions.emplace_back(std::move(transaction));
            transactionQueue.pop();
        }

        if (transactionQueue.empty()) {
            it = mPendingTransactionQueues.erase(it);
            mTransactionQueueCV.broadcast();
        } else {
            it = std::next(it, 1);
        }
    }
    return transactionsPendingBarrier;
}

std::vector<TransactionState> SurfaceFlinger::flushTransactions() {
    // to prevent onHandleDestroyed from being called while the lock is held,
    // we must keep a copy of the transactions (specifically the composer
    // states) around outside the scope of the lock
    std::vector<TransactionState> transactions;
    // Layer handles that have transactions with buffers that are ready to be applied.
    std::unordered_map<sp<IBinder>, uint64_t, SpHash<IBinder>> bufferLayersReadyToPresent;
    std::unordered_set<sp<IBinder>, SpHash<IBinder>> applyTokensWithUnsignaledTransactions;
    {
        Mutex::Autolock _l(mStateLock);
        {
            Mutex::Autolock _l(mQueueLock);

            int lastTransactionsPendingBarrier = 0;
            int transactionsPendingBarrier = 0;
            // First collect transactions from the pending transaction queues.
            // We are not allowing unsignaled buffers here as we want to
            // collect all the transactions from applyTokens that are ready first.
            transactionsPendingBarrier =
                    flushPendingTransactionQueues(transactions, bufferLayersReadyToPresent,
                            applyTokensWithUnsignaledTransactions, /*tryApplyUnsignaled*/ false);

            // Second, collect transactions from the transaction queue.
            // Here as well we are not allowing unsignaled buffers for the same
            // reason as above.
            while (!mTransactionQueue.empty()) {
                auto& transaction = mTransactionQueue.front();
                const bool pendingTransactions =
                        mPendingTransactionQueues.find(transaction.applyToken) !=
                        mPendingTransactionQueues.end();
                const auto ready = [&]() REQUIRES(mStateLock) {
                    if (pendingTransactions) {
                        ATRACE_NAME("pendingTransactions");
                        return TransactionReadiness::NotReady;
                    }

                    return transactionIsReadyToBeApplied(transaction, transaction.frameTimelineInfo,
                                                         transaction.isAutoTimestamp,
                                                         transaction.desiredPresentTime,
                                                         transaction.originUid, transaction.states,
                                                         bufferLayersReadyToPresent,
                                                         transactions.size(),
                                                         /*tryApplyUnsignaled*/ false);
                }();
                ATRACE_INT("TransactionReadiness", static_cast<int>(ready));
                if (ready != TransactionReadiness::Ready) {
                    if (ready == TransactionReadiness::NotReadyBarrier) {
                        transactionsPendingBarrier++;
                    }
                    mPendingTransactionQueues[transaction.applyToken].push(std::move(transaction));
                } else {
                    transaction.traverseStatesWithBuffers([&](const layer_state_t& state) {
                        const bool frameNumberChanged = state.bufferData->flags.test(
                                BufferData::BufferDataChange::frameNumberChanged);
                        if (frameNumberChanged) {
                            bufferLayersReadyToPresent[state.surface] = state.bufferData->frameNumber;
                        } else {
                            // Barrier function only used for BBQ which always includes a frame number.
                            // This value only used for barrier logic.
                            bufferLayersReadyToPresent[state.surface] =
                                std::numeric_limits<uint64_t>::max();
                        }
                    });
                    transactions.emplace_back(std::move(transaction));
                }
                mTransactionQueue.pop_front();
                ATRACE_INT("TransactionQueue", mTransactionQueue.size());
            }

            // Transactions with a buffer pending on a barrier may be on a different applyToken
            // than the transaction which satisfies our barrier. In fact this is the exact use case
            // that the primitive is designed for. This means we may first process
            // the barrier dependent transaction, determine it ineligible to complete
            // and then satisfy in a later inner iteration of flushPendingTransactionQueues.
            // The barrier dependent transaction was eligible to be presented in this frame
            // but we would have prevented it without case. To fix this we continually
            // loop through flushPendingTransactionQueues until we perform an iteration
            // where the number of transactionsPendingBarrier doesn't change. This way
            // we can continue to resolve dependency chains of barriers as far as possible.
            while (lastTransactionsPendingBarrier != transactionsPendingBarrier) {
                lastTransactionsPendingBarrier = transactionsPendingBarrier;
                transactionsPendingBarrier =
                    flushPendingTransactionQueues(transactions, bufferLayersReadyToPresent,
                        applyTokensWithUnsignaledTransactions,
                        /*tryApplyUnsignaled*/ false);
            }

            // We collected all transactions that could apply without latching unsignaled buffers.
            // If we are allowing latch unsignaled of some form, now it's the time to go over the
            // transactions that were not applied and try to apply them unsignaled.
            if (enableLatchUnsignaledConfig != LatchUnsignaledConfig::Disabled) {
                flushUnsignaledPendingTransactionQueues(transactions, bufferLayersReadyToPresent,
                                                        applyTokensWithUnsignaledTransactions);
            }
        }
    }
    return transactions;
}

// for test only
bool SurfaceFlinger::flushTransactionQueues(int64_t vsyncId) {
    std::vector<TransactionState> transactions = flushTransactions();
    return applyTransactions(transactions, vsyncId);
}

bool SurfaceFlinger::applyTransactions(std::vector<TransactionState>& transactions,
                                       int64_t vsyncId) {
    Mutex::Autolock _l(mStateLock);
    return applyTransactionsLocked(transactions, vsyncId);
}

bool SurfaceFlinger::applyTransactionsLocked(std::vector<TransactionState>& transactions,
                                             int64_t vsyncId) {
    bool needsTraversal = false;
    // Now apply all transactions.
    for (auto& transaction : transactions) {
        needsTraversal |=
                applyTransactionState(transaction.frameTimelineInfo, transaction.states,
                                      transaction.displays, transaction.flags,
                                      transaction.inputWindowCommands,
                                      transaction.desiredPresentTime, transaction.isAutoTimestamp,
                                      transaction.buffer, transaction.postTime,
                                      transaction.permissions, transaction.hasListenerCallbacks,
                                      transaction.listenerCallbacks, transaction.originPid,
                                      transaction.originUid, transaction.id);
        if (transaction.transactionCommittedSignal) {
            mTransactionCommittedSignals.emplace_back(
                    std::move(transaction.transactionCommittedSignal));
        }
    }

    if (mTransactionTracing) {
        mTransactionTracing->addCommittedTransactions(transactions, vsyncId);
    }
    return needsTraversal;
}

bool SurfaceFlinger::transactionFlushNeeded() {
    Mutex::Autolock _l(mQueueLock);
    return !mPendingTransactionQueues.empty() || !mTransactionQueue.empty();
}

bool SurfaceFlinger::frameIsEarly(nsecs_t expectedPresentTime, int64_t vsyncId) const {
    // The amount of time SF can delay a frame if it is considered early based
    // on the VsyncModulator::VsyncConfig::appWorkDuration
    constexpr static std::chrono::nanoseconds kEarlyLatchMaxThreshold = 100ms;

    const auto currentVsyncPeriod = mScheduler->getDisplayStatInfo(systemTime()).vsyncPeriod;
    const auto earlyLatchVsyncThreshold = currentVsyncPeriod / 2;

    const auto prediction = mFrameTimeline->getTokenManager()->getPredictionsForToken(vsyncId);
    if (!prediction.has_value()) {
        return false;
    }

    if (std::abs(prediction->presentTime - expectedPresentTime) >=
        kEarlyLatchMaxThreshold.count()) {
        return false;
    }

    return prediction->presentTime >= expectedPresentTime &&
            prediction->presentTime - expectedPresentTime >= earlyLatchVsyncThreshold;
}
bool SurfaceFlinger::shouldLatchUnsignaled(const sp<Layer>& layer, const layer_state_t& state,
                                           size_t numStates, size_t totalTXapplied) const {
    if (enableLatchUnsignaledConfig == LatchUnsignaledConfig::Disabled) {
        ALOGV("%s: false (LatchUnsignaledConfig::Disabled)", __func__);
        return false;
    }

    if (enableLatchUnsignaledConfig == LatchUnsignaledConfig::Always) {
        ALOGV("%s: true (LatchUnsignaledConfig::Always)", __func__);
        return true;
    }

    // We only want to latch unsignaled when a single layer is updated in this
    // transaction (i.e. not a blast sync transaction).
    if (numStates != 1) {
        ALOGV("%s: false (numStates=%zu)", __func__, numStates);
        return false;
    }

    if (enableLatchUnsignaledConfig == LatchUnsignaledConfig::AutoSingleLayer) {
        if (totalTXapplied > 0) {
            ALOGV("%s: false (LatchUnsignaledConfig::AutoSingleLayer; totalTXapplied=%zu)",
                  __func__, totalTXapplied);
            return false;
        }

        // We don't want to latch unsignaled if are in early / client composition
        // as it leads to jank due to RenderEngine waiting for unsignaled buffer
        // or window animations being slow.
        const auto isDefaultVsyncConfig = mVsyncModulator->isVsyncConfigDefault();
        if (!isDefaultVsyncConfig) {
            ALOGV("%s: false (LatchUnsignaledConfig::AutoSingleLayer; !isDefaultVsyncConfig)",
                  __func__);
            return false;
        }
    }

    if (!layer->simpleBufferUpdate(state)) {
        ALOGV("%s: false (!simpleBufferUpdate)", __func__);
        return false;
    }

    ALOGV("%s: true", __func__);
    return true;
}

auto SurfaceFlinger::transactionIsReadyToBeApplied(TransactionState& transaction,
        const FrameTimelineInfo& info, bool isAutoTimestamp, int64_t desiredPresentTime,
        uid_t originUid, const Vector<ComposerState>& states,
        const std::unordered_map<
            sp<IBinder>, uint64_t, SpHash<IBinder>>& bufferLayersReadyToPresent,
        size_t totalTXapplied, bool tryApplyUnsignaled) const -> TransactionReadiness {
    ATRACE_FORMAT("transactionIsReadyToBeApplied vsyncId: %" PRId64, info.vsyncId);
    const nsecs_t expectedPresentTime = mExpectedPresentTime.load();
    // Do not present if the desiredPresentTime has not passed unless it is more than one second
    // in the future. We ignore timestamps more than 1 second in the future for stability reasons.
    if (!isAutoTimestamp && desiredPresentTime >= expectedPresentTime &&
        desiredPresentTime < expectedPresentTime + s2ns(1)) {
        ATRACE_NAME("not current");
        return TransactionReadiness::NotReady;
    }

    if (!mScheduler->isVsyncValid(expectedPresentTime, originUid)) {
        ATRACE_NAME("!isVsyncValid");
        return TransactionReadiness::NotReady;
    }

    // If the client didn't specify desiredPresentTime, use the vsyncId to determine the expected
    // present time of this transaction.
    if (isAutoTimestamp && frameIsEarly(expectedPresentTime, info.vsyncId)) {
        ATRACE_NAME("frameIsEarly");
        return TransactionReadiness::NotReady;
    }

    bool fenceUnsignaled = false;
    auto queueProcessTime = systemTime();
    for (const ComposerState& state : states) {
        const layer_state_t& s = state.state;

        sp<Layer> layer = nullptr;
        if (s.surface) {
            layer = fromHandle(s.surface).promote();
        } else if (s.hasBufferChanges()) {
            ALOGW("Transaction with buffer, but no Layer?");
            continue;
        }
        if (!layer) {
            continue;
        }

        if (s.hasBufferChanges() && s.bufferData->hasBarrier &&
            ((layer->getDrawingState().frameNumber) < s.bufferData->barrierFrameNumber)) {
            const bool willApplyBarrierFrame =
                (bufferLayersReadyToPresent.find(s.surface) != bufferLayersReadyToPresent.end()) &&
                (bufferLayersReadyToPresent.at(s.surface) >= s.bufferData->barrierFrameNumber);
            if (!willApplyBarrierFrame) {
                ATRACE_NAME("NotReadyBarrier");
                return TransactionReadiness::NotReadyBarrier;
            }
        }

        const bool allowLatchUnsignaled = tryApplyUnsignaled &&
                shouldLatchUnsignaled(layer, s, states.size(), totalTXapplied);
        ATRACE_FORMAT("%s allowLatchUnsignaled=%s", layer->getName().c_str(),
                      allowLatchUnsignaled ? "true" : "false");

        const bool acquireFenceChanged = s.bufferData &&
                s.bufferData->flags.test(BufferData::BufferDataChange::fenceChanged) &&
                s.bufferData->acquireFence;
        fenceUnsignaled = fenceUnsignaled ||
                (acquireFenceChanged &&
                 s.bufferData->acquireFence->getStatus() == Fence::Status::Unsignaled);

        if (fenceUnsignaled && !allowLatchUnsignaled) {
            if (!transaction.sentFenceTimeoutWarning &&
                queueProcessTime - transaction.queueTime > std::chrono::nanoseconds(4s).count()) {
                transaction.sentFenceTimeoutWarning = true;
                auto listener = s.bufferData->releaseBufferListener;
                if (listener) {
                    listener->onTransactionQueueStalled();
                }
            }

            ATRACE_NAME("fence unsignaled");
            return TransactionReadiness::NotReady;
        }

        if (s.hasBufferChanges()) {
            // If backpressure is enabled and we already have a buffer to commit, keep the
            // transaction in the queue.
            const bool hasPendingBuffer = bufferLayersReadyToPresent.find(s.surface) !=
                bufferLayersReadyToPresent.end();
            if (layer->backpressureEnabled() && hasPendingBuffer && isAutoTimestamp) {
                ATRACE_NAME("hasPendingBuffer");
                return TransactionReadiness::NotReady;
            }
        }
    }
    return fenceUnsignaled ? TransactionReadiness::ReadyUnsignaled : TransactionReadiness::Ready;
}

void SurfaceFlinger::queueTransaction(TransactionState& state) {
    state.queueTime = systemTime();

    Mutex::Autolock lock(mQueueLock);

    // Generate a CountDownLatch pending state if this is a synchronous transaction.
    if ((state.flags & eSynchronous) || state.inputWindowCommands.syncInputWindows) {
        state.transactionCommittedSignal = std::make_shared<CountDownLatch>(
                (state.inputWindowCommands.syncInputWindows
                         ? (CountDownLatch::eSyncInputWindows | CountDownLatch::eSyncTransaction)
                         : CountDownLatch::eSyncTransaction));
    }

    mTransactionQueue.emplace_back(state);
    ATRACE_INT("TransactionQueue", mTransactionQueue.size());

    const auto schedule = [](uint32_t flags) {
        if (flags & eEarlyWakeupEnd) return TransactionSchedule::EarlyEnd;
        if (flags & eEarlyWakeupStart) return TransactionSchedule::EarlyStart;
        return TransactionSchedule::Late;
    }(state.flags);

    const auto frameHint = state.isFrameActive() ? FrameHint::kActive : FrameHint::kNone;

    setTransactionFlags(eTransactionFlushNeeded, schedule, state.applyToken, frameHint);
}

void SurfaceFlinger::waitForSynchronousTransaction(
        const CountDownLatch& transactionCommittedSignal) {
    // applyTransactionState is called on the main SF thread.  While a given process may wish
    // to wait on synchronous transactions, the main SF thread should apply the transaction and
    // set the value to notify this after committed.
    if (!transactionCommittedSignal.wait_until(
                std::chrono::nanoseconds(mAnimationTransactionTimeout))) {
        ALOGE("setTransactionState timed out!");
    }
}

void SurfaceFlinger::signalSynchronousTransactions(const uint32_t flag) {
    for (auto it = mTransactionCommittedSignals.begin();
         it != mTransactionCommittedSignals.end();) {
        if ((*it)->countDown(flag)) {
            it = mTransactionCommittedSignals.erase(it);
        } else {
            it++;
        }
    }
}

status_t SurfaceFlinger::setTransactionState(
        const FrameTimelineInfo& frameTimelineInfo, const Vector<ComposerState>& states,
        const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
        const InputWindowCommands& inputWindowCommands, int64_t desiredPresentTime,
        bool isAutoTimestamp, const client_cache_t& uncacheBuffer, bool hasListenerCallbacks,
        const std::vector<ListenerCallbacks>& listenerCallbacks, uint64_t transactionId) {
    ATRACE_CALL();

    uint32_t permissions =
        callingThreadHasUnscopedSurfaceFlingerAccess() ?
        layer_state_t::Permission::ACCESS_SURFACE_FLINGER : 0;
    // Avoid checking for rotation permissions if the caller already has ACCESS_SURFACE_FLINGER
    // permissions.
    if ((permissions & layer_state_t::Permission::ACCESS_SURFACE_FLINGER) ||
        callingThreadHasRotateSurfaceFlingerAccess()) {
        permissions |= layer_state_t::Permission::ROTATE_SURFACE_FLINGER;
    }

    if (callingThreadHasInternalSystemWindowAccess()) {
        permissions |= layer_state_t::Permission::INTERNAL_SYSTEM_WINDOW;
    }

    if (!(permissions & layer_state_t::Permission::ACCESS_SURFACE_FLINGER) &&
        (flags & (eEarlyWakeupStart | eEarlyWakeupEnd))) {
        ALOGE("Only WindowManager is allowed to use eEarlyWakeup[Start|End] flags");
        flags &= ~(eEarlyWakeupStart | eEarlyWakeupEnd);
    }

    const int64_t postTime = systemTime();

    IPCThreadState* ipc = IPCThreadState::self();
    const int originPid = ipc->getCallingPid();
    const int originUid = ipc->getCallingUid();
    TransactionState state{frameTimelineInfo,  states,
                           displays,           flags,
                           applyToken,         inputWindowCommands,
                           desiredPresentTime, isAutoTimestamp,
                           uncacheBuffer,      postTime,
                           permissions,        hasListenerCallbacks,
                           listenerCallbacks,  originPid,
                           originUid,          transactionId};

    // Check for incoming buffer updates and increment the pending buffer count.
    state.traverseStatesWithBuffers([&](const layer_state_t& state) {
        mBufferCountTracker.increment(state.surface->localBinder());
    });

    if (mTransactionTracing) {
        mTransactionTracing->addQueuedTransaction(state);
    }
    queueTransaction(state);

    // Check the pending state to make sure the transaction is synchronous.
    if (state.transactionCommittedSignal) {
        waitForSynchronousTransaction(*state.transactionCommittedSignal);
    }

    return NO_ERROR;
}

bool SurfaceFlinger::applyTransactionState(const FrameTimelineInfo& frameTimelineInfo,
                                           Vector<ComposerState>& states,
                                           Vector<DisplayState>& displays, uint32_t flags,
                                           const InputWindowCommands& inputWindowCommands,
                                           const int64_t desiredPresentTime, bool isAutoTimestamp,
                                           const client_cache_t& uncacheBuffer,
                                           const int64_t postTime, uint32_t permissions,
                                           bool hasListenerCallbacks,
                                           const std::vector<ListenerCallbacks>& listenerCallbacks,
                                           int originPid, int originUid, uint64_t transactionId) {
    uint32_t transactionFlags = 0;
    for (DisplayState& display : displays) {
        display.sanitize(permissions);
        transactionFlags |= setDisplayStateLocked(display);
    }

    // start and end registration for listeners w/ no surface so they can get their callback.  Note
    // that listeners with SurfaceControls will start registration during setClientStateLocked
    // below.
    for (const auto& listener : listenerCallbacks) {
        mTransactionCallbackInvoker.addEmptyTransaction(listener);
    }

    uint32_t clientStateFlags = 0;
    for (int i = 0; i < states.size(); i++) {
        ComposerState& state = states.editItemAt(i);
        clientStateFlags |= setClientStateLocked(frameTimelineInfo, state, desiredPresentTime,
                                                 isAutoTimestamp, postTime, permissions);
        if ((flags & eAnimation) && state.state.surface) {
            if (const auto layer = fromHandle(state.state.surface).promote()) {
                using LayerUpdateType = scheduler::LayerHistory::LayerUpdateType;
                mScheduler->recordLayerHistory(layer.get(),
                                               isAutoTimestamp ? 0 : desiredPresentTime,
                                               LayerUpdateType::AnimationTX);
            }
        }
    }

    transactionFlags |= clientStateFlags;

    if (permissions & layer_state_t::Permission::ACCESS_SURFACE_FLINGER) {
        transactionFlags |= addInputWindowCommands(inputWindowCommands);
    } else if (!inputWindowCommands.empty()) {
        ALOGE("Only privileged callers are allowed to send input commands.");
    }

    if (uncacheBuffer.isValid()) {
        ClientCache::getInstance().erase(uncacheBuffer);
    }

    // If a synchronous transaction is explicitly requested without any changes, force a transaction
    // anyway. This can be used as a flush mechanism for previous async transactions.
    // Empty animation transaction can be used to simulate back-pressure, so also force a
    // transaction for empty animation transactions.
    if (transactionFlags == 0 &&
            ((flags & eSynchronous) || (flags & eAnimation))) {
        transactionFlags = eTransactionNeeded;
    }

    bool needsTraversal = false;
    if (transactionFlags) {
        if (mInterceptor->isEnabled()) {
            mInterceptor->saveTransaction(states, mCurrentState.displays, displays, flags,
                                          originPid, originUid, transactionId);
        }

        // We are on the main thread, we are about to preform a traversal. Clear the traversal bit
        // so we don't have to wake up again next frame to preform an unnecessary traversal.
        if (transactionFlags & eTraversalNeeded) {
            transactionFlags = transactionFlags & (~eTraversalNeeded);
            needsTraversal = true;
        }
        if (transactionFlags) {
            setTransactionFlags(transactionFlags);
        }

        if (flags & eAnimation) {
            mAnimTransactionPending = true;
        }
    }

    return needsTraversal;
}

uint32_t SurfaceFlinger::setDisplayStateLocked(const DisplayState& s) {
    const ssize_t index = mCurrentState.displays.indexOfKey(s.token);
    if (index < 0) return 0;

    uint32_t flags = 0;
    DisplayDeviceState& state = mCurrentState.displays.editValueAt(index);

    const uint32_t what = s.what;
    if (what & DisplayState::eSurfaceChanged) {
        if (IInterface::asBinder(state.surface) != IInterface::asBinder(s.surface)) {
            state.surface = s.surface;
            flags |= eDisplayTransactionNeeded;
        }
    }
    if (what & DisplayState::eLayerStackChanged) {
        if (state.layerStack != s.layerStack) {
            state.layerStack = s.layerStack;
            flags |= eDisplayTransactionNeeded;
        }
    }
    if (what & DisplayState::eFlagsChanged) {
        if (state.flags != s.flags) {
            state.flags = s.flags;
            flags |= eDisplayTransactionNeeded;
        }
    }
    if (what & DisplayState::eDisplayProjectionChanged) {
        if (state.orientation != s.orientation) {
            state.orientation = s.orientation;
            flags |= eDisplayTransactionNeeded;
        }
        if (state.orientedDisplaySpaceRect != s.orientedDisplaySpaceRect) {
            state.orientedDisplaySpaceRect = s.orientedDisplaySpaceRect;
            flags |= eDisplayTransactionNeeded;
        }
        if (state.layerStackSpaceRect != s.layerStackSpaceRect) {
            state.layerStackSpaceRect = s.layerStackSpaceRect;
            flags |= eDisplayTransactionNeeded;
        }
    }
    if (what & DisplayState::eDisplaySizeChanged) {
        if (state.width != s.width) {
            state.width = s.width;
            flags |= eDisplayTransactionNeeded;
        }
        if (state.height != s.height) {
            state.height = s.height;
            flags |= eDisplayTransactionNeeded;
        }
    }

    return flags;
}

bool SurfaceFlinger::callingThreadHasUnscopedSurfaceFlingerAccess(bool usePermissionCache) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if ((uid != AID_GRAPHICS && uid != AID_SYSTEM) &&
        (usePermissionCache ? !PermissionCache::checkPermission(sAccessSurfaceFlinger, pid, uid)
                            : !checkPermission(sAccessSurfaceFlinger, pid, uid))) {
        return false;
    }
    return true;
}

uint32_t SurfaceFlinger::setClientStateLocked(const FrameTimelineInfo& frameTimelineInfo,
                                              ComposerState& composerState,
                                              int64_t desiredPresentTime, bool isAutoTimestamp,
                                              int64_t postTime, uint32_t permissions) {
    layer_state_t& s = composerState.state;
    s.sanitize(permissions);

    std::vector<ListenerCallbacks> filteredListeners;
    for (auto& listener : s.listeners) {
        // Starts a registration but separates the callback ids according to callback type. This
        // allows the callback invoker to send on latch callbacks earlier.
        // note that startRegistration will not re-register if the listener has
        // already be registered for a prior surface control

        ListenerCallbacks onCommitCallbacks = listener.filter(CallbackId::Type::ON_COMMIT);
        if (!onCommitCallbacks.callbackIds.empty()) {
            filteredListeners.push_back(onCommitCallbacks);
        }

        ListenerCallbacks onCompleteCallbacks = listener.filter(CallbackId::Type::ON_COMPLETE);
        if (!onCompleteCallbacks.callbackIds.empty()) {
            filteredListeners.push_back(onCompleteCallbacks);
        }
    }

    const uint64_t what = s.what;
    uint32_t flags = 0;
    sp<Layer> layer = nullptr;
    if (s.surface) {
        layer = fromHandle(s.surface).promote();
    } else {
        // The client may provide us a null handle. Treat it as if the layer was removed.
        ALOGW("Attempt to set client state with a null layer handle");
    }
    if (layer == nullptr) {
        for (auto& [listener, callbackIds] : s.listeners) {
            mTransactionCallbackInvoker.registerUnpresentedCallbackHandle(
                    new CallbackHandle(listener, callbackIds, s.surface));
        }
        return 0;
    }
    MUTEX_ALIAS(mStateLock, layer->mFlinger->mStateLock);

    // Only set by BLAST adapter layers
    if (what & layer_state_t::eProducerDisconnect) {
        layer->onDisconnect();
    }

    if (what & layer_state_t::ePositionChanged) {
        if (layer->setPosition(s.x, s.y)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eLayerChanged) {
        // NOTE: index needs to be calculated before we update the state
        const auto& p = layer->getParent();
        if (p == nullptr) {
            ssize_t idx = mCurrentState.layersSortedByZ.indexOf(layer);
            if (layer->setLayer(s.z) && idx >= 0) {
                mCurrentState.layersSortedByZ.removeAt(idx);
                mCurrentState.layersSortedByZ.add(layer);
                // we need traversal (state changed)
                // AND transaction (list changed)
                flags |= eTransactionNeeded|eTraversalNeeded;
            }
        } else {
            if (p->setChildLayer(layer, s.z)) {
                flags |= eTransactionNeeded|eTraversalNeeded;
            }
        }
    }
    if (what & layer_state_t::eRelativeLayerChanged) {
        // NOTE: index needs to be calculated before we update the state
        const auto& p = layer->getParent();
        const auto& relativeHandle = s.relativeLayerSurfaceControl ?
                s.relativeLayerSurfaceControl->getHandle() : nullptr;
        if (p == nullptr) {
            ssize_t idx = mCurrentState.layersSortedByZ.indexOf(layer);
            if (layer->setRelativeLayer(relativeHandle, s.z) &&
                idx >= 0) {
                mCurrentState.layersSortedByZ.removeAt(idx);
                mCurrentState.layersSortedByZ.add(layer);
                // we need traversal (state changed)
                // AND transaction (list changed)
                flags |= eTransactionNeeded|eTraversalNeeded;
            }
        } else {
            if (p->setChildRelativeLayer(layer, relativeHandle, s.z)) {
                flags |= eTransactionNeeded|eTraversalNeeded;
            }
        }
    }
    if (what & layer_state_t::eSizeChanged) {
        if (layer->setSize(s.w, s.h)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eAlphaChanged) {
        if (layer->setAlpha(s.alpha))
            flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eColorChanged) {
        if (layer->setColor(s.color))
            flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eColorTransformChanged) {
        if (layer->setColorTransform(s.colorTransform)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eBackgroundColorChanged) {
        if (layer->setBackgroundColor(s.color, s.bgColorAlpha, s.bgColorDataspace)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eMatrixChanged) {
        if (layer->setMatrix(s.matrix)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eTransparentRegionChanged) {
        if (layer->setTransparentRegionHint(s.transparentRegion))
            flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eFlagsChanged) {
        if (layer->setFlags(s.flags, s.mask)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eCornerRadiusChanged) {
        if (layer->setCornerRadius(s.cornerRadius))
            flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eBackgroundBlurRadiusChanged && mSupportsBlur) {
        if (layer->setBackgroundBlurRadius(s.backgroundBlurRadius)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eBlurRegionsChanged) {
        if (layer->setBlurRegions(s.blurRegions)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eLayerStackChanged) {
        ssize_t idx = mCurrentState.layersSortedByZ.indexOf(layer);
        // We only allow setting layer stacks for top level layers,
        // everything else inherits layer stack from its parent.
        if (layer->hasParent()) {
            ALOGE("Attempt to set layer stack on layer with parent (%s) is invalid",
                  layer->getDebugName());
        } else if (idx < 0) {
            ALOGE("Attempt to set layer stack on layer without parent (%s) that "
                  "that also does not appear in the top level layer list. Something"
                  " has gone wrong.",
                  layer->getDebugName());
        } else if (layer->setLayerStack(s.layerStack)) {
            mCurrentState.layersSortedByZ.removeAt(idx);
            mCurrentState.layersSortedByZ.add(layer);
            // we need traversal (state changed)
            // AND transaction (list changed)
            flags |= eTransactionNeeded | eTraversalNeeded | eTransformHintUpdateNeeded;
        }
    }
    if (what & layer_state_t::eTransformChanged) {
        if (layer->setTransform(s.transform)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eTransformToDisplayInverseChanged) {
        if (layer->setTransformToDisplayInverse(s.transformToDisplayInverse))
            flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eCropChanged) {
        if (layer->setCrop(s.crop)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eDataspaceChanged) {
        if (layer->setDataspace(s.dataspace)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eHdrMetadataChanged) {
        if (layer->setHdrMetadata(s.hdrMetadata)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eSurfaceDamageRegionChanged) {
        if (layer->setSurfaceDamageRegion(s.surfaceDamageRegion)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eApiChanged) {
        if (layer->setApi(s.api)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eSidebandStreamChanged) {
        if (layer->setSidebandStream(s.sidebandStream)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eInputInfoChanged) {
        layer->setInputInfo(*s.windowInfoHandle->getInfo());
        flags |= eTraversalNeeded;
    }
    std::optional<nsecs_t> dequeueBufferTimestamp;
    if (what & layer_state_t::eMetadataChanged) {
        dequeueBufferTimestamp = s.metadata.getInt64(METADATA_DEQUEUE_TIME);

        if (const int32_t gameMode = s.metadata.getInt32(METADATA_GAME_MODE, -1); gameMode != -1) {
            // The transaction will be received on the Task layer and needs to be applied to all
            // child layers. Child layers that are added at a later point will obtain the game mode
            // info through addChild().
            layer->setGameModeForTree(static_cast<GameMode>(gameMode));
        }

        if (layer->setMetadata(s.metadata)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eColorSpaceAgnosticChanged) {
        if (layer->setColorSpaceAgnostic(s.colorSpaceAgnostic)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eShadowRadiusChanged) {
        if (layer->setShadowRadius(s.shadowRadius)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eFrameRateSelectionPriority) {
        if (layer->setFrameRateSelectionPriority(s.frameRateSelectionPriority)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eFrameRateChanged) {
        const auto compatibility =
            Layer::FrameRate::convertCompatibility(s.frameRateCompatibility);
        const auto strategy =
            Layer::FrameRate::convertChangeFrameRateStrategy(s.changeFrameRateStrategy);

        if (layer->setFrameRate(
                Layer::FrameRate(Fps::fromValue(s.frameRate), compatibility, strategy))) {
          flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eFixedTransformHintChanged) {
        if (layer->setFixedTransformHint(s.fixedTransformHint)) {
            flags |= eTraversalNeeded | eTransformHintUpdateNeeded;
        }
    }
    if (what & layer_state_t::eAutoRefreshChanged) {
        layer->setAutoRefresh(s.autoRefresh);
    }
    if (what & layer_state_t::eDimmingEnabledChanged) {
        if (layer->setDimmingEnabled(s.dimmingEnabled)) flags |= eTraversalNeeded;
    }
    if (what & layer_state_t::eTrustedOverlayChanged) {
        if (layer->setTrustedOverlay(s.isTrustedOverlay)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eStretchChanged) {
        if (layer->setStretchEffect(s.stretchEffect)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eBufferCropChanged) {
        if (layer->setBufferCrop(s.bufferCrop)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eDestinationFrameChanged) {
        if (layer->setDestinationFrame(s.destinationFrame)) {
            flags |= eTraversalNeeded;
        }
    }
    if (what & layer_state_t::eDropInputModeChanged) {
        if (layer->setDropInputMode(s.dropInputMode)) {
            flags |= eTraversalNeeded;
            mInputInfoChanged = true;
        }
    }
    // This has to happen after we reparent children because when we reparent to null we remove
    // child layers from current state and remove its relative z. If the children are reparented in
    // the same transaction, then we have to make sure we reparent the children first so we do not
    // lose its relative z order.
    if (what & layer_state_t::eReparent) {
        bool hadParent = layer->hasParent();
        auto parentHandle = (s.parentSurfaceControlForChild)
                ? s.parentSurfaceControlForChild->getHandle()
                : nullptr;
        if (layer->reparent(parentHandle)) {
            if (!hadParent) {
                layer->setIsAtRoot(false);
                mCurrentState.layersSortedByZ.remove(layer);
            }
            flags |= eTransactionNeeded | eTraversalNeeded;
        }
    }
    std::vector<sp<CallbackHandle>> callbackHandles;
    if ((what & layer_state_t::eHasListenerCallbacksChanged) && (!filteredListeners.empty())) {
        for (auto& [listener, callbackIds] : filteredListeners) {
            callbackHandles.emplace_back(new CallbackHandle(listener, callbackIds, s.surface));
        }
    }

    if (what & layer_state_t::eBufferChanged) {
        std::shared_ptr<renderengine::ExternalTexture> buffer =
                getExternalTextureFromBufferData(*s.bufferData, layer->getDebugName());
        if (layer->setBuffer(buffer, *s.bufferData, postTime, desiredPresentTime, isAutoTimestamp,
                             dequeueBufferTimestamp, frameTimelineInfo)) {
            flags |= eTraversalNeeded;
        }
    } else if (frameTimelineInfo.vsyncId != FrameTimelineInfo::INVALID_VSYNC_ID) {
        layer->setFrameTimelineVsyncForBufferlessTransaction(frameTimelineInfo, postTime);
    }

    if (layer->setTransactionCompletedListeners(callbackHandles)) flags |= eTraversalNeeded;
    // Do not put anything that updates layer state or modifies flags after
    // setTransactionCompletedListener
    return flags;
}

uint32_t SurfaceFlinger::addInputWindowCommands(const InputWindowCommands& inputWindowCommands) {
    bool hasChanges = mInputWindowCommands.merge(inputWindowCommands);
    return hasChanges ? eTraversalNeeded : 0;
}

status_t SurfaceFlinger::mirrorLayer(const LayerCreationArgs& args,
                                     const sp<IBinder>& mirrorFromHandle, sp<IBinder>* outHandle,
                                     int32_t* outLayerId) {
    if (!mirrorFromHandle) {
        return NAME_NOT_FOUND;
    }

    sp<Layer> mirrorLayer;
    sp<Layer> mirrorFrom;
    {
        Mutex::Autolock _l(mStateLock);
        mirrorFrom = fromHandle(mirrorFromHandle).promote();
        if (!mirrorFrom) {
            return NAME_NOT_FOUND;
        }
        status_t result = createContainerLayer(args, outHandle, &mirrorLayer);
        if (result != NO_ERROR) {
            return result;
        }

        mirrorLayer->setClonedChild(mirrorFrom->createClone());
    }

    *outLayerId = mirrorLayer->sequence;
    if (mTransactionTracing) {
        mTransactionTracing->onMirrorLayerAdded((*outHandle)->localBinder(), mirrorLayer->sequence,
                                                args.name, mirrorFrom->sequence);
    }
    return addClientLayer(args.client, *outHandle, mirrorLayer /* layer */, nullptr /* parent */,
                          false /* addToRoot */, nullptr /* outTransformHint */);
}

status_t SurfaceFlinger::createLayer(LayerCreationArgs& args, sp<IBinder>* outHandle,
                                     const sp<IBinder>& parentHandle, int32_t* outLayerId,
                                     const sp<Layer>& parentLayer, uint32_t* outTransformHint) {
    ALOG_ASSERT(parentLayer == nullptr || parentHandle == nullptr,
            "Expected only one of parentLayer or parentHandle to be non-null. "
            "Programmer error?");

    status_t result = NO_ERROR;

    sp<Layer> layer;

    switch (args.flags & ISurfaceComposerClient::eFXSurfaceMask) {
        case ISurfaceComposerClient::eFXSurfaceBufferQueue:
        case ISurfaceComposerClient::eFXSurfaceBufferState: {
            result = createBufferStateLayer(args, outHandle, &layer);
            std::atomic<int32_t>* pendingBufferCounter = layer->getPendingBufferCounter();
            if (pendingBufferCounter) {
                std::string counterName = layer->getPendingBufferCounterName();
                mBufferCountTracker.add((*outHandle)->localBinder(), counterName,
                                        pendingBufferCounter);
            }
        } break;
        case ISurfaceComposerClient::eFXSurfaceEffect:
            result = createEffectLayer(args, outHandle, &layer);
            break;
        case ISurfaceComposerClient::eFXSurfaceContainer:
            result = createContainerLayer(args, outHandle, &layer);
            break;
        default:
            result = BAD_VALUE;
            break;
    }

    if (result != NO_ERROR) {
        return result;
    }

    bool addToRoot = args.addToRoot && callingThreadHasUnscopedSurfaceFlingerAccess();
    wp<Layer> parent(parentHandle != nullptr ? fromHandle(parentHandle) : parentLayer);
    if (parentHandle != nullptr && parent == nullptr) {
        ALOGE("Invalid parent handle %p.", parentHandle.get());
        addToRoot = false;
    }
    if (parentLayer != nullptr) {
        addToRoot = false;
    }

    int parentId = -1;
    // We can safely promote the layer in binder thread because we have a strong reference
    // to the layer's handle inside this scope or we were passed in a sp reference to the layer.
    sp<Layer> parentSp = parent.promote();
    if (parentSp != nullptr) {
        parentId = parentSp->getSequence();
    }
    if (mTransactionTracing) {
        mTransactionTracing->onLayerAdded((*outHandle)->localBinder(), layer->sequence, args.name,
                                          args.flags, parentId);
    }

    result = addClientLayer(args.client, *outHandle, layer, parent, addToRoot, outTransformHint);
    if (result != NO_ERROR) {
        return result;
    }

    *outLayerId = layer->sequence;
    return result;
}

status_t SurfaceFlinger::createBufferQueueLayer(LayerCreationArgs& args, PixelFormat& format,
                                                sp<IBinder>* handle,
                                                sp<IGraphicBufferProducer>* gbp,
                                                sp<Layer>* outLayer) {
    // initialize the surfaces
    switch (format) {
    case PIXEL_FORMAT_TRANSPARENT:
    case PIXEL_FORMAT_TRANSLUCENT:
        format = PIXEL_FORMAT_RGBA_8888;
        break;
    case PIXEL_FORMAT_OPAQUE:
        format = PIXEL_FORMAT_RGBX_8888;
        break;
    }

    sp<BufferQueueLayer> layer;
    args.textureName = getNewTexture();
    {
        // Grab the SF state lock during this since it's the only safe way to access
        // RenderEngine when creating a BufferLayerConsumer
        // TODO: Check if this lock is still needed here
        Mutex::Autolock lock(mStateLock);
        layer = getFactory().createBufferQueueLayer(args);
    }

    status_t err = layer->setDefaultBufferProperties(0, 0, format);
    if (err == NO_ERROR) {
        *handle = layer->getHandle();
        *gbp = layer->getProducer();
        *outLayer = layer;
    }

    ALOGE_IF(err, "createBufferQueueLayer() failed (%s)", strerror(-err));
    return err;
}

status_t SurfaceFlinger::createBufferStateLayer(LayerCreationArgs& args, sp<IBinder>* handle,
                                                sp<Layer>* outLayer) {
    args.textureName = getNewTexture();
    *outLayer = getFactory().createBufferStateLayer(args);
    *handle = (*outLayer)->getHandle();
    return NO_ERROR;
}

status_t SurfaceFlinger::createEffectLayer(const LayerCreationArgs& args, sp<IBinder>* handle,
                                           sp<Layer>* outLayer) {
    *outLayer = getFactory().createEffectLayer(args);
    *handle = (*outLayer)->getHandle();
    return NO_ERROR;
}

status_t SurfaceFlinger::createContainerLayer(const LayerCreationArgs& args, sp<IBinder>* handle,
                                              sp<Layer>* outLayer) {
    *outLayer = getFactory().createContainerLayer(args);
    *handle = (*outLayer)->getHandle();
    return NO_ERROR;
}

void SurfaceFlinger::markLayerPendingRemovalLocked(const sp<Layer>& layer) {
    mLayersPendingRemoval.add(layer);
    mLayersRemoved = true;
    setTransactionFlags(eTransactionNeeded);
}

void SurfaceFlinger::onHandleDestroyed(BBinder* handle, sp<Layer>& layer) {
    Mutex::Autolock lock(mStateLock);
    markLayerPendingRemovalLocked(layer);
    mBufferCountTracker.remove(handle);
    layer.clear();
    if (mTransactionTracing) {
        mTransactionTracing->onHandleRemoved(handle);
    }
}

// ---------------------------------------------------------------------------

void SurfaceFlinger::onInitializeDisplays() {
    const auto display = getDefaultDisplayDeviceLocked();
    if (!display) return;

    const sp<IBinder> token = display->getDisplayToken().promote();
    LOG_ALWAYS_FATAL_IF(token == nullptr);

    // reset screen orientation and use primary layer stack
    Vector<ComposerState> state;
    Vector<DisplayState> displays;
    DisplayState d;
    d.what = DisplayState::eDisplayProjectionChanged |
             DisplayState::eLayerStackChanged;
    d.token = token;
    d.layerStack = ui::DEFAULT_LAYER_STACK;
    d.orientation = ui::ROTATION_0;
    d.orientedDisplaySpaceRect.makeInvalid();
    d.layerStackSpaceRect.makeInvalid();
    d.width = 0;
    d.height = 0;
    displays.add(d);

    nsecs_t now = systemTime();

    int64_t transactionId = (((int64_t)mPid) << 32) | mUniqueTransactionId++;
    // It should be on the main thread, apply it directly.
    applyTransactionState(FrameTimelineInfo{}, state, displays, 0, mInputWindowCommands,
                          /* desiredPresentTime */ now, true, {}, /* postTime */ now, true, false,
                          {}, mPid, getuid(), transactionId);

    setPowerModeInternal(display, hal::PowerMode::ON);
    const nsecs_t vsyncPeriod = display->refreshRateConfigs().getActiveMode()->getVsyncPeriod();
    mAnimFrameTracker.setDisplayRefreshPeriod(vsyncPeriod);
    mActiveDisplayTransformHint = display->getTransformHint();
    // Use phase of 0 since phase is not known.
    // Use latency of 0, which will snap to the ideal latency.
    DisplayStatInfo stats{0 /* vsyncTime */, vsyncPeriod};
    setCompositorTimingSnapped(stats, 0);
}

void SurfaceFlinger::initializeDisplays() {
    // Async since we may be called from the main thread.
    static_cast<void>(
            mScheduler->schedule([this]() FTL_FAKE_GUARD(mStateLock) { onInitializeDisplays(); }));
}

void SurfaceFlinger::setPowerModeInternal(const sp<DisplayDevice>& display, hal::PowerMode mode) {
    if (display->isVirtual()) {
        ALOGE("%s: Invalid operation on virtual display", __func__);
        return;
    }

    const auto displayId = display->getPhysicalId();
    ALOGD("Setting power mode %d on display %s", mode, to_string(displayId).c_str());

    std::optional<hal::PowerMode> currentMode = display->getPowerMode();
    if (currentMode.has_value() && mode == *currentMode) {
        return;
    }

    const auto activeDisplay = getDisplayDeviceLocked(mActiveDisplayToken);
    if (activeDisplay != display && display->isInternal() && activeDisplay &&
        activeDisplay->isPoweredOn()) {
        ALOGW("Trying to change power mode on non active display while the active display is ON");
    }

    display->setPowerMode(mode);

    if (mInterceptor->isEnabled()) {
        mInterceptor->savePowerModeUpdate(display->getSequenceId(), static_cast<int32_t>(mode));
    }
    const auto refreshRate = display->refreshRateConfigs().getActiveMode()->getFps();
    if (!currentMode || *currentMode == hal::PowerMode::OFF) {
        // Turn on the display
        if (display->isInternal() && (!activeDisplay || !activeDisplay->isPoweredOn())) {
            onActiveDisplayChangedLocked(display);
        }
        // Keep uclamp in a separate syscall and set it before changing to RT due to b/190237315.
        // We can merge the syscall later.
        if (SurfaceFlinger::setSchedAttr(true) != NO_ERROR) {
            ALOGW("Couldn't set uclamp.min on display on: %s\n", strerror(errno));
        }
        if (SurfaceFlinger::setSchedFifo(true) != NO_ERROR) {
            ALOGW("Couldn't set SCHED_FIFO on display on: %s\n", strerror(errno));
        }
        getHwComposer().setPowerMode(displayId, mode);
        if (isDisplayActiveLocked(display) && mode != hal::PowerMode::DOZE_SUSPEND) {
            setHWCVsyncEnabled(displayId, mHWCVsyncPendingState);
            mScheduler->onScreenAcquired(mAppConnectionHandle);
            mScheduler->resyncToHardwareVsync(true, refreshRate);
        }

        mVisibleRegionsDirty = true;
        mHasPoweredOff = true;
        scheduleComposite(FrameHint::kActive);
    } else if (mode == hal::PowerMode::OFF) {
        // Turn off the display
        if (SurfaceFlinger::setSchedFifo(false) != NO_ERROR) {
            ALOGW("Couldn't set SCHED_OTHER on display off: %s\n", strerror(errno));
        }
        if (SurfaceFlinger::setSchedAttr(false) != NO_ERROR) {
            ALOGW("Couldn't set uclamp.min on display off: %s\n", strerror(errno));
        }
        if (isDisplayActiveLocked(display) && *currentMode != hal::PowerMode::DOZE_SUSPEND) {
            mScheduler->disableHardwareVsync(true);
            mScheduler->onScreenReleased(mAppConnectionHandle);
        }

        // Make sure HWVsync is disabled before turning off the display
        setHWCVsyncEnabled(displayId, hal::Vsync::DISABLE);

        getHwComposer().setPowerMode(displayId, mode);
        mVisibleRegionsDirty = true;
        // from this point on, SF will stop drawing on this display
    } else if (mode == hal::PowerMode::DOZE || mode == hal::PowerMode::ON) {
        // Update display while dozing
        getHwComposer().setPowerMode(displayId, mode);
        if (isDisplayActiveLocked(display) && *currentMode == hal::PowerMode::DOZE_SUSPEND) {
            mScheduler->onScreenAcquired(mAppConnectionHandle);
            mScheduler->resyncToHardwareVsync(true, refreshRate);
        }
    } else if (mode == hal::PowerMode::DOZE_SUSPEND) {
        // Leave display going to doze
        if (isDisplayActiveLocked(display)) {
            mScheduler->disableHardwareVsync(true);
            mScheduler->onScreenReleased(mAppConnectionHandle);
        }
        getHwComposer().setPowerMode(displayId, mode);
    } else {
        ALOGE("Attempting to set unknown power mode: %d\n", mode);
        getHwComposer().setPowerMode(displayId, mode);
    }

    if (isDisplayActiveLocked(display)) {
        mTimeStats->setPowerMode(mode);
        mRefreshRateStats->setPowerMode(mode);
        mScheduler->setDisplayPowerMode(mode);
    }

    ALOGD("Finished setting power mode %d on display %s", mode, to_string(displayId).c_str());
}

void SurfaceFlinger::setPowerMode(const sp<IBinder>& displayToken, int mode) {
    auto future = mScheduler->schedule([=]() FTL_FAKE_GUARD(mStateLock) {
        const auto display = getDisplayDeviceLocked(displayToken);
        if (!display) {
            ALOGE("Attempt to set power mode %d for invalid display token %p", mode,
                  displayToken.get());
        } else if (display->isVirtual()) {
            ALOGW("Attempt to set power mode %d for virtual display", mode);
        } else {
            setPowerModeInternal(display, static_cast<hal::PowerMode>(mode));
        }
    });

    future.wait();
}

status_t SurfaceFlinger::doDump(int fd, const DumpArgs& args, bool asProto) {
    std::string result;

    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();

    if ((uid != AID_SHELL) &&
            !PermissionCache::checkPermission(sDump, pid, uid)) {
        StringAppendF(&result, "Permission Denial: can't dump SurfaceFlinger from pid=%d, uid=%d\n",
                      pid, uid);
    } else {
        static const std::unordered_map<std::string, Dumper> dumpers = {
                {"--comp-displays"s, dumper(&SurfaceFlinger::dumpCompositionDisplays)},
                {"--display-id"s, dumper(&SurfaceFlinger::dumpDisplayIdentificationData)},
                {"--displays"s, dumper(&SurfaceFlinger::dumpDisplays)},
                {"--dispsync"s, dumper([this](std::string& s) { mScheduler->dumpVsync(s); })},
                {"--edid"s, argsDumper(&SurfaceFlinger::dumpRawDisplayIdentificationData)},
                {"--latency"s, argsDumper(&SurfaceFlinger::dumpStatsLocked)},
                {"--latency-clear"s, argsDumper(&SurfaceFlinger::clearStatsLocked)},
                {"--list"s, dumper(&SurfaceFlinger::listLayersLocked)},
                {"--planner"s, argsDumper(&SurfaceFlinger::dumpPlannerInfo)},
                {"--static-screen"s, dumper(&SurfaceFlinger::dumpStaticScreenStats)},
                {"--timestats"s, protoDumper(&SurfaceFlinger::dumpTimeStats)},
                {"--vsync"s, dumper(&SurfaceFlinger::dumpVSync)},
                {"--wide-color"s, dumper(&SurfaceFlinger::dumpWideColorInfo)},
                {"--frametimeline"s, argsDumper(&SurfaceFlinger::dumpFrameTimeline)},
        };

        const auto flag = args.empty() ? ""s : std::string(String8(args[0]));

        // Traversal of drawing state must happen on the main thread.
        // Otherwise, SortedVector may have shared ownership during concurrent
        // traversals, which can result in use-after-frees.
        std::string compositionLayers;
        mScheduler
                ->schedule([&] {
                    StringAppendF(&compositionLayers, "Composition layers\n");
                    mDrawingState.traverseInZOrder([&](Layer* layer) {
                        auto* compositionState = layer->getCompositionState();
                        if (!compositionState || !compositionState->isVisible) return;

                        android::base::StringAppendF(&compositionLayers, "* Layer %p (%s)\n", layer,
                                                     layer->getDebugName() ? layer->getDebugName()
                                                                           : "<unknown>");
                        compositionState->dump(compositionLayers);
                    });
                })
                .get();

        bool dumpLayers = true;
        {
            TimedLock lock(mStateLock, s2ns(1), __func__);
            if (!lock.locked()) {
                StringAppendF(&result, "Dumping without lock after timeout: %s (%d)\n",
                              strerror(-lock.status), lock.status);
            }

            if (const auto it = dumpers.find(flag); it != dumpers.end()) {
                (it->second)(args, asProto, result);
                dumpLayers = false;
            } else if (!asProto) {
                dumpAllLocked(args, compositionLayers, result);
            }
        }

        if (dumpLayers) {
            LayersTraceFileProto traceFileProto = mLayerTracing.createTraceFileProto();
            LayersTraceProto* layersTrace = traceFileProto.add_entry();
            LayersProto layersProto = dumpProtoFromMainThread();
            layersTrace->mutable_layers()->Swap(&layersProto);
            dumpDisplayProto(*layersTrace);

            if (asProto) {
                result.append(traceFileProto.SerializeAsString());
            } else {
                // Dump info that we need to access from the main thread
                const auto layerTree = LayerProtoParser::generateLayerTree(layersTrace->layers());
                result.append(LayerProtoParser::layerTreeToString(layerTree));
                result.append("\n");
                dumpOffscreenLayers(result);
            }
        }
    }
    write(fd, result.c_str(), result.size());
    return NO_ERROR;
}

status_t SurfaceFlinger::dumpCritical(int fd, const DumpArgs&, bool asProto) {
    if (asProto) {
        mLayerTracing.writeToFile();
        if (mTransactionTracing) {
            mTransactionTracing->writeToFile();
        }
    }

    return doDump(fd, DumpArgs(), asProto);
}

void SurfaceFlinger::listLayersLocked(std::string& result) const {
    mCurrentState.traverseInZOrder(
            [&](Layer* layer) { StringAppendF(&result, "%s\n", layer->getDebugName()); });
}

void SurfaceFlinger::dumpStatsLocked(const DumpArgs& args, std::string& result) const {
    StringAppendF(&result, "%" PRId64 "\n", getVsyncPeriodFromHWC());

    if (args.size() > 1) {
        const auto name = String8(args[1]);
        mCurrentState.traverseInZOrder([&](Layer* layer) {
            if (layer->getName() == name.string()) {
                layer->dumpFrameStats(result);
            }
        });
    } else {
        mAnimFrameTracker.dumpStats(result);
    }
}

void SurfaceFlinger::clearStatsLocked(const DumpArgs& args, std::string&) {
    const bool clearAll = args.size() < 2;
    const auto name = clearAll ? String8() : String8(args[1]);

    mCurrentState.traverse([&](Layer* layer) {
        if (clearAll || layer->getName() == name.string()) {
            layer->clearFrameStats();
        }
    });

    mAnimFrameTracker.clearStats();
}

void SurfaceFlinger::dumpTimeStats(const DumpArgs& args, bool asProto, std::string& result) const {
    mTimeStats->parseArgs(asProto, args, result);
}

void SurfaceFlinger::dumpFrameTimeline(const DumpArgs& args, std::string& result) const {
    mFrameTimeline->parseArgs(args, result);
}

void SurfaceFlinger::logFrameStats() {
    mDrawingState.traverse([&](Layer* layer) {
        layer->logFrameStats();
    });

    mAnimFrameTracker.logAndResetStats("<win-anim>");
}

void SurfaceFlinger::appendSfConfigString(std::string& result) const {
    result.append(" [sf");

    StringAppendF(&result, " PRESENT_TIME_OFFSET=%" PRId64, dispSyncPresentTimeOffset);
    StringAppendF(&result, " FORCE_HWC_FOR_RBG_TO_YUV=%d", useHwcForRgbToYuv);
    StringAppendF(&result, " MAX_VIRT_DISPLAY_DIM=%zu",
                  getHwComposer().getMaxVirtualDisplayDimension());
    StringAppendF(&result, " RUNNING_WITHOUT_SYNC_FRAMEWORK=%d", !hasSyncFramework);
    StringAppendF(&result, " NUM_FRAMEBUFFER_SURFACE_BUFFERS=%" PRId64,
                  maxFrameBufferAcquiredBuffers);
    result.append("]");
}

void SurfaceFlinger::dumpVSync(std::string& result) const {
    mScheduler->dump(result);

    mRefreshRateStats->dump(result);
    result.append("\n");

    mVsyncConfiguration->dump(result);
    StringAppendF(&result,
                  "      present offset: %9" PRId64 " ns\t     VSYNC period: %9" PRId64 " ns\n\n",
                  dispSyncPresentTimeOffset, getVsyncPeriodFromHWC());

    StringAppendF(&result, "(mode override by backdoor: %s)\n\n",
                  mDebugDisplayModeSetByBackdoor ? "yes" : "no");

    mScheduler->dump(mAppConnectionHandle, result);
    mScheduler->dumpVsync(result);
    StringAppendF(&result, "mHWCVsyncPendingState=%s mLastHWCVsyncState=%s\n",
                  to_string(mHWCVsyncPendingState).c_str(), to_string(mLastHWCVsyncState).c_str());
}

void SurfaceFlinger::dumpPlannerInfo(const DumpArgs& args, std::string& result) const {
    for (const auto& [token, display] : mDisplays) {
        const auto compositionDisplay = display->getCompositionDisplay();
        compositionDisplay->dumpPlannerInfo(args, result);
    }
}

void SurfaceFlinger::dumpStaticScreenStats(std::string& result) const {
    result.append("Static screen stats:\n");
    for (size_t b = 0; b < SurfaceFlingerBE::NUM_BUCKETS - 1; ++b) {
        float bucketTimeSec = getBE().mFrameBuckets[b] / 1e9;
        float percent = 100.0f *
                static_cast<float>(getBE().mFrameBuckets[b]) / getBE().mTotalTime;
        StringAppendF(&result, "  < %zd frames: %.3f s (%.1f%%)\n", b + 1, bucketTimeSec, percent);
    }
    float bucketTimeSec = getBE().mFrameBuckets[SurfaceFlingerBE::NUM_BUCKETS - 1] / 1e9;
    float percent = 100.0f *
            static_cast<float>(getBE().mFrameBuckets[SurfaceFlingerBE::NUM_BUCKETS - 1]) / getBE().mTotalTime;
    StringAppendF(&result, "  %zd+ frames: %.3f s (%.1f%%)\n", SurfaceFlingerBE::NUM_BUCKETS - 1,
                  bucketTimeSec, percent);
}

void SurfaceFlinger::dumpCompositionDisplays(std::string& result) const {
    for (const auto& [token, display] : mDisplays) {
        display->getCompositionDisplay()->dump(result);
        result += '\n';
    }
}

void SurfaceFlinger::dumpDisplays(std::string& result) const {
    for (const auto& [token, display] : mDisplays) {
        display->dump(result);
        result += '\n';
    }
}

void SurfaceFlinger::dumpDisplayIdentificationData(std::string& result) const {
    for (const auto& [token, display] : mDisplays) {
        const auto displayId = PhysicalDisplayId::tryCast(display->getId());
        if (!displayId) {
            continue;
        }
        const auto hwcDisplayId = getHwComposer().fromPhysicalDisplayId(*displayId);
        if (!hwcDisplayId) {
            continue;
        }

        StringAppendF(&result,
                      "Display %s (HWC display %" PRIu64 "): ", to_string(*displayId).c_str(),
                      *hwcDisplayId);
        uint8_t port;
        DisplayIdentificationData data;
        if (!getHwComposer().getDisplayIdentificationData(*hwcDisplayId, &port, &data)) {
            result.append("no identification data\n");
            continue;
        }

        if (!isEdid(data)) {
            result.append("unknown identification data\n");
            continue;
        }

        const auto edid = parseEdid(data);
        if (!edid) {
            result.append("invalid EDID\n");
            continue;
        }

        StringAppendF(&result, "port=%u pnpId=%s displayName=\"", port, edid->pnpId.data());
        result.append(edid->displayName.data(), edid->displayName.length());
        result.append("\"\n");
    }
}

void SurfaceFlinger::dumpRawDisplayIdentificationData(const DumpArgs& args,
                                                      std::string& result) const {
    hal::HWDisplayId hwcDisplayId;
    uint8_t port;
    DisplayIdentificationData data;

    if (args.size() > 1 && base::ParseUint(String8(args[1]), &hwcDisplayId) &&
        getHwComposer().getDisplayIdentificationData(hwcDisplayId, &port, &data)) {
        result.append(reinterpret_cast<const char*>(data.data()), data.size());
    }
}

void SurfaceFlinger::dumpWideColorInfo(std::string& result) const {
    StringAppendF(&result, "Device has wide color built-in display: %d\n", hasWideColorDisplay);
    StringAppendF(&result, "Device uses color management: %d\n", useColorManagement);
    StringAppendF(&result, "DisplayColorSetting: %s\n",
                  decodeDisplayColorSetting(mDisplayColorSetting).c_str());

    // TODO: print out if wide-color mode is active or not

    for (const auto& [token, display] : mDisplays) {
        const auto displayId = PhysicalDisplayId::tryCast(display->getId());
        if (!displayId) {
            continue;
        }

        StringAppendF(&result, "Display %s color modes:\n", to_string(*displayId).c_str());
        std::vector<ColorMode> modes = getHwComposer().getColorModes(*displayId);
        for (auto&& mode : modes) {
            StringAppendF(&result, "    %s (%d)\n", decodeColorMode(mode).c_str(), mode);
        }

        ColorMode currentMode = display->getCompositionDisplay()->getState().colorMode;
        StringAppendF(&result, "    Current color mode: %s (%d)\n",
                      decodeColorMode(currentMode).c_str(), currentMode);
    }
    result.append("\n");
}

LayersProto SurfaceFlinger::dumpDrawingStateProto(uint32_t traceFlags) const {
    LayersProto layersProto;
    for (const sp<Layer>& layer : mDrawingState.layersSortedByZ) {
        layer->writeToProto(layersProto, traceFlags);
    }

    return layersProto;
}

void SurfaceFlinger::dumpDisplayProto(LayersTraceProto& layersTraceProto) const {
    for (const auto& [_, display] : FTL_FAKE_GUARD(mStateLock, mDisplays)) {
        DisplayProto* displayProto = layersTraceProto.add_displays();
        displayProto->set_id(display->getId().value);
        displayProto->set_name(display->getDisplayName());
        displayProto->set_layer_stack(display->getLayerStack().id);
        LayerProtoHelper::writeSizeToProto(display->getWidth(), display->getHeight(),
                                           [&]() { return displayProto->mutable_size(); });
        LayerProtoHelper::writeToProto(display->getLayerStackSpaceRect(), [&]() {
            return displayProto->mutable_layer_stack_space_rect();
        });
        LayerProtoHelper::writeTransformToProto(display->getTransform(),
                                                displayProto->mutable_transform());
        displayProto->set_is_virtual(display->isVirtual());
    }
}

void SurfaceFlinger::dumpHwc(std::string& result) const {
    getHwComposer().dump(result);
}

void SurfaceFlinger::dumpOffscreenLayersProto(LayersProto& layersProto, uint32_t traceFlags) const {
    // Add a fake invisible root layer to the proto output and parent all the offscreen layers to
    // it.
    LayerProto* rootProto = layersProto.add_layers();
    const int32_t offscreenRootLayerId = INT32_MAX - 2;
    rootProto->set_id(offscreenRootLayerId);
    rootProto->set_name("Offscreen Root");
    rootProto->set_parent(-1);

    for (Layer* offscreenLayer : mOffscreenLayers) {
        // Add layer as child of the fake root
        rootProto->add_children(offscreenLayer->sequence);

        // Add layer
        LayerProto* layerProto = offscreenLayer->writeToProto(layersProto, traceFlags);
        layerProto->set_parent(offscreenRootLayerId);
    }
}

LayersProto SurfaceFlinger::dumpProtoFromMainThread(uint32_t traceFlags) {
    return mScheduler->schedule([=] { return dumpDrawingStateProto(traceFlags); }).get();
}

void SurfaceFlinger::dumpOffscreenLayers(std::string& result) {
    auto future = mScheduler->schedule([this] {
        std::string result;
        for (Layer* offscreenLayer : mOffscreenLayers) {
            offscreenLayer->traverse(LayerVector::StateSet::Drawing,
                                     [&](Layer* layer) { layer->dumpCallingUidPid(result); });
        }
        return result;
    });

    result.append("Offscreen Layers:\n");
    result.append(future.get());
}

void SurfaceFlinger::dumpAllLocked(const DumpArgs& args, const std::string& compositionLayers,
                                   std::string& result) const {
    const bool colorize = !args.empty() && args[0] == String16("--color");
    Colorizer colorizer(colorize);

    // figure out if we're stuck somewhere
    const nsecs_t now = systemTime();
    const nsecs_t inTransaction(mDebugInTransaction);
    nsecs_t inTransactionDuration = (inTransaction) ? now-inTransaction : 0;

    /*
     * Dump library configuration.
     */

    colorizer.bold(result);
    result.append("Build configuration:");
    colorizer.reset(result);
    appendSfConfigString(result);
    result.append("\n");

    result.append("\nDisplay identification data:\n");
    dumpDisplayIdentificationData(result);

    result.append("\nWide-Color information:\n");
    dumpWideColorInfo(result);

    colorizer.bold(result);
    result.append("Sync configuration: ");
    colorizer.reset(result);
    result.append(SyncFeatures::getInstance().toString());
    result.append("\n\n");

    colorizer.bold(result);
    result.append("Scheduler:\n");
    colorizer.reset(result);
    dumpVSync(result);
    result.append("\n");

    dumpStaticScreenStats(result);
    result.append("\n");

    StringAppendF(&result, "Total missed frame count: %u\n", mFrameMissedCount.load());
    StringAppendF(&result, "HWC missed frame count: %u\n", mHwcFrameMissedCount.load());
    StringAppendF(&result, "GPU missed frame count: %u\n\n", mGpuFrameMissedCount.load());

    /*
     * Dump the visible layer list
     */
    colorizer.bold(result);
    StringAppendF(&result, "Visible layers (count = %zu)\n", mNumLayers.load());
    colorizer.reset(result);

    result.append(compositionLayers);

    colorizer.bold(result);
    StringAppendF(&result, "Displays (%zu entries)\n", mDisplays.size());
    colorizer.reset(result);
    dumpDisplays(result);
    dumpCompositionDisplays(result);
    result.push_back('\n');

    mCompositionEngine->dump(result);

    /*
     * Dump SurfaceFlinger global state
     */

    colorizer.bold(result);
    result.append("SurfaceFlinger global state:\n");
    colorizer.reset(result);

    getRenderEngine().dump(result);

    result.append("ClientCache state:\n");
    ClientCache::getInstance().dump(result);
    DebugEGLImageTracker::getInstance()->dump(result);

    if (const auto display = getDefaultDisplayDeviceLocked()) {
        display->getCompositionDisplay()->getState().undefinedRegion.dump(result,
                                                                          "undefinedRegion");
        StringAppendF(&result, "  orientation=%s, isPoweredOn=%d\n",
                      toCString(display->getOrientation()), display->isPoweredOn());
    }
    StringAppendF(&result,
                  "  transaction-flags         : %08x\n"
                  "  gpu_to_cpu_unsupported    : %d\n",
                  mTransactionFlags.load(), !mGpuToCpuSupported);

    if (const auto display = getDefaultDisplayDeviceLocked()) {
        std::string fps, xDpi, yDpi;
        if (const auto activeMode = display->getActiveMode()) {
            fps = to_string(activeMode->getFps());

            const auto dpi = activeMode->getDpi();
            xDpi = base::StringPrintf("%.2f", dpi.x);
            yDpi = base::StringPrintf("%.2f", dpi.y);
        } else {
            fps = "unknown";
            xDpi = "unknown";
            yDpi = "unknown";
        }
        StringAppendF(&result,
                      "  refresh-rate              : %s\n"
                      "  x-dpi                     : %s\n"
                      "  y-dpi                     : %s\n",
                      fps.c_str(), xDpi.c_str(), yDpi.c_str());
    }

    StringAppendF(&result, "  transaction time: %f us\n", inTransactionDuration / 1000.0);

    /*
     * Tracing state
     */
    mLayerTracing.dump(result);

    result.append("\nTransaction tracing: ");
    if (mTransactionTracing) {
        result.append("enabled\n");
        mTransactionTracing->dump(result);
    } else {
        result.append("disabled\n");
    }
    result.push_back('\n');

    /*
     * HWC layer minidump
     */
    for (const auto& [token, display] : mDisplays) {
        const auto displayId = HalDisplayId::tryCast(display->getId());
        if (!displayId) {
            continue;
        }

        StringAppendF(&result, "Display %s (%s) HWC layers:\n", to_string(*displayId).c_str(),
                      (isDisplayActiveLocked(display) ? "active" : "inactive"));
        Layer::miniDumpHeader(result);

        const DisplayDevice& ref = *display;
        mCurrentState.traverseInZOrder([&](Layer* layer) { layer->miniDump(result, ref); });
        result.append("\n");
    }

    {
        DumpArgs plannerArgs;
        plannerArgs.add(); // first argument is ignored
        plannerArgs.add(String16("--layers"));
        dumpPlannerInfo(plannerArgs, result);
    }

    /*
     * Dump HWComposer state
     */
    colorizer.bold(result);
    result.append("h/w composer state:\n");
    colorizer.reset(result);
    const bool hwcDisabled = mDebugDisableHWC || mDebugFlashDelay;
    StringAppendF(&result, "  h/w composer %s\n", hwcDisabled ? "disabled" : "enabled");
    dumpHwc(result);

    /*
     * Dump gralloc state
     */
    const GraphicBufferAllocator& alloc(GraphicBufferAllocator::get());
    alloc.dump(result);

    /*
     * Dump flag/property manager state
     */
    mFlagManager.dump(result);

    result.append(mTimeStats->miniDump());
    result.append("\n");
}

mat4 SurfaceFlinger::calculateColorMatrix(float saturation) {
    if (saturation == 1) {
        return mat4();
    }

    float3 luminance{0.213f, 0.715f, 0.072f};
    luminance *= 1.0f - saturation;
    mat4 saturationMatrix = mat4(vec4{luminance.r + saturation, luminance.r, luminance.r, 0.0f},
                                 vec4{luminance.g, luminance.g + saturation, luminance.g, 0.0f},
                                 vec4{luminance.b, luminance.b, luminance.b + saturation, 0.0f},
                                 vec4{0.0f, 0.0f, 0.0f, 1.0f});
    return saturationMatrix;
}

void SurfaceFlinger::updateColorMatrixLocked() {
    mat4 colorMatrix =
            mClientColorMatrix * calculateColorMatrix(mGlobalSaturationFactor) * mDaltonizer();

    if (mCurrentState.colorMatrix != colorMatrix) {
        mCurrentState.colorMatrix = colorMatrix;
        mCurrentState.colorMatrixChanged = true;
        setTransactionFlags(eTransactionNeeded);
    }
}

status_t SurfaceFlinger::CheckTransactCodeCredentials(uint32_t code) {
#pragma clang diagnostic push
#pragma clang diagnostic error "-Wswitch-enum"
    switch (static_cast<ISurfaceComposerTag>(code)) {
        case ENABLE_VSYNC_INJECTIONS:
        case INJECT_VSYNC:
            if (!hasMockHwc()) return PERMISSION_DENIED;
            [[fallthrough]];
        // These methods should at minimum make sure that the client requested
        // access to SF.
        case BOOT_FINISHED:
        case CLEAR_ANIMATION_FRAME_STATS:
        case GET_ANIMATION_FRAME_STATS:
        case OVERRIDE_HDR_TYPES:
        case GET_HDR_CAPABILITIES:
        case SET_DESIRED_DISPLAY_MODE_SPECS:
        case GET_DESIRED_DISPLAY_MODE_SPECS:
        case SET_ACTIVE_COLOR_MODE:
        case SET_BOOT_DISPLAY_MODE:
        case GET_AUTO_LOW_LATENCY_MODE_SUPPORT:
        case GET_GAME_CONTENT_TYPE_SUPPORT:
        case GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES:
        case SET_DISPLAY_CONTENT_SAMPLING_ENABLED:
        case GET_DISPLAYED_CONTENT_SAMPLE:
        case ADD_TUNNEL_MODE_ENABLED_LISTENER:
        case REMOVE_TUNNEL_MODE_ENABLED_LISTENER:
        case SET_GLOBAL_SHADOW_SETTINGS:
        case ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN: {
            // OVERRIDE_HDR_TYPES is used by CTS tests, which acquire the necessary
            // permission dynamically. Don't use the permission cache for this check.
            bool usePermissionCache = code != OVERRIDE_HDR_TYPES;
            if (!callingThreadHasUnscopedSurfaceFlingerAccess(usePermissionCache)) {
                IPCThreadState* ipc = IPCThreadState::self();
                ALOGE("Permission Denial: can't access SurfaceFlinger pid=%d, uid=%d",
                        ipc->getCallingPid(), ipc->getCallingUid());
                return PERMISSION_DENIED;
            }
            return OK;
        }
        case GET_LAYER_DEBUG_INFO: {
            IPCThreadState* ipc = IPCThreadState::self();
            const int pid = ipc->getCallingPid();
            const int uid = ipc->getCallingUid();
            if ((uid != AID_SHELL) && !PermissionCache::checkPermission(sDump, pid, uid)) {
                ALOGE("Layer debug info permission denied for pid=%d, uid=%d", pid, uid);
                return PERMISSION_DENIED;
            }
            return OK;
        }
        // Used by apps to hook Choreographer to SurfaceFlinger.
        case CREATE_DISPLAY_EVENT_CONNECTION:
        // The following calls are currently used by clients that do not
        // request necessary permissions. However, they do not expose any secret
        // information, so it is OK to pass them.
        case AUTHENTICATE_SURFACE:
        case GET_ACTIVE_COLOR_MODE:
        case GET_ACTIVE_DISPLAY_MODE:
        case GET_DISPLAY_COLOR_MODES:
        case GET_DISPLAY_NATIVE_PRIMARIES:
        case GET_STATIC_DISPLAY_INFO:
        case GET_DYNAMIC_DISPLAY_INFO:
        case GET_DISPLAY_MODES:
        case GET_SUPPORTED_FRAME_TIMESTAMPS:
        // Calling setTransactionState is safe, because you need to have been
        // granted a reference to Client* and Handle* to do anything with it.
        case SET_TRANSACTION_STATE:
        case CREATE_CONNECTION:
        case GET_COLOR_MANAGEMENT:
        case GET_COMPOSITION_PREFERENCE:
        case GET_PROTECTED_CONTENT_SUPPORT:
        // setFrameRate() is deliberately available for apps to call without any
        // special permissions.
        case SET_FRAME_RATE:
        case GET_DISPLAY_DECORATION_SUPPORT:
        case SET_FRAME_TIMELINE_INFO:
        case GET_GPU_CONTEXT_PRIORITY:
        case GET_MAX_ACQUIRED_BUFFER_COUNT: {
            // This is not sensitive information, so should not require permission control.
            return OK;
        }
        case ADD_FPS_LISTENER:
        case REMOVE_FPS_LISTENER:
        case ADD_REGION_SAMPLING_LISTENER:
        case REMOVE_REGION_SAMPLING_LISTENER: {
            // codes that require permission check
            IPCThreadState* ipc = IPCThreadState::self();
            const int pid = ipc->getCallingPid();
            const int uid = ipc->getCallingUid();
            if ((uid != AID_GRAPHICS) &&
                !PermissionCache::checkPermission(sReadFramebuffer, pid, uid)) {
                ALOGE("Permission Denial: can't read framebuffer pid=%d, uid=%d", pid, uid);
                return PERMISSION_DENIED;
            }
            return OK;
        }
        case ADD_TRANSACTION_TRACE_LISTENER: {
            IPCThreadState* ipc = IPCThreadState::self();
            const int uid = ipc->getCallingUid();
            if (uid == AID_ROOT || uid == AID_GRAPHICS || uid == AID_SYSTEM || uid == AID_SHELL) {
                return OK;
            }
            return PERMISSION_DENIED;
        }
        case SET_OVERRIDE_FRAME_RATE: {
            const int uid = IPCThreadState::self()->getCallingUid();
            if (uid == AID_ROOT || uid == AID_SYSTEM) {
                return OK;
            }
            return PERMISSION_DENIED;
        }
        case ON_PULL_ATOM: {
            const int uid = IPCThreadState::self()->getCallingUid();
            if (uid == AID_SYSTEM) {
                return OK;
            }
            return PERMISSION_DENIED;
        }
        case ADD_WINDOW_INFOS_LISTENER:
        case REMOVE_WINDOW_INFOS_LISTENER: {
            const int uid = IPCThreadState::self()->getCallingUid();
            if (uid == AID_SYSTEM || uid == AID_GRAPHICS) {
                return OK;
            }
            return PERMISSION_DENIED;
        }
        case CREATE_DISPLAY:
        case DESTROY_DISPLAY:
        case GET_PRIMARY_PHYSICAL_DISPLAY_ID:
        case GET_PHYSICAL_DISPLAY_IDS:
        case GET_PHYSICAL_DISPLAY_TOKEN:
        case SET_POWER_MODE:
        case GET_DISPLAY_STATE:
        case GET_DISPLAY_STATS:
        case CLEAR_BOOT_DISPLAY_MODE:
        case GET_BOOT_DISPLAY_MODE_SUPPORT:
        case SET_AUTO_LOW_LATENCY_MODE:
        case SET_GAME_CONTENT_TYPE:
        case CAPTURE_LAYERS:
        case CAPTURE_DISPLAY:
        case CAPTURE_DISPLAY_BY_ID:
        case IS_WIDE_COLOR_DISPLAY:
        case GET_DISPLAY_BRIGHTNESS_SUPPORT:
        case SET_DISPLAY_BRIGHTNESS:
        case ADD_HDR_LAYER_INFO_LISTENER:
        case REMOVE_HDR_LAYER_INFO_LISTENER:
        case NOTIFY_POWER_BOOST:
            LOG_FATAL("Deprecated opcode: %d, migrated to AIDL", code);
            return PERMISSION_DENIED;
    }

    // These codes are used for the IBinder protocol to either interrogate the recipient
    // side of the transaction for its canonical interface descriptor or to dump its state.
    // We let them pass by default.
    if (code == IBinder::INTERFACE_TRANSACTION || code == IBinder::DUMP_TRANSACTION ||
        code == IBinder::PING_TRANSACTION || code == IBinder::SHELL_COMMAND_TRANSACTION ||
        code == IBinder::SYSPROPS_TRANSACTION) {
        return OK;
    }
    // Numbers from 1000 to 1042 are currently used for backdoors. The code
    // in onTransact verifies that the user is root, and has access to use SF.
    if (code >= 1000 && code <= 1042) {
        ALOGV("Accessing SurfaceFlinger through backdoor code: %u", code);
        return OK;
    }
    ALOGE("Permission Denial: SurfaceFlinger did not recognize request code: %u", code);
    return PERMISSION_DENIED;
#pragma clang diagnostic pop
}

status_t SurfaceFlinger::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                    uint32_t flags) {
    if (const status_t error = CheckTransactCodeCredentials(code); error != OK) {
        return error;
    }

    status_t err = BnSurfaceComposer::onTransact(code, data, reply, flags);
    if (err == UNKNOWN_TRANSACTION || err == PERMISSION_DENIED) {
        CHECK_INTERFACE(ISurfaceComposer, data, reply);
        IPCThreadState* ipc = IPCThreadState::self();
        const int uid = ipc->getCallingUid();
        if (CC_UNLIKELY(uid != AID_SYSTEM
                && !PermissionCache::checkCallingPermission(sHardwareTest))) {
            const int pid = ipc->getCallingPid();
            ALOGE("Permission Denial: "
                    "can't access SurfaceFlinger pid=%d, uid=%d", pid, uid);
            return PERMISSION_DENIED;
        }
        int n;
        switch (code) {
            case 1000: // Unused.
            case 1001:
                return NAME_NOT_FOUND;
            case 1002: // Toggle flashing on surface damage.
                if (const int delay = data.readInt32(); delay > 0) {
                    mDebugFlashDelay = delay;
                } else {
                    mDebugFlashDelay = mDebugFlashDelay ? 0 : 1;
                }
                scheduleRepaint();
                return NO_ERROR;
            case 1004: // Force composite ahead of next VSYNC.
            case 1006:
                scheduleComposite(FrameHint::kActive);
                return NO_ERROR;
            case 1005: { // Force commit ahead of next VSYNC.
                Mutex::Autolock lock(mStateLock);
                setTransactionFlags(eTransactionNeeded | eDisplayTransactionNeeded |
                                    eTraversalNeeded);
                return NO_ERROR;
            }
            case 1007: // Unused.
                return NAME_NOT_FOUND;
            case 1008: // Toggle forced GPU composition.
                mDebugDisableHWC = data.readInt32() != 0;
                scheduleRepaint();
                return NO_ERROR;
            case 1009: // Toggle use of transform hint.
                mDebugDisableTransformHint = data.readInt32() != 0;
                scheduleRepaint();
                return NO_ERROR;
            case 1010: // Interrogate.
                reply->writeInt32(0);
                reply->writeInt32(0);
                reply->writeInt32(mDebugFlashDelay);
                reply->writeInt32(0);
                reply->writeInt32(mDebugDisableHWC);
                return NO_ERROR;
            case 1013: {
                const auto display = getDefaultDisplayDevice();
                if (!display) {
                    return NAME_NOT_FOUND;
                }

                reply->writeInt32(display->getPageFlipCount());
                return NO_ERROR;
            }
            case 1014: {
                Mutex::Autolock _l(mStateLock);
                // daltonize
                n = data.readInt32();
                switch (n % 10) {
                    case 1:
                        mDaltonizer.setType(ColorBlindnessType::Protanomaly);
                        break;
                    case 2:
                        mDaltonizer.setType(ColorBlindnessType::Deuteranomaly);
                        break;
                    case 3:
                        mDaltonizer.setType(ColorBlindnessType::Tritanomaly);
                        break;
                    default:
                        mDaltonizer.setType(ColorBlindnessType::None);
                        break;
                }
                if (n >= 10) {
                    mDaltonizer.setMode(ColorBlindnessMode::Correction);
                } else {
                    mDaltonizer.setMode(ColorBlindnessMode::Simulation);
                }

                updateColorMatrixLocked();
                return NO_ERROR;
            }
            case 1015: {
                Mutex::Autolock _l(mStateLock);
                // apply a color matrix
                n = data.readInt32();
                if (n) {
                    // color matrix is sent as a column-major mat4 matrix
                    for (size_t i = 0 ; i < 4; i++) {
                        for (size_t j = 0; j < 4; j++) {
                            mClientColorMatrix[i][j] = data.readFloat();
                        }
                    }
                } else {
                    mClientColorMatrix = mat4();
                }

                // Check that supplied matrix's last row is {0,0,0,1} so we can avoid
                // the division by w in the fragment shader
                float4 lastRow(transpose(mClientColorMatrix)[3]);
                if (any(greaterThan(abs(lastRow - float4{0, 0, 0, 1}), float4{1e-4f}))) {
                    ALOGE("The color transform's last row must be (0, 0, 0, 1)");
                }

                updateColorMatrixLocked();
                return NO_ERROR;
            }
            case 1016: { // Unused.
                return NAME_NOT_FOUND;
            }
            case 1017: {
                n = data.readInt32();
                mForceFullDamage = n != 0;
                return NO_ERROR;
            }
            case 1018: { // Modify Choreographer's duration
                n = data.readInt32();
                mScheduler->setDuration(mAppConnectionHandle, std::chrono::nanoseconds(n), 0ns);
                return NO_ERROR;
            }
            case 1019: { // Modify SurfaceFlinger's duration
                n = data.readInt32();
                mScheduler->setDuration(mSfConnectionHandle, std::chrono::nanoseconds(n), 0ns);
                return NO_ERROR;
            }
            case 1020: { // Layer updates interceptor
                n = data.readInt32();
                if (n) {
                    ALOGV("Interceptor enabled");
                    mInterceptor->enable(mDrawingState.layersSortedByZ, mDrawingState.displays);
                }
                else{
                    ALOGV("Interceptor disabled");
                    mInterceptor->disable();
                }
                return NO_ERROR;
            }
            case 1021: { // Disable HWC virtual displays
                const bool enable = data.readInt32() != 0;
                static_cast<void>(
                        mScheduler->schedule([this, enable] { enableHalVirtualDisplays(enable); }));
                return NO_ERROR;
            }
            case 1022: { // Set saturation boost
                Mutex::Autolock _l(mStateLock);
                mGlobalSaturationFactor = std::max(0.0f, std::min(data.readFloat(), 2.0f));

                updateColorMatrixLocked();
                return NO_ERROR;
            }
            case 1023: { // Set native mode
                int32_t colorMode;

                mDisplayColorSetting = static_cast<DisplayColorSetting>(data.readInt32());
                if (data.readInt32(&colorMode) == NO_ERROR) {
                    mForceColorMode = static_cast<ColorMode>(colorMode);
                }
                scheduleRepaint();
                return NO_ERROR;
            }
            // Deprecate, use 1030 to check whether the device is color managed.
            case 1024: {
                return NAME_NOT_FOUND;
            }
            case 1025: { // Set layer tracing
                n = data.readInt32();
                bool tracingEnabledChanged;
                if (n == 1) {
                    int64_t fixedStartingTime = data.readInt64();
                    ALOGD("LayerTracing enabled");
                    tracingEnabledChanged = mLayerTracing.enable();
                    if (tracingEnabledChanged) {
                        int64_t startingTime =
                                (fixedStartingTime) ? fixedStartingTime : systemTime();
                        mScheduler
                                ->schedule([&]() FTL_FAKE_GUARD(mStateLock) {
                                    mLayerTracing.notify("start", startingTime);
                                })
                                .wait();
                    }
                } else if (n == 2) {
                    std::string filename = std::string(data.readCString());
                    ALOGD("LayerTracing disabled. Trace wrote to %s", filename.c_str());
                    tracingEnabledChanged = mLayerTracing.disable(filename.c_str());
                } else {
                    ALOGD("LayerTracing disabled");
                    tracingEnabledChanged = mLayerTracing.disable();
                }
                mTracingEnabledChanged = tracingEnabledChanged;
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
            case 1026: { // Get layer tracing status
                reply->writeBool(mLayerTracing.isEnabled());
                return NO_ERROR;
            }
            // Is a DisplayColorSetting supported?
            case 1027: {
                const auto display = getDefaultDisplayDevice();
                if (!display) {
                    return NAME_NOT_FOUND;
                }

                DisplayColorSetting setting = static_cast<DisplayColorSetting>(data.readInt32());
                switch (setting) {
                    case DisplayColorSetting::kManaged:
                        reply->writeBool(useColorManagement);
                        break;
                    case DisplayColorSetting::kUnmanaged:
                        reply->writeBool(true);
                        break;
                    case DisplayColorSetting::kEnhanced:
                        reply->writeBool(display->hasRenderIntent(RenderIntent::ENHANCE));
                        break;
                    default: // vendor display color setting
                        reply->writeBool(
                                display->hasRenderIntent(static_cast<RenderIntent>(setting)));
                        break;
                }
                return NO_ERROR;
            }
            case 1028: { // Unused.
                return NAME_NOT_FOUND;
            }
            // Set buffer size for SF tracing (value in KB)
            case 1029: {
                n = data.readInt32();
                if (n <= 0 || n > MAX_TRACING_MEMORY) {
                    ALOGW("Invalid buffer size: %d KB", n);
                    reply->writeInt32(BAD_VALUE);
                    return BAD_VALUE;
                }

                ALOGD("Updating trace buffer to %d KB", n);
                mLayerTracing.setBufferSize(n * 1024);
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
            // Is device color managed?
            case 1030: {
                reply->writeBool(useColorManagement);
                return NO_ERROR;
            }
            // Override default composition data space
            // adb shell service call SurfaceFlinger 1031 i32 1 DATASPACE_NUMBER DATASPACE_NUMBER \
            // && adb shell stop zygote && adb shell start zygote
            // to restore: adb shell service call SurfaceFlinger 1031 i32 0 && \
            // adb shell stop zygote && adb shell start zygote
            case 1031: {
                Mutex::Autolock _l(mStateLock);
                n = data.readInt32();
                if (n) {
                    n = data.readInt32();
                    if (n) {
                        Dataspace dataspace = static_cast<Dataspace>(n);
                        if (!validateCompositionDataspace(dataspace)) {
                            return BAD_VALUE;
                        }
                        mDefaultCompositionDataspace = dataspace;
                    }
                    n = data.readInt32();
                    if (n) {
                        Dataspace dataspace = static_cast<Dataspace>(n);
                        if (!validateCompositionDataspace(dataspace)) {
                            return BAD_VALUE;
                        }
                        mWideColorGamutCompositionDataspace = dataspace;
                    }
                } else {
                    // restore composition data space.
                    mDefaultCompositionDataspace = defaultCompositionDataspace;
                    mWideColorGamutCompositionDataspace = wideColorGamutCompositionDataspace;
                }
                return NO_ERROR;
            }
            // Set trace flags
            case 1033: {
                n = data.readUint32();
                ALOGD("Updating trace flags to 0x%x", n);
                mLayerTracing.setTraceFlags(n);
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
            case 1034: {
                auto future = mScheduler->schedule([&] {
                    switch (n = data.readInt32()) {
                        case 0:
                        case 1:
                            FTL_FAKE_GUARD(mStateLock,
                                           enableRefreshRateOverlay(static_cast<bool>(n)));
                            break;
                        default: {
                            reply->writeBool(
                                    FTL_FAKE_GUARD(mStateLock, isRefreshRateOverlayEnabled()));
                        }
                    }
                });

                future.wait();
                return NO_ERROR;
            }
            case 1035: {
                const int modeId = data.readInt32();

                const auto display = [&]() -> sp<IBinder> {
                    uint64_t value;
                    if (data.readUint64(&value) != NO_ERROR) {
                        return getDefaultDisplayDevice()->getDisplayToken().promote();
                    }

                    if (const auto id = DisplayId::fromValue<PhysicalDisplayId>(value)) {
                        return getPhysicalDisplayToken(*id);
                    }

                    ALOGE("Invalid physical display ID");
                    return nullptr;
                }();

                mDebugDisplayModeSetByBackdoor = false;
                const status_t result = setActiveModeFromBackdoor(display, modeId);
                mDebugDisplayModeSetByBackdoor = result == NO_ERROR;
                return result;
            }
            // Turn on/off frame rate flexibility mode. When turned on it overrides the display
            // manager frame rate policy a new policy which allows switching between all refresh
            // rates.
            case 1036: {
                if (data.readInt32() > 0) { // turn on
                    return mScheduler
                            ->schedule([this] {
                                const auto display =
                                        FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());

                                // This is a little racy, but not in a way that hurts anything. As
                                // we grab the defaultMode from the display manager policy, we could
                                // be setting a new display manager policy, leaving us using a stale
                                // defaultMode. The defaultMode doesn't matter for the override
                                // policy though, since we set allowGroupSwitching to true, so it's
                                // not a problem.
                                scheduler::RefreshRateConfigs::Policy overridePolicy;
                                overridePolicy.defaultMode = display->refreshRateConfigs()
                                                                     .getDisplayManagerPolicy()
                                                                     .defaultMode;
                                overridePolicy.allowGroupSwitching = true;
                                constexpr bool kOverridePolicy = true;
                                return setDesiredDisplayModeSpecsInternal(display, overridePolicy,
                                                                          kOverridePolicy);
                            })
                            .get();
                } else { // turn off
                    return mScheduler
                            ->schedule([this] {
                                const auto display =
                                        FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());
                                constexpr bool kOverridePolicy = true;
                                return setDesiredDisplayModeSpecsInternal(display, {},
                                                                          kOverridePolicy);
                            })
                            .get();
                }
            }
            // Inject a hotplug connected event for the primary display. This will deallocate and
            // reallocate the display state including framebuffers.
            case 1037: {
                const hal::HWDisplayId hwcId =
                        (Mutex::Autolock(mStateLock), getHwComposer().getPrimaryHwcDisplayId());

                onComposerHalHotplug(hwcId, hal::Connection::CONNECTED);
                return NO_ERROR;
            }
            // Modify the max number of display frames stored within FrameTimeline
            case 1038: {
                n = data.readInt32();
                if (n < 0 || n > MAX_ALLOWED_DISPLAY_FRAMES) {
                    ALOGW("Invalid max size. Maximum allowed is %d", MAX_ALLOWED_DISPLAY_FRAMES);
                    return BAD_VALUE;
                }
                if (n == 0) {
                    // restore to default
                    mFrameTimeline->reset();
                    return NO_ERROR;
                }
                mFrameTimeline->setMaxDisplayFrames(n);
                return NO_ERROR;
            }
            case 1039: {
                PhysicalDisplayId displayId = [&]() {
                    Mutex::Autolock lock(mStateLock);
                    return getDefaultDisplayDeviceLocked()->getPhysicalId();
                }();

                auto inUid = static_cast<uid_t>(data.readInt32());
                const auto refreshRate = data.readFloat();
                mScheduler->setPreferredRefreshRateForUid(FrameRateOverride{inUid, refreshRate});
                mScheduler->onFrameRateOverridesChanged(mAppConnectionHandle, displayId);
                return NO_ERROR;
            }
            // Toggle caching feature
            // First argument is an int32 - nonzero enables caching and zero disables caching
            // Second argument is an optional uint64 - if present, then limits enabling/disabling
            // caching to a particular physical display
            case 1040: {
                auto future = mScheduler->schedule([&] {
                    n = data.readInt32();
                    std::optional<PhysicalDisplayId> inputId = std::nullopt;
                    if (uint64_t inputDisplayId; data.readUint64(&inputDisplayId) == NO_ERROR) {
                        inputId = DisplayId::fromValue<PhysicalDisplayId>(inputDisplayId);
                        if (!inputId || getPhysicalDisplayToken(*inputId)) {
                            ALOGE("No display with id: %" PRIu64, inputDisplayId);
                            return NAME_NOT_FOUND;
                        }
                    }
                    {
                        Mutex::Autolock lock(mStateLock);
                        mLayerCachingEnabled = n != 0;
                        for (const auto& [_, display] : mDisplays) {
                            if (!inputId || *inputId == display->getPhysicalId()) {
                                display->enableLayerCaching(mLayerCachingEnabled);
                            }
                        }
                    }
                    return OK;
                });

                if (const status_t error = future.get(); error != OK) {
                    return error;
                }
                scheduleRepaint();
                return NO_ERROR;
            }
            case 1041: { // Transaction tracing
                if (mTransactionTracing) {
                    if (data.readInt32()) {
                        // Transaction tracing is always running but allow the user to temporarily
                        // increase the buffer when actively debugging.
                        mTransactionTracing->setBufferSize(
                                TransactionTracing::ACTIVE_TRACING_BUFFER_SIZE);
                    } else {
                        mTransactionTracing->writeToFile();
                        mTransactionTracing->setBufferSize(
                                TransactionTracing::CONTINUOUS_TRACING_BUFFER_SIZE);
                    }
                }
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
            case 1042: { // Write layers trace or transaction trace to file
                if (mTransactionTracing) {
                    mTransactionTracing->writeToFile();
                }
                if (mLayerTracingEnabled) {
                    mLayerTracing.writeToFile();
                }
                reply->writeInt32(NO_ERROR);
                return NO_ERROR;
            }
        }
    }
    return err;
}

void SurfaceFlinger::kernelTimerChanged(bool expired) {
    static bool updateOverlay =
            property_get_bool("debug.sf.kernel_idle_timer_update_overlay", true);
    if (!updateOverlay) return;

    // Update the overlay on the main thread to avoid race conditions with
    // mRefreshRateConfigs->getActiveMode()
    static_cast<void>(mScheduler->schedule([=] {
        const auto display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked());
        if (!display) {
            ALOGW("%s: default display is null", __func__);
            return;
        }
        if (!display->isRefreshRateOverlayEnabled()) return;

        const auto desiredActiveMode = display->getDesiredActiveMode();
        const std::optional<DisplayModeId> desiredModeId = desiredActiveMode
                ? std::make_optional(desiredActiveMode->mode->getId())
                : std::nullopt;

        const bool timerExpired = mKernelIdleTimerEnabled && expired;

        if (display->onKernelTimerChanged(desiredModeId, timerExpired)) {
            mScheduler->scheduleFrame();
        }
    }));
}

std::pair<std::optional<KernelIdleTimerController>, std::chrono::milliseconds>
SurfaceFlinger::getKernelIdleTimerProperties(DisplayId displayId) {
    const bool isKernelIdleTimerHwcSupported = getHwComposer().getComposer()->isSupported(
            android::Hwc2::Composer::OptionalFeature::KernelIdleTimer);
    const auto timeout = getIdleTimerTimeout(displayId);
    if (isKernelIdleTimerHwcSupported) {
        if (const auto id = PhysicalDisplayId::tryCast(displayId);
            getHwComposer().hasDisplayIdleTimerCapability(*id)) {
            // In order to decide if we can use the HWC api for idle timer
            // we query DisplayCapability::DISPLAY_IDLE_TIMER directly on the composer
            // without relying on hasDisplayCapability.
            // hasDisplayCapability relies on DisplayCapabilities
            // which are updated after we set the PowerMode::ON.
            // DISPLAY_IDLE_TIMER is a display driver property
            // and is available before the PowerMode::ON
            return {KernelIdleTimerController::HwcApi, timeout};
        }
        return {std::nullopt, timeout};
    }
    if (getKernelIdleTimerSyspropConfig(displayId)) {
        return {KernelIdleTimerController::Sysprop, timeout};
    }

    return {std::nullopt, timeout};
}

void SurfaceFlinger::updateKernelIdleTimer(std::chrono::milliseconds timeout,
                                           KernelIdleTimerController controller,
                                           PhysicalDisplayId displayId) {
    switch (controller) {
        case KernelIdleTimerController::HwcApi: {
            getHwComposer().setIdleTimerEnabled(displayId, timeout);
            break;
        }
        case KernelIdleTimerController::Sysprop: {
            base::SetProperty(KERNEL_IDLE_TIMER_PROP, timeout > 0ms ? "true" : "false");
            break;
        }
    }
}

void SurfaceFlinger::toggleKernelIdleTimer() {
    using KernelIdleTimerAction = scheduler::RefreshRateConfigs::KernelIdleTimerAction;

    const auto display = getDefaultDisplayDeviceLocked();
    if (!display) {
        ALOGW("%s: default display is null", __func__);
        return;
    }

    // If the support for kernel idle timer is disabled for the active display,
    // don't do anything.
    const std::optional<KernelIdleTimerController> kernelIdleTimerController =
            display->refreshRateConfigs().kernelIdleTimerController();
    if (!kernelIdleTimerController.has_value()) {
        return;
    }

    const KernelIdleTimerAction action = display->refreshRateConfigs().getIdleTimerAction();

    switch (action) {
        case KernelIdleTimerAction::TurnOff:
            if (mKernelIdleTimerEnabled) {
                ATRACE_INT("KernelIdleTimer", 0);
                std::chrono::milliseconds constexpr kTimerDisabledTimeout = 0ms;
                updateKernelIdleTimer(kTimerDisabledTimeout, kernelIdleTimerController.value(),
                                      display->getPhysicalId());
                mKernelIdleTimerEnabled = false;
            }
            break;
        case KernelIdleTimerAction::TurnOn:
            if (!mKernelIdleTimerEnabled) {
                ATRACE_INT("KernelIdleTimer", 1);
                const std::chrono::milliseconds timeout =
                        display->refreshRateConfigs().getIdleTimerTimeout();
                updateKernelIdleTimer(timeout, kernelIdleTimerController.value(),
                                      display->getPhysicalId());
                mKernelIdleTimerEnabled = true;
            }
            break;
    }
}

// A simple RAII class to disconnect from an ANativeWindow* when it goes out of scope
class WindowDisconnector {
public:
    WindowDisconnector(ANativeWindow* window, int api) : mWindow(window), mApi(api) {}
    ~WindowDisconnector() {
        native_window_api_disconnect(mWindow, mApi);
    }

private:
    ANativeWindow* mWindow;
    const int mApi;
};

static Dataspace pickDataspaceFromColorMode(const ColorMode colorMode) {
    switch (colorMode) {
        case ColorMode::DISPLAY_P3:
        case ColorMode::BT2100_PQ:
        case ColorMode::BT2100_HLG:
        case ColorMode::DISPLAY_BT2020:
            return Dataspace::DISPLAY_P3;
        default:
            return Dataspace::V0_SRGB;
    }
}

static bool hasCaptureBlackoutContentPermission() {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    return uid == AID_GRAPHICS || uid == AID_SYSTEM ||
            PermissionCache::checkPermission(sCaptureBlackoutContent, pid, uid);
}

static status_t validateScreenshotPermissions(const CaptureArgs& captureArgs) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if (uid == AID_GRAPHICS || PermissionCache::checkPermission(sReadFramebuffer, pid, uid)) {
        return OK;
    }

    // If the caller doesn't have the correct permissions but is only attempting to screenshot
    // itself, we allow it to continue.
    if (captureArgs.uid == uid) {
        return OK;
    }

    ALOGE("Permission Denial: can't take screenshot pid=%d, uid=%d", pid, uid);
    return PERMISSION_DENIED;
}

status_t SurfaceFlinger::setSchedFifo(bool enabled) {
    static constexpr int kFifoPriority = 2;
    static constexpr int kOtherPriority = 0;

    struct sched_param param = {0};
    int sched_policy;
    if (enabled) {
        sched_policy = SCHED_FIFO;
        param.sched_priority = kFifoPriority;
    } else {
        sched_policy = SCHED_OTHER;
        param.sched_priority = kOtherPriority;
    }

    if (sched_setscheduler(0, sched_policy, &param) != 0) {
        return -errno;
    }

    return NO_ERROR;
}

status_t SurfaceFlinger::setSchedAttr(bool enabled) {
    static const unsigned int kUclampMin =
            base::GetUintProperty<unsigned int>("ro.surface_flinger.uclamp.min", 0U);

    if (!kUclampMin) {
        // uclamp.min set to 0 (default), skip setting
        return NO_ERROR;
    }

    // Currently, there is no wrapper in bionic: b/183240349.
    struct sched_attr {
        uint32_t size;
        uint32_t sched_policy;
        uint64_t sched_flags;
        int32_t sched_nice;
        uint32_t sched_priority;
        uint64_t sched_runtime;
        uint64_t sched_deadline;
        uint64_t sched_period;
        uint32_t sched_util_min;
        uint32_t sched_util_max;
    };

    sched_attr attr = {};
    attr.size = sizeof(attr);

    attr.sched_flags = (SCHED_FLAG_KEEP_ALL | SCHED_FLAG_UTIL_CLAMP);
    attr.sched_util_min = enabled ? kUclampMin : 0;
    attr.sched_util_max = 1024;

    if (syscall(__NR_sched_setattr, 0, &attr, 0)) {
        return -errno;
    }

    return NO_ERROR;
}

status_t SurfaceFlinger::captureDisplay(const DisplayCaptureArgs& args,
                                        const sp<IScreenCaptureListener>& captureListener) {
    ATRACE_CALL();

    status_t validate = validateScreenshotPermissions(args);
    if (validate != OK) {
        return validate;
    }

    if (!args.displayToken) return BAD_VALUE;

    wp<const DisplayDevice> displayWeak;
    ui::LayerStack layerStack;
    ui::Size reqSize(args.width, args.height);
    ui::Dataspace dataspace;
    {
        Mutex::Autolock lock(mStateLock);
        sp<DisplayDevice> display = getDisplayDeviceLocked(args.displayToken);
        if (!display) return NAME_NOT_FOUND;
        displayWeak = display;
        layerStack = display->getLayerStack();

        // set the requested width/height to the logical display layer stack rect size by default
        if (args.width == 0 || args.height == 0) {
            reqSize = display->getLayerStackSpaceRect().getSize();
        }

        // The dataspace is depended on the color mode of display, that could use non-native mode
        // (ex. displayP3) to enhance the content, but some cases are checking native RGB in bytes,
        // and failed if display is not in native mode. This provide a way to force using native
        // colors when capture.
        dataspace = args.dataspace;
        if (dataspace == ui::Dataspace::UNKNOWN) {
            const ui::ColorMode colorMode = display->getCompositionDisplay()->getState().colorMode;
            dataspace = pickDataspaceFromColorMode(colorMode);
        }
    }

    RenderAreaFuture renderAreaFuture = ftl::defer([=] {
        return DisplayRenderArea::create(displayWeak, args.sourceCrop, reqSize, dataspace,
                                         args.useIdentityTransform, args.captureSecureLayers);
    });

    auto traverseLayers = [this, args, layerStack](const LayerVector::Visitor& visitor) {
        traverseLayersInLayerStack(layerStack, args.uid, visitor);
    };

    auto future = captureScreenCommon(std::move(renderAreaFuture), traverseLayers, reqSize,
                                      args.pixelFormat, args.allowProtected, args.grayscale,
                                      captureListener);
    return fenceStatus(future.get());
}

status_t SurfaceFlinger::captureDisplay(DisplayId displayId,
                                        const sp<IScreenCaptureListener>& captureListener) {
    ui::LayerStack layerStack;
    wp<const DisplayDevice> displayWeak;
    ui::Size size;
    ui::Dataspace dataspace;
    {
        Mutex::Autolock lock(mStateLock);

        const auto display = getDisplayDeviceLocked(displayId);
        if (!display) {
            return NAME_NOT_FOUND;
        }

        displayWeak = display;
        layerStack = display->getLayerStack();
        size = display->getLayerStackSpaceRect().getSize();

        dataspace =
                pickDataspaceFromColorMode(display->getCompositionDisplay()->getState().colorMode);
    }

    RenderAreaFuture renderAreaFuture = ftl::defer([=] {
        return DisplayRenderArea::create(displayWeak, Rect(), size, dataspace,
                                         false /* useIdentityTransform */,
                                         false /* captureSecureLayers */);
    });

    auto traverseLayers = [this, layerStack](const LayerVector::Visitor& visitor) {
        traverseLayersInLayerStack(layerStack, CaptureArgs::UNSET_UID, visitor);
    };

    if (captureListener == nullptr) {
        ALOGE("capture screen must provide a capture listener callback");
        return BAD_VALUE;
    }

    constexpr bool kAllowProtected = false;
    constexpr bool kGrayscale = false;

    auto future = captureScreenCommon(std::move(renderAreaFuture), traverseLayers, size,
                                      ui::PixelFormat::RGBA_8888, kAllowProtected, kGrayscale,
                                      captureListener);
    return fenceStatus(future.get());
}

status_t SurfaceFlinger::captureLayers(const LayerCaptureArgs& args,
                                       const sp<IScreenCaptureListener>& captureListener) {
    ATRACE_CALL();

    status_t validate = validateScreenshotPermissions(args);
    if (validate != OK) {
        return validate;
    }

    ui::Size reqSize;
    sp<Layer> parent;
    Rect crop(args.sourceCrop);
    std::unordered_set<sp<Layer>, SpHash<Layer>> excludeLayers;
    ui::Dataspace dataspace;

    // Call this before holding mStateLock to avoid any deadlocking.
    bool canCaptureBlackoutContent = hasCaptureBlackoutContentPermission();

    {
        Mutex::Autolock lock(mStateLock);

        parent = fromHandle(args.layerHandle).promote();
        if (parent == nullptr) {
            ALOGE("captureLayers called with an invalid or removed parent");
            return NAME_NOT_FOUND;
        }

        if (!canCaptureBlackoutContent &&
            parent->getDrawingState().flags & layer_state_t::eLayerSecure) {
            ALOGW("Attempting to capture secure layer: PERMISSION_DENIED");
            return PERMISSION_DENIED;
        }

        Rect parentSourceBounds = parent->getCroppedBufferSize(parent->getDrawingState());
        if (args.sourceCrop.width() <= 0) {
            crop.left = 0;
            crop.right = parentSourceBounds.getWidth();
        }

        if (args.sourceCrop.height() <= 0) {
            crop.top = 0;
            crop.bottom = parentSourceBounds.getHeight();
        }

        if (crop.isEmpty() || args.frameScaleX <= 0.0f || args.frameScaleY <= 0.0f) {
            // Error out if the layer has no source bounds (i.e. they are boundless) and a source
            // crop was not specified, or an invalid frame scale was provided.
            return BAD_VALUE;
        }
        reqSize = ui::Size(crop.width() * args.frameScaleX, crop.height() * args.frameScaleY);

        for (const auto& handle : args.excludeHandles) {
            sp<Layer> excludeLayer = fromHandle(handle).promote();
            if (excludeLayer != nullptr) {
                excludeLayers.emplace(excludeLayer);
            } else {
                ALOGW("Invalid layer handle passed as excludeLayer to captureLayers");
                return NAME_NOT_FOUND;
            }
        }

        // The dataspace is depended on the color mode of display, that could use non-native mode
        // (ex. displayP3) to enhance the content, but some cases are checking native RGB in bytes,
        // and failed if display is not in native mode. This provide a way to force using native
        // colors when capture.
        dataspace = args.dataspace;
    } // mStateLock

    // really small crop or frameScale
    if (reqSize.width <= 0 || reqSize.height <= 0) {
        ALOGW("Failed to captureLayes: crop or scale too small");
        return BAD_VALUE;
    }

    Rect layerStackSpaceRect(0, 0, reqSize.width, reqSize.height);
    bool childrenOnly = args.childrenOnly;
    RenderAreaFuture renderAreaFuture = ftl::defer([=]() -> std::unique_ptr<RenderArea> {
        return std::make_unique<LayerRenderArea>(*this, parent, crop, reqSize, dataspace,
                                                 childrenOnly, layerStackSpaceRect,
                                                 args.captureSecureLayers);
    });

    auto traverseLayers = [parent, args, excludeLayers](const LayerVector::Visitor& visitor) {
        parent->traverseChildrenInZOrder(LayerVector::StateSet::Drawing, [&](Layer* layer) {
            if (!layer->isVisible()) {
                return;
            } else if (args.childrenOnly && layer == parent.get()) {
                return;
            } else if (args.uid != CaptureArgs::UNSET_UID && args.uid != layer->getOwnerUid()) {
                return;
            }

            sp<Layer> p = layer;
            while (p != nullptr) {
                if (excludeLayers.count(p) != 0) {
                    return;
                }
                p = p->getParent();
            }

            visitor(layer);
        });
    };

    if (captureListener == nullptr) {
        ALOGE("capture screen must provide a capture listener callback");
        return BAD_VALUE;
    }

    auto future = captureScreenCommon(std::move(renderAreaFuture), traverseLayers, reqSize,
                                      args.pixelFormat, args.allowProtected, args.grayscale,
                                      captureListener);
    return fenceStatus(future.get());
}

ftl::SharedFuture<FenceResult> SurfaceFlinger::captureScreenCommon(
        RenderAreaFuture renderAreaFuture, TraverseLayersFunction traverseLayers,
        ui::Size bufferSize, ui::PixelFormat reqPixelFormat, bool allowProtected, bool grayscale,
        const sp<IScreenCaptureListener>& captureListener) {
    ATRACE_CALL();

    if (exceedsMaxRenderTargetSize(bufferSize.getWidth(), bufferSize.getHeight())) {
        ALOGE("Attempted to capture screen with size (%" PRId32 ", %" PRId32
              ") that exceeds render target size limit.",
              bufferSize.getWidth(), bufferSize.getHeight());
        return ftl::yield<FenceResult>(base::unexpected(BAD_VALUE)).share();
    }

    // Loop over all visible layers to see whether there's any protected layer. A protected layer is
    // typically a layer with DRM contents, or have the GRALLOC_USAGE_PROTECTED set on the buffer.
    // A protected layer has no implication on whether it's secure, which is explicitly set by
    // application to avoid being screenshot or drawn via unsecure display.
    const bool supportsProtected = getRenderEngine().supportsProtectedContent();
    bool hasProtectedLayer = false;
    if (allowProtected && supportsProtected) {
        auto future = mScheduler->schedule([=]() {
            bool protectedLayerFound = false;
            traverseLayers([&](Layer* layer) {
                protectedLayerFound =
                        protectedLayerFound || (layer->isVisible() && layer->isProtected());
            });
            return protectedLayerFound;
        });
        hasProtectedLayer = future.get();
    }

    const uint32_t usage = GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_RENDER |
            GRALLOC_USAGE_HW_TEXTURE |
            (hasProtectedLayer && allowProtected && supportsProtected
                     ? GRALLOC_USAGE_PROTECTED
                     : GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN);
    sp<GraphicBuffer> buffer =
            getFactory().createGraphicBuffer(bufferSize.getWidth(), bufferSize.getHeight(),
                                             static_cast<android_pixel_format>(reqPixelFormat),
                                             1 /* layerCount */, usage, "screenshot");

    const status_t bufferStatus = buffer->initCheck();
    if (bufferStatus != OK) {
        // Animations may end up being really janky, but don't crash here.
        // Otherwise an irreponsible process may cause an SF crash by allocating
        // too much.
        ALOGE("%s: Buffer failed to allocate: %d", __func__, bufferStatus);
        return ftl::yield<FenceResult>(base::unexpected(bufferStatus)).share();
    }
    const std::shared_ptr<renderengine::ExternalTexture> texture = std::make_shared<
            renderengine::impl::ExternalTexture>(buffer, getRenderEngine(),
                                                 renderengine::impl::ExternalTexture::Usage::
                                                         WRITEABLE);
    return captureScreenCommon(std::move(renderAreaFuture), traverseLayers, texture,
                               false /* regionSampling */, grayscale, captureListener);
}

ftl::SharedFuture<FenceResult> SurfaceFlinger::captureScreenCommon(
        RenderAreaFuture renderAreaFuture, TraverseLayersFunction traverseLayers,
        const std::shared_ptr<renderengine::ExternalTexture>& buffer, bool regionSampling,
        bool grayscale, const sp<IScreenCaptureListener>& captureListener) {
    ATRACE_CALL();

    bool canCaptureBlackoutContent = hasCaptureBlackoutContentPermission();

    auto future = mScheduler->schedule([=, renderAreaFuture = std::move(renderAreaFuture)]() mutable
                                       -> ftl::SharedFuture<FenceResult> {
        ScreenCaptureResults captureResults;
        std::unique_ptr<RenderArea> renderArea = renderAreaFuture.get();
        if (!renderArea) {
            ALOGW("Skipping screen capture because of invalid render area.");
            if (captureListener) {
                captureResults.result = NO_MEMORY;
                captureListener->onScreenCaptureCompleted(captureResults);
            }
            return ftl::yield<FenceResult>(base::unexpected(NO_ERROR)).share();
        }

        ftl::SharedFuture<FenceResult> renderFuture;
        renderArea->render([&] {
            renderFuture =
                    renderScreenImpl(*renderArea, traverseLayers, buffer, canCaptureBlackoutContent,
                                     regionSampling, grayscale, captureResults);
        });

        if (captureListener) {
            // TODO: The future returned by std::async blocks the main thread. Return a chain of
            // futures to the Binder thread instead.
            std::async([=]() mutable {
                ATRACE_NAME("captureListener is nonnull!");
                auto fenceResult = renderFuture.get();
                // TODO(b/232535621): Change ScreenCaptureResults to store a FenceResult.
                captureResults.result = fenceStatus(fenceResult);
                captureResults.fence = std::move(fenceResult).value_or(Fence::NO_FENCE);
                captureListener->onScreenCaptureCompleted(captureResults);
            });
        }
        return renderFuture;
    });

    if (captureListener) {
        return ftl::yield<FenceResult>(base::unexpected(NO_ERROR)).share();
    }

    // Flatten nested futures.
    auto chain = ftl::Future(std::move(future)).then([](ftl::SharedFuture<FenceResult> future) {
        return future;
    });

    return chain.share();
}

ftl::SharedFuture<FenceResult> SurfaceFlinger::renderScreenImpl(
        const RenderArea& renderArea, TraverseLayersFunction traverseLayers,
        const std::shared_ptr<renderengine::ExternalTexture>& buffer,
        bool canCaptureBlackoutContent, bool regionSampling, bool grayscale,
        ScreenCaptureResults& captureResults) {
    ATRACE_CALL();

    traverseLayers([&](Layer* layer) {
        captureResults.capturedSecureLayers =
                captureResults.capturedSecureLayers || (layer->isVisible() && layer->isSecure());
    });

    const bool useProtected = buffer->getUsage() & GRALLOC_USAGE_PROTECTED;

    // We allow the system server to take screenshots of secure layers for
    // use in situations like the Screen-rotation animation and place
    // the impetus on WindowManager to not persist them.
    if (captureResults.capturedSecureLayers && !canCaptureBlackoutContent) {
        ALOGW("FB is protected: PERMISSION_DENIED");
        return ftl::yield<FenceResult>(base::unexpected(PERMISSION_DENIED)).share();
    }

    captureResults.buffer = buffer->getBuffer();
    auto dataspace = renderArea.getReqDataSpace();
    auto parent = renderArea.getParentLayer();
    auto renderIntent = RenderIntent::TONE_MAP_COLORIMETRIC;
    auto sdrWhitePointNits = DisplayDevice::sDefaultMaxLumiance;
    auto displayBrightnessNits = DisplayDevice::sDefaultMaxLumiance;

    if ((dataspace == ui::Dataspace::UNKNOWN) && (parent != nullptr)) {
        Mutex::Autolock lock(mStateLock);
        auto display = findDisplay([layerStack = parent->getLayerStack()](const auto& display) {
            return display.getLayerStack() == layerStack;
        });
        if (!display) {
            // If the layer is not on a display, use the dataspace for the default display.
            display = getDefaultDisplayDeviceLocked();
        }

        const ui::ColorMode colorMode = display->getCompositionDisplay()->getState().colorMode;
        dataspace = pickDataspaceFromColorMode(colorMode);
        renderIntent = display->getCompositionDisplay()->getState().renderIntent;
        sdrWhitePointNits = display->getCompositionDisplay()->getState().sdrWhitePointNits;
        displayBrightnessNits = display->getCompositionDisplay()->getState().displayBrightnessNits;
    }
    captureResults.capturedDataspace = dataspace;

    const auto reqWidth = renderArea.getReqWidth();
    const auto reqHeight = renderArea.getReqHeight();
    const auto sourceCrop = renderArea.getSourceCrop();
    const auto transform = renderArea.getTransform();
    const auto rotation = renderArea.getRotationFlags();
    const auto& layerStackSpaceRect = renderArea.getLayerStackSpaceRect();

    renderengine::DisplaySettings clientCompositionDisplay;
    std::vector<compositionengine::LayerFE::LayerSettings> clientCompositionLayers;

    // assume that bounds are never offset, and that they are the same as the
    // buffer bounds.
    clientCompositionDisplay.physicalDisplay = Rect(reqWidth, reqHeight);
    clientCompositionDisplay.clip = sourceCrop;
    clientCompositionDisplay.orientation = rotation;

    clientCompositionDisplay.outputDataspace = dataspace;
    clientCompositionDisplay.currentLuminanceNits = displayBrightnessNits;
    clientCompositionDisplay.maxLuminance = DisplayDevice::sDefaultMaxLumiance;
    clientCompositionDisplay.renderIntent =
            static_cast<aidl::android::hardware::graphics::composer3::RenderIntent>(renderIntent);

    const float colorSaturation = grayscale ? 0 : 1;
    clientCompositionDisplay.colorTransform = calculateColorMatrix(colorSaturation);

    const float alpha = RenderArea::getCaptureFillValue(renderArea.getCaptureFill());

    compositionengine::LayerFE::LayerSettings fillLayer;
    fillLayer.source.buffer.buffer = nullptr;
    fillLayer.source.solidColor = half3(0.0, 0.0, 0.0);
    fillLayer.geometry.boundaries =
            FloatRect(sourceCrop.left, sourceCrop.top, sourceCrop.right, sourceCrop.bottom);
    fillLayer.alpha = half(alpha);
    clientCompositionLayers.push_back(fillLayer);

    const auto display = renderArea.getDisplayDevice();
    std::vector<Layer*> renderedLayers;
    bool disableBlurs = false;
    traverseLayers([&](Layer* layer) {
        disableBlurs |= layer->getDrawingState().sidebandStream != nullptr;

        Region clip(renderArea.getBounds());
        compositionengine::LayerFE::ClientCompositionTargetSettings targetSettings{
                clip,
                layer->needsFilteringForScreenshots(display.get(), transform) ||
                        renderArea.needsFiltering(),
                renderArea.isSecure(),
                useProtected,
                layerStackSpaceRect,
                clientCompositionDisplay.outputDataspace,
                true,  /* realContentIsVisible */
                false, /* clearContent */
                disableBlurs ? compositionengine::LayerFE::ClientCompositionTargetSettings::
                                       BlurSetting::Disabled
                             : compositionengine::LayerFE::ClientCompositionTargetSettings::
                                       BlurSetting::Enabled,
                isHdrLayer(layer) ? displayBrightnessNits : sdrWhitePointNits,

        };
        std::vector<compositionengine::LayerFE::LayerSettings> results =
                layer->prepareClientCompositionList(targetSettings);
        if (results.size() > 0) {
            for (auto& settings : results) {
                settings.geometry.positionTransform =
                        transform.asMatrix4() * settings.geometry.positionTransform;
                // There's no need to process blurs when we're executing region sampling,
                // we're just trying to understand what we're drawing, and doing so without
                // blurs is already a pretty good approximation.
                if (regionSampling) {
                    settings.backgroundBlurRadius = 0;
                }
                captureResults.capturedHdrLayers |= isHdrLayer(layer);
            }

            clientCompositionLayers.insert(clientCompositionLayers.end(),
                                           std::make_move_iterator(results.begin()),
                                           std::make_move_iterator(results.end()));
            renderedLayers.push_back(layer);
        }

    });

    std::vector<renderengine::LayerSettings> clientRenderEngineLayers;
    clientRenderEngineLayers.reserve(clientCompositionLayers.size());
    std::transform(clientCompositionLayers.begin(), clientCompositionLayers.end(),
                   std::back_inserter(clientRenderEngineLayers),
                   [](compositionengine::LayerFE::LayerSettings& settings)
                           -> renderengine::LayerSettings { return settings; });

    // Use an empty fence for the buffer fence, since we just created the buffer so
    // there is no need for synchronization with the GPU.
    base::unique_fd bufferFence;
    getRenderEngine().useProtectedContext(useProtected);

    constexpr bool kUseFramebufferCache = false;
    auto chain =
            ftl::Future(getRenderEngine().drawLayers(clientCompositionDisplay,
                                                     clientRenderEngineLayers, buffer,
                                                     kUseFramebufferCache, std::move(bufferFence)))
                    .then(&toFenceResult);

    const auto future = chain.share();
    for (auto* layer : renderedLayers) {
        layer->onLayerDisplayed(future);
    }

    // Always switch back to unprotected context.
    getRenderEngine().useProtectedContext(false);

    return future;
}

void SurfaceFlinger::windowInfosReported() {
    Mutex::Autolock _l(mStateLock);
    signalSynchronousTransactions(CountDownLatch::eSyncInputWindows);
}

// ---------------------------------------------------------------------------

void SurfaceFlinger::State::traverse(const LayerVector::Visitor& visitor) const {
    layersSortedByZ.traverse(visitor);
}

void SurfaceFlinger::State::traverseInZOrder(const LayerVector::Visitor& visitor) const {
    layersSortedByZ.traverseInZOrder(stateSet, visitor);
}

void SurfaceFlinger::State::traverseInReverseZOrder(const LayerVector::Visitor& visitor) const {
    layersSortedByZ.traverseInReverseZOrder(stateSet, visitor);
}

void SurfaceFlinger::traverseLayersInLayerStack(ui::LayerStack layerStack, const int32_t uid,
                                                const LayerVector::Visitor& visitor) {
    // We loop through the first level of layers without traversing,
    // as we need to determine which layers belong to the requested display.
    for (const auto& layer : mDrawingState.layersSortedByZ) {
        if (layer->getLayerStack() != layerStack) {
            continue;
        }
        // relative layers are traversed in Layer::traverseInZOrder
        layer->traverseInZOrder(LayerVector::StateSet::Drawing, [&](Layer* layer) {
            if (layer->isInternalDisplayOverlay()) {
                return;
            }
            if (!layer->isVisible()) {
                return;
            }
            if (uid != CaptureArgs::UNSET_UID && layer->getOwnerUid() != uid) {
                return;
            }
            visitor(layer);
        });
    }
}

status_t SurfaceFlinger::setDesiredDisplayModeSpecsInternal(
        const sp<DisplayDevice>& display,
        const std::optional<scheduler::RefreshRateConfigs::Policy>& policy, bool overridePolicy) {
    Mutex::Autolock lock(mStateLock);

    if (mDebugDisplayModeSetByBackdoor) {
        // ignore this request as mode is overridden by backdoor
        return NO_ERROR;
    }

    const status_t setPolicyResult = display->setRefreshRatePolicy(policy, overridePolicy);
    if (setPolicyResult < 0) {
        return BAD_VALUE;
    }
    if (setPolicyResult == scheduler::RefreshRateConfigs::CURRENT_POLICY_UNCHANGED) {
        return NO_ERROR;
    }

    if (display->isInternal() && !isDisplayActiveLocked(display)) {
        // The policy will be be applied when the display becomes active.
        ALOGV("%s(%s): Inactive display", __func__, to_string(display->getId()).c_str());
        return NO_ERROR;
    }

    return applyRefreshRateConfigsPolicy(display);
}

status_t SurfaceFlinger::applyRefreshRateConfigsPolicy(const sp<DisplayDevice>& display,
                                                       bool force) {
    const scheduler::RefreshRateConfigs::Policy currentPolicy =
            display->refreshRateConfigs().getCurrentPolicy();
    ALOGV("Setting desired display mode specs: %s", currentPolicy.toString().c_str());

    // TODO(b/140204874): Leave the event in until we do proper testing with all apps that might
    // be depending in this callback.
    const auto activeMode = display->getActiveMode();
    if (isDisplayActiveLocked(display)) {
        mScheduler->onPrimaryDisplayModeChanged(mAppConnectionHandle, activeMode);
        toggleKernelIdleTimer();
    } else {
        mScheduler->onNonPrimaryDisplayModeChanged(mAppConnectionHandle, activeMode);
    }

    const DisplayModePtr preferredDisplayMode = [&] {
        const auto schedulerMode = mScheduler->getPreferredDisplayMode();
        if (schedulerMode && schedulerMode->getPhysicalDisplayId() == display->getPhysicalId()) {
            return schedulerMode;
        }

        return display->getMode(currentPolicy.defaultMode);
    }();

    ALOGV("trying to switch to Scheduler preferred mode %d (%s)",
          preferredDisplayMode->getId().value(), to_string(preferredDisplayMode->getFps()).c_str());

    if (display->refreshRateConfigs().isModeAllowed(preferredDisplayMode->getId())) {
        ALOGV("switching to Scheduler preferred display mode %d",
              preferredDisplayMode->getId().value());
        setDesiredActiveMode({preferredDisplayMode, DisplayModeEvent::Changed}, force);
    } else {
        LOG_ALWAYS_FATAL("Desired display mode not allowed: %d",
                         preferredDisplayMode->getId().value());
    }

    return NO_ERROR;
}

status_t SurfaceFlinger::setDesiredDisplayModeSpecs(
        const sp<IBinder>& displayToken, ui::DisplayModeId defaultMode, bool allowGroupSwitching,
        float primaryRefreshRateMin, float primaryRefreshRateMax, float appRequestRefreshRateMin,
        float appRequestRefreshRateMax) {
    ATRACE_CALL();

    if (!displayToken) {
        return BAD_VALUE;
    }

    auto future = mScheduler->schedule([=]() -> status_t {
        const auto display = FTL_FAKE_GUARD(mStateLock, getDisplayDeviceLocked(displayToken));
        if (!display) {
            ALOGE("Attempt to set desired display modes for invalid display token %p",
                  displayToken.get());
            return NAME_NOT_FOUND;
        } else if (display->isVirtual()) {
            ALOGW("Attempt to set desired display modes for virtual display");
            return INVALID_OPERATION;
        } else {
            using Policy = scheduler::RefreshRateConfigs::Policy;
            const Policy policy{DisplayModeId(defaultMode),
                                allowGroupSwitching,
                                {Fps::fromValue(primaryRefreshRateMin),
                                 Fps::fromValue(primaryRefreshRateMax)},
                                {Fps::fromValue(appRequestRefreshRateMin),
                                 Fps::fromValue(appRequestRefreshRateMax)}};
            constexpr bool kOverridePolicy = false;

            return setDesiredDisplayModeSpecsInternal(display, policy, kOverridePolicy);
        }
    });

    return future.get();
}

status_t SurfaceFlinger::getDesiredDisplayModeSpecs(const sp<IBinder>& displayToken,
                                                    ui::DisplayModeId* outDefaultMode,
                                                    bool* outAllowGroupSwitching,
                                                    float* outPrimaryRefreshRateMin,
                                                    float* outPrimaryRefreshRateMax,
                                                    float* outAppRequestRefreshRateMin,
                                                    float* outAppRequestRefreshRateMax) {
    ATRACE_CALL();

    if (!displayToken || !outDefaultMode || !outPrimaryRefreshRateMin ||
        !outPrimaryRefreshRateMax || !outAppRequestRefreshRateMin || !outAppRequestRefreshRateMax) {
        return BAD_VALUE;
    }

    Mutex::Autolock lock(mStateLock);
    const auto display = getDisplayDeviceLocked(displayToken);
    if (!display) {
        return NAME_NOT_FOUND;
    }

    if (display->isVirtual()) {
        return INVALID_OPERATION;
    }

    scheduler::RefreshRateConfigs::Policy policy =
            display->refreshRateConfigs().getDisplayManagerPolicy();
    *outDefaultMode = policy.defaultMode.value();
    *outAllowGroupSwitching = policy.allowGroupSwitching;
    *outPrimaryRefreshRateMin = policy.primaryRange.min.getValue();
    *outPrimaryRefreshRateMax = policy.primaryRange.max.getValue();
    *outAppRequestRefreshRateMin = policy.appRequestRange.min.getValue();
    *outAppRequestRefreshRateMax = policy.appRequestRange.max.getValue();
    return NO_ERROR;
}

wp<Layer> SurfaceFlinger::fromHandle(const sp<IBinder>& handle) const {
    return Layer::fromHandle(handle);
}

void SurfaceFlinger::onLayerFirstRef(Layer* layer) {
    mNumLayers++;
    if (!layer->isRemovedFromCurrentState()) {
        mScheduler->registerLayer(layer);
    }
}

void SurfaceFlinger::onLayerDestroyed(Layer* layer) {
    mNumLayers--;
    removeHierarchyFromOffscreenLayers(layer);
    if (!layer->isRemovedFromCurrentState()) {
        mScheduler->deregisterLayer(layer);
    }
    if (mTransactionTracing) {
        mTransactionTracing->onLayerRemoved(layer->getSequence());
    }
}

void SurfaceFlinger::onLayerUpdate() {
    scheduleCommit(FrameHint::kActive);
}

// WARNING: ONLY CALL THIS FROM LAYER DTOR
// Here we add children in the current state to offscreen layers and remove the
// layer itself from the offscreen layer list.  Since
// this is the dtor, it is safe to access the current state.  This keeps us
// from dangling children layers such that they are not reachable from the
// Drawing state nor the offscreen layer list
// See b/141111965
void SurfaceFlinger::removeHierarchyFromOffscreenLayers(Layer* layer) {
    for (auto& child : layer->getCurrentChildren()) {
        mOffscreenLayers.emplace(child.get());
    }
    mOffscreenLayers.erase(layer);
}

void SurfaceFlinger::removeFromOffscreenLayers(Layer* layer) {
    mOffscreenLayers.erase(layer);
}

status_t SurfaceFlinger::setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                                 float lightPosY, float lightPosZ,
                                                 float lightRadius) {
    Mutex::Autolock _l(mStateLock);
    mCurrentState.globalShadowSettings.ambientColor = vec4(ambientColor);
    mCurrentState.globalShadowSettings.spotColor = vec4(spotColor);
    mCurrentState.globalShadowSettings.lightPos.y = lightPosY;
    mCurrentState.globalShadowSettings.lightPos.z = lightPosZ;
    mCurrentState.globalShadowSettings.lightRadius = lightRadius;

    // these values are overridden when calculating the shadow settings for a layer.
    mCurrentState.globalShadowSettings.lightPos.x = 0.f;
    mCurrentState.globalShadowSettings.length = 0.f;
    return NO_ERROR;
}

const std::unordered_map<std::string, uint32_t>& SurfaceFlinger::getGenericLayerMetadataKeyMap()
        const {
    // TODO(b/149500060): Remove this fixed/static mapping. Please prefer taking
    // on the work to remove the table in that bug rather than adding more to
    // it.
    static const std::unordered_map<std::string, uint32_t> genericLayerMetadataKeyMap{
            {"org.chromium.arc.V1_0.TaskId", METADATA_TASK_ID},
            {"org.chromium.arc.V1_0.CursorInfo", METADATA_MOUSE_CURSOR},
    };
    return genericLayerMetadataKeyMap;
}

status_t SurfaceFlinger::setFrameRate(const sp<IGraphicBufferProducer>& surface, float frameRate,
                                      int8_t compatibility, int8_t changeFrameRateStrategy) {
    if (!ValidateFrameRate(frameRate, compatibility, changeFrameRateStrategy,
                           "SurfaceFlinger::setFrameRate")) {
        return BAD_VALUE;
    }

    static_cast<void>(mScheduler->schedule([=] {
        Mutex::Autolock lock(mStateLock);
        if (authenticateSurfaceTextureLocked(surface)) {
            sp<Layer> layer = (static_cast<MonitoredProducer*>(surface.get()))->getLayer();
            if (layer == nullptr) {
                ALOGE("Attempt to set frame rate on a layer that no longer exists");
                return BAD_VALUE;
            }
            const auto strategy =
                    Layer::FrameRate::convertChangeFrameRateStrategy(changeFrameRateStrategy);
            if (layer->setFrameRate(
                        Layer::FrameRate(Fps::fromValue(frameRate),
                                         Layer::FrameRate::convertCompatibility(compatibility),
                                         strategy))) {
                setTransactionFlags(eTraversalNeeded);
            }
        } else {
            ALOGE("Attempt to set frame rate on an unrecognized IGraphicBufferProducer");
            return BAD_VALUE;
        }
        return NO_ERROR;
    }));

    return NO_ERROR;
}

status_t SurfaceFlinger::setOverrideFrameRate(uid_t uid, float frameRate) {
    PhysicalDisplayId displayId = [&]() {
        Mutex::Autolock lock(mStateLock);
        return getDefaultDisplayDeviceLocked()->getPhysicalId();
    }();

    mScheduler->setGameModeRefreshRateForUid(FrameRateOverride{static_cast<uid_t>(uid), frameRate});
    mScheduler->onFrameRateOverridesChanged(mAppConnectionHandle, displayId);
    return NO_ERROR;
}

status_t SurfaceFlinger::setFrameTimelineInfo(const sp<IGraphicBufferProducer>& surface,
                                              const FrameTimelineInfo& frameTimelineInfo) {
    Mutex::Autolock lock(mStateLock);
    if (!authenticateSurfaceTextureLocked(surface)) {
        ALOGE("Attempt to set frame timeline info on an unrecognized IGraphicBufferProducer");
        return BAD_VALUE;
    }

    sp<Layer> layer = (static_cast<MonitoredProducer*>(surface.get()))->getLayer();
    if (layer == nullptr) {
        ALOGE("Attempt to set frame timeline info on a layer that no longer exists");
        return BAD_VALUE;
    }

    layer->setFrameTimelineInfoForBuffer(frameTimelineInfo);
    return NO_ERROR;
}

void SurfaceFlinger::enableRefreshRateOverlay(bool enable) {
    for (const auto& [ignored, display] : mDisplays) {
        if (display->isInternal()) {
            display->enableRefreshRateOverlay(enable, mRefreshRateOverlaySpinner);
        }
    }
}

status_t SurfaceFlinger::addTransactionTraceListener(
        const sp<gui::ITransactionTraceListener>& listener) {
    if (!listener) {
        return BAD_VALUE;
    }

    mInterceptor->addTransactionTraceListener(listener);

    return NO_ERROR;
}

int SurfaceFlinger::getGPUContextPriority() {
    return getRenderEngine().getContextPriority();
}

int SurfaceFlinger::calculateMaxAcquiredBufferCount(Fps refreshRate,
                                                    std::chrono::nanoseconds presentLatency) {
    auto pipelineDepth = presentLatency.count() / refreshRate.getPeriodNsecs();
    if (presentLatency.count() % refreshRate.getPeriodNsecs()) {
        pipelineDepth++;
    }
    return std::max(1ll, pipelineDepth - 1);
}

status_t SurfaceFlinger::getMaxAcquiredBufferCount(int* buffers) const {
    Fps maxRefreshRate = 60_Hz;

    if (!getHwComposer().isHeadless()) {
        if (const auto display = getDefaultDisplayDevice()) {
            maxRefreshRate = display->refreshRateConfigs().getSupportedRefreshRateRange().max;
        }
    }

    *buffers = getMaxAcquiredBufferCountForRefreshRate(maxRefreshRate);
    return NO_ERROR;
}

uint32_t SurfaceFlinger::getMaxAcquiredBufferCountForCurrentRefreshRate(uid_t uid) const {
    Fps refreshRate = 60_Hz;

    if (const auto frameRateOverride = mScheduler->getFrameRateOverride(uid)) {
        refreshRate = *frameRateOverride;
    } else if (!getHwComposer().isHeadless()) {
        if (const auto display = FTL_FAKE_GUARD(mStateLock, getDefaultDisplayDeviceLocked())) {
            refreshRate = display->refreshRateConfigs().getActiveMode()->getFps();
        }
    }

    return getMaxAcquiredBufferCountForRefreshRate(refreshRate);
}

int SurfaceFlinger::getMaxAcquiredBufferCountForRefreshRate(Fps refreshRate) const {
    const auto vsyncConfig = mVsyncConfiguration->getConfigsForRefreshRate(refreshRate).late;
    const auto presentLatency = vsyncConfig.appWorkDuration + vsyncConfig.sfWorkDuration;
    return calculateMaxAcquiredBufferCount(refreshRate, presentLatency);
}

void SurfaceFlinger::handleLayerCreatedLocked(const LayerCreatedState& state) {
    sp<Layer> layer = state.layer.promote();
    if (!layer) {
        ALOGD("Layer was destroyed soon after creation %p", state.layer.unsafe_get());
        return;
    }
    MUTEX_ALIAS(mStateLock, layer->mFlinger->mStateLock);

    sp<Layer> parent;
    bool addToRoot = state.addToRoot;
    if (state.initialParent != nullptr) {
        parent = state.initialParent.promote();
        if (parent == nullptr) {
            ALOGD("Parent was destroyed soon after creation %p", state.initialParent.unsafe_get());
            addToRoot = false;
        }
    }

    if (parent == nullptr && addToRoot) {
        layer->setIsAtRoot(true);
        mCurrentState.layersSortedByZ.add(layer);
    } else if (parent == nullptr) {
        layer->onRemovedFromCurrentState();
    } else if (parent->isRemovedFromCurrentState()) {
        parent->addChild(layer);
        layer->onRemovedFromCurrentState();
    } else {
        parent->addChild(layer);
    }

    layer->updateTransformHint(mActiveDisplayTransformHint);

    mInterceptor->saveSurfaceCreation(layer);
}

void SurfaceFlinger::sample() {
    if (!mLumaSampling || !mRegionSamplingThread) {
        return;
    }

    mRegionSamplingThread->onCompositionComplete(mScheduler->getScheduledFrameTime());
}

void SurfaceFlinger::onActiveDisplaySizeChanged(const sp<DisplayDevice>& activeDisplay) {
    mScheduler->onActiveDisplayAreaChanged(activeDisplay->getWidth() * activeDisplay->getHeight());
    getRenderEngine().onActiveDisplaySizeChanged(activeDisplay->getSize());
}

void SurfaceFlinger::onActiveDisplayChangedLocked(const sp<DisplayDevice>& activeDisplay) {
    ATRACE_CALL();

    // During boot, SF powers on the primary display, which is the first display to be active. In
    // that case, there is no need to force setDesiredActiveMode, because DM is about to send its
    // policy via setDesiredDisplayModeSpecs.
    bool forceApplyPolicy = false;

    if (const auto display = getDisplayDeviceLocked(mActiveDisplayToken)) {
        display->getCompositionDisplay()->setLayerCachingTexturePoolEnabled(false);
        forceApplyPolicy = true;
    }

    if (!activeDisplay) {
        ALOGE("%s: activeDisplay is null", __func__);
        return;
    }

    ALOGI("Active display is %s", to_string(activeDisplay->getPhysicalId()).c_str());

    mActiveDisplayToken = activeDisplay->getDisplayToken();
    activeDisplay->getCompositionDisplay()->setLayerCachingTexturePoolEnabled(true);
    updateInternalDisplayVsyncLocked(activeDisplay);
    mScheduler->setModeChangePending(false);
    mScheduler->setRefreshRateConfigs(activeDisplay->holdRefreshRateConfigs());
    onActiveDisplaySizeChanged(activeDisplay);
    mActiveDisplayTransformHint = activeDisplay->getTransformHint();

    // The policy of the new active/leader display may have changed while it was inactive. In that
    // case, its preferred mode has not been propagated to HWC (via setDesiredActiveMode). In either
    // case, the Scheduler's cachedModeChangedParams must be initialized to the newly active mode,
    // and the kernel idle timer of the newly active display must be toggled.
    applyRefreshRateConfigsPolicy(activeDisplay, forceApplyPolicy);
}

status_t SurfaceFlinger::addWindowInfosListener(
        const sp<IWindowInfosListener>& windowInfosListener) const {
    mWindowInfosListenerInvoker->addWindowInfosListener(windowInfosListener);
    return NO_ERROR;
}

status_t SurfaceFlinger::removeWindowInfosListener(
        const sp<IWindowInfosListener>& windowInfosListener) const {
    mWindowInfosListenerInvoker->removeWindowInfosListener(windowInfosListener);
    return NO_ERROR;
}

std::shared_ptr<renderengine::ExternalTexture> SurfaceFlinger::getExternalTextureFromBufferData(
        const BufferData& bufferData, const char* layerName) const {
    bool cacheIdChanged = bufferData.flags.test(BufferData::BufferDataChange::cachedBufferChanged);
    bool bufferSizeExceedsLimit = false;
    std::shared_ptr<renderengine::ExternalTexture> buffer = nullptr;
    if (cacheIdChanged && bufferData.buffer != nullptr) {
        bufferSizeExceedsLimit = exceedsMaxRenderTargetSize(bufferData.buffer->getWidth(),
                                                            bufferData.buffer->getHeight());
        if (!bufferSizeExceedsLimit) {
            ClientCache::getInstance().add(bufferData.cachedBuffer, bufferData.buffer);
            buffer = ClientCache::getInstance().get(bufferData.cachedBuffer);
        }
    } else if (cacheIdChanged) {
        buffer = ClientCache::getInstance().get(bufferData.cachedBuffer);
    } else if (bufferData.buffer != nullptr) {
        bufferSizeExceedsLimit = exceedsMaxRenderTargetSize(bufferData.buffer->getWidth(),
                                                            bufferData.buffer->getHeight());
        if (!bufferSizeExceedsLimit) {
            buffer = std::make_shared<
                    renderengine::impl::ExternalTexture>(bufferData.buffer, getRenderEngine(),
                                                         renderengine::impl::ExternalTexture::
                                                                 Usage::READABLE);
        }
    }
    ALOGE_IF(bufferSizeExceedsLimit,
             "Attempted to create an ExternalTexture for layer %s that exceeds render target size "
             "limit.",
             layerName);
    return buffer;
}

bool SurfaceFlinger::commitCreatedLayers() {
    std::vector<LayerCreatedState> createdLayers;
    {
        std::scoped_lock<std::mutex> lock(mCreatedLayersLock);
        createdLayers = std::move(mCreatedLayers);
        mCreatedLayers.clear();
        if (createdLayers.size() == 0) {
            return false;
        }
    }

    Mutex::Autolock _l(mStateLock);
    for (const auto& createdLayer : createdLayers) {
        handleLayerCreatedLocked(createdLayer);
    }
    createdLayers.clear();
    mLayersAdded = true;
    return true;
}

// gui::ISurfaceComposer

binder::Status SurfaceComposerAIDL::createDisplay(const std::string& displayName, bool secure,
                                                  sp<IBinder>* outDisplay) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        String8 displayName8 = String8::format("%s", displayName.c_str());
        *outDisplay = mFlinger->createDisplay(displayName8, secure);
        return binder::Status::ok();
    }
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::destroyDisplay(const sp<IBinder>& display) {
    status_t status = checkAccessPermission();
    if (status == OK) {
        mFlinger->destroyDisplay(display);
        return binder::Status::ok();
    }
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getPhysicalDisplayIds(std::vector<int64_t>* outDisplayIds) {
    std::vector<PhysicalDisplayId> physicalDisplayIds = mFlinger->getPhysicalDisplayIds();
    std::vector<int64_t> displayIds;
    displayIds.reserve(physicalDisplayIds.size());
    for (auto item : physicalDisplayIds) {
        displayIds.push_back(static_cast<int64_t>(item.value));
    }
    *outDisplayIds = displayIds;
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::getPrimaryPhysicalDisplayId(int64_t* outDisplayId) {
    status_t status = checkAccessPermission();
    if (status != OK) {
        return binder::Status::fromStatusT(status);
    }

    PhysicalDisplayId id;
    status = mFlinger->getPrimaryPhysicalDisplayId(&id);
    if (status == NO_ERROR) {
        *outDisplayId = id.value;
    }
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getPhysicalDisplayToken(int64_t displayId,
                                                            sp<IBinder>* outDisplay) {
    const auto id = DisplayId::fromValue<PhysicalDisplayId>(static_cast<uint64_t>(displayId));
    *outDisplay = mFlinger->getPhysicalDisplayToken(*id);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::setPowerMode(const sp<IBinder>& display, int mode) {
    status_t status = checkAccessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    mFlinger->setPowerMode(display, mode);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::getDisplayStats(const sp<IBinder>& display,
                                                    gui::DisplayStatInfo* outStatInfo) {
    DisplayStatInfo statInfo;
    status_t status = mFlinger->getDisplayStats(display, &statInfo);
    if (status == NO_ERROR) {
        outStatInfo->vsyncTime = static_cast<long>(statInfo.vsyncTime);
        outStatInfo->vsyncPeriod = static_cast<long>(statInfo.vsyncPeriod);
    }
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayState(const sp<IBinder>& display,
                                                    gui::DisplayState* outState) {
    ui::DisplayState state;
    status_t status = mFlinger->getDisplayState(display, &state);
    if (status == NO_ERROR) {
        outState->layerStack = state.layerStack.id;
        outState->orientation = static_cast<gui::Rotation>(state.orientation);
        outState->layerStackSpaceRect.width = state.layerStackSpaceRect.width;
        outState->layerStackSpaceRect.height = state.layerStackSpaceRect.height;
    }
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::clearBootDisplayMode(const sp<IBinder>& display) {
    status_t status = checkAccessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    status = mFlinger->clearBootDisplayMode(display);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getBootDisplayModeSupport(bool* outMode) {
    status_t status = checkAccessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    status = mFlinger->getBootDisplayModeSupport(outMode);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setAutoLowLatencyMode(const sp<IBinder>& display, bool on) {
    status_t status = checkAccessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    mFlinger->setAutoLowLatencyMode(display, on);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::setGameContentType(const sp<IBinder>& display, bool on) {
    status_t status = checkAccessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    mFlinger->setGameContentType(display, on);
    return binder::Status::ok();
}

binder::Status SurfaceComposerAIDL::captureDisplay(
        const DisplayCaptureArgs& args, const sp<IScreenCaptureListener>& captureListener) {
    status_t status = mFlinger->captureDisplay(args, captureListener);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::captureDisplayById(
        int64_t displayId, const sp<IScreenCaptureListener>& captureListener) {
    status_t status;
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();
    if (uid == AID_ROOT || uid == AID_GRAPHICS || uid == AID_SYSTEM || uid == AID_SHELL) {
        std::optional<DisplayId> id = DisplayId::fromValue(static_cast<uint64_t>(displayId));
        status = mFlinger->captureDisplay(*id, captureListener);
    } else {
        status = PERMISSION_DENIED;
    }
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::captureLayers(
        const LayerCaptureArgs& args, const sp<IScreenCaptureListener>& captureListener) {
    status_t status = mFlinger->captureLayers(args, captureListener);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::isWideColorDisplay(const sp<IBinder>& token,
                                                       bool* outIsWideColorDisplay) {
    status_t status = mFlinger->isWideColorDisplay(token, outIsWideColorDisplay);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::getDisplayBrightnessSupport(const sp<IBinder>& displayToken,
                                                                bool* outSupport) {
    status_t status = mFlinger->getDisplayBrightnessSupport(displayToken, outSupport);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::setDisplayBrightness(const sp<IBinder>& displayToken,
                                                         const gui::DisplayBrightness& brightness) {
    status_t status = checkControlDisplayBrightnessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    status = mFlinger->setDisplayBrightness(displayToken, brightness);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::addHdrLayerInfoListener(
        const sp<IBinder>& displayToken, const sp<gui::IHdrLayerInfoListener>& listener) {
    status_t status = checkControlDisplayBrightnessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    status = mFlinger->addHdrLayerInfoListener(displayToken, listener);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::removeHdrLayerInfoListener(
        const sp<IBinder>& displayToken, const sp<gui::IHdrLayerInfoListener>& listener) {
    status_t status = checkControlDisplayBrightnessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    status = mFlinger->removeHdrLayerInfoListener(displayToken, listener);
    return binder::Status::fromStatusT(status);
}

binder::Status SurfaceComposerAIDL::notifyPowerBoost(int boostId) {
    status_t status = checkAccessPermission();
    if (status != OK) return binder::Status::fromStatusT(status);

    status = mFlinger->notifyPowerBoost(boostId);
    return binder::Status::fromStatusT(status);
}

status_t SurfaceComposerAIDL::checkAccessPermission(bool usePermissionCache) {
    if (!mFlinger->callingThreadHasUnscopedSurfaceFlingerAccess(usePermissionCache)) {
        IPCThreadState* ipc = IPCThreadState::self();
        ALOGE("Permission Denial: can't access SurfaceFlinger pid=%d, uid=%d", ipc->getCallingPid(),
              ipc->getCallingUid());
        return PERMISSION_DENIED;
    }
    return OK;
}

status_t SurfaceComposerAIDL::checkControlDisplayBrightnessPermission() {
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    const int uid = ipc->getCallingUid();
    if ((uid != AID_GRAPHICS) && (uid != AID_SYSTEM) &&
        !PermissionCache::checkPermission(sControlDisplayBrightness, pid, uid)) {
        ALOGE("Permission Denial: can't control brightness pid=%d, uid=%d", pid, uid);
        return PERMISSION_DENIED;
    }
    return OK;
}

} // namespace android

#if defined(__gl_h_)
#error "don't include gl/gl.h in this file"
#endif

#if defined(__gl2_h_)
#error "don't include gl2/gl2.h in this file"
#endif

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
