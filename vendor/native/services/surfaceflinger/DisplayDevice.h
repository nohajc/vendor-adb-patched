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

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include <android-base/thread_annotations.h>
#include <android/native_window.h>
#include <binder/IBinder.h>
#include <gui/LayerState.h>
#include <math/mat4.h>
#include <renderengine/RenderEngine.h>
#include <system/window.h>
#include <ui/DisplayId.h>
#include <ui/DisplayIdentification.h>
#include <ui/DisplayState.h>
#include <ui/GraphicTypes.h>
#include <ui/HdrCapabilities.h>
#include <ui/Region.h>
#include <ui/StaticDisplayInfo.h>
#include <ui/Transform.h>
#include <utils/Errors.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include "DisplayHardware/DisplayMode.h"
#include "DisplayHardware/Hal.h"
#include "DisplayHardware/PowerAdvisor.h"
#include "Scheduler/RefreshRateConfigs.h"
#include "ThreadContext.h"
#include "TracedOrdinal.h"

namespace android {

class Fence;
class HWComposer;
class IGraphicBufferProducer;
class Layer;
class RefreshRateOverlay;
class SurfaceFlinger;

struct CompositionInfo;
struct DisplayDeviceCreationArgs;

namespace compositionengine {
class Display;
class DisplaySurface;
} // namespace compositionengine

class DisplayDevice : public RefBase {
public:
    constexpr static float sDefaultMinLumiance = 0.0;
    constexpr static float sDefaultMaxLumiance = 500.0;
    enum { eReceivesInput = 0x01 };

    explicit DisplayDevice(DisplayDeviceCreationArgs& args);

    // Must be destroyed on the main thread because it may call into HWComposer.
    virtual ~DisplayDevice();

    std::shared_ptr<compositionengine::Display> getCompositionDisplay() const {
        return mCompositionDisplay;
    }

    std::optional<ui::DisplayConnectionType> getConnectionType() const { return mConnectionType; }

    bool isVirtual() const { return !mConnectionType; }
    bool isPrimary() const { return mIsPrimary; }
    bool isInternal() const { return mConnectionType == ui::DisplayConnectionType::Internal; }

    // isSecure indicates whether this display can be trusted to display
    // secure surfaces.
    bool isSecure() const;

    int getWidth() const;
    int getHeight() const;
    ui::Size getSize() const { return {getWidth(), getHeight()}; }

    void setLayerStack(ui::LayerStack);
    void setDisplaySize(int width, int height);
    void setProjection(ui::Rotation orientation, Rect viewport, Rect frame);
    void stageBrightness(float brightness) REQUIRES(kMainThreadContext);
    void persistBrightness(bool needsComposite) REQUIRES(kMainThreadContext);
    bool isBrightnessStale() const REQUIRES(kMainThreadContext);
    void setFlags(uint32_t flags);

    ui::Rotation getPhysicalOrientation() const { return mPhysicalOrientation; }
    ui::Rotation getOrientation() const { return mOrientation; }

    static ui::Transform::RotationFlags getPrimaryDisplayRotationFlags();

    std::optional<float> getStagedBrightness() const REQUIRES(kMainThreadContext);
    ui::Transform::RotationFlags getTransformHint() const;
    const ui::Transform& getTransform() const;
    const Rect& getLayerStackSpaceRect() const;
    const Rect& getOrientedDisplaySpaceRect() const;
    bool needsFiltering() const;
    ui::LayerStack getLayerStack() const;
    bool receivesInput() const { return mFlags & eReceivesInput; }

    DisplayId getId() const;

    // Shorthand to upcast the ID of a display whose type is known as a precondition.
    PhysicalDisplayId getPhysicalId() const {
        const auto id = PhysicalDisplayId::tryCast(getId());
        LOG_FATAL_IF(!id);
        return *id;
    }

    VirtualDisplayId getVirtualId() const {
        const auto id = VirtualDisplayId::tryCast(getId());
        LOG_FATAL_IF(!id);
        return *id;
    }

    const wp<IBinder>& getDisplayToken() const { return mDisplayToken; }
    int32_t getSequenceId() const { return mSequenceId; }

    const Region& getUndefinedRegion() const;

    int32_t getSupportedPerFrameMetadata() const;

    bool hasWideColorGamut() const;
    // Whether h/w composer has native support for specific HDR type.
    bool hasHDR10PlusSupport() const;
    bool hasHDR10Support() const;
    bool hasHLGSupport() const;
    bool hasDolbyVisionSupport() const;

    void overrideHdrTypes(const std::vector<ui::Hdr>& hdrTypes);

    // The returned HdrCapabilities is the combination of HDR capabilities from
    // hardware composer and RenderEngine. When the DisplayDevice supports wide
    // color gamut, RenderEngine is able to simulate HDR support in Display P3
    // color space for both PQ and HLG HDR contents. The minimum and maximum
    // luminance will be set to sDefaultMinLumiance and sDefaultMaxLumiance
    // respectively if hardware composer doesn't return meaningful values.
    HdrCapabilities getHdrCapabilities() const;

    // Return true if intent is supported by the display.
    bool hasRenderIntent(ui::RenderIntent intent) const;

    const Rect getBounds() const;
    const Rect bounds() const { return getBounds(); }

    void setDisplayName(const std::string& displayName);
    const std::string& getDisplayName() const { return mDisplayName; }

    void setDeviceProductInfo(std::optional<DeviceProductInfo> info);
    const std::optional<DeviceProductInfo>& getDeviceProductInfo() const {
        return mDeviceProductInfo;
    }

    struct InputInfo {
        gui::DisplayInfo info;
        ui::Transform transform;
        bool receivesInput;
        bool isSecure;
    };

    InputInfo getInputInfo() const;

    /* ------------------------------------------------------------------------
     * Display power mode management.
     */
    std::optional<hardware::graphics::composer::hal::PowerMode> getPowerMode() const;
    void setPowerMode(hardware::graphics::composer::hal::PowerMode mode);
    bool isPoweredOn() const;

    // Enables layer caching on this DisplayDevice
    void enableLayerCaching(bool enable);

    ui::Dataspace getCompositionDataSpace() const;

    /* ------------------------------------------------------------------------
     * Display mode management.
     */
    const DisplayModePtr& getActiveMode() const;

    struct ActiveModeInfo {
        DisplayModePtr mode;
        scheduler::DisplayModeEvent event = scheduler::DisplayModeEvent::None;

        bool operator!=(const ActiveModeInfo& other) const {
            return mode != other.mode || event != other.event;
        }
    };

    bool setDesiredActiveMode(const ActiveModeInfo&, bool force = false) EXCLUDES(mActiveModeLock);
    std::optional<ActiveModeInfo> getDesiredActiveMode() const EXCLUDES(mActiveModeLock);
    void clearDesiredActiveModeState() EXCLUDES(mActiveModeLock);
    ActiveModeInfo getUpcomingActiveMode() const REQUIRES(kMainThreadContext) {
        return mUpcomingActiveMode;
    }

    void setActiveMode(DisplayModeId) REQUIRES(kMainThreadContext);
    status_t initiateModeChange(const ActiveModeInfo&,
                                const hal::VsyncPeriodChangeConstraints& constraints,
                                hal::VsyncPeriodChangeTimeline* outTimeline)
            REQUIRES(kMainThreadContext);

    // Return the immutable list of supported display modes. The HWC may report different modes
    // after a hotplug reconnect event, in which case the DisplayDevice object will be recreated.
    // Hotplug reconnects are common for external displays.
    const DisplayModes& getSupportedModes() const;

    // Returns nullptr if the given mode ID is not supported. A previously
    // supported mode may be no longer supported for some devices like TVs and
    // set-top boxes after a hotplug reconnect.
    DisplayModePtr getMode(DisplayModeId) const;

    std::optional<DisplayModeId> translateModeId(hal::HWConfigId) const;

    // Returns the refresh rate configs for this display.
    scheduler::RefreshRateConfigs& refreshRateConfigs() const { return *mRefreshRateConfigs; }

    // Returns a shared pointer to the refresh rate configs for this display.
    // Clients can store this refresh rate configs and use it even if the DisplayDevice
    // is destroyed.
    std::shared_ptr<scheduler::RefreshRateConfigs> holdRefreshRateConfigs() const {
        return mRefreshRateConfigs;
    }

    // Enables an overlay to be displayed with the current refresh rate
    void enableRefreshRateOverlay(bool enable, bool showSpinner);
    bool isRefreshRateOverlayEnabled() const { return mRefreshRateOverlay != nullptr; }
    bool onKernelTimerChanged(std::optional<DisplayModeId>, bool timerExpired);
    void animateRefreshRateOverlay();

    void onVsync(nsecs_t timestamp);
    nsecs_t getVsyncPeriodFromHWC() const;
    nsecs_t getRefreshTimestamp() const;

    status_t setRefreshRatePolicy(
            const std::optional<scheduler::RefreshRateConfigs::Policy>& policy,
            bool overridePolicy);

    // release HWC resources (if any) for removable displays
    void disconnect();

    /* ------------------------------------------------------------------------
     * Debugging
     */
    uint32_t getPageFlipCount() const;
    std::string getDebugName() const;
    void dump(std::string& result) const;

private:
    const sp<SurfaceFlinger> mFlinger;
    HWComposer& mHwComposer;
    const wp<IBinder> mDisplayToken;
    const int32_t mSequenceId;
    const std::optional<ui::DisplayConnectionType> mConnectionType;

    const std::shared_ptr<compositionengine::Display> mCompositionDisplay;

    std::string mDisplayName;
    std::string mActiveModeFPSTrace;
    std::string mActiveModeFPSHwcTrace;

    const ui::Rotation mPhysicalOrientation;
    ui::Rotation mOrientation = ui::ROTATION_0;

    static ui::Transform::RotationFlags sPrimaryDisplayRotationFlags;

     // allow initial power mode as null.
    std::optional<hardware::graphics::composer::hal::PowerMode> mPowerMode;
    DisplayModePtr mActiveMode;
    std::optional<float> mStagedBrightness;
    std::optional<float> mBrightness;
    const DisplayModes mSupportedModes;

    std::atomic<nsecs_t> mLastHwVsync = 0;

    // TODO(b/182939859): Remove special cases for primary display.
    const bool mIsPrimary;

    uint32_t mFlags = 0;

    std::optional<DeviceProductInfo> mDeviceProductInfo;

    std::vector<ui::Hdr> mOverrideHdrTypes;

    std::shared_ptr<scheduler::RefreshRateConfigs> mRefreshRateConfigs;
    std::unique_ptr<RefreshRateOverlay> mRefreshRateOverlay;

    mutable std::mutex mActiveModeLock;
    ActiveModeInfo mDesiredActiveMode GUARDED_BY(mActiveModeLock);
    TracedOrdinal<bool> mDesiredActiveModeChanged
            GUARDED_BY(mActiveModeLock) = {"DesiredActiveModeChanged", false};
    ActiveModeInfo mUpcomingActiveMode GUARDED_BY(kMainThreadContext);

    std::atomic_int mNumModeSwitchesInPolicy = 0;
};

struct DisplayDeviceState {
    struct Physical {
        PhysicalDisplayId id;
        ui::DisplayConnectionType type;
        hardware::graphics::composer::hal::HWDisplayId hwcDisplayId;
        std::optional<DeviceProductInfo> deviceProductInfo;
        DisplayModes supportedModes;
        DisplayModePtr activeMode;

        bool operator==(const Physical& other) const {
            return id == other.id && type == other.type && hwcDisplayId == other.hwcDisplayId;
        }
    };

    bool isVirtual() const { return !physical; }

    int32_t sequenceId = sNextSequenceId++;
    std::optional<Physical> physical;
    sp<IGraphicBufferProducer> surface;
    ui::LayerStack layerStack;
    uint32_t flags = 0;
    Rect layerStackSpaceRect;
    Rect orientedDisplaySpaceRect;
    ui::Rotation orientation = ui::ROTATION_0;
    uint32_t width = 0;
    uint32_t height = 0;
    std::string displayName;
    bool isSecure = false;

private:
    static std::atomic<int32_t> sNextSequenceId;
};

struct DisplayDeviceCreationArgs {
    // We use a constructor to ensure some of the values are set, without
    // assuming a default value.
    DisplayDeviceCreationArgs(const sp<SurfaceFlinger>&, HWComposer& hwComposer,
                              const wp<IBinder>& displayToken,
                              std::shared_ptr<compositionengine::Display>);
    const sp<SurfaceFlinger> flinger;
    HWComposer& hwComposer;
    const wp<IBinder> displayToken;
    const std::shared_ptr<compositionengine::Display> compositionDisplay;
    std::shared_ptr<scheduler::RefreshRateConfigs> refreshRateConfigs;

    int32_t sequenceId{0};
    std::optional<ui::DisplayConnectionType> connectionType;
    bool isSecure{false};
    sp<ANativeWindow> nativeWindow;
    sp<compositionengine::DisplaySurface> displaySurface;
    ui::Rotation physicalOrientation{ui::ROTATION_0};
    bool hasWideColorGamut{false};
    HdrCapabilities hdrCapabilities;
    int32_t supportedPerFrameMetadata{0};
    std::unordered_map<ui::ColorMode, std::vector<ui::RenderIntent>> hwcColorModes;
    std::optional<hardware::graphics::composer::hal::PowerMode> initialPowerMode;
    bool isPrimary{false};
    DisplayModes supportedModes;
    DisplayModeId activeModeId;
};

} // namespace android
