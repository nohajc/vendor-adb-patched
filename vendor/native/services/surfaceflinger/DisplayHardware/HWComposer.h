/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/thread_annotations.h>
#include <ftl/future.h>
#include <ui/DisplayIdentification.h>
#include <ui/FenceTime.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"
#include <ui/GraphicTypes.h>
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"

#include <utils/StrongPointer.h>
#include <utils/Timers.h>

#include "DisplayMode.h"
#include "HWC2.h"
#include "Hal.h"

#include <aidl/android/hardware/graphics/common/DisplayDecorationSupport.h>
#include <aidl/android/hardware/graphics/composer3/Capability.h>
#include <aidl/android/hardware/graphics/composer3/ClientTargetPropertyWithBrightness.h>
#include <aidl/android/hardware/graphics/composer3/Composition.h>
#include <aidl/android/hardware/graphics/composer3/DisplayCapability.h>

namespace android {

namespace hal = hardware::graphics::composer::hal;

struct DisplayedFrameStats;
class GraphicBuffer;
class TestableSurfaceFlinger;
struct CompositionInfo;

namespace Hwc2 {
class Composer;
} // namespace Hwc2

namespace compositionengine {
class Output;
} // namespace compositionengine

struct KnownHWCGenericLayerMetadata {
    const char* name;
    const uint32_t id;
};

// See the comment for SurfaceFlinger::getHwComposer for the thread safety rules for accessing
// this class.
class HWComposer {
public:
    struct DeviceRequestedChanges {
        using ChangedTypes =
                std::unordered_map<HWC2::Layer*,
                                   aidl::android::hardware::graphics::composer3::Composition>;
        using ClientTargetProperty =
                aidl::android::hardware::graphics::composer3::ClientTargetPropertyWithBrightness;
        using DisplayRequests = hal::DisplayRequest;
        using LayerRequests = std::unordered_map<HWC2::Layer*, hal::LayerRequest>;

        ChangedTypes changedTypes;
        DisplayRequests displayRequests;
        LayerRequests layerRequests;
        ClientTargetProperty clientTargetProperty;
    };

    struct HWCDisplayMode {
        hal::HWConfigId hwcId;
        int32_t width = -1;
        int32_t height = -1;
        nsecs_t vsyncPeriod = -1;
        int32_t dpiX = -1;
        int32_t dpiY = -1;
        int32_t configGroup = -1;

        friend std::ostream& operator<<(std::ostream& os, const HWCDisplayMode& mode) {
            return os << "id=" << mode.hwcId << " res=" << mode.width << "x" << mode.height
                      << " vsyncPeriod=" << mode.vsyncPeriod << " dpi=" << mode.dpiX << "x"
                      << mode.dpiY << " group=" << mode.configGroup;
        }
    };

    virtual ~HWComposer();

    virtual void setCallback(HWC2::ComposerCallback&) = 0;

    virtual bool getDisplayIdentificationData(hal::HWDisplayId, uint8_t* outPort,
                                              DisplayIdentificationData* outData) const = 0;

    virtual bool hasCapability(aidl::android::hardware::graphics::composer3::Capability) const = 0;
    virtual bool hasDisplayCapability(
            HalDisplayId,
            aidl::android::hardware::graphics::composer3::DisplayCapability) const = 0;

    virtual size_t getMaxVirtualDisplayCount() const = 0;
    virtual size_t getMaxVirtualDisplayDimension() const = 0;

    // Attempts to allocate a virtual display on the HWC. The maximum number of virtual displays
    // supported by the HWC can be queried in advance, but allocation may fail for other reasons.
    virtual bool allocateVirtualDisplay(HalVirtualDisplayId, ui::Size, ui::PixelFormat*) = 0;

    virtual void allocatePhysicalDisplay(hal::HWDisplayId, PhysicalDisplayId) = 0;

    // Attempts to create a new layer on this display
    virtual std::shared_ptr<HWC2::Layer> createLayer(HalDisplayId) = 0;

    // Gets any required composition change requests from the HWC device.
    //
    // Note that frameUsesClientComposition must be set correctly based on
    // whether the current frame appears to use client composition. If it is
    // false some internal optimizations are allowed to present the display
    // with fewer handshakes, but this does not work if client composition is
    // expected.
    virtual status_t getDeviceCompositionChanges(
            HalDisplayId, bool frameUsesClientComposition,
            std::chrono::steady_clock::time_point earliestPresentTime,
            const std::shared_ptr<FenceTime>& previousPresentFence, nsecs_t expectedPresentTime,
            std::optional<DeviceRequestedChanges>* outChanges) = 0;

    virtual status_t setClientTarget(HalDisplayId, uint32_t slot, const sp<Fence>& acquireFence,
                                     const sp<GraphicBuffer>& target, ui::Dataspace) = 0;

    // Present layers to the display and read releaseFences.
    virtual status_t presentAndGetReleaseFences(
            HalDisplayId, std::chrono::steady_clock::time_point earliestPresentTime,
            const std::shared_ptr<FenceTime>& previousPresentFence) = 0;

    // set power mode
    virtual status_t setPowerMode(PhysicalDisplayId, hal::PowerMode) = 0;

    // Sets a color transform to be applied to the result of composition
    virtual status_t setColorTransform(HalDisplayId, const mat4& transform) = 0;

    // reset state when a display is disconnected
    virtual void disconnectDisplay(HalDisplayId) = 0;

    // get the present fence received from the last call to present.
    virtual sp<Fence> getPresentFence(HalDisplayId) const = 0;

    // Get last release fence for the given layer
    virtual sp<Fence> getLayerReleaseFence(HalDisplayId, HWC2::Layer*) const = 0;

    // Set the output buffer and acquire fence for a virtual display.
    virtual status_t setOutputBuffer(HalVirtualDisplayId, const sp<Fence>& acquireFence,
                                     const sp<GraphicBuffer>& buffer) = 0;

    // After SurfaceFlinger has retrieved the release fences for all the frames,
    // it can call this to clear the shared pointers in the release fence map
    virtual void clearReleaseFences(HalDisplayId) = 0;

    // Fetches the HDR capabilities of the given display
    virtual status_t getHdrCapabilities(HalDisplayId, HdrCapabilities* outCapabilities) = 0;

    virtual int32_t getSupportedPerFrameMetadata(HalDisplayId) const = 0;

    // Returns the available RenderIntent of the given display.
    virtual std::vector<ui::RenderIntent> getRenderIntents(HalDisplayId, ui::ColorMode) const = 0;

    virtual mat4 getDataspaceSaturationMatrix(HalDisplayId, ui::Dataspace) = 0;

    // Returns the attributes of the color sampling engine.
    virtual status_t getDisplayedContentSamplingAttributes(HalDisplayId, ui::PixelFormat* outFormat,
                                                           ui::Dataspace* outDataspace,
                                                           uint8_t* outComponentMask) = 0;
    virtual status_t setDisplayContentSamplingEnabled(HalDisplayId, bool enabled,
                                                      uint8_t componentMask,
                                                      uint64_t maxFrames) = 0;
    virtual status_t getDisplayedContentSample(HalDisplayId, uint64_t maxFrames, uint64_t timestamp,
                                               DisplayedFrameStats* outStats) = 0;

    // Sets the brightness of a display.
    virtual ftl::Future<status_t> setDisplayBrightness(
            PhysicalDisplayId, float brightness, float brightnessNits,
            const Hwc2::Composer::DisplayBrightnessOptions&) = 0;

    // Get whether the display skipped validation on the latest present
    virtual bool getValidateSkipped(HalDisplayId displayId) const = 0;

    // Events handling ---------------------------------------------------------

    // Returns stable display ID (and display name on connection of new or previously disconnected
    // display), or std::nullopt if hotplug event was ignored.
    // This function is called from SurfaceFlinger.
    virtual std::optional<DisplayIdentificationInfo> onHotplug(hal::HWDisplayId,
                                                               hal::Connection) = 0;

    // If true we'll update the DeviceProductInfo on subsequent hotplug connected events.
    // TODO(b/157555476): Remove when the framework has proper support for headless mode
    virtual bool updatesDeviceProductInfoOnHotplugReconnect() const = 0;

    virtual bool onVsync(hal::HWDisplayId, int64_t timestamp) = 0;
    virtual void setVsyncEnabled(PhysicalDisplayId, hal::Vsync enabled) = 0;

    virtual bool isConnected(PhysicalDisplayId) const = 0;

    virtual std::vector<HWCDisplayMode> getModes(PhysicalDisplayId) const = 0;

    virtual std::optional<hal::HWConfigId> getActiveMode(PhysicalDisplayId) const = 0;

    virtual std::vector<ui::ColorMode> getColorModes(PhysicalDisplayId) const = 0;

    virtual status_t setActiveColorMode(PhysicalDisplayId, ui::ColorMode mode,
                                        ui::RenderIntent) = 0;

    // Composer 2.4
    virtual ui::DisplayConnectionType getDisplayConnectionType(PhysicalDisplayId) const = 0;
    virtual bool isVsyncPeriodSwitchSupported(PhysicalDisplayId) const = 0;
    virtual status_t getDisplayVsyncPeriod(PhysicalDisplayId displayId,
                                           nsecs_t* outVsyncPeriod) const = 0;
    virtual status_t setActiveModeWithConstraints(PhysicalDisplayId, hal::HWConfigId,
                                                  const hal::VsyncPeriodChangeConstraints&,
                                                  hal::VsyncPeriodChangeTimeline* outTimeline) = 0;
    virtual status_t setAutoLowLatencyMode(PhysicalDisplayId, bool on) = 0;
    virtual status_t getSupportedContentTypes(
            PhysicalDisplayId, std::vector<hal::ContentType>* outSupportedContentTypes) const = 0;

    bool supportsContentType(PhysicalDisplayId displayId, hal::ContentType type) const {
        std::vector<hal::ContentType> types;
        return getSupportedContentTypes(displayId, &types) == NO_ERROR &&
                std::find(types.begin(), types.end(), type) != types.end();
    }

    virtual status_t setContentType(PhysicalDisplayId, hal::ContentType) = 0;

    virtual const std::unordered_map<std::string, bool>& getSupportedLayerGenericMetadata()
            const = 0;

    virtual void dump(std::string& out) const = 0;

    virtual Hwc2::Composer* getComposer() const = 0;

    // Returns the first display connected at boot. Its connection via HWComposer::onHotplug,
    // which in practice is immediately after HWComposer construction, must occur before any
    // call to this function.
    // The primary display can be temporarily disconnected from the perspective
    // of this class. Callers must not call getPrimaryHwcDisplayId() or getPrimaryDisplayId()
    // if isHeadless().
    //
    // TODO(b/182939859): Remove special cases for primary display.
    virtual hal::HWDisplayId getPrimaryHwcDisplayId() const = 0;
    virtual PhysicalDisplayId getPrimaryDisplayId() const = 0;
    virtual bool isHeadless() const = 0;

    virtual std::optional<PhysicalDisplayId> toPhysicalDisplayId(hal::HWDisplayId) const = 0;
    virtual std::optional<hal::HWDisplayId> fromPhysicalDisplayId(PhysicalDisplayId) const = 0;

    // Composer 3.0
    virtual status_t setBootDisplayMode(PhysicalDisplayId, hal::HWConfigId) = 0;
    virtual status_t clearBootDisplayMode(PhysicalDisplayId) = 0;
    virtual std::optional<hal::HWConfigId> getPreferredBootDisplayMode(PhysicalDisplayId) = 0;
    virtual status_t getDisplayDecorationSupport(
            PhysicalDisplayId,
            std::optional<aidl::android::hardware::graphics::common::DisplayDecorationSupport>*
                    support) = 0;
    virtual status_t setIdleTimerEnabled(PhysicalDisplayId, std::chrono::milliseconds timeout) = 0;
    virtual bool hasDisplayIdleTimerCapability(PhysicalDisplayId) const = 0;
    virtual Hwc2::AidlTransform getPhysicalDisplayOrientation(PhysicalDisplayId) const = 0;
};

static inline bool operator==(const android::HWComposer::DeviceRequestedChanges& lhs,
                              const android::HWComposer::DeviceRequestedChanges& rhs) {
    return lhs.changedTypes == rhs.changedTypes && lhs.displayRequests == rhs.displayRequests &&
            lhs.layerRequests == rhs.layerRequests &&
            lhs.clientTargetProperty == rhs.clientTargetProperty;
}

namespace impl {

class HWComposer final : public android::HWComposer {
public:
    explicit HWComposer(std::unique_ptr<Hwc2::Composer> composer);
    explicit HWComposer(const std::string& composerServiceName);

    ~HWComposer() override;

    void setCallback(HWC2::ComposerCallback&) override;

    bool getDisplayIdentificationData(hal::HWDisplayId, uint8_t* outPort,
                                      DisplayIdentificationData* outData) const override;

    bool hasCapability(aidl::android::hardware::graphics::composer3::Capability) const override;
    bool hasDisplayCapability(
            HalDisplayId,
            aidl::android::hardware::graphics::composer3::DisplayCapability) const override;

    size_t getMaxVirtualDisplayCount() const override;
    size_t getMaxVirtualDisplayDimension() const override;

    bool allocateVirtualDisplay(HalVirtualDisplayId, ui::Size, ui::PixelFormat*) override;

    // Called from SurfaceFlinger, when the state for a new physical display needs to be recreated.
    void allocatePhysicalDisplay(hal::HWDisplayId, PhysicalDisplayId) override;

    // Attempts to create a new layer on this display
    std::shared_ptr<HWC2::Layer> createLayer(HalDisplayId) override;

    status_t getDeviceCompositionChanges(
            HalDisplayId, bool frameUsesClientComposition,
            std::chrono::steady_clock::time_point earliestPresentTime,
            const std::shared_ptr<FenceTime>& previousPresentFence, nsecs_t expectedPresentTime,
            std::optional<DeviceRequestedChanges>* outChanges) override;

    status_t setClientTarget(HalDisplayId, uint32_t slot, const sp<Fence>& acquireFence,
                             const sp<GraphicBuffer>& target, ui::Dataspace) override;

    // Present layers to the display and read releaseFences.
    status_t presentAndGetReleaseFences(
            HalDisplayId, std::chrono::steady_clock::time_point earliestPresentTime,
            const std::shared_ptr<FenceTime>& previousPresentFence) override;

    // set power mode
    status_t setPowerMode(PhysicalDisplayId, hal::PowerMode mode) override;

    // Sets a color transform to be applied to the result of composition
    status_t setColorTransform(HalDisplayId, const mat4& transform) override;

    // reset state when a display is disconnected
    void disconnectDisplay(HalDisplayId) override;

    // get the present fence received from the last call to present.
    sp<Fence> getPresentFence(HalDisplayId) const override;

    // Get last release fence for the given layer
    sp<Fence> getLayerReleaseFence(HalDisplayId, HWC2::Layer*) const override;

    // Set the output buffer and acquire fence for a virtual display.
    status_t setOutputBuffer(HalVirtualDisplayId, const sp<Fence>& acquireFence,
                             const sp<GraphicBuffer>& buffer) override;

    // After SurfaceFlinger has retrieved the release fences for all the frames,
    // it can call this to clear the shared pointers in the release fence map
    void clearReleaseFences(HalDisplayId) override;

    // Fetches the HDR capabilities of the given display
    status_t getHdrCapabilities(HalDisplayId, HdrCapabilities* outCapabilities) override;

    int32_t getSupportedPerFrameMetadata(HalDisplayId) const override;

    // Returns the available RenderIntent of the given display.
    std::vector<ui::RenderIntent> getRenderIntents(HalDisplayId, ui::ColorMode) const override;

    mat4 getDataspaceSaturationMatrix(HalDisplayId, ui::Dataspace) override;

    // Returns the attributes of the color sampling engine.
    status_t getDisplayedContentSamplingAttributes(HalDisplayId, ui::PixelFormat* outFormat,
                                                   ui::Dataspace* outDataspace,
                                                   uint8_t* outComponentMask) override;
    status_t setDisplayContentSamplingEnabled(HalDisplayId, bool enabled, uint8_t componentMask,
                                              uint64_t maxFrames) override;
    status_t getDisplayedContentSample(HalDisplayId, uint64_t maxFrames, uint64_t timestamp,
                                       DisplayedFrameStats* outStats) override;
    ftl::Future<status_t> setDisplayBrightness(
            PhysicalDisplayId, float brightness, float brightnessNits,
            const Hwc2::Composer::DisplayBrightnessOptions&) override;

    // Events handling ---------------------------------------------------------

    // Returns PhysicalDisplayId (and display name on connection of new or previously disconnected
    // display), or std::nullopt if hotplug event was ignored.
    std::optional<DisplayIdentificationInfo> onHotplug(hal::HWDisplayId, hal::Connection) override;

    bool updatesDeviceProductInfoOnHotplugReconnect() const override;

    bool onVsync(hal::HWDisplayId, int64_t timestamp) override;
    void setVsyncEnabled(PhysicalDisplayId, hal::Vsync enabled) override;

    bool isConnected(PhysicalDisplayId) const override;

    std::vector<HWCDisplayMode> getModes(PhysicalDisplayId) const override;

    std::optional<hal::HWConfigId> getActiveMode(PhysicalDisplayId) const override;

    std::vector<ui::ColorMode> getColorModes(PhysicalDisplayId) const override;

    status_t setActiveColorMode(PhysicalDisplayId, ui::ColorMode, ui::RenderIntent) override;

    bool getValidateSkipped(HalDisplayId displayId) const override;

    // Composer 2.4
    ui::DisplayConnectionType getDisplayConnectionType(PhysicalDisplayId) const override;
    bool isVsyncPeriodSwitchSupported(PhysicalDisplayId) const override;
    status_t getDisplayVsyncPeriod(PhysicalDisplayId displayId,
                                   nsecs_t* outVsyncPeriod) const override;
    status_t setActiveModeWithConstraints(PhysicalDisplayId, hal::HWConfigId,
                                          const hal::VsyncPeriodChangeConstraints&,
                                          hal::VsyncPeriodChangeTimeline* outTimeline) override;
    status_t setAutoLowLatencyMode(PhysicalDisplayId, bool) override;
    status_t getSupportedContentTypes(PhysicalDisplayId,
                                      std::vector<hal::ContentType>*) const override;
    status_t setContentType(PhysicalDisplayId, hal::ContentType) override;

    const std::unordered_map<std::string, bool>& getSupportedLayerGenericMetadata() const override;

    // Composer 3.0
    status_t setBootDisplayMode(PhysicalDisplayId, hal::HWConfigId) override;
    status_t clearBootDisplayMode(PhysicalDisplayId) override;
    std::optional<hal::HWConfigId> getPreferredBootDisplayMode(PhysicalDisplayId) override;
    status_t getDisplayDecorationSupport(
            PhysicalDisplayId,
            std::optional<aidl::android::hardware::graphics::common::DisplayDecorationSupport>*
                    support) override;
    status_t setIdleTimerEnabled(PhysicalDisplayId, std::chrono::milliseconds timeout) override;
    bool hasDisplayIdleTimerCapability(PhysicalDisplayId) const override;
    Hwc2::AidlTransform getPhysicalDisplayOrientation(PhysicalDisplayId) const override;

    // for debugging ----------------------------------------------------------
    void dump(std::string& out) const override;

    Hwc2::Composer* getComposer() const override { return mComposer.get(); }

    hal::HWDisplayId getPrimaryHwcDisplayId() const override {
        LOG_ALWAYS_FATAL_IF(!mPrimaryHwcDisplayId, "Missing HWC primary display");
        return *mPrimaryHwcDisplayId;
    }

    PhysicalDisplayId getPrimaryDisplayId() const override {
        const auto id = toPhysicalDisplayId(getPrimaryHwcDisplayId());
        LOG_ALWAYS_FATAL_IF(!id, "Missing primary display");
        return *id;
    }

    virtual bool isHeadless() const override { return !mPrimaryHwcDisplayId; }

    std::optional<PhysicalDisplayId> toPhysicalDisplayId(hal::HWDisplayId) const override;
    std::optional<hal::HWDisplayId> fromPhysicalDisplayId(PhysicalDisplayId) const override;

private:
    // For unit tests
    friend TestableSurfaceFlinger;

    struct DisplayData {
        std::unique_ptr<HWC2::Display> hwcDisplay;
        sp<Fence> lastPresentFence = Fence::NO_FENCE; // signals when the last set op retires
        std::unordered_map<HWC2::Layer*, sp<Fence>> releaseFences;

        bool validateWasSkipped;
        hal::Error presentError;

        bool vsyncTraceToggle = false;

        std::mutex vsyncEnabledLock;
        hal::Vsync vsyncEnabled GUARDED_BY(vsyncEnabledLock) = hal::Vsync::DISABLE;

        nsecs_t lastHwVsync = 0;
    };

    std::optional<DisplayIdentificationInfo> onHotplugConnect(hal::HWDisplayId);
    std::optional<DisplayIdentificationInfo> onHotplugDisconnect(hal::HWDisplayId);
    bool shouldIgnoreHotplugConnect(hal::HWDisplayId, bool hasDisplayIdentificationData) const;

    int32_t getAttribute(hal::HWDisplayId hwcDisplayId, hal::HWConfigId configId,
                         hal::Attribute attribute) const;

    void loadCapabilities();
    void loadLayerMetadataSupport();

    std::unordered_map<HalDisplayId, DisplayData> mDisplayData;

    std::unique_ptr<android::Hwc2::Composer> mComposer;
    std::unordered_set<aidl::android::hardware::graphics::composer3::Capability> mCapabilities;
    std::unordered_map<std::string, bool> mSupportedLayerGenericMetadata;
    bool mRegisteredCallback = false;

    std::unordered_map<hal::HWDisplayId, PhysicalDisplayId> mPhysicalDisplayIdMap;
    std::optional<hal::HWDisplayId> mPrimaryHwcDisplayId;
    bool mHasMultiDisplaySupport = false;

    const size_t mMaxVirtualDisplayDimension;
    const bool mUpdateDeviceProductInfoOnHotplugReconnect;
};

} // namespace impl
} // namespace android
