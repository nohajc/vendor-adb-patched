/*
 * Copyright 2015 The Android Open Source Project
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

#ifndef ANDROID_SF_HWC2_H
#define ANDROID_SF_HWC2_H

#include <gui/HdrMetadata.h>
#include <math/mat4.h>
#include <ui/DisplayInfo.h>
#include <ui/HdrCapabilities.h>
#include <ui/Region.h>
#include <utils/Log.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

#include <functional>
#include <future>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Hal.h"

namespace android {
    struct DisplayedFrameStats;
    class Fence;
    class FloatRect;
    class GraphicBuffer;
    namespace Hwc2 {
        class Composer;
    }

    class TestableSurfaceFlinger;

namespace HWC2 {

class Layer;

namespace hal = android::hardware::graphics::composer::hal;

// Implement this interface to receive hardware composer events.
//
// These callback functions will generally be called on a hwbinder thread, but
// when first registering the callback the onHotplugReceived() function will
// immediately be called on the thread calling registerCallback().
//
// All calls receive a sequenceId, which will be the value that was supplied to
// HWC2::Device::registerCallback(). It's used to help differentiate callbacks
// from different hardware composer instances.
class ComposerCallback {
 public:
     virtual void onHotplugReceived(int32_t sequenceId, hal::HWDisplayId display,
                                    hal::Connection connection) = 0;
     virtual void onRefreshReceived(int32_t sequenceId, hal::HWDisplayId display) = 0;
     virtual void onVsyncReceived(int32_t sequenceId, hal::HWDisplayId display, int64_t timestamp,
                                  std::optional<hal::VsyncPeriodNanos> vsyncPeriod) = 0;
     virtual void onVsyncPeriodTimingChangedReceived(
             int32_t sequenceId, hal::HWDisplayId display,
             const hal::VsyncPeriodChangeTimeline& updatedTimeline) = 0;
     virtual void onSeamlessPossible(int32_t sequenceId, hal::HWDisplayId display) = 0;

     virtual ~ComposerCallback() = default;
};

// Convenience C++ class to access per display functions directly.
class Display {
public:
    virtual ~Display();

    class Config {
    public:
        class Builder
        {
        public:
            Builder(Display& display, hal::HWConfigId id);

            std::shared_ptr<const Config> build() {
                return std::const_pointer_cast<const Config>(
                        std::move(mConfig));
            }

            Builder& setWidth(int32_t width) {
                mConfig->mWidth = width;
                return *this;
            }
            Builder& setHeight(int32_t height) {
                mConfig->mHeight = height;
                return *this;
            }
            Builder& setVsyncPeriod(int32_t vsyncPeriod) {
                mConfig->mVsyncPeriod = vsyncPeriod;
                return *this;
            }
            Builder& setDpiX(int32_t dpiX) {
                if (dpiX == -1) {
                    mConfig->mDpiX = getDefaultDensity();
                } else {
                    mConfig->mDpiX = dpiX / 1000.0f;
                }
                return *this;
            }
            Builder& setDpiY(int32_t dpiY) {
                if (dpiY == -1) {
                    mConfig->mDpiY = getDefaultDensity();
                } else {
                    mConfig->mDpiY = dpiY / 1000.0f;
                }
                return *this;
            }
            Builder& setConfigGroup(int32_t configGroup) {
                mConfig->mConfigGroup = configGroup;
                return *this;
            }

        private:
            float getDefaultDensity();
            std::shared_ptr<Config> mConfig;
        };

        hal::HWDisplayId getDisplayId() const { return mDisplay.getId(); }
        hal::HWConfigId getId() const { return mId; }

        int32_t getWidth() const { return mWidth; }
        int32_t getHeight() const { return mHeight; }
        nsecs_t getVsyncPeriod() const { return mVsyncPeriod; }
        float getDpiX() const { return mDpiX; }
        float getDpiY() const { return mDpiY; }
        int32_t getConfigGroup() const { return mConfigGroup; }

    private:
        Config(Display& display, hal::HWConfigId id);

        Display& mDisplay;
        hal::HWConfigId mId;

        int32_t mWidth;
        int32_t mHeight;
        nsecs_t mVsyncPeriod;
        float mDpiX;
        float mDpiY;
        int32_t mConfigGroup;
    };

    virtual hal::HWDisplayId getId() const = 0;
    virtual bool isConnected() const = 0;
    virtual void setConnected(bool connected) = 0; // For use by Device only
    virtual const std::unordered_set<hal::DisplayCapability>& getCapabilities() const = 0;
    virtual bool isVsyncPeriodSwitchSupported() const = 0;

    [[clang::warn_unused_result]] virtual hal::Error acceptChanges() = 0;
    [[clang::warn_unused_result]] virtual hal::Error createLayer(Layer** outLayer) = 0;
    [[clang::warn_unused_result]] virtual hal::Error destroyLayer(Layer* layer) = 0;
    [[clang::warn_unused_result]] virtual hal::Error getActiveConfig(
            std::shared_ptr<const Config>* outConfig) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getActiveConfigIndex(int* outIndex) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getChangedCompositionTypes(
            std::unordered_map<Layer*, hal::Composition>* outTypes) = 0;
    [[clang::warn_unused_result]] virtual hal::Error getColorModes(
            std::vector<hal::ColorMode>* outModes) const = 0;
    // Returns a bitmask which contains HdrMetadata::Type::*.
    [[clang::warn_unused_result]] virtual int32_t getSupportedPerFrameMetadata() const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getRenderIntents(
            hal::ColorMode colorMode, std::vector<hal::RenderIntent>* outRenderIntents) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getDataspaceSaturationMatrix(
            hal::Dataspace dataspace, android::mat4* outMatrix) = 0;

    // Doesn't call into the HWC2 device, so no errors are possible
    [[clang::warn_unused_result]] virtual std::vector<std::shared_ptr<const Config>> getConfigs()
            const = 0;

    [[clang::warn_unused_result]] virtual hal::Error getName(std::string* outName) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getRequests(
            hal::DisplayRequest* outDisplayRequests,
            std::unordered_map<Layer*, hal::LayerRequest>* outLayerRequests) = 0;
    [[clang::warn_unused_result]] virtual hal::Error getConnectionType(
            android::DisplayConnectionType*) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error supportsDoze(bool* outSupport) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getHdrCapabilities(
            android::HdrCapabilities* outCapabilities) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getDisplayedContentSamplingAttributes(
            hal::PixelFormat* outFormat, hal::Dataspace* outDataspace,
            uint8_t* outComponentMask) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error setDisplayContentSamplingEnabled(
            bool enabled, uint8_t componentMask, uint64_t maxFrames) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getDisplayedContentSample(
            uint64_t maxFrames, uint64_t timestamp,
            android::DisplayedFrameStats* outStats) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error getReleaseFences(
            std::unordered_map<Layer*, android::sp<android::Fence>>* outFences) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error present(
            android::sp<android::Fence>* outPresentFence) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setActiveConfig(
            const std::shared_ptr<const Config>& config) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setClientTarget(
            uint32_t slot, const android::sp<android::GraphicBuffer>& target,
            const android::sp<android::Fence>& acquireFence, hal::Dataspace dataspace) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setColorMode(
            hal::ColorMode mode, hal::RenderIntent renderIntent) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setColorTransform(
            const android::mat4& matrix, hal::ColorTransform hint) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setOutputBuffer(
            const android::sp<android::GraphicBuffer>& buffer,
            const android::sp<android::Fence>& releaseFence) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setPowerMode(hal::PowerMode mode) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setVsyncEnabled(hal::Vsync enabled) = 0;
    [[clang::warn_unused_result]] virtual hal::Error validate(uint32_t* outNumTypes,
                                                              uint32_t* outNumRequests) = 0;
    [[clang::warn_unused_result]] virtual hal::Error presentOrValidate(
            uint32_t* outNumTypes, uint32_t* outNumRequests,
            android::sp<android::Fence>* outPresentFence, uint32_t* state) = 0;
    [[clang::warn_unused_result]] virtual std::future<hal::Error> setDisplayBrightness(
            float brightness) = 0;
    [[clang::warn_unused_result]] virtual hal::Error getDisplayVsyncPeriod(
            nsecs_t* outVsyncPeriod) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error setActiveConfigWithConstraints(
            const std::shared_ptr<const HWC2::Display::Config>& config,
            const hal::VsyncPeriodChangeConstraints& constraints,
            hal::VsyncPeriodChangeTimeline* outTimeline) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setAutoLowLatencyMode(bool on) = 0;
    [[clang::warn_unused_result]] virtual hal::Error getSupportedContentTypes(
            std::vector<hal::ContentType>*) const = 0;
    [[clang::warn_unused_result]] virtual hal::Error setContentType(hal::ContentType) = 0;
    [[clang::warn_unused_result]] virtual hal::Error getClientTargetProperty(
            hal::ClientTargetProperty* outClientTargetProperty) = 0;
};

namespace impl {

class Display : public HWC2::Display {
public:
    Display(android::Hwc2::Composer& composer,
            const std::unordered_set<hal::Capability>& capabilities, hal::HWDisplayId id,
            hal::DisplayType type);
    ~Display() override;

    // Required by HWC2
    hal::Error acceptChanges() override;
    hal::Error createLayer(Layer** outLayer) override;
    hal::Error destroyLayer(Layer* layer) override;
    hal::Error getActiveConfig(std::shared_ptr<const Config>* outConfig) const override;
    hal::Error getActiveConfigIndex(int* outIndex) const override;
    hal::Error getChangedCompositionTypes(
            std::unordered_map<Layer*, hal::Composition>* outTypes) override;
    hal::Error getColorModes(std::vector<hal::ColorMode>* outModes) const override;
    // Returns a bitmask which contains HdrMetadata::Type::*.
    int32_t getSupportedPerFrameMetadata() const override;
    hal::Error getRenderIntents(hal::ColorMode colorMode,
                                std::vector<hal::RenderIntent>* outRenderIntents) const override;
    hal::Error getDataspaceSaturationMatrix(hal::Dataspace dataspace,
                                            android::mat4* outMatrix) override;

    // Doesn't call into the HWC2 device, so no errors are possible
    std::vector<std::shared_ptr<const Config>> getConfigs() const override;

    hal::Error getName(std::string* outName) const override;
    hal::Error getRequests(
            hal::DisplayRequest* outDisplayRequests,
            std::unordered_map<Layer*, hal::LayerRequest>* outLayerRequests) override;
    hal::Error getConnectionType(android::DisplayConnectionType*) const override;
    hal::Error supportsDoze(bool* outSupport) const override;
    hal::Error getHdrCapabilities(android::HdrCapabilities* outCapabilities) const override;
    hal::Error getDisplayedContentSamplingAttributes(hal::PixelFormat* outFormat,
                                                     hal::Dataspace* outDataspace,
                                                     uint8_t* outComponentMask) const override;
    hal::Error setDisplayContentSamplingEnabled(bool enabled, uint8_t componentMask,
                                                uint64_t maxFrames) const override;
    hal::Error getDisplayedContentSample(uint64_t maxFrames, uint64_t timestamp,
                                         android::DisplayedFrameStats* outStats) const override;
    hal::Error getReleaseFences(
            std::unordered_map<Layer*, android::sp<android::Fence>>* outFences) const override;
    hal::Error present(android::sp<android::Fence>* outPresentFence) override;
    hal::Error setActiveConfig(const std::shared_ptr<const HWC2::Display::Config>& config) override;
    hal::Error setClientTarget(uint32_t slot, const android::sp<android::GraphicBuffer>& target,
                               const android::sp<android::Fence>& acquireFence,
                               hal::Dataspace dataspace) override;
    hal::Error setColorMode(hal::ColorMode mode, hal::RenderIntent renderIntent) override;
    hal::Error setColorTransform(const android::mat4& matrix, hal::ColorTransform hint) override;
    hal::Error setOutputBuffer(const android::sp<android::GraphicBuffer>& buffer,
                               const android::sp<android::Fence>& releaseFence) override;
    hal::Error setPowerMode(hal::PowerMode mode) override;
    hal::Error setVsyncEnabled(hal::Vsync enabled) override;
    hal::Error validate(uint32_t* outNumTypes, uint32_t* outNumRequests) override;
    hal::Error presentOrValidate(uint32_t* outNumTypes, uint32_t* outNumRequests,
                                 android::sp<android::Fence>* outPresentFence,
                                 uint32_t* state) override;
    std::future<hal::Error> setDisplayBrightness(float brightness) override;
    hal::Error getDisplayVsyncPeriod(nsecs_t* outVsyncPeriod) const override;
    hal::Error setActiveConfigWithConstraints(
            const std::shared_ptr<const HWC2::Display::Config>& config,
            const hal::VsyncPeriodChangeConstraints& constraints,
            hal::VsyncPeriodChangeTimeline* outTimeline) override;
    hal::Error setAutoLowLatencyMode(bool on) override;
    hal::Error getSupportedContentTypes(
            std::vector<hal::ContentType>* outSupportedContentTypes) const override;
    hal::Error setContentType(hal::ContentType) override;
    hal::Error getClientTargetProperty(hal::ClientTargetProperty* outClientTargetProperty) override;

    // Other Display methods
    hal::HWDisplayId getId() const override { return mId; }
    bool isConnected() const override { return mIsConnected; }
    void setConnected(bool connected) override; // For use by Device only
    const std::unordered_set<hal::DisplayCapability>& getCapabilities() const override {
        return mDisplayCapabilities;
    };
    virtual bool isVsyncPeriodSwitchSupported() const override;

private:
    int32_t getAttribute(hal::HWConfigId configId, hal::Attribute attribute);
    void loadConfig(hal::HWConfigId configId);
    void loadConfigs();

    // This may fail (and return a null pointer) if no layer with this ID exists
    // on this display
    Layer* getLayerById(hal::HWLayerId id) const;

    friend android::TestableSurfaceFlinger;

    // Member variables

    // These are references to data owned by HWC2::Device, which will outlive
    // this HWC2::Display, so these references are guaranteed to be valid for
    // the lifetime of this object.
    android::Hwc2::Composer& mComposer;
    const std::unordered_set<hal::Capability>& mCapabilities;

    const hal::HWDisplayId mId;
    hal::DisplayType mType;
    bool mIsConnected = false;

    std::unordered_map<hal::HWLayerId, std::unique_ptr<Layer>> mLayers;
    std::unordered_map<hal::HWConfigId, std::shared_ptr<const Config>> mConfigs;

    std::once_flag mDisplayCapabilityQueryFlag;
    std::unordered_set<hal::DisplayCapability> mDisplayCapabilities;
};

} // namespace impl

class Layer {
public:
    virtual ~Layer();

    virtual hal::HWLayerId getId() const = 0;

    [[clang::warn_unused_result]] virtual hal::Error setCursorPosition(int32_t x, int32_t y) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setBuffer(
            uint32_t slot, const android::sp<android::GraphicBuffer>& buffer,
            const android::sp<android::Fence>& acquireFence) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setSurfaceDamage(
            const android::Region& damage) = 0;

    [[clang::warn_unused_result]] virtual hal::Error setBlendMode(hal::BlendMode mode) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setColor(hal::Color color) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setCompositionType(hal::Composition type) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setDataspace(hal::Dataspace dataspace) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setPerFrameMetadata(
            const int32_t supportedPerFrameMetadata, const android::HdrMetadata& metadata) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setDisplayFrame(
            const android::Rect& frame) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setPlaneAlpha(float alpha) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setSidebandStream(
            const native_handle_t* stream) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setSourceCrop(
            const android::FloatRect& crop) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setTransform(hal::Transform transform) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setVisibleRegion(
            const android::Region& region) = 0;
    [[clang::warn_unused_result]] virtual hal::Error setZOrder(uint32_t z) = 0;

    // Composer HAL 2.3
    [[clang::warn_unused_result]] virtual hal::Error setColorTransform(
            const android::mat4& matrix) = 0;

    // Composer HAL 2.4
    [[clang::warn_unused_result]] virtual hal::Error setLayerGenericMetadata(
            const std::string& name, bool mandatory, const std::vector<uint8_t>& value) = 0;
};

namespace impl {

// Convenience C++ class to access per layer functions directly.

class Layer : public HWC2::Layer {
public:
    Layer(android::Hwc2::Composer& composer,
          const std::unordered_set<hal::Capability>& capabilities, hal::HWDisplayId displayId,
          hal::HWLayerId layerId);
    ~Layer() override;

    hal::HWLayerId getId() const override { return mId; }

    hal::Error setCursorPosition(int32_t x, int32_t y) override;
    hal::Error setBuffer(uint32_t slot, const android::sp<android::GraphicBuffer>& buffer,
                         const android::sp<android::Fence>& acquireFence) override;
    hal::Error setSurfaceDamage(const android::Region& damage) override;

    hal::Error setBlendMode(hal::BlendMode mode) override;
    hal::Error setColor(hal::Color color) override;
    hal::Error setCompositionType(hal::Composition type) override;
    hal::Error setDataspace(hal::Dataspace dataspace) override;
    hal::Error setPerFrameMetadata(const int32_t supportedPerFrameMetadata,
                                   const android::HdrMetadata& metadata) override;
    hal::Error setDisplayFrame(const android::Rect& frame) override;
    hal::Error setPlaneAlpha(float alpha) override;
    hal::Error setSidebandStream(const native_handle_t* stream) override;
    hal::Error setSourceCrop(const android::FloatRect& crop) override;
    hal::Error setTransform(hal::Transform transform) override;
    hal::Error setVisibleRegion(const android::Region& region) override;
    hal::Error setZOrder(uint32_t z) override;

    // Composer HAL 2.3
    hal::Error setColorTransform(const android::mat4& matrix) override;

    // Composer HAL 2.4
    hal::Error setLayerGenericMetadata(const std::string& name, bool mandatory,
                                       const std::vector<uint8_t>& value) override;

private:
    // These are references to data owned by HWC2::Device, which will outlive
    // this HWC2::Layer, so these references are guaranteed to be valid for
    // the lifetime of this object.
    android::Hwc2::Composer& mComposer;
    const std::unordered_set<hal::Capability>& mCapabilities;

    hal::HWDisplayId mDisplayId;
    hal::HWLayerId mId;

    // Cached HWC2 data, to ensure the same commands aren't sent to the HWC
    // multiple times.
    android::Region mVisibleRegion = android::Region::INVALID_REGION;
    android::Region mDamageRegion = android::Region::INVALID_REGION;
    hal::Dataspace mDataSpace = hal::Dataspace::UNKNOWN;
    android::HdrMetadata mHdrMetadata;
    android::mat4 mColorMatrix;
    uint32_t mBufferSlot;
};

} // namespace impl
} // namespace HWC2
} // namespace android

#endif // ANDROID_SF_HWC2_H
