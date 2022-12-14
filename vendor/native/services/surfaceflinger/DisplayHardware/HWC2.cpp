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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

// #define LOG_NDEBUG 0

#undef LOG_TAG
#define LOG_TAG "HWC2"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "HWC2.h"

#include <ui/Fence.h>
#include <ui/FloatRect.h>
#include <ui/GraphicBuffer.h>

#include <android/configuration.h>

#include <inttypes.h>
#include <algorithm>
#include <iterator>
#include <set>

#include "../Promise.h"
#include "ComposerHal.h"

namespace android {

using android::Fence;
using android::FloatRect;
using android::GraphicBuffer;
using android::HdrCapabilities;
using android::HdrMetadata;
using android::Rect;
using android::Region;
using android::sp;

namespace HWC2 {

using namespace android::hardware::graphics::composer::hal;

namespace Hwc2 = android::Hwc2;

namespace {

inline bool hasMetadataKey(const std::set<Hwc2::PerFrameMetadataKey>& keys,
                           const Hwc2::PerFrameMetadataKey& key) {
    return keys.find(key) != keys.end();
}

} // namespace anonymous

// Display methods
Display::~Display() = default;

Display::Config::Config(Display& display, HWConfigId id)
      : mDisplay(display),
        mId(id),
        mWidth(-1),
        mHeight(-1),
        mVsyncPeriod(-1),
        mDpiX(-1),
        mDpiY(-1) {}

Display::Config::Builder::Builder(Display& display, HWConfigId id)
      : mConfig(new Config(display, id)) {}

float Display::Config::Builder::getDefaultDensity() {
    // Default density is based on TVs: 1080p displays get XHIGH density, lower-
    // resolution displays get TV density. Maybe eventually we'll need to update
    // it for 4k displays, though hopefully those will just report accurate DPI
    // information to begin with. This is also used for virtual displays and
    // older HWC implementations, so be careful about orientation.

    auto longDimension = std::max(mConfig->mWidth, mConfig->mHeight);
    if (longDimension >= 1080) {
        return ACONFIGURATION_DENSITY_XHIGH;
    } else {
        return ACONFIGURATION_DENSITY_TV;
    }
}

namespace impl {

Display::Display(android::Hwc2::Composer& composer,
                 const std::unordered_set<Capability>& capabilities, HWDisplayId id,
                 DisplayType type)
      : mComposer(composer), mCapabilities(capabilities), mId(id), mType(type) {
    ALOGV("Created display %" PRIu64, id);
}

Display::~Display() {
    mLayers.clear();

    Error error = Error::NONE;
    const char* msg;
    switch (mType) {
        case DisplayType::PHYSICAL:
            error = setVsyncEnabled(HWC2::Vsync::DISABLE);
            msg = "disable VSYNC for";
            break;

        case DisplayType::VIRTUAL:
            error = static_cast<Error>(mComposer.destroyVirtualDisplay(mId));
            msg = "destroy virtual";
            break;

        case DisplayType::INVALID: // Used in unit tests.
            break;
    }

    ALOGE_IF(error != Error::NONE, "%s: Failed to %s display %" PRIu64 ": %d", __FUNCTION__, msg,
             mId, static_cast<int32_t>(error));

    ALOGV("Destroyed display %" PRIu64, mId);
}

// Required by HWC2 display
Error Display::acceptChanges()
{
    auto intError = mComposer.acceptDisplayChanges(mId);
    return static_cast<Error>(intError);
}

Error Display::createLayer(HWC2::Layer** outLayer) {
    if (!outLayer) {
        return Error::BAD_PARAMETER;
    }
    HWLayerId layerId = 0;
    auto intError = mComposer.createLayer(mId, &layerId);
    auto error = static_cast<Error>(intError);
    if (error != Error::NONE) {
        return error;
    }

    auto layer = std::make_unique<impl::Layer>(mComposer, mCapabilities, mId, layerId);
    *outLayer = layer.get();
    mLayers.emplace(layerId, std::move(layer));
    return Error::NONE;
}

Error Display::destroyLayer(HWC2::Layer* layer) {
    if (!layer) {
        return Error::BAD_PARAMETER;
    }
    mLayers.erase(layer->getId());
    return Error::NONE;
}

Error Display::getActiveConfig(
        std::shared_ptr<const Display::Config>* outConfig) const
{
    ALOGV("[%" PRIu64 "] getActiveConfig", mId);
    HWConfigId configId = 0;
    auto intError = mComposer.getActiveConfig(mId, &configId);
    auto error = static_cast<Error>(intError);

    if (error != Error::NONE) {
        ALOGE("Unable to get active config for mId:[%" PRIu64 "]", mId);
        *outConfig = nullptr;
        return error;
    }

    if (mConfigs.count(configId) != 0) {
        *outConfig = mConfigs.at(configId);
    } else {
        ALOGE("[%" PRIu64 "] getActiveConfig returned unknown config %u", mId,
                configId);
        // Return no error, but the caller needs to check for a null pointer to
        // detect this case
        *outConfig = nullptr;
    }

    return Error::NONE;
}

bool Display::isVsyncPeriodSwitchSupported() const {
    ALOGV("[%" PRIu64 "] isVsyncPeriodSwitchSupported()", mId);

    return mComposer.isVsyncPeriodSwitchSupported();
}

Error Display::getDisplayVsyncPeriod(nsecs_t* outVsyncPeriod) const {
    ALOGV("[%" PRIu64 "] getDisplayVsyncPeriod", mId);

    Error error;

    if (isVsyncPeriodSwitchSupported()) {
        Hwc2::VsyncPeriodNanos vsyncPeriodNanos = 0;
        auto intError = mComposer.getDisplayVsyncPeriod(mId, &vsyncPeriodNanos);
        error = static_cast<Error>(intError);
        *outVsyncPeriod = static_cast<nsecs_t>(vsyncPeriodNanos);
    } else {
        // Get the default vsync period
        std::shared_ptr<const Display::Config> config;
        error = getActiveConfig(&config);
        if (error != Error::NONE) {
            return error;
        }
        if (!config) {
            // HWC has updated the display modes and hasn't notified us yet.
            return Error::BAD_CONFIG;
        }

        *outVsyncPeriod = config->getVsyncPeriod();
    }

    return error;
}

Error Display::getActiveConfigIndex(int* outIndex) const {
    ALOGV("[%" PRIu64 "] getActiveConfigIndex", mId);
    HWConfigId configId = 0;
    auto intError = mComposer.getActiveConfig(mId, &configId);
    auto error = static_cast<Error>(intError);

    if (error != Error::NONE) {
        ALOGE("Unable to get active config for mId:[%" PRIu64 "]", mId);
        *outIndex = -1;
        return error;
    }

    auto pos = mConfigs.find(configId);
    if (pos != mConfigs.end()) {
        *outIndex = std::distance(mConfigs.begin(), pos);
        ALOGV("[%" PRIu64 "] index = %d", mId, *outIndex);
    } else {
        ALOGE("[%" PRIu64 "] getActiveConfig returned unknown config %u", mId, configId);
        // Return no error, but the caller needs to check for a negative index
        // to detect this case
        *outIndex = -1;
    }

    return Error::NONE;
}

Error Display::getChangedCompositionTypes(std::unordered_map<HWC2::Layer*, Composition>* outTypes) {
    std::vector<Hwc2::Layer> layerIds;
    std::vector<Hwc2::IComposerClient::Composition> types;
    auto intError = mComposer.getChangedCompositionTypes(
            mId, &layerIds, &types);
    uint32_t numElements = layerIds.size();
    auto error = static_cast<Error>(intError);
    error = static_cast<Error>(intError);
    if (error != Error::NONE) {
        return error;
    }

    outTypes->clear();
    outTypes->reserve(numElements);
    for (uint32_t element = 0; element < numElements; ++element) {
        auto layer = getLayerById(layerIds[element]);
        if (layer) {
            auto type = types[element];
            ALOGV("getChangedCompositionTypes: adding %" PRIu64 " %s",
                    layer->getId(), to_string(type).c_str());
            outTypes->emplace(layer, type);
        } else {
            ALOGE("getChangedCompositionTypes: invalid layer %" PRIu64 " found"
                    " on display %" PRIu64, layerIds[element], mId);
        }
    }

    return Error::NONE;
}

Error Display::getColorModes(std::vector<ColorMode>* outModes) const
{
    auto intError = mComposer.getColorModes(mId, outModes);
    return static_cast<Error>(intError);
}

int32_t Display::getSupportedPerFrameMetadata() const
{
    int32_t supportedPerFrameMetadata = 0;

    std::vector<Hwc2::PerFrameMetadataKey> tmpKeys = mComposer.getPerFrameMetadataKeys(mId);
    std::set<Hwc2::PerFrameMetadataKey> keys(tmpKeys.begin(), tmpKeys.end());

    // Check whether a specific metadata type is supported. A metadata type is considered
    // supported if and only if all required fields are supported.

    // SMPTE2086
    if (hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::DISPLAY_RED_PRIMARY_X) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::DISPLAY_RED_PRIMARY_Y) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::DISPLAY_GREEN_PRIMARY_X) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::DISPLAY_GREEN_PRIMARY_Y) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::DISPLAY_BLUE_PRIMARY_X) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::DISPLAY_BLUE_PRIMARY_Y) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::WHITE_POINT_X) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::WHITE_POINT_Y) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::MAX_LUMINANCE) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::MIN_LUMINANCE)) {
        supportedPerFrameMetadata |= HdrMetadata::Type::SMPTE2086;
    }
    // CTA861_3
    if (hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::MAX_CONTENT_LIGHT_LEVEL) &&
        hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::MAX_FRAME_AVERAGE_LIGHT_LEVEL)) {
        supportedPerFrameMetadata |= HdrMetadata::Type::CTA861_3;
    }

    // HDR10PLUS
    if (hasMetadataKey(keys, Hwc2::PerFrameMetadataKey::HDR10_PLUS_SEI)) {
        supportedPerFrameMetadata |= HdrMetadata::Type::HDR10PLUS;
    }

    return supportedPerFrameMetadata;
}

Error Display::getRenderIntents(ColorMode colorMode,
        std::vector<RenderIntent>* outRenderIntents) const
{
    auto intError = mComposer.getRenderIntents(mId, colorMode, outRenderIntents);
    return static_cast<Error>(intError);
}

Error Display::getDataspaceSaturationMatrix(Dataspace dataspace, android::mat4* outMatrix)
{
    auto intError = mComposer.getDataspaceSaturationMatrix(dataspace, outMatrix);
    return static_cast<Error>(intError);
}

std::vector<std::shared_ptr<const Display::Config>> Display::getConfigs() const
{
    std::vector<std::shared_ptr<const Config>> configs;
    for (const auto& element : mConfigs) {
        configs.emplace_back(element.second);
    }
    return configs;
}

Error Display::getName(std::string* outName) const
{
    auto intError = mComposer.getDisplayName(mId, outName);
    return static_cast<Error>(intError);
}

Error Display::getRequests(HWC2::DisplayRequest* outDisplayRequests,
                           std::unordered_map<HWC2::Layer*, LayerRequest>* outLayerRequests) {
    uint32_t intDisplayRequests = 0;
    std::vector<Hwc2::Layer> layerIds;
    std::vector<uint32_t> layerRequests;
    auto intError = mComposer.getDisplayRequests(
            mId, &intDisplayRequests, &layerIds, &layerRequests);
    uint32_t numElements = layerIds.size();
    auto error = static_cast<Error>(intError);
    if (error != Error::NONE) {
        return error;
    }

    *outDisplayRequests = static_cast<DisplayRequest>(intDisplayRequests);
    outLayerRequests->clear();
    outLayerRequests->reserve(numElements);
    for (uint32_t element = 0; element < numElements; ++element) {
        auto layer = getLayerById(layerIds[element]);
        if (layer) {
            auto layerRequest =
                    static_cast<LayerRequest>(layerRequests[element]);
            outLayerRequests->emplace(layer, layerRequest);
        } else {
            ALOGE("getRequests: invalid layer %" PRIu64 " found on display %"
                    PRIu64, layerIds[element], mId);
        }
    }

    return Error::NONE;
}

Error Display::getConnectionType(android::DisplayConnectionType* outType) const {
    if (mType != DisplayType::PHYSICAL) return Error::BAD_DISPLAY;

    using ConnectionType = Hwc2::IComposerClient::DisplayConnectionType;
    ConnectionType connectionType;
    const auto error = static_cast<Error>(mComposer.getDisplayConnectionType(mId, &connectionType));
    if (error != Error::NONE) {
        return error;
    }

    *outType = connectionType == ConnectionType::INTERNAL
            ? android::DisplayConnectionType::Internal
            : android::DisplayConnectionType::External;
    return Error::NONE;
}

Error Display::supportsDoze(bool* outSupport) const {
    *outSupport = mDisplayCapabilities.count(DisplayCapability::DOZE) > 0;
    return Error::NONE;
}

Error Display::getHdrCapabilities(HdrCapabilities* outCapabilities) const
{
    float maxLuminance = -1.0f;
    float maxAverageLuminance = -1.0f;
    float minLuminance = -1.0f;
    std::vector<Hwc2::Hdr> types;
    auto intError = mComposer.getHdrCapabilities(mId, &types,
            &maxLuminance, &maxAverageLuminance, &minLuminance);
    auto error = static_cast<HWC2::Error>(intError);

    if (error != Error::NONE) {
        return error;
    }

    *outCapabilities = HdrCapabilities(std::move(types),
            maxLuminance, maxAverageLuminance, minLuminance);
    return Error::NONE;
}

Error Display::getDisplayedContentSamplingAttributes(hal::PixelFormat* outFormat,
                                                     Dataspace* outDataspace,
                                                     uint8_t* outComponentMask) const {
    auto intError = mComposer.getDisplayedContentSamplingAttributes(mId, outFormat, outDataspace,
                                                                    outComponentMask);
    return static_cast<Error>(intError);
}

Error Display::setDisplayContentSamplingEnabled(bool enabled, uint8_t componentMask,
                                                uint64_t maxFrames) const {
    auto intError =
            mComposer.setDisplayContentSamplingEnabled(mId, enabled, componentMask, maxFrames);
    return static_cast<Error>(intError);
}

Error Display::getDisplayedContentSample(uint64_t maxFrames, uint64_t timestamp,
                                         android::DisplayedFrameStats* outStats) const {
    auto intError = mComposer.getDisplayedContentSample(mId, maxFrames, timestamp, outStats);
    return static_cast<Error>(intError);
}

Error Display::getReleaseFences(std::unordered_map<HWC2::Layer*, sp<Fence>>* outFences) const {
    std::vector<Hwc2::Layer> layerIds;
    std::vector<int> fenceFds;
    auto intError = mComposer.getReleaseFences(mId, &layerIds, &fenceFds);
    auto error = static_cast<Error>(intError);
    uint32_t numElements = layerIds.size();
    if (error != Error::NONE) {
        return error;
    }

    std::unordered_map<HWC2::Layer*, sp<Fence>> releaseFences;
    releaseFences.reserve(numElements);
    for (uint32_t element = 0; element < numElements; ++element) {
        auto layer = getLayerById(layerIds[element]);
        if (layer) {
            sp<Fence> fence(new Fence(fenceFds[element]));
            releaseFences.emplace(layer, fence);
        } else {
            ALOGE("getReleaseFences: invalid layer %" PRIu64
                    " found on display %" PRIu64, layerIds[element], mId);
            for (; element < numElements; ++element) {
                close(fenceFds[element]);
            }
            return Error::BAD_LAYER;
        }
    }

    *outFences = std::move(releaseFences);
    return Error::NONE;
}

Error Display::present(sp<Fence>* outPresentFence)
{
    int32_t presentFenceFd = -1;
    auto intError = mComposer.presentDisplay(mId, &presentFenceFd);
    auto error = static_cast<Error>(intError);
    if (error != Error::NONE) {
        return error;
    }

    *outPresentFence = new Fence(presentFenceFd);
    return Error::NONE;
}

Error Display::setActiveConfigWithConstraints(
        const std::shared_ptr<const HWC2::Display::Config>& config,
        const VsyncPeriodChangeConstraints& constraints, VsyncPeriodChangeTimeline* outTimeline) {
    ALOGV("[%" PRIu64 "] setActiveConfigWithConstraints", mId);
    if (config->getDisplayId() != mId) {
        ALOGE("setActiveConfigWithConstraints received config %u for the wrong display %" PRIu64
              " (expected %" PRIu64 ")",
              config->getId(), config->getDisplayId(), mId);
        return Error::BAD_CONFIG;
    }

    if (isVsyncPeriodSwitchSupported()) {
        Hwc2::IComposerClient::VsyncPeriodChangeConstraints hwc2Constraints;
        hwc2Constraints.desiredTimeNanos = constraints.desiredTimeNanos;
        hwc2Constraints.seamlessRequired = constraints.seamlessRequired;

        Hwc2::VsyncPeriodChangeTimeline vsyncPeriodChangeTimeline = {};
        auto intError =
                mComposer.setActiveConfigWithConstraints(mId, config->getId(), hwc2Constraints,
                                                         &vsyncPeriodChangeTimeline);
        outTimeline->newVsyncAppliedTimeNanos = vsyncPeriodChangeTimeline.newVsyncAppliedTimeNanos;
        outTimeline->refreshRequired = vsyncPeriodChangeTimeline.refreshRequired;
        outTimeline->refreshTimeNanos = vsyncPeriodChangeTimeline.refreshTimeNanos;
        return static_cast<Error>(intError);
    }

    // Use legacy setActiveConfig instead
    ALOGV("fallback to legacy setActiveConfig");
    const auto now = systemTime();
    if (constraints.desiredTimeNanos > now || constraints.seamlessRequired) {
        ALOGE("setActiveConfigWithConstraints received constraints that can't be satisfied");
    }

    auto intError_2_4 = mComposer.setActiveConfig(mId, config->getId());
    outTimeline->newVsyncAppliedTimeNanos = std::max(now, constraints.desiredTimeNanos);
    outTimeline->refreshRequired = true;
    outTimeline->refreshTimeNanos = now;
    return static_cast<Error>(intError_2_4);
}

Error Display::setActiveConfig(const std::shared_ptr<const Config>& config)
{
    if (config->getDisplayId() != mId) {
        ALOGE("setActiveConfig received config %u for the wrong display %"
                PRIu64 " (expected %" PRIu64 ")", config->getId(),
                config->getDisplayId(), mId);
        return Error::BAD_CONFIG;
    }
    auto intError = mComposer.setActiveConfig(mId, config->getId());
    return static_cast<Error>(intError);
}

Error Display::setClientTarget(uint32_t slot, const sp<GraphicBuffer>& target,
        const sp<Fence>& acquireFence, Dataspace dataspace)
{
    // TODO: Properly encode client target surface damage
    int32_t fenceFd = acquireFence->dup();
    auto intError = mComposer.setClientTarget(mId, slot, target,
            fenceFd, dataspace, std::vector<Hwc2::IComposerClient::Rect>());
    return static_cast<Error>(intError);
}

Error Display::setColorMode(ColorMode mode, RenderIntent renderIntent)
{
    auto intError = mComposer.setColorMode(mId, mode, renderIntent);
    return static_cast<Error>(intError);
}

Error Display::setColorTransform(const android::mat4& matrix, ColorTransform hint) {
    auto intError = mComposer.setColorTransform(mId, matrix.asArray(), hint);
    return static_cast<Error>(intError);
}

Error Display::setOutputBuffer(const sp<GraphicBuffer>& buffer,
        const sp<Fence>& releaseFence)
{
    int32_t fenceFd = releaseFence->dup();
    auto handle = buffer->getNativeBuffer()->handle;
    auto intError = mComposer.setOutputBuffer(mId, handle, fenceFd);
    close(fenceFd);
    return static_cast<Error>(intError);
}

Error Display::setPowerMode(PowerMode mode)
{
    auto intMode = static_cast<Hwc2::IComposerClient::PowerMode>(mode);
    auto intError = mComposer.setPowerMode(mId, intMode);

    if (mode == PowerMode::ON) {
        std::call_once(mDisplayCapabilityQueryFlag, [this]() {
            std::vector<Hwc2::DisplayCapability> tmpCapabilities;
            auto error =
                    static_cast<Error>(mComposer.getDisplayCapabilities(mId, &tmpCapabilities));
            if (error == Error::NONE) {
                for (auto capability : tmpCapabilities) {
                    mDisplayCapabilities.emplace(static_cast<DisplayCapability>(capability));
                }
            } else if (error == Error::UNSUPPORTED) {
                if (mCapabilities.count(Capability::SKIP_CLIENT_COLOR_TRANSFORM)) {
                    mDisplayCapabilities.emplace(DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM);
                }
                bool dozeSupport = false;
                error = static_cast<Error>(mComposer.getDozeSupport(mId, &dozeSupport));
                if (error == Error::NONE && dozeSupport) {
                    mDisplayCapabilities.emplace(DisplayCapability::DOZE);
                }
            }
        });
    }

    return static_cast<Error>(intError);
}

Error Display::setVsyncEnabled(Vsync enabled)
{
    auto intEnabled = static_cast<Hwc2::IComposerClient::Vsync>(enabled);
    auto intError = mComposer.setVsyncEnabled(mId, intEnabled);
    return static_cast<Error>(intError);
}

Error Display::validate(uint32_t* outNumTypes, uint32_t* outNumRequests)
{
    uint32_t numTypes = 0;
    uint32_t numRequests = 0;
    auto intError = mComposer.validateDisplay(mId, &numTypes, &numRequests);
    auto error = static_cast<Error>(intError);
    if (error != Error::NONE && !hasChangesError(error)) {
        return error;
    }

    *outNumTypes = numTypes;
    *outNumRequests = numRequests;
    return error;
}

Error Display::presentOrValidate(uint32_t* outNumTypes, uint32_t* outNumRequests,
                                 sp<android::Fence>* outPresentFence, uint32_t* state) {

    uint32_t numTypes = 0;
    uint32_t numRequests = 0;
    int32_t presentFenceFd = -1;
    auto intError = mComposer.presentOrValidateDisplay(
            mId, &numTypes, &numRequests, &presentFenceFd, state);
    auto error = static_cast<Error>(intError);
    if (error != Error::NONE && !hasChangesError(error)) {
        return error;
    }

    if (*state == 1) {
        *outPresentFence = new Fence(presentFenceFd);
    }

    if (*state == 0) {
        *outNumTypes = numTypes;
        *outNumRequests = numRequests;
    }
    return error;
}

std::future<Error> Display::setDisplayBrightness(float brightness) {
    return promise::defer([composer = &mComposer, id = mId, brightness] {
        const auto intError = composer->setDisplayBrightness(id, brightness);
        return static_cast<Error>(intError);
    });
}

Error Display::setAutoLowLatencyMode(bool on) {
    auto intError = mComposer.setAutoLowLatencyMode(mId, on);
    return static_cast<Error>(intError);
}

Error Display::getSupportedContentTypes(std::vector<ContentType>* outSupportedContentTypes) const {
    std::vector<Hwc2::IComposerClient::ContentType> tmpSupportedContentTypes;
    auto intError = mComposer.getSupportedContentTypes(mId, &tmpSupportedContentTypes);
    for (Hwc2::IComposerClient::ContentType contentType : tmpSupportedContentTypes) {
        outSupportedContentTypes->push_back(static_cast<ContentType>(contentType));
    }
    return static_cast<Error>(intError);
}

Error Display::setContentType(ContentType contentType) {
    auto intError = mComposer.setContentType(mId, contentType);
    return static_cast<Error>(intError);
}

Error Display::getClientTargetProperty(ClientTargetProperty* outClientTargetProperty) {
    const auto error = mComposer.getClientTargetProperty(mId, outClientTargetProperty);
    return static_cast<Error>(error);
}

// For use by Device

void Display::setConnected(bool connected) {
    if (!mIsConnected && connected) {
        mComposer.setClientTargetSlotCount(mId);
        if (mType == DisplayType::PHYSICAL) {
            loadConfigs();
        }
    }
    mIsConnected = connected;
}

int32_t Display::getAttribute(HWConfigId configId, Attribute attribute) {
    int32_t value = 0;
    auto intError = mComposer.getDisplayAttribute(mId, configId, attribute, &value);
    auto error = static_cast<Error>(intError);
    if (error != Error::NONE) {
        ALOGE("getDisplayAttribute(%" PRIu64 ", %u, %s) failed: %s (%d)", mId,
                configId, to_string(attribute).c_str(),
                to_string(error).c_str(), intError);
        return -1;
    }
    return value;
}

void Display::loadConfig(HWConfigId configId) {
    ALOGV("[%" PRIu64 "] loadConfig(%u)", mId, configId);

    auto config = Config::Builder(*this, configId)
                          .setWidth(getAttribute(configId, hal::Attribute::WIDTH))
                          .setHeight(getAttribute(configId, hal::Attribute::HEIGHT))
                          .setVsyncPeriod(getAttribute(configId, hal::Attribute::VSYNC_PERIOD))
                          .setDpiX(getAttribute(configId, hal::Attribute::DPI_X))
                          .setDpiY(getAttribute(configId, hal::Attribute::DPI_Y))
                          .setConfigGroup(getAttribute(configId, hal::Attribute::CONFIG_GROUP))
                          .build();
    mConfigs.emplace(configId, std::move(config));
}

void Display::loadConfigs()
{
    ALOGV("[%" PRIu64 "] loadConfigs", mId);

    std::vector<HWConfigId> configIds;
    auto intError = mComposer.getDisplayConfigs(mId, &configIds);
    auto error = static_cast<Error>(intError);
    if (error != Error::NONE) {
        ALOGE("[%" PRIu64 "] getDisplayConfigs [2] failed: %s (%d)", mId,
                to_string(error).c_str(), intError);
        return;
    }

    for (auto configId : configIds) {
        loadConfig(configId);
    }
}

// Other Display methods

HWC2::Layer* Display::getLayerById(HWLayerId id) const {
    if (mLayers.count(id) == 0) {
        return nullptr;
    }

    return mLayers.at(id).get();
}
} // namespace impl

// Layer methods

Layer::~Layer() = default;

namespace impl {

Layer::Layer(android::Hwc2::Composer& composer, const std::unordered_set<Capability>& capabilities,
             HWDisplayId displayId, HWLayerId layerId)
      : mComposer(composer),
        mCapabilities(capabilities),
        mDisplayId(displayId),
        mId(layerId),
        mColorMatrix(android::mat4()) {
    ALOGV("Created layer %" PRIu64 " on display %" PRIu64, layerId, displayId);
}

Layer::~Layer()
{
    auto intError = mComposer.destroyLayer(mDisplayId, mId);
    auto error = static_cast<Error>(intError);
    ALOGE_IF(error != Error::NONE,
             "destroyLayer(%" PRIu64 ", %" PRIu64 ")"
             " failed: %s (%d)",
             mDisplayId, mId, to_string(error).c_str(), intError);
}

Error Layer::setCursorPosition(int32_t x, int32_t y)
{
    auto intError = mComposer.setCursorPosition(mDisplayId, mId, x, y);
    return static_cast<Error>(intError);
}

Error Layer::setBuffer(uint32_t slot, const sp<GraphicBuffer>& buffer,
        const sp<Fence>& acquireFence)
{
    if (buffer == nullptr && mBufferSlot == slot) {
        return Error::NONE;
    }
    mBufferSlot = slot;

    int32_t fenceFd = acquireFence->dup();
    auto intError = mComposer.setLayerBuffer(mDisplayId, mId, slot, buffer,
                                             fenceFd);
    return static_cast<Error>(intError);
}

Error Layer::setSurfaceDamage(const Region& damage)
{
    if (damage.isRect() && mDamageRegion.isRect() &&
        (damage.getBounds() == mDamageRegion.getBounds())) {
        return Error::NONE;
    }
    mDamageRegion = damage;

    // We encode default full-screen damage as INVALID_RECT upstream, but as 0
    // rects for HWC
    Hwc2::Error intError = Hwc2::Error::NONE;
    if (damage.isRect() && damage.getBounds() == Rect::INVALID_RECT) {
        intError = mComposer.setLayerSurfaceDamage(mDisplayId,
                mId, std::vector<Hwc2::IComposerClient::Rect>());
    } else {
        size_t rectCount = 0;
        auto rectArray = damage.getArray(&rectCount);

        std::vector<Hwc2::IComposerClient::Rect> hwcRects;
        for (size_t rect = 0; rect < rectCount; ++rect) {
            hwcRects.push_back({rectArray[rect].left, rectArray[rect].top,
                    rectArray[rect].right, rectArray[rect].bottom});
        }

        intError = mComposer.setLayerSurfaceDamage(mDisplayId, mId, hwcRects);
    }

    return static_cast<Error>(intError);
}

Error Layer::setBlendMode(BlendMode mode)
{
    auto intError = mComposer.setLayerBlendMode(mDisplayId, mId, mode);
    return static_cast<Error>(intError);
}

Error Layer::setColor(Color color) {
    auto intError = mComposer.setLayerColor(mDisplayId, mId, color);
    return static_cast<Error>(intError);
}

Error Layer::setCompositionType(Composition type)
{
    auto intError = mComposer.setLayerCompositionType(mDisplayId, mId, type);
    return static_cast<Error>(intError);
}

Error Layer::setDataspace(Dataspace dataspace)
{
    if (dataspace == mDataSpace) {
        return Error::NONE;
    }
    mDataSpace = dataspace;
    auto intError = mComposer.setLayerDataspace(mDisplayId, mId, mDataSpace);
    return static_cast<Error>(intError);
}

Error Layer::setPerFrameMetadata(const int32_t supportedPerFrameMetadata,
        const android::HdrMetadata& metadata)
{
    if (metadata == mHdrMetadata) {
        return Error::NONE;
    }

    mHdrMetadata = metadata;
    int validTypes = mHdrMetadata.validTypes & supportedPerFrameMetadata;
    std::vector<Hwc2::PerFrameMetadata> perFrameMetadatas;
    if (validTypes & HdrMetadata::SMPTE2086) {
        perFrameMetadatas.insert(perFrameMetadatas.end(),
                                 {{Hwc2::PerFrameMetadataKey::DISPLAY_RED_PRIMARY_X,
                                   mHdrMetadata.smpte2086.displayPrimaryRed.x},
                                  {Hwc2::PerFrameMetadataKey::DISPLAY_RED_PRIMARY_Y,
                                   mHdrMetadata.smpte2086.displayPrimaryRed.y},
                                  {Hwc2::PerFrameMetadataKey::DISPLAY_GREEN_PRIMARY_X,
                                   mHdrMetadata.smpte2086.displayPrimaryGreen.x},
                                  {Hwc2::PerFrameMetadataKey::DISPLAY_GREEN_PRIMARY_Y,
                                   mHdrMetadata.smpte2086.displayPrimaryGreen.y},
                                  {Hwc2::PerFrameMetadataKey::DISPLAY_BLUE_PRIMARY_X,
                                   mHdrMetadata.smpte2086.displayPrimaryBlue.x},
                                  {Hwc2::PerFrameMetadataKey::DISPLAY_BLUE_PRIMARY_Y,
                                   mHdrMetadata.smpte2086.displayPrimaryBlue.y},
                                  {Hwc2::PerFrameMetadataKey::WHITE_POINT_X,
                                   mHdrMetadata.smpte2086.whitePoint.x},
                                  {Hwc2::PerFrameMetadataKey::WHITE_POINT_Y,
                                   mHdrMetadata.smpte2086.whitePoint.y},
                                  {Hwc2::PerFrameMetadataKey::MAX_LUMINANCE,
                                   mHdrMetadata.smpte2086.maxLuminance},
                                  {Hwc2::PerFrameMetadataKey::MIN_LUMINANCE,
                                   mHdrMetadata.smpte2086.minLuminance}});
    }

    if (validTypes & HdrMetadata::CTA861_3) {
        perFrameMetadatas.insert(perFrameMetadatas.end(),
                                 {{Hwc2::PerFrameMetadataKey::MAX_CONTENT_LIGHT_LEVEL,
                                   mHdrMetadata.cta8613.maxContentLightLevel},
                                  {Hwc2::PerFrameMetadataKey::MAX_FRAME_AVERAGE_LIGHT_LEVEL,
                                   mHdrMetadata.cta8613.maxFrameAverageLightLevel}});
    }

    Error error = static_cast<Error>(
            mComposer.setLayerPerFrameMetadata(mDisplayId, mId, perFrameMetadatas));

    if (validTypes & HdrMetadata::HDR10PLUS) {
        if (CC_UNLIKELY(mHdrMetadata.hdr10plus.size() == 0)) {
            return Error::BAD_PARAMETER;
        }

        std::vector<Hwc2::PerFrameMetadataBlob> perFrameMetadataBlobs;
        perFrameMetadataBlobs.push_back(
                {Hwc2::PerFrameMetadataKey::HDR10_PLUS_SEI, mHdrMetadata.hdr10plus});
        Error setMetadataBlobsError = static_cast<Error>(
                mComposer.setLayerPerFrameMetadataBlobs(mDisplayId, mId, perFrameMetadataBlobs));
        if (error == Error::NONE) {
            return setMetadataBlobsError;
        }
    }
    return error;
}

Error Layer::setDisplayFrame(const Rect& frame)
{
    Hwc2::IComposerClient::Rect hwcRect{frame.left, frame.top,
        frame.right, frame.bottom};
    auto intError = mComposer.setLayerDisplayFrame(mDisplayId, mId, hwcRect);
    return static_cast<Error>(intError);
}

Error Layer::setPlaneAlpha(float alpha)
{
    auto intError = mComposer.setLayerPlaneAlpha(mDisplayId, mId, alpha);
    return static_cast<Error>(intError);
}

Error Layer::setSidebandStream(const native_handle_t* stream)
{
    if (mCapabilities.count(Capability::SIDEBAND_STREAM) == 0) {
        ALOGE("Attempted to call setSidebandStream without checking that the "
                "device supports sideband streams");
        return Error::UNSUPPORTED;
    }
    auto intError = mComposer.setLayerSidebandStream(mDisplayId, mId, stream);
    return static_cast<Error>(intError);
}

Error Layer::setSourceCrop(const FloatRect& crop)
{
    Hwc2::IComposerClient::FRect hwcRect{
        crop.left, crop.top, crop.right, crop.bottom};
    auto intError = mComposer.setLayerSourceCrop(mDisplayId, mId, hwcRect);
    return static_cast<Error>(intError);
}

Error Layer::setTransform(Transform transform)
{
    auto intTransform = static_cast<Hwc2::Transform>(transform);
    auto intError = mComposer.setLayerTransform(mDisplayId, mId, intTransform);
    return static_cast<Error>(intError);
}

Error Layer::setVisibleRegion(const Region& region)
{
    if (region.isRect() && mVisibleRegion.isRect() &&
        (region.getBounds() == mVisibleRegion.getBounds())) {
        return Error::NONE;
    }
    mVisibleRegion = region;

    size_t rectCount = 0;
    auto rectArray = region.getArray(&rectCount);

    std::vector<Hwc2::IComposerClient::Rect> hwcRects;
    for (size_t rect = 0; rect < rectCount; ++rect) {
        hwcRects.push_back({rectArray[rect].left, rectArray[rect].top,
                rectArray[rect].right, rectArray[rect].bottom});
    }

    auto intError = mComposer.setLayerVisibleRegion(mDisplayId, mId, hwcRects);
    return static_cast<Error>(intError);
}

Error Layer::setZOrder(uint32_t z)
{
    auto intError = mComposer.setLayerZOrder(mDisplayId, mId, z);
    return static_cast<Error>(intError);
}

// Composer HAL 2.3
Error Layer::setColorTransform(const android::mat4& matrix) {
    if (matrix == mColorMatrix) {
        return Error::NONE;
    }
    auto intError = mComposer.setLayerColorTransform(mDisplayId, mId, matrix.asArray());
    Error error = static_cast<Error>(intError);
    if (error != Error::NONE) {
        return error;
    }
    mColorMatrix = matrix;
    return error;
}

// Composer HAL 2.4
Error Layer::setLayerGenericMetadata(const std::string& name, bool mandatory,
                                     const std::vector<uint8_t>& value) {
    auto intError = mComposer.setLayerGenericMetadata(mDisplayId, mId, name, mandatory, value);
    return static_cast<Error>(intError);
}

} // namespace impl
} // namespace HWC2
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
