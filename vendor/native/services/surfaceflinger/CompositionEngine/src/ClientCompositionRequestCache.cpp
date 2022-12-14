/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <algorithm>

#include <compositionengine/impl/ClientCompositionRequestCache.h>
#include <renderengine/DisplaySettings.h>
#include <renderengine/LayerSettings.h>

namespace android::compositionengine::impl {

namespace {
LayerFE::LayerSettings getLayerSettingsSnapshot(const LayerFE::LayerSettings& settings) {
    LayerFE::LayerSettings snapshot = settings;
    snapshot.source.buffer.buffer = nullptr;
    snapshot.source.buffer.fence = nullptr;
    return snapshot;
}

inline bool equalIgnoringSource(const renderengine::LayerSettings& lhs,
                                const renderengine::LayerSettings& rhs) {
    return lhs.geometry == rhs.geometry && lhs.alpha == rhs.alpha &&
            lhs.sourceDataspace == rhs.sourceDataspace &&
            lhs.colorTransform == rhs.colorTransform &&
            lhs.disableBlending == rhs.disableBlending && lhs.shadow == rhs.shadow &&
            lhs.backgroundBlurRadius == rhs.backgroundBlurRadius;
}

inline bool equalIgnoringBuffer(const renderengine::Buffer& lhs, const renderengine::Buffer& rhs) {
    return lhs.textureName == rhs.textureName &&
            lhs.useTextureFiltering == rhs.useTextureFiltering &&
            lhs.textureTransform == rhs.textureTransform &&
            lhs.usePremultipliedAlpha == rhs.usePremultipliedAlpha &&
            lhs.isOpaque == rhs.isOpaque && lhs.isY410BT2020 == rhs.isY410BT2020 &&
            lhs.maxMasteringLuminance == rhs.maxMasteringLuminance &&
            lhs.maxContentLuminance == rhs.maxContentLuminance;
}

inline bool equalIgnoringBuffer(const renderengine::LayerSettings& lhs,
                                const renderengine::LayerSettings& rhs) {
    // compare LayerSettings without LayerSettings.PixelSource
    return equalIgnoringSource(lhs, rhs) &&

            // compare LayerSettings.PixelSource without buffer
            lhs.source.solidColor == rhs.source.solidColor &&

            // compare LayerSettings.PixelSource.Buffer without buffer & fence
            equalIgnoringBuffer(lhs.source.buffer, rhs.source.buffer);
}

bool layerSettingsAreEqual(const LayerFE::LayerSettings& lhs, const LayerFE::LayerSettings& rhs) {
    return lhs.bufferId == rhs.bufferId && lhs.frameNumber == rhs.frameNumber &&
            equalIgnoringBuffer(lhs, rhs);
}

} // namespace

ClientCompositionRequestCache::ClientCompositionRequest::ClientCompositionRequest(
        const renderengine::DisplaySettings& initDisplay,
        const std::vector<LayerFE::LayerSettings>& initLayerSettings)
      : display(initDisplay) {
    layerSettings.reserve(initLayerSettings.size());
    for (const LayerFE::LayerSettings& settings : initLayerSettings) {
        layerSettings.push_back(getLayerSettingsSnapshot(settings));
    }
}

bool ClientCompositionRequestCache::ClientCompositionRequest::equals(
        const renderengine::DisplaySettings& newDisplay,
        const std::vector<LayerFE::LayerSettings>& newLayerSettings) const {
    return newDisplay == display &&
            std::equal(layerSettings.begin(), layerSettings.end(), newLayerSettings.begin(),
                       newLayerSettings.end(), layerSettingsAreEqual);
}

bool ClientCompositionRequestCache::exists(
        uint64_t bufferId, const renderengine::DisplaySettings& display,
        const std::vector<LayerFE::LayerSettings>& layerSettings) const {
    for (const auto& [cachedBufferId, cachedRequest] : mCache) {
        if (cachedBufferId == bufferId) {
            return cachedRequest.equals(display, layerSettings);
        }
    }
    return false;
}

void ClientCompositionRequestCache::add(uint64_t bufferId,
                                        const renderengine::DisplaySettings& display,
                                        const std::vector<LayerFE::LayerSettings>& layerSettings) {
    const ClientCompositionRequest request(display, layerSettings);
    for (auto& [cachedBufferId, cachedRequest] : mCache) {
        if (cachedBufferId == bufferId) {
            cachedRequest = std::move(request);
            return;
        }
    }

    if (mCache.size() >= mMaxCacheSize) {
        mCache.pop_front();
    }

    mCache.emplace_back(bufferId, std::move(request));
}

void ClientCompositionRequestCache::remove(uint64_t bufferId) {
    for (auto it = mCache.begin(); it != mCache.end(); it++) {
        if (it->first == bufferId) {
            mCache.erase(it);
            return;
        }
    }
}

} // namespace android::compositionengine::impl
