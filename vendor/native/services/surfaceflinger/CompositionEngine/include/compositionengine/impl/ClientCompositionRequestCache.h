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

#pragma once

#include <cstdint>
#include <deque>

#include <compositionengine/LayerFE.h>
#include <renderengine/DisplaySettings.h>
#include <renderengine/LayerSettings.h>

namespace android {

namespace compositionengine::impl {

// The cache is used to skip duplicate client composition requests. We do so by keeping track
// of every composition request and the buffer that the request is rendered into. During the
// next composition request, if the request matches what was rendered into the buffer, then
// we can skip of the request, pass back an empty fence, and let HWC use the previous render
// result.
//
// The cache is a mapping of the RenderSurface buffer id (unique per process) and a snapshot of
// the composition request. We need to make sure the request, including the order of the
// layers, do not change from call to call. The snapshot removes strong references to the
// client buffer id so we don't extend the lifetime of the buffer by storing it in the cache.
class ClientCompositionRequestCache {
public:
    explicit ClientCompositionRequestCache(uint32_t cacheSize) : mMaxCacheSize(cacheSize){};
    ~ClientCompositionRequestCache() = default;
    bool exists(uint64_t bufferId, const renderengine::DisplaySettings& display,
                const std::vector<LayerFE::LayerSettings>& layerSettings) const;
    void add(uint64_t bufferId, const renderengine::DisplaySettings& display,
             const std::vector<LayerFE::LayerSettings>& layerSettings);
    void remove(uint64_t bufferId);

private:
    uint32_t mMaxCacheSize;
    struct ClientCompositionRequest {
        renderengine::DisplaySettings display;
        std::vector<LayerFE::LayerSettings> layerSettings;
        ClientCompositionRequest(const renderengine::DisplaySettings& _display,
                                 const std::vector<LayerFE::LayerSettings>& _layerSettings);
        bool equals(const renderengine::DisplaySettings& _display,
                    const std::vector<LayerFE::LayerSettings>& _layerSettings) const;
    };

    // Cache of requests, keyed by corresponding GraphicBuffer ID.
    std::deque<std::pair<uint64_t /* bufferId */, ClientCompositionRequest>> mCache;
};

} // namespace compositionengine::impl
} // namespace android
