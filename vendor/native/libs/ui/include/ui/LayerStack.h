/*
 * Copyright 2021 The Android Open Source Project
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

#include <ftl/cast.h>
#include <ftl/string.h>
#include <log/log.h>

namespace android::ui {

// A LayerStack identifies a Z-ordered group of layers. A layer can only be associated to a single
// LayerStack, but a LayerStack can be associated to multiple displays, mirroring the same content.
struct LayerStack {
    uint32_t id = UINT32_MAX;

    template <typename T>
    static constexpr LayerStack fromValue(T v) {
        if (ftl::cast_safety<uint32_t>(v) == ftl::CastSafety::kSafe) {
            return {static_cast<uint32_t>(v)};
        }

        ALOGW("Invalid layer stack %s", ftl::to_string(v).c_str());
        return {};
    }
};

constexpr LayerStack INVALID_LAYER_STACK;
constexpr LayerStack DEFAULT_LAYER_STACK{0u};

inline bool operator==(LayerStack lhs, LayerStack rhs) {
    return lhs.id == rhs.id;
}

inline bool operator!=(LayerStack lhs, LayerStack rhs) {
    return !(lhs == rhs);
}

inline bool operator>(LayerStack lhs, LayerStack rhs) {
    return lhs.id > rhs.id;
}

// A LayerFilter determines if a layer is included for output to a display.
struct LayerFilter {
    LayerStack layerStack;

    // True if the layer is only output to internal displays, i.e. excluded from screenshots, screen
    // recordings, and mirroring to virtual or external displays. Used for display cutout overlays.
    bool toInternalDisplay = false;

    // Returns true if the input filter can be output to this filter.
    bool includes(LayerFilter other) const {
        // The layer stacks must match.
        if (other.layerStack == INVALID_LAYER_STACK || other.layerStack != layerStack) {
            return false;
        }

        // The output must be to an internal display if the input filter has that constraint.
        return !other.toInternalDisplay || toInternalDisplay;
    }
};

} // namespace android::ui
