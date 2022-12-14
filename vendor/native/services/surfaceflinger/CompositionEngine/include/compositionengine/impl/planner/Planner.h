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

#include <compositionengine/Output.h>
#include <compositionengine/impl/planner/Flattener.h>
#include <compositionengine/impl/planner/LayerState.h>
#include <compositionengine/impl/planner/Predictor.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <optional>
#include <string>
#include <unordered_map>

namespace android {

namespace renderengine {
class RenderEngine;
} // namespace renderengine

namespace compositionengine::impl::planner {

// This is the top level class for layer caching. It is responsible for
// heuristically determining the composition strategy of the current layer stack,
// and flattens inactive layers into an override buffer so it can be used
// as a more efficient representation of parts of the layer stack.
// Implicitly, layer caching must also be enabled for the Planner to have any effect
// E.g., setprop debug.sf.enable_layer_caching 1, or
// adb shell service call SurfaceFlinger 1040 i32 1 [i64 <display ID>]
class Planner {
public:
    Planner(renderengine::RenderEngine& renderengine);

    void setDisplaySize(ui::Size);

    // Updates the Planner with the current set of layers before a composition strategy is
    // determined.
    // The Planner will call to the Flattener to determine to:
    // 1. Replace any cached sets with a newly available flattened cached set
    // 2. Create a new cached set if possible
    void plan(
            compositionengine::Output::OutputLayersEnumerator<compositionengine::Output>&& layers);

    // Updates the Planner with the current set of layers after a composition strategy is
    // determined.
    void reportFinalPlan(
            compositionengine::Output::OutputLayersEnumerator<compositionengine::Output>&& layers);

    // The planner will call to the Flattener to render any pending cached set.
    // Rendering a pending cached set is optional: if the renderDeadline is not far enough in the
    // future then the planner may opt to skip rendering the cached set.
    void renderCachedSets(const OutputCompositionState& outputState,
                          std::optional<std::chrono::steady_clock::time_point> renderDeadline,
                          bool deviceHandlesColorTransform);

    void setTexturePoolEnabled(bool enabled) { mFlattener.setTexturePoolEnabled(enabled); }

    void dump(const Vector<String16>& args, std::string&);

private:
    void dumpUsage(std::string&) const;

    std::unordered_map<LayerId, LayerState> mPreviousLayers;

    std::vector<const LayerState*> mCurrentLayers;

    Predictor mPredictor;
    Flattener mFlattener;

    std::optional<Predictor::PredictedPlan> mPredictedPlan;
    NonBufferHash mFlattenedHash = 0;

    bool mPredictorEnabled = false;
};

} // namespace compositionengine::impl::planner
} // namespace android
