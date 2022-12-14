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

// #define LOG_NDEBUG 0

#undef LOG_TAG
#define LOG_TAG "Planner"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <android-base/properties.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <compositionengine/impl/planner/Planner.h>

#include <utils/Trace.h>
#include <chrono>

namespace android::compositionengine::impl::planner {

namespace {

std::optional<Flattener::Tunables::RenderScheduling> buildRenderSchedulingTunables() {
    if (!base::GetBoolProperty(std::string("debug.sf.enable_cached_set_render_scheduling"), true)) {
        return std::nullopt;
    }

    const auto renderDuration = std::chrono::nanoseconds(
            base::GetUintProperty<uint64_t>(std::string("debug.sf.cached_set_render_duration_ns"),
                                            Flattener::Tunables::RenderScheduling::
                                                    kDefaultCachedSetRenderDuration.count()));

    const auto maxDeferRenderAttempts = base::GetUintProperty<
            size_t>(std::string("debug.sf.cached_set_max_defer_render_attmpts"),
                    Flattener::Tunables::RenderScheduling::kDefaultMaxDeferRenderAttempts);

    return std::make_optional<Flattener::Tunables::RenderScheduling>(
            Flattener::Tunables::RenderScheduling{
                    .cachedSetRenderDuration = renderDuration,
                    .maxDeferRenderAttempts = maxDeferRenderAttempts,
            });
}

Flattener::Tunables buildFlattenerTuneables() {
    const auto activeLayerTimeout = std::chrono::milliseconds(
            base::GetIntProperty<int32_t>(std::string(
                                                  "debug.sf.layer_caching_active_layer_timeout_ms"),
                                          Flattener::Tunables::kDefaultActiveLayerTimeout.count()));
    const auto enableHolePunch =
            base::GetBoolProperty(std::string("debug.sf.enable_hole_punch_pip"),
                                  Flattener::Tunables::kDefaultEnableHolePunch);
    return Flattener::Tunables{
            .mActiveLayerTimeout = activeLayerTimeout,
            .mRenderScheduling = buildRenderSchedulingTunables(),
            .mEnableHolePunch = enableHolePunch,
    };
}

} // namespace

Planner::Planner(renderengine::RenderEngine& renderEngine)
      : mFlattener(renderEngine,
                   buildFlattenerTuneables()) {
    mPredictorEnabled =
            base::GetBoolProperty(std::string("debug.sf.enable_planner_prediction"), false);
}

void Planner::setDisplaySize(ui::Size size) {
    mFlattener.setDisplaySize(size);
}

void Planner::plan(
        compositionengine::Output::OutputLayersEnumerator<compositionengine::Output>&& layers) {
    ATRACE_CALL();
    std::unordered_set<LayerId> removedLayers;
    removedLayers.reserve(mPreviousLayers.size());

    std::transform(mPreviousLayers.begin(), mPreviousLayers.end(),
                   std::inserter(removedLayers, removedLayers.begin()),
                   [](const auto& layer) { return layer.first; });

    std::vector<LayerId> currentLayerIds;
    for (auto layer : layers) {
        LayerId id = layer->getLayerFE().getSequence();
        if (const auto layerEntry = mPreviousLayers.find(id); layerEntry != mPreviousLayers.end()) {
            // Track changes from previous info
            LayerState& state = layerEntry->second;
            ftl::Flags<LayerStateField> differences = state.update(layer);
            if (differences.get() == 0) {
                state.incrementFramesSinceBufferUpdate();
            } else {
                ALOGV("Layer %s changed: %s", state.getName().c_str(),
                      differences.string().c_str());

                if (differences.test(LayerStateField::Buffer)) {
                    state.resetFramesSinceBufferUpdate();
                } else {
                    state.incrementFramesSinceBufferUpdate();
                }
            }
        } else {
            LayerState state(layer);
            ALOGV("Added layer %s", state.getName().c_str());
            mPreviousLayers.emplace(std::make_pair(id, std::move(state)));
        }

        currentLayerIds.emplace_back(id);

        if (const auto found = removedLayers.find(id); found != removedLayers.end()) {
            removedLayers.erase(found);
        }
    }

    mCurrentLayers.clear();
    mCurrentLayers.reserve(currentLayerIds.size());
    std::transform(currentLayerIds.cbegin(), currentLayerIds.cend(),
                   std::back_inserter(mCurrentLayers), [this](LayerId id) {
                       LayerState* state = &mPreviousLayers.at(id);
                       state->getOutputLayer()->editState().overrideInfo = {};
                       return state;
                   });

    const NonBufferHash hash = getNonBufferHash(mCurrentLayers);
    mFlattenedHash =
            mFlattener.flattenLayers(mCurrentLayers, hash, std::chrono::steady_clock::now());
    const bool layersWereFlattened = hash != mFlattenedHash;

    ALOGV("[%s] Initial hash %zx flattened hash %zx", __func__, hash, mFlattenedHash);

    if (mPredictorEnabled) {
        mPredictedPlan =
                mPredictor.getPredictedPlan(layersWereFlattened ? std::vector<const LayerState*>()
                                                                : mCurrentLayers,
                                            mFlattenedHash);
        if (mPredictedPlan) {
            ALOGV("[%s] Predicting plan %s", __func__, to_string(mPredictedPlan->plan).c_str());
        } else {
            ALOGV("[%s] No prediction found\n", __func__);
        }
    }

    // Clean up the set of previous layers now that the view of the LayerStates in the flattener are
    // up-to-date.
    for (LayerId removedLayer : removedLayers) {
        if (const auto layerEntry = mPreviousLayers.find(removedLayer);
            layerEntry != mPreviousLayers.end()) {
            const auto& [id, state] = *layerEntry;
            ALOGV("Removed layer %s", state.getName().c_str());
            mPreviousLayers.erase(removedLayer);
        }
    }
}

void Planner::reportFinalPlan(
        compositionengine::Output::OutputLayersEnumerator<compositionengine::Output>&& layers) {
    ATRACE_CALL();
    if (!mPredictorEnabled) {
        return;
    }

    Plan finalPlan;
    const GraphicBuffer* currentOverrideBuffer = nullptr;
    bool hasSkippedLayers = false;
    for (auto layer : layers) {
        if (!layer->getState().overrideInfo.buffer) {
            continue;
        }

        const GraphicBuffer* overrideBuffer =
                layer->getState().overrideInfo.buffer->getBuffer().get();
        if (overrideBuffer != nullptr && overrideBuffer == currentOverrideBuffer) {
            // Skip this layer since it is part of a previous cached set
            hasSkippedLayers = true;
            continue;
        }

        currentOverrideBuffer = overrideBuffer;

        const bool forcedOrRequestedClient =
                layer->getState().forceClientComposition || layer->requiresClientComposition();

        finalPlan.addLayerType(
                forcedOrRequestedClient
                        ? aidl::android::hardware::graphics::composer3::Composition::CLIENT
                        : layer->getLayerFE().getCompositionState()->compositionType);
    }

    mPredictor.recordResult(mPredictedPlan, mFlattenedHash, mCurrentLayers, hasSkippedLayers,
                            finalPlan);
}

void Planner::renderCachedSets(const OutputCompositionState& outputState,
                               std::optional<std::chrono::steady_clock::time_point> renderDeadline,
                               bool deviceHandlesColorTransform) {
    ATRACE_CALL();
    mFlattener.renderCachedSets(outputState, renderDeadline, deviceHandlesColorTransform);
}

void Planner::dump(const Vector<String16>& args, std::string& result) {
    if (args.size() > 1) {
        const String8 command(args[1]);
        if (command == "--compare" || command == "-c") {
            if (args.size() < 4) {
                base::StringAppendF(&result,
                                    "Expected two layer stack hashes, e.g. '--planner %s "
                                    "<left_hash> <right_hash>'\n",
                                    command.string());
                return;
            }
            if (args.size() > 4) {
                base::StringAppendF(&result,
                                    "Too many arguments found, expected '--planner %s <left_hash> "
                                    "<right_hash>'\n",
                                    command.string());
                return;
            }

            const String8 leftHashString(args[2]);
            size_t leftHash = 0;
            int fieldsRead = sscanf(leftHashString.string(), "%zx", &leftHash);
            if (fieldsRead != 1) {
                base::StringAppendF(&result, "Failed to parse %s as a size_t\n",
                                    leftHashString.string());
                return;
            }

            const String8 rightHashString(args[3]);
            size_t rightHash = 0;
            fieldsRead = sscanf(rightHashString.string(), "%zx", &rightHash);
            if (fieldsRead != 1) {
                base::StringAppendF(&result, "Failed to parse %s as a size_t\n",
                                    rightHashString.string());
                return;
            }

            if (mPredictorEnabled) {
                mPredictor.compareLayerStacks(leftHash, rightHash, result);
            }
        } else if (command == "--describe" || command == "-d") {
            if (args.size() < 3) {
                base::StringAppendF(&result,
                                    "Expected a layer stack hash, e.g. '--planner %s <hash>'\n",
                                    command.string());
                return;
            }
            if (args.size() > 3) {
                base::StringAppendF(&result,
                                    "Too many arguments found, expected '--planner %s <hash>'\n",
                                    command.string());
                return;
            }

            const String8 hashString(args[2]);
            size_t hash = 0;
            const int fieldsRead = sscanf(hashString.string(), "%zx", &hash);
            if (fieldsRead != 1) {
                base::StringAppendF(&result, "Failed to parse %s as a size_t\n",
                                    hashString.string());
                return;
            }

            if (mPredictorEnabled) {
                mPredictor.describeLayerStack(hash, result);
            }
        } else if (command == "--help" || command == "-h") {
            dumpUsage(result);
        } else if (command == "--similar" || command == "-s") {
            if (args.size() < 3) {
                base::StringAppendF(&result, "Expected a plan string, e.g. '--planner %s <plan>'\n",
                                    command.string());
                return;
            }
            if (args.size() > 3) {
                base::StringAppendF(&result,
                                    "Too many arguments found, expected '--planner %s <plan>'\n",
                                    command.string());
                return;
            }

            const String8 planString(args[2]);
            std::optional<Plan> plan = Plan::fromString(std::string(planString.string()));
            if (!plan) {
                base::StringAppendF(&result, "Failed to parse %s as a Plan\n", planString.string());
                return;
            }

            if (mPredictorEnabled) {
                mPredictor.listSimilarStacks(*plan, result);
            }
        } else if (command == "--layers" || command == "-l") {
            mFlattener.dumpLayers(result);
        } else {
            base::StringAppendF(&result, "Unknown command '%s'\n\n", command.string());
            dumpUsage(result);
        }
        return;
    }

    // If there are no specific commands, dump the usual state

    mFlattener.dump(result);
    result.append("\n");

    if (mPredictorEnabled) {
        mPredictor.dump(result);
    }
}

void Planner::dumpUsage(std::string& result) const {
    result.append("Planner command line interface usage\n");
    result.append("  dumpsys SurfaceFlinger --planner <command> [arguments]\n\n");

    result.append("If run without a command, dumps current Planner state\n\n");

    result.append("Commands:\n");

    result.append("[--compare|-c] <left_hash> <right_hash>\n");
    result.append("  Compares the predictions <left_hash> and <right_hash> by showing differences"
                  " in their example layer stacks\n");

    result.append("[--describe|-d] <hash>\n");
    result.append("  Prints the example layer stack and prediction statistics for <hash>\n");

    result.append("[--help|-h]\n");
    result.append("  Shows this message\n");

    result.append("[--similar|-s] <plan>\n");
    result.append("  Prints the example layer names for similar stacks matching <plan>\n");

    result.append("[--layers|-l]\n");
    result.append("  Prints the current layers\n");
}

} // namespace android::compositionengine::impl::planner
