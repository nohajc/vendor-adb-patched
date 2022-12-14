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

#include <compositionengine/impl/planner/Predictor.h>

namespace android::compositionengine::impl::planner {

std::optional<LayerStack::ApproximateMatch> LayerStack::getApproximateMatch(
        const std::vector<const LayerState*>& other) const {
    // Differing numbers of layers are never an approximate match
    if (mLayers.size() != other.size()) {
        return std::nullopt;
    }

    std::optional<ApproximateMatch> approximateMatch = {};
    for (size_t i = 0; i < mLayers.size(); ++i) {
        // Skip identical layers
        if (mLayers[i].getHash() == other[i]->getHash()) {
            continue;
        }

        // Skip layers where both are client-composited, since that doesn't change the
        // composition plan
        if (mLayers[i].getCompositionType() == hal::Composition::CLIENT &&
            other[i]->getCompositionType() == hal::Composition::CLIENT) {
            continue;
        }

        // If layers differ in composition type, their stacks are too different
        if (mLayers[i].getCompositionType() != other[i]->getCompositionType()) {
            return std::nullopt;
        }

        // If layers are not identical, but we already detected a prior approximate match for a
        // previous layer, the LayerStacks differ by too much, so return nothing
        if (approximateMatch) {
            return std::nullopt;
        }

        Flags<LayerStateField> differingFields = mLayers[i].getDifferingFields(*other[i]);

        // If we don't find an approximate match on this layer, then the LayerStacks differ
        // by too much, so return nothing
        const int differingFieldCount = __builtin_popcount(differingFields.get());
        if (differingFieldCount <= kMaxDifferingFields) {
            approximateMatch = ApproximateMatch{
                    .differingIndex = i,
                    .differingFields = differingFields,
            };
        } else {
            return std::nullopt;
        }
    }

    if (approximateMatch) {
        return approximateMatch;
    }

    // If we make it through the layer-by-layer comparison without an approximate match,
    // it means that all layers were either identical or had client-composited layers in common,
    // which don't affect the composition strategy, so return a successful result with
    // no differences.
    return ApproximateMatch{
            .differingIndex = 0,
            .differingFields = {},
    };
}

std::optional<Plan> Plan::fromString(const std::string& string) {
    Plan plan;
    for (char c : string) {
        switch (c) {
            case 'C':
                plan.addLayerType(hal::Composition::CLIENT);
                continue;
            case 'U':
                plan.addLayerType(hal::Composition::CURSOR);
                continue;
            case 'D':
                plan.addLayerType(hal::Composition::DEVICE);
                continue;
            case 'I':
                plan.addLayerType(hal::Composition::INVALID);
                continue;
            case 'B':
                plan.addLayerType(hal::Composition::SIDEBAND);
                continue;
            case 'S':
                plan.addLayerType(hal::Composition::SOLID_COLOR);
                continue;
            default:
                return std::nullopt;
        }
    }
    return plan;
}

std::string to_string(const Plan& plan) {
    std::string result;
    for (auto type : plan.mLayerTypes) {
        switch (type) {
            case hal::Composition::CLIENT:
                result.append("C");
                break;
            case hal::Composition::CURSOR:
                result.append("U");
                break;
            case hal::Composition::DEVICE:
                result.append("D");
                break;
            case hal::Composition::INVALID:
                result.append("I");
                break;
            case hal::Composition::SIDEBAND:
                result.append("B");
                break;
            case hal::Composition::SOLID_COLOR:
                result.append("S");
                break;
        }
    }
    return result;
}

void Prediction::dump(std::string& result) const {
    result.append(to_string(mPlan));
    result.append(" [Exact ");
    mExactStats.dump(result);
    result.append("] [Approximate ");
    mApproximateStats.dump(result);
    result.append("]");
}

std::optional<Predictor::PredictedPlan> Predictor::getPredictedPlan(
        const std::vector<const LayerState*>& layers, NonBufferHash hash) const {
    // First check for an exact match
    if (std::optional<Plan> exactMatch = getExactMatch(hash); exactMatch) {
        ALOGV("[%s] Found an exact match for %zx", __func__, hash);
        return PredictedPlan{.hash = hash, .plan = *exactMatch, .type = Prediction::Type::Exact};
    }

    // If only a hash was passed in for a layer stack with a cached set, don't perform
    // approximate matches and return early
    if (layers.empty()) {
        ALOGV("[%s] Only hash was passed, but no exact match was found", __func__);
        return std::nullopt;
    }

    // Then check for approximate matches
    if (std::optional<NonBufferHash> approximateMatch = getApproximateMatch(layers);
        approximateMatch) {
        ALOGV("[%s] Found an approximate match for %zx", __func__, *approximateMatch);
        const Prediction& prediction = getPrediction(*approximateMatch);
        return PredictedPlan{.hash = *approximateMatch,
                             .plan = prediction.getPlan(),
                             .type = Prediction::Type::Approximate};
    }

    return std::nullopt;
}

void Predictor::recordResult(std::optional<PredictedPlan> predictedPlan,
                             NonBufferHash flattenedHash,
                             const std::vector<const LayerState*>& layers, bool hasSkippedLayers,
                             Plan result) {
    if (predictedPlan) {
        recordPredictedResult(*predictedPlan, layers, std::move(result));
        return;
    }

    ++mMissCount;

    if (!hasSkippedLayers && findSimilarPrediction(layers, result)) {
        return;
    }

    ALOGV("[%s] Adding novel candidate %zx", __func__, flattenedHash);
    mCandidates.emplace_front(flattenedHash, Prediction(layers, result));
    if (mCandidates.size() > MAX_CANDIDATES) {
        mCandidates.pop_back();
    }
}

void Predictor::dump(std::string& result) const {
    result.append("Predictor state:\n");

    const size_t hitCount = mExactHitCount + mApproximateHitCount;
    const size_t totalAttempts = hitCount + mMissCount;
    base::StringAppendF(&result, "Global non-skipped hit rate: %.2f%% (%zd/%zd)\n",
                        100.0f * hitCount / totalAttempts, hitCount, totalAttempts);
    base::StringAppendF(&result, "  Exact hits: %zd\n", mExactHitCount);
    base::StringAppendF(&result, "  Approximate hits: %zd\n", mApproximateHitCount);
    base::StringAppendF(&result, "  Misses: %zd\n\n", mMissCount);

    dumpPredictionsByFrequency(result);
}

void Predictor::compareLayerStacks(NonBufferHash leftHash, NonBufferHash rightHash,
                                   std::string& result) const {
    const auto& [leftPredictionEntry, rightPredictionEntry] =
            std::make_tuple(mPredictions.find(leftHash), mPredictions.find(rightHash));
    if (leftPredictionEntry == mPredictions.end()) {
        base::StringAppendF(&result, "No prediction found for %zx\n", leftHash);
        return;
    }
    if (rightPredictionEntry == mPredictions.end()) {
        base::StringAppendF(&result, "No prediction found for %zx\n", rightHash);
        return;
    }

    base::StringAppendF(&result,
                        "Comparing           %-16zx                                %-16zx\n",
                        leftHash, rightHash);

    const auto& [leftPrediction, rightPrediction] =
            std::make_tuple(leftPredictionEntry->second, rightPredictionEntry->second);
    const auto& [leftStack, rightStack] = std::make_tuple(leftPrediction.getExampleLayerStack(),
                                                          rightPrediction.getExampleLayerStack());
    leftStack.compare(rightStack, result);
}

void Predictor::describeLayerStack(NonBufferHash hash, std::string& result) const {
    base::StringAppendF(&result, "Describing %zx:\n\n", hash);

    if (const auto predictionsEntry = mPredictions.find(hash);
        predictionsEntry != mPredictions.cend()) {
        const auto& [hash, prediction] = *predictionsEntry;

        prediction.getExampleLayerStack().dump(result);

        result.append("Prediction: ");
        prediction.dump(result);
        result.append("\n");
    } else {
        result.append("No predictions found\n");
    }
}

void Predictor::listSimilarStacks(Plan plan, std::string& result) const {
    base::StringAppendF(&result, "Similar stacks for plan %s:\n", to_string(plan).c_str());

    if (const auto similarStacksEntry = mSimilarStacks.find(plan);
        similarStacksEntry != mSimilarStacks.end()) {
        const auto& [_, similarStacks] = *similarStacksEntry;
        for (NonBufferHash hash : similarStacks) {
            base::StringAppendF(&result, "\nPrediction hash %zx:\n", hash);
            const Prediction& prediction = mPredictions.at(hash);
            prediction.getExampleLayerStack().dumpLayerNames(result);
        }
    } else {
        result.append("No similar stacks found\n");
    }
}

const Prediction& Predictor::getPrediction(NonBufferHash hash) const {
    if (const auto predictionEntry = mPredictions.find(hash);
        predictionEntry != mPredictions.end()) {
        const auto& [_, prediction] = *predictionEntry;
        return prediction;
    } else {
        const auto candidateEntry = getCandidateEntryByHash(hash);
        ALOGE_IF(candidateEntry == mCandidates.cend(),
                 "Hash should have been found in either predictions or candidates");
        const auto& [_, prediction] = *candidateEntry;
        return prediction;
    }
}

Prediction& Predictor::getPrediction(NonBufferHash hash) {
    return const_cast<Prediction&>(const_cast<const Predictor*>(this)->getPrediction(hash));
}

std::optional<Plan> Predictor::getExactMatch(NonBufferHash hash) const {
    const Prediction* match = nullptr;
    if (const auto predictionEntry = mPredictions.find(hash);
        predictionEntry != mPredictions.end()) {
        const auto& [hash, prediction] = *predictionEntry;
        match = &prediction;
    } else if (const auto candidateEntry = getCandidateEntryByHash(hash);
               candidateEntry != mCandidates.cend()) {
        match = &(candidateEntry->prediction);
    }

    if (match == nullptr) {
        return std::nullopt;
    }

    if (match->getMissCount(Prediction::Type::Exact) != 0) {
        ALOGV("[%s] Skipping exact match for %zx because of prior miss", __func__, hash);
        return std::nullopt;
    }

    return match->getPlan();
}

std::optional<NonBufferHash> Predictor::getApproximateMatch(
        const std::vector<const LayerState*>& layers) const {
    const auto approximateStackMatches = [&](const ApproximateStack& approximateStack) {
        const auto& exampleStack = mPredictions.at(approximateStack.hash).getExampleLayerStack();
        if (const auto approximateMatchOpt = exampleStack.getApproximateMatch(layers);
            approximateMatchOpt) {
            return *approximateMatchOpt == approximateStack.match;
        }
        return false;
    };

    const auto candidateMatches = [&](const PromotionCandidate& candidate) {
        ALOGV("[getApproximateMatch] checking against %zx", candidate.hash);
        return candidate.prediction.getExampleLayerStack().getApproximateMatch(layers) !=
                std::nullopt;
    };

    const Prediction* match = nullptr;
    NonBufferHash hash;
    if (const auto approximateStackIter =
                std::find_if(mApproximateStacks.cbegin(), mApproximateStacks.cend(),
                             approximateStackMatches);
        approximateStackIter != mApproximateStacks.cend()) {
        match = &mPredictions.at(approximateStackIter->hash);
        hash = approximateStackIter->hash;
    } else if (const auto candidateEntry =
                       std::find_if(mCandidates.cbegin(), mCandidates.cend(), candidateMatches);
               candidateEntry != mCandidates.cend()) {
        match = &(candidateEntry->prediction);
        hash = candidateEntry->hash;
    }

    if (match == nullptr) {
        return std::nullopt;
    }

    if (match->getMissCount(Prediction::Type::Approximate) != 0) {
        ALOGV("[%s] Skipping approximate match for %zx because of prior miss", __func__, hash);
        return std::nullopt;
    }

    return hash;
}

void Predictor::promoteIfCandidate(NonBufferHash predictionHash) {
    // Return if the candidate has already been promoted
    if (mPredictions.count(predictionHash) != 0) {
        return;
    }

    ALOGV("[%s] Promoting %zx from candidate to prediction", __func__, predictionHash);

    auto candidateEntry = getCandidateEntryByHash(predictionHash);
    ALOGE_IF(candidateEntry == mCandidates.end(), "Expected to find candidate");

    mSimilarStacks[candidateEntry->prediction.getPlan()].push_back(predictionHash);
    mPredictions.emplace(predictionHash, std::move(candidateEntry->prediction));
    mCandidates.erase(candidateEntry);
}

void Predictor::recordPredictedResult(PredictedPlan predictedPlan,
                                      const std::vector<const LayerState*>& layers, Plan result) {
    Prediction& prediction = getPrediction(predictedPlan.hash);
    if (prediction.getPlan() != result) {
        ALOGV("[%s] %s prediction missed, expected %s, found %s", __func__,
              to_string(predictedPlan.type).c_str(), to_string(prediction.getPlan()).c_str(),
              to_string(result).c_str());
        prediction.recordMiss(predictedPlan.type);
        ++mMissCount;
        return;
    }

    switch (predictedPlan.type) {
        case Prediction::Type::Approximate:
            ++mApproximateHitCount;
            break;
        case Prediction::Type::Exact:
            ++mExactHitCount;
            break;
        default:
            break;
    }

    ALOGV("[%s] %s prediction hit", __func__, to_string(predictedPlan.type).c_str());
    ALOGV("[%s] Plan: %s", __func__, to_string(result).c_str());
    prediction.recordHit(predictedPlan.type);

    const auto stackMatchesHash = [hash = predictedPlan.hash](const ApproximateStack& stack) {
        return stack.hash == hash;
    };

    if (predictedPlan.type == Prediction::Type::Approximate) {
        // If this approximate match is not already in the list of approximate stacks, add it
        if (std::find_if(mApproximateStacks.cbegin(), mApproximateStacks.cend(),
                         stackMatchesHash) == mApproximateStacks.cend()) {
            ALOGV("[%s] Adding approximate match to list", __func__);
            const auto approximateMatchOpt =
                    prediction.getExampleLayerStack().getApproximateMatch(layers);
            ALOGE_IF(!approximateMatchOpt, "Expected an approximate match");
            mApproximateStacks.emplace_back(predictedPlan.hash, *approximateMatchOpt);
        }
    }

    promoteIfCandidate(predictedPlan.hash);
}

bool Predictor::findSimilarPrediction(const std::vector<const LayerState*>& layers, Plan result) {
    const auto stacksEntry = mSimilarStacks.find(result);
    if (stacksEntry == mSimilarStacks.end()) {
        return false;
    }

    std::optional<ApproximateStack> bestMatch;
    const auto& [plan, similarStacks] = *stacksEntry;
    for (NonBufferHash hash : similarStacks) {
        const Prediction& prediction = mPredictions.at(hash);
        auto approximateMatch = prediction.getExampleLayerStack().getApproximateMatch(layers);
        if (!approximateMatch) {
            continue;
        }

        const int differingFieldCount = __builtin_popcount(approximateMatch->differingFields.get());
        if (!bestMatch ||
            differingFieldCount < __builtin_popcount(bestMatch->match.differingFields.get())) {
            bestMatch = {hash, *approximateMatch};
        }
    }

    if (!bestMatch) {
        return false;
    }

    ALOGV("[%s] Adding %zx to approximate stacks", __func__, bestMatch->hash);

    mApproximateStacks.emplace_back(*bestMatch);
    return true;
}

void Predictor::dumpPredictionsByFrequency(std::string& result) const {
    struct HashFrequency {
        HashFrequency(NonBufferHash hash, size_t totalAttempts)
              : hash(hash), totalAttempts(totalAttempts) {}

        NonBufferHash hash;
        size_t totalAttempts;
    };

    std::vector<HashFrequency> hashFrequencies;
    for (const auto& [hash, prediction] : mPredictions) {
        hashFrequencies.emplace_back(hash,
                                     prediction.getHitCount(Prediction::Type::Total) +
                                             prediction.getMissCount(Prediction::Type::Total));
    }

    std::sort(hashFrequencies.begin(), hashFrequencies.end(),
              [](const HashFrequency& lhs, const HashFrequency& rhs) {
                  return lhs.totalAttempts > rhs.totalAttempts;
              });

    result.append("Predictions:\n");
    for (const auto& [hash, totalAttempts] : hashFrequencies) {
        base::StringAppendF(&result, "  %016zx ", hash);
        mPredictions.at(hash).dump(result);
        result.append("\n");
    }
}

} // namespace android::compositionengine::impl::planner
