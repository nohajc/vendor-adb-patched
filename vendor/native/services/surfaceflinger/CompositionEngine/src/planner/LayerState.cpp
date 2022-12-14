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

#include <compositionengine/impl/planner/LayerState.h>

namespace {
extern "C" const char* __attribute__((unused)) __asan_default_options() {
    return "detect_container_overflow=0";
}
} // namespace

namespace android::compositionengine::impl::planner {

LayerState::LayerState(compositionengine::OutputLayer* layer)
      : mOutputLayer(layer),
        mColorTransform({[](auto layer) {
                             const auto state = layer->getLayerFE().getCompositionState();
                             return state->colorTransformIsIdentity ? mat4{}
                                                                    : state->colorTransform;
                         },
                         [](const mat4& mat) {
                             using namespace std::string_literals;
                             std::vector<std::string> split =
                                     base::Split(std::string(mat.asString().string()), "\n"s);
                             split.pop_back(); // Strip the last (empty) line
                             return split;
                         }}) {
    update(layer);
}

ftl::Flags<LayerStateField> LayerState::update(compositionengine::OutputLayer* layer) {
    ALOGE_IF(mOutputLayer != layer && layer->getLayerFE().getSequence() != mId.get(),
             "[%s] Expected mOutputLayer ID to never change: %d, %d", __func__,
             layer->getLayerFE().getSequence(), mId.get());

    // It's possible for the OutputLayer pointer to change even when the layer is logically the
    // same, i.e., the LayerFE is the same. An example use-case is screen rotation.
    mOutputLayer = layer;

    ftl::Flags<LayerStateField> differences;

    // Update the unique fields as well, since we have to set them at least
    // once from the OutputLayer
    differences |= mId.update(layer);
    differences |= mName.update(layer);

    for (StateInterface* field : getNonUniqueFields()) {
        differences |= field->update(layer);
    }

    return differences;
}

size_t LayerState::getHash() const {
    size_t hash = 0;
    for (const StateInterface* field : getNonUniqueFields()) {
        if (field->getField() == LayerStateField::Buffer) {
            continue;
        }
        android::hashCombineSingleHashed(hash, field->getHash());
    }

    return hash;
}

ftl::Flags<LayerStateField> LayerState::getDifferingFields(const LayerState& other) const {
    ftl::Flags<LayerStateField> differences;
    auto myFields = getNonUniqueFields();
    auto otherFields = other.getNonUniqueFields();
    for (size_t i = 0; i < myFields.size(); ++i) {
        if (myFields[i]->getField() == LayerStateField::Buffer) {
            continue;
        }

        differences |= myFields[i]->getFieldIfDifferent(otherFields[i]);
    }

    return differences;
}

void LayerState::dump(std::string& result) const {
    for (const StateInterface* field : getNonUniqueFields()) {
        base::StringAppendF(&result, "  %16s: ", ftl::flag_string(field->getField()).c_str());

        bool first = true;
        for (const std::string& line : field->toStrings()) {
            base::StringAppendF(&result, "%s%s\n", first ? "" : "                    ",
                                line.c_str());
            first = false;
        }
    }
    result.append("\n");
}

std::optional<std::string> LayerState::compare(const LayerState& other) const {
    std::string result;

    const auto& thisFields = getNonUniqueFields();
    const auto& otherFields = other.getNonUniqueFields();
    for (size_t f = 0; f < thisFields.size(); ++f) {
        const auto& thisField = thisFields[f];
        const auto& otherField = otherFields[f];
        // Skip comparing buffers
        if (thisField->getField() == LayerStateField::Buffer) {
            continue;
        }

        if (thisField->equals(otherField)) {
            continue;
        }

        base::StringAppendF(&result, "  %16s: ", ftl::flag_string(thisField->getField()).c_str());

        const auto& thisStrings = thisField->toStrings();
        const auto& otherStrings = otherField->toStrings();
        bool first = true;
        for (size_t line = 0; line < std::max(thisStrings.size(), otherStrings.size()); ++line) {
            if (!first) {
                result.append("                    ");
            }
            first = false;

            if (line < thisStrings.size()) {
                base::StringAppendF(&result, "%-48.48s", thisStrings[line].c_str());
            } else {
                result.append("                                                ");
            }

            if (line < otherStrings.size()) {
                base::StringAppendF(&result, "%-48.48s", otherStrings[line].c_str());
            } else {
                result.append("                                                ");
            }
            result.append("\n");
        }
    }

    return result.empty() ? std::nullopt : std::make_optional(result);
}

bool operator==(const LayerState& lhs, const LayerState& rhs) {
    return lhs.mId == rhs.mId && lhs.mName == rhs.mName && lhs.mDisplayFrame == rhs.mDisplayFrame &&
            lhs.mSourceCrop == rhs.mSourceCrop && lhs.mBufferTransform == rhs.mBufferTransform &&
            lhs.mBlendMode == rhs.mBlendMode && lhs.mAlpha == rhs.mAlpha &&
            lhs.mLayerMetadata == rhs.mLayerMetadata && lhs.mVisibleRegion == rhs.mVisibleRegion &&
            lhs.mOutputDataspace == rhs.mOutputDataspace && lhs.mPixelFormat == rhs.mPixelFormat &&
            lhs.mColorTransform == rhs.mColorTransform &&
            lhs.mCompositionType == rhs.mCompositionType &&
            lhs.mSidebandStream == rhs.mSidebandStream && lhs.mBuffer == rhs.mBuffer &&
            (lhs.mCompositionType.get() !=
                     aidl::android::hardware::graphics::composer3::Composition::SOLID_COLOR ||
             lhs.mSolidColor == rhs.mSolidColor);
}

NonBufferHash getNonBufferHash(const std::vector<const LayerState*>& layers) {
    size_t hash = 0;
    for (const auto layer : layers) {
        android::hashCombineSingleHashed(hash, layer->getHash());
    }

    return hash;
}

} // namespace android::compositionengine::impl::planner
