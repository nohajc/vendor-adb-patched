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

#include <string>

#include <aidl/android/hardware/graphics/common/BufferUsage.h>
#include <aidl/android/hardware/graphics/composer3/Composition.h>
#include <android-base/strings.h>
#include <ftl/flags.h>
#include <math/HashCombine.h>

#include <compositionengine/LayerFE.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>

#include "DisplayHardware/Hal.h"

namespace std {
template <typename T>
struct hash<android::sp<T>> {
    size_t operator()(const android::sp<T>& p) { return std::hash<void*>()(p.get()); }
};

template <typename T>
struct hash<android::wp<T>> {
    size_t operator()(const android::wp<T>& p) {
        android::sp<T> promoted = p.promote();
        return std::hash<void*>()(promoted ? promoted.get() : nullptr);
    }
};
} // namespace std

namespace android::compositionengine::impl::planner {

using LayerId = int32_t;

// clang-format off
enum class LayerStateField : uint32_t {
    None                  = 0u,
    Id                    = 1u << 0,
    Name                  = 1u << 1,
    DisplayFrame          = 1u << 2,
    SourceCrop            = 1u << 3,
    BufferTransform       = 1u << 4,
    BlendMode             = 1u << 5,
    Alpha                 = 1u << 6,
    LayerMetadata         = 1u << 7,
    VisibleRegion         = 1u << 8,
    Dataspace             = 1u << 9,
    PixelFormat           = 1u << 10,
    ColorTransform        = 1u << 11,
    SurfaceDamage         = 1u << 12,
    CompositionType       = 1u << 13,
    SidebandStream        = 1u << 14,
    Buffer                = 1u << 15,
    SolidColor            = 1u << 16,
    BackgroundBlurRadius  = 1u << 17,
    BlurRegions           = 1u << 18,
};
// clang-format on

std::string to_string(LayerStateField field);

// An abstract interface allows us to iterate over all of the OutputLayerState fields
// without having to worry about their templated types.
// See `LayerState::getNonUniqueFields` below.
class StateInterface {
public:
    virtual ~StateInterface() = default;

    virtual ftl::Flags<LayerStateField> update(const compositionengine::OutputLayer* layer) = 0;

    virtual size_t getHash() const = 0;

    virtual LayerStateField getField() const = 0;

    virtual ftl::Flags<LayerStateField> getFieldIfDifferent(const StateInterface* other) const = 0;

    virtual bool equals(const StateInterface* other) const = 0;

    virtual std::vector<std::string> toStrings() const = 0;
};

template <typename T, LayerStateField FIELD>
class OutputLayerState : public StateInterface {
public:
    using ReadFromLayerState = std::function<T(const compositionengine::OutputLayer* layer)>;
    using ToStrings = std::function<std::vector<std::string>(const T&)>;
    using Equals = std::function<bool(const T&, const T&)>;
    using Hashes = std::function<size_t(const T&)>;

    static ToStrings getDefaultToStrings() {
        return [](const T& value) {
            using std::to_string;
            return std::vector<std::string>{to_string(value)};
        };
    }

    static ToStrings getHalToStrings() {
        return [](const T& value) { return std::vector<std::string>{toString(value)}; };
    }

    static ToStrings getRegionToStrings() {
        return [](const Region& region) {
            using namespace std::string_literals;
            std::string dump;
            region.dump(dump, "");
            std::vector<std::string> split = base::Split(dump, "\n"s);
            split.erase(split.begin()); // Strip the header
            split.pop_back();           // Strip the last (empty) line
            for (std::string& line : split) {
                line.erase(0, 4); // Strip leading padding before each rect
            }
            return split;
        };
    }

    static Equals getDefaultEquals() {
        return [](const T& lhs, const T& rhs) { return lhs == rhs; };
    }

    static Equals getRegionEquals() {
        return [](const Region& lhs, const Region& rhs) { return lhs.hasSameRects(rhs); };
    }

    static Hashes getDefaultHashes() {
        return [](const T& value) { return std::hash<T>{}(value); };
    }

    OutputLayerState(ReadFromLayerState reader,
                     ToStrings toStrings = OutputLayerState::getDefaultToStrings(),
                     Equals equals = OutputLayerState::getDefaultEquals(),
                     Hashes hashes = OutputLayerState::getDefaultHashes())
          : mReader(reader), mToStrings(toStrings), mEquals(equals), mHashes(hashes) {}

    ~OutputLayerState() override = default;

    // Returns this member's field flag if it was changed
    ftl::Flags<LayerStateField> update(const compositionengine::OutputLayer* layer) override {
        T newValue = mReader(layer);
        return update(newValue);
    }

    ftl::Flags<LayerStateField> update(const T& newValue) {
        if (!mEquals(mValue, newValue)) {
            mValue = newValue;
            mHash = {};
            return FIELD;
        }
        return {};
    }

    LayerStateField getField() const override { return FIELD; }
    const T& get() const { return mValue; }

    size_t getHash() const override {
        if (!mHash) {
            mHash = mHashes(mValue);
        }
        return *mHash;
    }

    ftl::Flags<LayerStateField> getFieldIfDifferent(const StateInterface* other) const override {
        if (other->getField() != FIELD) {
            return {};
        }

        // The early return ensures that this downcast is sound
        const OutputLayerState* otherState = static_cast<const OutputLayerState*>(other);
        return *this != *otherState ? FIELD : ftl::Flags<LayerStateField>{};
    }

    bool equals(const StateInterface* other) const override {
        if (other->getField() != FIELD) {
            return false;
        }

        // The early return ensures that this downcast is sound
        const OutputLayerState* otherState = static_cast<const OutputLayerState*>(other);
        return *this == *otherState;
    }

    std::vector<std::string> toStrings() const override { return mToStrings(mValue); }

    bool operator==(const OutputLayerState& other) const { return mEquals(mValue, other.mValue); }
    bool operator!=(const OutputLayerState& other) const { return !(*this == other); }

private:
    const ReadFromLayerState mReader;
    const ToStrings mToStrings;
    const Equals mEquals;
    const Hashes mHashes;
    T mValue = {};
    mutable std::optional<size_t> mHash = {};
};

class LayerState {
public:
    LayerState(compositionengine::OutputLayer* layer);

    // Returns which fields were updated
    ftl::Flags<LayerStateField> update(compositionengine::OutputLayer*);

    // Computes a hash for this LayerState.
    // The hash is only computed from NonUniqueFields, and excludes GraphicBuffers since they are
    // not guaranteed to live longer than the LayerState object.
    size_t getHash() const;

    // Returns the bit-set of differing fields between this LayerState and another LayerState.
    // This bit-set is based on NonUniqueFields only, and excludes GraphicBuffers.
    ftl::Flags<LayerStateField> getDifferingFields(const LayerState& other) const;

    compositionengine::OutputLayer* getOutputLayer() const { return mOutputLayer; }
    int32_t getId() const { return mId.get(); }
    const std::string& getName() const { return mName.get(); }
    Rect getDisplayFrame() const { return mDisplayFrame.get(); }
    const Region& getVisibleRegion() const { return mVisibleRegion.get(); }
    bool hasBlurBehind() const {
        return mBackgroundBlurRadius.get() > 0 || !mBlurRegions.get().empty();
    }
    int32_t getBackgroundBlurRadius() const { return mBackgroundBlurRadius.get(); }
    aidl::android::hardware::graphics::composer3::Composition getCompositionType() const {
        return mCompositionType.get();
    }

    void incrementFramesSinceBufferUpdate() { ++mFramesSinceBufferUpdate; }
    void resetFramesSinceBufferUpdate() { mFramesSinceBufferUpdate = 0; }
    int64_t getFramesSinceBufferUpdate() const { return mFramesSinceBufferUpdate; }

    ui::Dataspace getDataspace() const { return mOutputDataspace.get(); }

    bool isProtected() const {
        return getOutputLayer()->getLayerFE().getCompositionState()->hasProtectedContent;
    }

    bool hasSolidColorCompositionType() const {
        return getOutputLayer()->getLayerFE().getCompositionState()->compositionType ==
                aidl::android::hardware::graphics::composer3::Composition::SOLID_COLOR;
    }

    float getFps() const { return getOutputLayer()->getLayerFE().getCompositionState()->fps; }

    void dump(std::string& result) const;
    std::optional<std::string> compare(const LayerState& other) const;

    // This makes LayerState's private members accessible to the operator
    friend bool operator==(const LayerState& lhs, const LayerState& rhs);
    friend bool operator!=(const LayerState& lhs, const LayerState& rhs) { return !(lhs == rhs); }

private:
    compositionengine::OutputLayer* mOutputLayer = nullptr;

    OutputLayerState<LayerId, LayerStateField::Id> mId{
            [](const compositionengine::OutputLayer* layer) {
                return layer->getLayerFE().getSequence();
            }};

    OutputLayerState<std::string, LayerStateField::Name>
            mName{[](auto layer) { return layer->getLayerFE().getDebugName(); },
                  [](const std::string& name) { return std::vector<std::string>{name}; }};

    // Output-dependent geometry state

    OutputLayerState<Rect, LayerStateField::DisplayFrame>
            mDisplayFrame{[](auto layer) { return layer->getState().displayFrame; },
                          [](const Rect& rect) {
                              return std::vector<std::string>{
                                      base::StringPrintf("[%d, %d, %d, %d]", rect.left, rect.top,
                                                         rect.right, rect.bottom)};
                          }};

    OutputLayerState<FloatRect, LayerStateField::SourceCrop>
            mSourceCrop{[](auto layer) { return layer->getState().sourceCrop; },
                        [](const FloatRect& rect) {
                            return std::vector<std::string>{
                                    base::StringPrintf("[%.2f, %.2f, %.2f, %.2f]", rect.left,
                                                       rect.top, rect.right, rect.bottom)};
                        }};

    using BufferTransformState = OutputLayerState<hardware::graphics::composer::hal::Transform,
                                                  LayerStateField::BufferTransform>;
    BufferTransformState mBufferTransform{[](auto layer) {
                                              return layer->getState().bufferTransform;
                                          },
                                          BufferTransformState::getHalToStrings()};

    // Output-independent geometry state

    using BlendModeState = OutputLayerState<hardware::graphics::composer::hal::BlendMode,
                                            LayerStateField::BlendMode>;
    BlendModeState mBlendMode{[](auto layer) {
                                  return layer->getLayerFE().getCompositionState()->blendMode;
                              },
                              BlendModeState::getHalToStrings()};

    OutputLayerState<float, LayerStateField::Alpha> mAlpha{
            [](auto layer) { return layer->getLayerFE().getCompositionState()->alpha; }};

    using LayerMetadataState =
            OutputLayerState<GenericLayerMetadataMap, LayerStateField::LayerMetadata>;
    LayerMetadataState
            mLayerMetadata{[](auto layer) {
                               return layer->getLayerFE().getCompositionState()->metadata;
                           },
                           [](const GenericLayerMetadataMap& metadata) {
                               std::vector<std::string> result;
                               if (metadata.empty()) {
                                   result.push_back("{}");
                                   return result;
                               }
                               result.push_back("{");
                               for (const auto& [key, value] : metadata) {
                                   std::string keyValueDump;
                                   keyValueDump.append("           ");
                                   keyValueDump.append(key);
                                   keyValueDump.append("=");
                                   keyValueDump.append(value.dumpAsString());
                                   result.push_back(keyValueDump);
                               }
                               result.push_back("}");
                               return result;
                           },
                           LayerMetadataState::getDefaultEquals(),
                           [](const GenericLayerMetadataMap& metadata) {
                               size_t hash = 0;
                               for (const auto& [key, value] : metadata) {
                                   size_t entryHash = 0;
                                   hashCombineSingleHashed(entryHash,
                                                           std::hash<std::string>{}(key));
                                   hashCombineSingleHashed(entryHash,
                                                           GenericLayerMetadataEntry::Hasher{}(
                                                                   value));
                                   hash ^= entryHash;
                               }
                               return hash;
                           }};

    // Output-dependent per-frame state

    using VisibleRegionState = OutputLayerState<Region, LayerStateField::VisibleRegion>;
    VisibleRegionState mVisibleRegion{[](auto layer) { return layer->getState().visibleRegion; },
                                      VisibleRegionState::getRegionToStrings(),
                                      VisibleRegionState::getRegionEquals()};

    using DataspaceState = OutputLayerState<ui::Dataspace, LayerStateField::Dataspace>;
    DataspaceState mOutputDataspace{[](auto layer) { return layer->getState().dataspace; },
                                    DataspaceState::getHalToStrings()};

    // Output-independent per-frame state

    using PixelFormatState = OutputLayerState<hardware::graphics::composer::hal::PixelFormat,
                                              LayerStateField::PixelFormat>;
    PixelFormatState
            mPixelFormat{[](auto layer) {
                             return layer->getLayerFE().getCompositionState()->buffer
                                     ? static_cast<hardware::graphics::composer::hal::PixelFormat>(
                                               layer->getLayerFE()
                                                       .getCompositionState()
                                                       ->buffer->getPixelFormat())
                                     : hardware::graphics::composer::hal::PixelFormat::RGBA_8888;
                         },
                         PixelFormatState::getHalToStrings()};

    OutputLayerState<mat4, LayerStateField::ColorTransform> mColorTransform;

    using CompositionTypeState =
            OutputLayerState<aidl::android::hardware::graphics::composer3::Composition,
                             LayerStateField::CompositionType>;
    CompositionTypeState mCompositionType{[](auto layer) {
                                              return layer->getState().forceClientComposition
                                                      ? aidl::android::hardware::graphics::
                                                                composer3::Composition::CLIENT
                                                      : layer->getLayerFE()
                                                                .getCompositionState()
                                                                ->compositionType;
                                          },
                                          CompositionTypeState::getHalToStrings()};

    OutputLayerState<void*, LayerStateField::SidebandStream>
            mSidebandStream{[](auto layer) {
                                return layer->getLayerFE()
                                        .getCompositionState()
                                        ->sidebandStream.get();
                            },
                            [](void* p) {
                                return std::vector<std::string>{base::StringPrintf("%p", p)};
                            }};

    static auto constexpr BufferEquals = [](const wp<GraphicBuffer>& lhs,
                                            const wp<GraphicBuffer>& rhs) -> bool {
        // Avoid a promotion if the wp<>'s aren't equal
        if (lhs != rhs) return false;

        // Even if the buffer didn't change, check to see if we need to act as if the buffer changed
        // anyway. Specifically, look to see if the buffer is FRONT_BUFFER & if so act as if it's
        // always different
        using ::aidl::android::hardware::graphics::common::BufferUsage;
        sp<GraphicBuffer> promotedBuffer = lhs.promote();
        return !(promotedBuffer &&
                 ((promotedBuffer->getUsage() & static_cast<int64_t>(BufferUsage::FRONT_BUFFER)) !=
                  0));
    };

    OutputLayerState<wp<GraphicBuffer>, LayerStateField::Buffer>
            mBuffer{[](auto layer) { return layer->getLayerFE().getCompositionState()->buffer; },
                    [](const wp<GraphicBuffer>& buffer) {
                        sp<GraphicBuffer> promotedBuffer = buffer.promote();
                        return std::vector<std::string>{
                                base::StringPrintf("%p",
                                                   promotedBuffer ? promotedBuffer.get()
                                                                  : nullptr)};
                    },
                    BufferEquals};

    // Even if the same buffer is passed to BLAST's setBuffer(), we still increment the frame
    // number and need to treat it as if the buffer changed. Otherwise we break existing
    // front-buffer rendering paths (such as egl's EGL_SINGLE_BUFFER).
    OutputLayerState<uint64_t, LayerStateField::Buffer> mFrameNumber{
            [](auto layer) { return layer->getLayerFE().getCompositionState()->frameNumber; }};

    int64_t mFramesSinceBufferUpdate = 0;

    OutputLayerState<half4, LayerStateField::SolidColor>
            mSolidColor{[](auto layer) { return layer->getLayerFE().getCompositionState()->color; },
                        [](const half4& vec) {
                            std::stringstream stream;
                            stream << vec;
                            return std::vector<std::string>{stream.str()};
                        }};

    OutputLayerState<int32_t, LayerStateField::BackgroundBlurRadius> mBackgroundBlurRadius{
            [](auto layer) {
                return layer->getLayerFE().getCompositionState()->backgroundBlurRadius;
            }};

    using BlurRegionsState =
            OutputLayerState<std::vector<BlurRegion>, LayerStateField::BlurRegions>;
    BlurRegionsState mBlurRegions{[](auto layer) {
                                      return layer->getLayerFE().getCompositionState()->blurRegions;
                                  },
                                  [](const std::vector<BlurRegion>& regions) {
                                      std::vector<std::string> result;
                                      for (const auto region : regions) {
                                          std::string str;
                                          base::StringAppendF(&str,
                                                              "{radius=%du, cornerRadii=[%f, %f, "
                                                              "%f, %f], alpha=%f, rect=[%d, "
                                                              "%d, %d, %d]",
                                                              region.blurRadius,
                                                              region.cornerRadiusTL,
                                                              region.cornerRadiusTR,
                                                              region.cornerRadiusBL,
                                                              region.cornerRadiusBR, region.alpha,
                                                              region.left, region.top, region.right,
                                                              region.bottom);
                                          result.push_back(str);
                                      }
                                      return result;
                                  },
                                  BlurRegionsState::getDefaultEquals(),
                                  [](const std::vector<BlurRegion>& regions) {
                                      size_t hash = 0;
                                      for (const auto& region : regions) {
                                          android::hashCombineSingle(hash, region);
                                      }
                                      return hash;
                                  }};

    static const constexpr size_t kNumNonUniqueFields = 17;

    std::array<StateInterface*, kNumNonUniqueFields> getNonUniqueFields() {
        std::array<const StateInterface*, kNumNonUniqueFields> constFields =
                const_cast<const LayerState*>(this)->getNonUniqueFields();
        std::array<StateInterface*, kNumNonUniqueFields> fields;
        std::transform(constFields.cbegin(), constFields.cend(), fields.begin(),
                       [](const StateInterface* constField) {
                           return const_cast<StateInterface*>(constField);
                       });
        return fields;
    }

    std::array<const StateInterface*, kNumNonUniqueFields> getNonUniqueFields() const {
        return {
                &mDisplayFrame, &mSourceCrop,     &mBufferTransform,      &mBlendMode,
                &mAlpha,        &mLayerMetadata,  &mVisibleRegion,        &mOutputDataspace,
                &mPixelFormat,  &mColorTransform, &mCompositionType,      &mSidebandStream,
                &mBuffer,       &mSolidColor,     &mBackgroundBlurRadius, &mBlurRegions,
                &mFrameNumber,
        };
    }
};

using NonBufferHash = size_t;
NonBufferHash getNonBufferHash(const std::vector<const LayerState*>&);

} // namespace android::compositionengine::impl::planner
