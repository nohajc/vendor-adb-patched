/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "libgralloctypes"

#include <cstring>
#include <cinttypes>
#include <limits>

#include <hidl/HidlSupport.h>
#include <log/log.h>

#include "gralloctypes/Gralloc4.h"

using android::hardware::hidl_vec;

using aidl::android::hardware::graphics::common::BlendMode;
using aidl::android::hardware::graphics::common::ChromaSiting;
using aidl::android::hardware::graphics::common::Compression;
using aidl::android::hardware::graphics::common::Cta861_3;
using aidl::android::hardware::graphics::common::Dataspace;
using aidl::android::hardware::graphics::common::ExtendableType;
using aidl::android::hardware::graphics::common::Interlaced;
using aidl::android::hardware::graphics::common::PlaneLayout;
using aidl::android::hardware::graphics::common::PlaneLayoutComponent;
using aidl::android::hardware::graphics::common::PlaneLayoutComponentType;
using aidl::android::hardware::graphics::common::Rect;
using aidl::android::hardware::graphics::common::Smpte2086;
using aidl::android::hardware::graphics::common::StandardMetadataType;
using aidl::android::hardware::graphics::common::XyColor;

using BufferDescriptorInfo = android::hardware::graphics::mapper::V4_0::IMapper::BufferDescriptorInfo;
using MetadataType = android::hardware::graphics::mapper::V4_0::IMapper::MetadataType;

namespace android {

namespace gralloc4 {

static inline bool hasAdditionOverflow(size_t a, size_t b) {
    return a > SIZE_MAX - b;
}

/**
 * OutputHidlVec represents the hidl_vec that is outputed when a type is encoded into a byte stream.
 * This class is used to track the current state of a hidl_vec as it is filled with the encoded
 * byte stream.
 *
 * This type is needed because hidl_vec's resize() allocates a new backing array every time.
 * This type does not need an copies and only needs one resize operation.
 */
class OutputHidlVec {
public:
    OutputHidlVec(hidl_vec<uint8_t>* vec)
        : mVec(vec) {}

    status_t resize() {
        if (!mVec) {
            return BAD_VALUE;
        }
        mVec->resize(mNeededResize);
        mResized = true;
        return NO_ERROR;
    }

    status_t encode(const uint8_t* data, size_t size) {
        if (!mVec) {
            return BAD_VALUE;
        }
        if (!mResized) {
            if (hasAdditionOverflow(mNeededResize, size)) {
                clear();
                return BAD_VALUE;
            }
            /**
             * Update mNeededResize and return NO_ERROR here because if (!mResized), the
             * caller hasn't called resize(). No data will be written into the mVec until
             * the caller resizes. We can't resize here for the caller because hidl_vec::resize()
             * allocates a new backing array every time.
             */
            mNeededResize += size;
            return NO_ERROR;
        }

        if (hasAdditionOverflow(mOffset, size) || (mVec->size() < size + mOffset)) {
            clear();
            return BAD_VALUE;
        }

        std::copy(data, data + size, mVec->data() + mOffset);

        mOffset += size;
        return NO_ERROR;
    }

    void clear() {
        if (mVec) {
            mVec->resize(0);
        }
        mNeededResize = 0;
        mResized = false;
        mOffset = 0;
    }

private:
    hidl_vec<uint8_t>* mVec;
    size_t mNeededResize = 0;
    size_t mResized = false;
    size_t mOffset = 0;
};

/**
 * InputHidlVec represents the hidl_vec byte stream that is inputed when a type is decoded.
 * This class is used to track the current index of the byte stream of the hidl_vec as it is
 * decoded.
 */
class InputHidlVec {
public:
    InputHidlVec(const hidl_vec<uint8_t>* vec)
        : mVec(vec) {}

    status_t decode(uint8_t* data, size_t size) {
        if (!mVec || hasAdditionOverflow(mOffset, size) || mOffset + size > mVec->size()) {
            return BAD_VALUE;
        }

        std::copy(mVec->data() + mOffset, mVec->data() + mOffset + size, data);

        mOffset += size;
        return NO_ERROR;
    }

    status_t decode(std::string* string, size_t size) {
        if (!mVec || hasAdditionOverflow(mOffset, size) || mOffset + size > mVec->size()) {
            return BAD_VALUE;
        }

        string->assign(mVec->data() + mOffset, mVec->data() + mOffset + size);

        mOffset += size;
        return NO_ERROR;
    }

    bool hasRemainingData() {
        if (!mVec) {
            return false;
        }
        return mVec->size() > mOffset;
    }

    size_t getRemainingSize() {
        if (!mVec) {
            return 0;
        }
        return mVec->size() - mOffset;
    }

private:
    const hidl_vec<uint8_t>* mVec;
    size_t mOffset = 0;
};

/**
 * EncodeHelper is a function type that encodes T into the OutputHidlVec.
 */
template<class T>
using EncodeHelper = status_t(*)(const T&, OutputHidlVec*);

/**
 * DecodeHelper is a function type that decodes InputHidlVec into T.
 */
template<class T>
using DecodeHelper = status_t(*)(InputHidlVec*, T*);

/**
 * ErrorHandler is a function type that is called when the corresponding DecodeHelper function
 * fails. ErrorHandler cleans up the object T so the caller doesn't receive a partially created
 * T.
 */
template<class T>
using ErrorHandler = void(*)(T*);

status_t encodeMetadataType(const MetadataType& input, OutputHidlVec* output);
status_t validateMetadataType(InputHidlVec* input, const MetadataType& expectedMetadataType);

/**
 * encode/encodeMetadata are the main encoding functions. They take in T and uses the encodeHelper
 * function to turn T into the hidl_vec byte stream.
 *
 * These functions first call the encodeHelper function to determine how large the hidl_vec
 * needs to be. They resize the hidl_vec. Finally, it reruns the encodeHelper function which
 * encodes T into the hidl_vec byte stream.
 */
template <class T>
status_t encode(const T& input, hidl_vec<uint8_t>* output, EncodeHelper<T> encodeHelper) {
    OutputHidlVec outputHidlVec{output};

    status_t err = encodeHelper(input, &outputHidlVec);
    if (err) {
        return err;
    }

    err = outputHidlVec.resize();
    if (err) {
        return err;
    }

    return encodeHelper(input, &outputHidlVec);
}

template <class T>
status_t encodeMetadata(const MetadataType& metadataType, const T& input, hidl_vec<uint8_t>* output,
                EncodeHelper<T> encodeHelper) {
    OutputHidlVec outputHidlVec{output};

    status_t err = encodeMetadataType(metadataType, &outputHidlVec);
    if (err) {
        return err;
    }

    err = encodeHelper(input, &outputHidlVec);
    if (err) {
        return err;
    }

    err = outputHidlVec.resize();
    if (err) {
        return err;
    }

    err = encodeMetadataType(metadataType, &outputHidlVec);
    if (err) {
        return err;
    }

    return encodeHelper(input, &outputHidlVec);
}

template <class T>
status_t encodeOptionalMetadata(const MetadataType& metadataType, const std::optional<T>& input,
                        hidl_vec<uint8_t>* output, EncodeHelper<T> encodeHelper) {
    if (!input) {
        return NO_ERROR;
    }
    return encodeMetadata(metadataType, *input, output, encodeHelper);
}

/**
 * decode/decodeMetadata are the main decoding functions. They take in a hidl_vec and use the
 * decodeHelper function to turn the hidl_vec byte stream into T. If an error occurs, the
 * errorHandler function cleans up T.
 */
template <class T>
status_t decode(const hidl_vec<uint8_t>& input, T* output, DecodeHelper<T> decodeHelper,
                ErrorHandler<T> errorHandler = nullptr) {
    InputHidlVec inputHidlVec{&input};

    status_t err = decodeHelper(&inputHidlVec, output);
    if (err) {
        return err;
    }

    err = inputHidlVec.hasRemainingData();
    if (err) {
        if (errorHandler) {
            errorHandler(output);
        }
        return BAD_VALUE;
    }

    return NO_ERROR;
}

template <class T>
status_t decodeMetadata(const MetadataType& metadataType, const hidl_vec<uint8_t>& input, T* output,
                DecodeHelper<T> decodeHelper, ErrorHandler<T> errorHandler = nullptr) {
    InputHidlVec inputHidlVec{&input};

    status_t err = validateMetadataType(&inputHidlVec, metadataType);
    if (err) {
        return err;
    }

    err = decodeHelper(&inputHidlVec, output);
    if (err) {
        return err;
    }

    err = inputHidlVec.hasRemainingData();
    if (err) {
        if (errorHandler) {
            errorHandler(output);
        }
        return BAD_VALUE;
    }

    return NO_ERROR;
}

template <class T>
status_t decodeOptionalMetadata(const MetadataType& metadataType, const hidl_vec<uint8_t>& input,
                        std::optional<T>* output, DecodeHelper<T> decodeHelper) {
    if (!output) {
        return BAD_VALUE;
    }
    if (input.size() <= 0) {
        output->reset();
        return NO_ERROR;
    }
    T tmp;
    status_t err = decodeMetadata(metadataType, input, &tmp, decodeHelper);
    if (!err) {
        *output = tmp;
    }
    return err;
}

/**
 * Private helper functions
 */
template <class T>
status_t encodeInteger(const T& input, OutputHidlVec* output) {
    static_assert(std::is_same<T, uint32_t>::value || std::is_same<T, int32_t>::value ||
                  std::is_same<T, uint64_t>::value || std::is_same<T, int64_t>::value ||
                  std::is_same<T, float>::value || std::is_same<T, double>::value);
    if (!output) {
        return BAD_VALUE;
    }

    const uint8_t* tmp = reinterpret_cast<const uint8_t*>(&input);
    return output->encode(tmp, sizeof(input));
}

template <class T>
status_t decodeInteger(InputHidlVec* input, T* output) {
    static_assert(std::is_same<T, uint32_t>::value || std::is_same<T, int32_t>::value ||
                  std::is_same<T, uint64_t>::value || std::is_same<T, int64_t>::value ||
                  std::is_same<T, float>::value || std::is_same<T, double>::value);
    if (!output) {
        return BAD_VALUE;
    }

    uint8_t* tmp = reinterpret_cast<uint8_t*>(output);
    return input->decode(tmp, sizeof(*output));
}

status_t encodeString(const std::string& input, OutputHidlVec* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodeInteger<int64_t>(input.size(), output);
    if (err) {
        return err;
    }

    return output->encode(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}

status_t decodeString(InputHidlVec* input, std::string* output) {
    if (!output) {
        return BAD_VALUE;
    }

    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(input, &size);
    if (err) {
        return err;
    }
    if (size < 0) {
        return BAD_VALUE;
    }

    return input->decode(output, size);
}

status_t encodeByteVector(const std::vector<uint8_t>& input, OutputHidlVec* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodeInteger<int64_t>(input.size(), output);
    if (err) {
        return err;
    }

    return output->encode(input.data(), input.size());
}

status_t decodeByteVector(InputHidlVec* input, std::vector<uint8_t>* output) {
    if (!output) {
        return BAD_VALUE;
    }

    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(input, &size);
    if (err || size < 0) {
        return err;
    }

    if (size > input->getRemainingSize()) {
        return BAD_VALUE;
    }
    output->resize(size);

    return input->decode(output->data(), size);
}

status_t encodeExtendableType(const ExtendableType& input, OutputHidlVec* output) {
    status_t err = encodeString(input.name, output);
    if (err) {
        return err;
    }

    err = encodeInteger<int64_t>(input.value, output);
    if (err) {
        return err;
    }

    return NO_ERROR;
}

status_t decodeExtendableType(InputHidlVec* input, ExtendableType* output) {
    status_t err = decodeString(input, &output->name);
    if (err) {
        return err;
    }

    err = decodeInteger<int64_t>(input, &output->value);
    if (err) {
        return err;
    }

    return NO_ERROR;
}

void clearExtendableType(ExtendableType* output) {
    if (!output) {
        return;
    }
    output->name.clear();
    output->value = 0;
}

status_t encodeMetadataType(const MetadataType& input, OutputHidlVec* output) {
    status_t err = encodeString(input.name, output);
    if (err) {
        return err;
    }

    err = encodeInteger<int64_t>(input.value, output);
    if (err) {
        return err;
    }

    return NO_ERROR;
}

status_t decodeMetadataType(InputHidlVec* input, MetadataType* output) {
    std::string name;
    status_t err = decodeString(input, &name);
    if (err) {
        return err;
    }
    output->name = name;

    err = decodeInteger<int64_t>(input, &output->value);
    if (err) {
        return err;
    }

    return NO_ERROR;
}

status_t validateMetadataType(InputHidlVec* input, const MetadataType& expectedMetadataType) {
    MetadataType receivedMetadataType;

    status_t err = decodeMetadataType(input, &receivedMetadataType);
    if (err) {
        return err;
    }

    if (expectedMetadataType.name != receivedMetadataType.name) {
        return BAD_VALUE;
    }

    if (receivedMetadataType.value != expectedMetadataType.value) {
        return BAD_VALUE;
    }

    return NO_ERROR;
}

status_t encodeXyColor(const XyColor& input, OutputHidlVec* output) {
    status_t err = encodeInteger<float>(input.x, output);
    if (err) {
        return err;
    }
    return encodeInteger<float>(input.y, output);
}

status_t decodeXyColor(InputHidlVec* input, XyColor* output) {
    status_t err = decodeInteger<float>(input, &output->x);
    if (err) {
        return err;
    }
    return decodeInteger<float>(input, &output->y);
}

void clearXyColor(XyColor* output) {
    if (!output) {
        return;
    }
    output->x = 0;
    output->y = 0;
}

status_t encodeRect(const Rect& input, OutputHidlVec* output) {
    status_t err = encodeInteger<int32_t>(static_cast<int32_t>(input.left), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int32_t>(static_cast<int32_t>(input.top), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int32_t>(static_cast<int32_t>(input.right), output);
    if (err) {
        return err;
    }
    return encodeInteger<int32_t>(static_cast<int32_t>(input.bottom), output);
}

status_t decodeRect(InputHidlVec* input, Rect* output) {
    status_t err = decodeInteger<int32_t>(input, &output->left);
    if (err) {
        return err;
    }
    err = decodeInteger<int32_t>(input, &output->top);
    if (err) {
        return err;
    }
    err = decodeInteger<int32_t>(input, &output->right);
    if (err) {
        return err;
    }
    return decodeInteger<int32_t>(input, &output->bottom);
}

status_t encodeBufferDescriptorInfoHelper(const BufferDescriptorInfo& input,
        OutputHidlVec* output) {
    status_t err = encodeString(input.name, output);
    if (err) {
        return err;
    }
    err = encodeInteger<uint32_t>(input.width, output);
    if (err) {
        return err;
    }
    err = encodeInteger<uint32_t>(input.height, output);
    if (err) {
        return err;
    }
    err = encodeInteger<uint32_t>(input.layerCount, output);
    if (err) {
        return err;
    }
    err = encodeInteger<int32_t>(static_cast<int32_t>(input.format), output);
    if (err) {
        return err;
    }
    err = encodeInteger<uint64_t>(input.usage, output);
    if (err) {
        return err;
    }
    return encodeInteger<uint64_t>(input.reservedSize, output);
}

status_t decodeBufferDescriptorInfoHelper(InputHidlVec* input, BufferDescriptorInfo* output) {
    std::string name;
    status_t err = decodeString(input, &name);
    if (err) {
        return err;
    }
    output->name = name;

    err = decodeInteger<uint32_t>(input, &output->width);
    if (err) {
        return err;
    }
    err = decodeInteger<uint32_t>(input, &output->height);
    if (err) {
        return err;
    }
    err = decodeInteger<uint32_t>(input, &output->layerCount);
    if (err) {
        return err;
    }
    err = decodeInteger<int32_t>(input, reinterpret_cast<int32_t*>(&output->format));
    if (err) {
        return err;
    }
    err = decodeInteger<uint64_t>(input, &output->usage);
    if (err) {
        return err;
    }
    return decodeInteger<uint64_t>(input, &output->reservedSize);
}

status_t encodePlaneLayoutComponent(const PlaneLayoutComponent& input, OutputHidlVec* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodeExtendableType(input.type, output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int64_t>(input.offsetInBits), output);
    if (err) {
        return err;
    }
    return encodeInteger<int64_t>(static_cast<int64_t>(input.sizeInBits), output);
}

status_t decodePlaneLayoutComponent(InputHidlVec* input, PlaneLayoutComponent* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = decodeExtendableType(input, &output->type);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->offsetInBits);
    if (err) {
        return err;
    }
    return decodeInteger<int64_t>(input, &output->sizeInBits);
}

status_t encodePlaneLayoutComponents(const std::vector<PlaneLayoutComponent>& input, OutputHidlVec* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodeInteger<int64_t>(static_cast<int64_t>(input.size()), output);
    if (err) {
        return err;
    }

    for (const auto& planeLayoutComponent: input) {
        err = encodePlaneLayoutComponent(planeLayoutComponent, output);
        if (err) {
            return err;
        }
    }

    return NO_ERROR;
}

status_t decodePlaneLayoutComponents(InputHidlVec* input, std::vector<PlaneLayoutComponent>* output) {
    if (!output) {
        return BAD_VALUE;
    }

    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(input, &size);
    if (err) {
        return err;
    }
    if (size < 0 || size > 10000) {
        return BAD_VALUE;
    }

    output->resize(size);

    for (auto& planeLayoutComponent : *output) {
        err = decodePlaneLayoutComponent(input, &planeLayoutComponent);
        if (err) {
            return err;
        }
    }
    return NO_ERROR;
}

status_t encodePlaneLayout(const PlaneLayout& input, OutputHidlVec* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodePlaneLayoutComponents(input.components, output);
    if (err) {
        return err;
    }

    err = encodeInteger<int64_t>(static_cast<int64_t>(input.offsetInBytes), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int64_t>(input.sampleIncrementInBits), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int64_t>(input.strideInBytes), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int64_t>(input.widthInSamples), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int64_t>(input.heightInSamples), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int64_t>(input.totalSizeInBytes), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int64_t>(input.horizontalSubsampling), output);
    if (err) {
        return err;
    }
    return encodeInteger<int64_t>(static_cast<int64_t>(input.verticalSubsampling), output);
}

status_t decodePlaneLayout(InputHidlVec* input, PlaneLayout* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = decodePlaneLayoutComponents(input, &output->components);
    if (err) {
        return err;
    }

    err = decodeInteger<int64_t>(input, &output->offsetInBytes);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->sampleIncrementInBits);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->strideInBytes);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->widthInSamples);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->heightInSamples);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->totalSizeInBytes);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->horizontalSubsampling);
    if (err) {
        return err;
    }
    return decodeInteger<int64_t>(input, &output->verticalSubsampling);
}

status_t encodePlaneLayoutsHelper(const std::vector<PlaneLayout>& planeLayouts, OutputHidlVec* outOutputHidlVec) {
    status_t err = encodeInteger<int64_t>(static_cast<int64_t>(planeLayouts.size()), outOutputHidlVec);
    if (err) {
        return err;
    }

    for (const auto& planeLayout : planeLayouts) {
        err = encodePlaneLayout(planeLayout, outOutputHidlVec);
        if (err) {
            return err;
        }
    }

    return NO_ERROR;
}

status_t decodePlaneLayoutsHelper(InputHidlVec* inputHidlVec, std::vector<PlaneLayout>* outPlaneLayouts) {
    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(inputHidlVec, &size);
    if (err) {
        return err;
    }
    if (size < 0) {
        return BAD_VALUE;
    }

    for (size_t i = 0; i < size; i++) {
        outPlaneLayouts->emplace_back();
        err = decodePlaneLayout(inputHidlVec, &outPlaneLayouts->back());
        if (err) {
            return err;
        }
    }
    return NO_ERROR;
}

void clearPlaneLayouts(std::vector<PlaneLayout>* output) {
    if (!output) {
        return;
    }
    output->clear();
}

status_t encodeCropHelper(const std::vector<Rect>& crops, OutputHidlVec* outOutputHidlVec) {
    status_t err = encodeInteger<int64_t>(static_cast<int64_t>(crops.size()), outOutputHidlVec);
    if (err) {
        return err;
    }

    for (const auto& crop : crops) {
        err = encodeRect(crop, outOutputHidlVec);
        if (err) {
            return err;
        }
    }

    return NO_ERROR;
}

status_t decodeCropHelper(InputHidlVec* inputHidlVec, std::vector<Rect>* outCrops) {
    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(inputHidlVec, &size);
    if (err) {
        return err;
    }
    if (size < 0) {
        return BAD_VALUE;
    }

    for (size_t i = 0; i < size; i++) {
        outCrops->emplace_back();
        err = decodeRect(inputHidlVec, &outCrops->back());
        if (err) {
            return err;
        }
    }
    return NO_ERROR;
}

void clearCrop(std::vector<Rect>* output) {
    if (!output) {
        return;
    }
    output->clear();
}

status_t encodeSmpte2086Helper(const Smpte2086& smpte2086, OutputHidlVec* outOutputHidlVec) {
    status_t err = encodeXyColor(smpte2086.primaryRed, outOutputHidlVec);
    if (err) {
        return err;
    }
    err = encodeXyColor(smpte2086.primaryGreen, outOutputHidlVec);
    if (err) {
        return err;
    }
    err = encodeXyColor(smpte2086.primaryBlue, outOutputHidlVec);
    if (err) {
        return err;
    }
    err = encodeXyColor(smpte2086.whitePoint, outOutputHidlVec);
    if (err) {
        return err;
    }
    err = encodeInteger<float>(smpte2086.maxLuminance, outOutputHidlVec);
    if (err) {
        return err;
    }
    return encodeInteger<float>(smpte2086.minLuminance, outOutputHidlVec);
}

status_t decodeSmpte2086Helper(InputHidlVec* inputHidlVec, Smpte2086* outSmpte2086) {
    status_t err = decodeXyColor(inputHidlVec, &outSmpte2086->primaryRed);
    if (err) {
        return err;
    }
    err = decodeXyColor(inputHidlVec, &outSmpte2086->primaryGreen);
    if (err) {
        return err;
    }
    err = decodeXyColor(inputHidlVec, &outSmpte2086->primaryBlue);
    if (err) {
        return err;
    }
    err = decodeXyColor(inputHidlVec, &outSmpte2086->whitePoint);
    if (err) {
        return err;
    }
    err = decodeInteger<float>(inputHidlVec, &outSmpte2086->maxLuminance);
    if (err) {
        return err;
    }
    return decodeInteger<float>(inputHidlVec, &outSmpte2086->minLuminance);
}

status_t encodeCta861_3Helper(const Cta861_3& cta861_3, OutputHidlVec* outOutputHidlVec) {
    status_t err = encodeInteger<float>(cta861_3.maxContentLightLevel, outOutputHidlVec);
    if (err) {
        return err;
    }
    return encodeInteger<float>(cta861_3.maxFrameAverageLightLevel, outOutputHidlVec);
}

status_t decodeCta861_3Helper(InputHidlVec* inputHidlVec, Cta861_3* outCta861_3) {
    status_t err = decodeInteger<float>(inputHidlVec, &outCta861_3->maxContentLightLevel);
    if (err) {
        return err;
    }
    return decodeInteger<float>(inputHidlVec, &outCta861_3->maxFrameAverageLightLevel);
}

/**
 * Public API functions
 */
status_t encodeBufferDescriptorInfo(const BufferDescriptorInfo& bufferDescriptorInfo,
        hidl_vec<uint8_t>* outBufferDescriptorInfo) {
    return encode(bufferDescriptorInfo, outBufferDescriptorInfo, encodeBufferDescriptorInfoHelper);
}

status_t decodeBufferDescriptorInfo(const hidl_vec<uint8_t>& bufferDescriptorInfo,
        BufferDescriptorInfo* outBufferDescriptorInfo) {
    return decode(bufferDescriptorInfo, outBufferDescriptorInfo, decodeBufferDescriptorInfoHelper);
}

status_t encodeBufferId(uint64_t bufferId, hidl_vec<uint8_t>* outBufferId) {
    return encodeMetadata(MetadataType_BufferId, bufferId, outBufferId, encodeInteger);
}

status_t decodeBufferId(const hidl_vec<uint8_t>& bufferId, uint64_t* outBufferId) {
    return decodeMetadata(MetadataType_BufferId, bufferId, outBufferId, decodeInteger);
}

status_t encodeName(const std::string& name, hidl_vec<uint8_t>* outName) {
    return encodeMetadata(MetadataType_Name, name, outName, encodeString);
}

status_t decodeName(const hidl_vec<uint8_t>& name, std::string* outName) {
    return decodeMetadata(MetadataType_Name, name, outName, decodeString);
}

status_t encodeWidth(uint64_t width, hidl_vec<uint8_t>* outWidth) {
    return encodeMetadata(MetadataType_Width, width, outWidth, encodeInteger);
}

status_t decodeWidth(const hidl_vec<uint8_t>& width, uint64_t* outWidth) {
    return decodeMetadata(MetadataType_Width, width, outWidth, decodeInteger);
}

status_t encodeHeight(uint64_t height, hidl_vec<uint8_t>* outHeight) {
    return encodeMetadata(MetadataType_Height, height, outHeight, encodeInteger);
}

status_t decodeHeight(const hidl_vec<uint8_t>& height, uint64_t* outHeight) {
    return decodeMetadata(MetadataType_Height, height, outHeight, decodeInteger);
}

status_t encodeLayerCount(uint64_t layerCount, hidl_vec<uint8_t>* outLayerCount) {
    return encodeMetadata(MetadataType_LayerCount, layerCount, outLayerCount, encodeInteger);
}

status_t decodeLayerCount(const hidl_vec<uint8_t>& layerCount, uint64_t* outLayerCount) {
    return decodeMetadata(MetadataType_LayerCount, layerCount, outLayerCount, decodeInteger);
}

status_t encodePixelFormatRequested(const hardware::graphics::common::V1_2::PixelFormat& pixelFormatRequested,
        hidl_vec<uint8_t>* outPixelFormatRequested) {
    return encodeMetadata(MetadataType_PixelFormatRequested, static_cast<int32_t>(pixelFormatRequested),
                  outPixelFormatRequested, encodeInteger);
}

status_t decodePixelFormatRequested(const hidl_vec<uint8_t>& pixelFormatRequested,
        hardware::graphics::common::V1_2::PixelFormat* outPixelFormatRequested) {
    return decodeMetadata(MetadataType_PixelFormatRequested, pixelFormatRequested,
                  reinterpret_cast<int32_t*>(outPixelFormatRequested), decodeInteger);
}

status_t encodePixelFormatFourCC(uint32_t pixelFormatFourCC, hidl_vec<uint8_t>* outPixelFormatFourCC) {
    return encodeMetadata(MetadataType_PixelFormatFourCC, pixelFormatFourCC, outPixelFormatFourCC,
                  encodeInteger);
}

status_t decodePixelFormatFourCC(const hidl_vec<uint8_t>& pixelFormatFourCC, uint32_t* outPixelFormatFourCC) {
    return decodeMetadata(MetadataType_PixelFormatFourCC, pixelFormatFourCC, outPixelFormatFourCC,
                  decodeInteger);
}

status_t encodePixelFormatModifier(uint64_t pixelFormatModifier, hidl_vec<uint8_t>* outPixelFormatModifier) {
    return encodeMetadata(MetadataType_PixelFormatModifier, pixelFormatModifier, outPixelFormatModifier,
                  encodeInteger);
}

status_t decodePixelFormatModifier(const hidl_vec<uint8_t>& pixelFormatModifier, uint64_t* outPixelFormatModifier) {
    return decodeMetadata(MetadataType_PixelFormatModifier, pixelFormatModifier, outPixelFormatModifier,
                  decodeInteger);
}

status_t encodeUsage(uint64_t usage, hidl_vec<uint8_t>* outUsage) {
    return encodeMetadata(MetadataType_Usage, usage, outUsage, encodeInteger);
}

status_t decodeUsage(const hidl_vec<uint8_t>& usage, uint64_t* outUsage) {
    return decodeMetadata(MetadataType_Usage, usage, outUsage, decodeInteger);
}

status_t encodeAllocationSize(uint64_t allocationSize, hidl_vec<uint8_t>* outAllocationSize) {
    return encodeMetadata(MetadataType_AllocationSize, allocationSize, outAllocationSize, encodeInteger);
}

status_t decodeAllocationSize(const hidl_vec<uint8_t>& allocationSize, uint64_t* outAllocationSize) {
    return decodeMetadata(MetadataType_AllocationSize, allocationSize, outAllocationSize, decodeInteger);
}

status_t encodeProtectedContent(uint64_t protectedContent, hidl_vec<uint8_t>* outProtectedContent) {
    return encodeMetadata(MetadataType_ProtectedContent, protectedContent, outProtectedContent,
                  encodeInteger);
}

status_t decodeProtectedContent(const hidl_vec<uint8_t>& protectedContent, uint64_t* outProtectedContent) {
    return decodeMetadata(MetadataType_ProtectedContent, protectedContent, outProtectedContent,
                  decodeInteger);
}

status_t encodeCompression(const ExtendableType& compression, hidl_vec<uint8_t>* outCompression) {
    return encodeMetadata(MetadataType_Compression, compression, outCompression, encodeExtendableType);
}

status_t decodeCompression(const hidl_vec<uint8_t>& compression, ExtendableType* outCompression) {
    return decodeMetadata(MetadataType_Compression, compression, outCompression, decodeExtendableType,
                  clearExtendableType);
}

status_t encodeInterlaced(const ExtendableType& interlaced, hidl_vec<uint8_t>* outInterlaced) {
    return encodeMetadata(MetadataType_Interlaced, interlaced, outInterlaced, encodeExtendableType);
}

status_t decodeInterlaced(const hidl_vec<uint8_t>& interlaced, ExtendableType* outInterlaced) {
    return decodeMetadata(MetadataType_Interlaced, interlaced, outInterlaced, decodeExtendableType,
                  clearExtendableType);
}

status_t encodeChromaSiting(const ExtendableType& chromaSiting, hidl_vec<uint8_t>* outChromaSiting) {
    return encodeMetadata(MetadataType_ChromaSiting, chromaSiting, outChromaSiting, encodeExtendableType);
}

status_t decodeChromaSiting(const hidl_vec<uint8_t>& chromaSiting, ExtendableType* outChromaSiting) {
    return decodeMetadata(MetadataType_ChromaSiting, chromaSiting, outChromaSiting, decodeExtendableType,
                  clearExtendableType);
}

status_t encodePlaneLayouts(const std::vector<PlaneLayout>& planeLayouts, hidl_vec<uint8_t>* outPlaneLayouts) {
    return encodeMetadata(MetadataType_PlaneLayouts, planeLayouts, outPlaneLayouts,
                  encodePlaneLayoutsHelper);
}

status_t decodePlaneLayouts(const hidl_vec<uint8_t>& planeLayouts, std::vector<PlaneLayout>* outPlaneLayouts) {
    return decodeMetadata(MetadataType_PlaneLayouts, planeLayouts, outPlaneLayouts,
                  decodePlaneLayoutsHelper, clearPlaneLayouts);
}

status_t encodeCrop(const std::vector<Rect>& crop, hidl_vec<uint8_t>* outCrop) {
    return encodeMetadata(MetadataType_Crop, crop, outCrop, encodeCropHelper);
}

status_t decodeCrop(const hidl_vec<uint8_t>& crop, std::vector<Rect>* outCrop) {
    return decodeMetadata(MetadataType_Crop, crop, outCrop, decodeCropHelper, clearCrop);
}

status_t encodeDataspace(const Dataspace& dataspace, hidl_vec<uint8_t>* outDataspace) {
    return encodeMetadata(MetadataType_Dataspace, static_cast<int32_t>(dataspace), outDataspace,
                  encodeInteger);
}

status_t decodeDataspace(const hidl_vec<uint8_t>& dataspace, Dataspace* outDataspace) {
    return decodeMetadata(MetadataType_Dataspace, dataspace, reinterpret_cast<int32_t*>(outDataspace),
                  decodeInteger);
}

status_t encodeBlendMode(const BlendMode& blendMode, hidl_vec<uint8_t>* outBlendMode) {
    return encodeMetadata(MetadataType_BlendMode, static_cast<int32_t>(blendMode), outBlendMode,
                  encodeInteger);
}

status_t decodeBlendMode(const hidl_vec<uint8_t>& blendMode, BlendMode* outBlendMode) {
    return decodeMetadata(MetadataType_BlendMode, blendMode, reinterpret_cast<int32_t*>(outBlendMode),
                  decodeInteger);
}

status_t encodeSmpte2086(const std::optional<Smpte2086>& smpte2086,
                         hidl_vec<uint8_t>* outSmpte2086) {
    return encodeOptionalMetadata(MetadataType_Smpte2086, smpte2086, outSmpte2086, encodeSmpte2086Helper);
}

status_t decodeSmpte2086(const hidl_vec<uint8_t>& smpte2086,
                         std::optional<Smpte2086>* outSmpte2086) {
    return decodeOptionalMetadata(MetadataType_Smpte2086, smpte2086, outSmpte2086, decodeSmpte2086Helper);
}

status_t encodeCta861_3(const std::optional<Cta861_3>& cta861_3, hidl_vec<uint8_t>* outCta861_3) {
    return encodeOptionalMetadata(MetadataType_Cta861_3, cta861_3, outCta861_3, encodeCta861_3Helper);
}

status_t decodeCta861_3(const hidl_vec<uint8_t>& cta861_3, std::optional<Cta861_3>* outCta861_3) {
    return decodeOptionalMetadata(MetadataType_Cta861_3, cta861_3, outCta861_3, decodeCta861_3Helper);
}

status_t encodeSmpte2094_40(const std::optional<std::vector<uint8_t>>& smpte2094_40,
                            hidl_vec<uint8_t>* outSmpte2094_40) {
    return encodeOptionalMetadata(MetadataType_Smpte2094_40, smpte2094_40, outSmpte2094_40,
                          encodeByteVector);
}

status_t decodeSmpte2094_40(const hidl_vec<uint8_t>& smpte2094_40,
                            std::optional<std::vector<uint8_t>>* outSmpte2094_40) {
    return decodeOptionalMetadata(MetadataType_Smpte2094_40, smpte2094_40, outSmpte2094_40,
                          decodeByteVector);
}

status_t encodeUint32(const MetadataType& metadataType, uint32_t input,
                      hidl_vec<uint8_t>* output) {
    return encodeMetadata(metadataType, input, output, encodeInteger);
}

status_t decodeUint32(const MetadataType& metadataType, const hidl_vec<uint8_t>& input,
                      uint32_t* output) {
    return decodeMetadata(metadataType, input, output, decodeInteger);
}

status_t encodeInt32(const MetadataType& metadataType, int32_t input,
                     hidl_vec<uint8_t>* output) {
    return encodeMetadata(metadataType, input, output, encodeInteger);
}

status_t decodeInt32(const MetadataType& metadataType, const hidl_vec<uint8_t>& input,
                     int32_t* output) {
    return decodeMetadata(metadataType, input, output, decodeInteger);
}

status_t encodeUint64(const MetadataType& metadataType, uint64_t input,
                      hidl_vec<uint8_t>* output) {
    return encodeMetadata(metadataType, input, output, encodeInteger);
}

status_t decodeUint64(const MetadataType& metadataType, const hidl_vec<uint8_t>& input,
                      uint64_t* output) {
    return decodeMetadata(metadataType, input, output, decodeInteger);
}

status_t encodeInt64(const MetadataType& metadataType, int64_t input,
                     hidl_vec<uint8_t>* output) {
    return encodeMetadata(metadataType, input, output, encodeInteger);
}

status_t decodeInt64(const MetadataType& metadataType, const hidl_vec<uint8_t>& input,
                     int64_t* output) {
    return decodeMetadata(metadataType, input, output, decodeInteger);
}

status_t encodeFloat(const MetadataType& metadataType, float input,
                     hidl_vec<uint8_t>* output) {
    return encodeMetadata(metadataType, input, output, encodeInteger);
}

status_t decodeFloat(const MetadataType& metadataType, const hidl_vec<uint8_t>& input,
                     float* output) {
    return decodeMetadata(metadataType, input, output, decodeInteger);
}

status_t encodeDouble(const MetadataType& metadataType, double input,
                      hidl_vec<uint8_t>* output) {
    return encodeMetadata(metadataType, input, output, encodeInteger);
}

status_t decodeDouble(const MetadataType& metadataType, const hidl_vec<uint8_t>& input,
                      double* output) {
    return decodeMetadata(metadataType, input, output, decodeInteger);
}

status_t encodeString(const MetadataType& metadataType, const std::string& input,
                      hidl_vec<uint8_t>* output) {
    return encodeMetadata(metadataType, input, output, encodeString);
}

status_t decodeString(const MetadataType& metadataType, const hidl_vec<uint8_t>& input,
                      std::string* output) {
    return decodeMetadata(metadataType, input, output, decodeString);
}

bool isStandardMetadataType(const MetadataType& metadataType) {
    return !std::strncmp(metadataType.name.c_str(), GRALLOC4_STANDARD_METADATA_TYPE,
                         metadataType.name.size());
}

bool isStandardCompression(const ExtendableType& compression) {
    return !std::strncmp(compression.name.c_str(), GRALLOC4_STANDARD_COMPRESSION,
                         compression.name.size());
}

bool isStandardInterlaced(const ExtendableType& interlaced) {
    return !std::strncmp(interlaced.name.c_str(), GRALLOC4_STANDARD_INTERLACED,
                         interlaced.name.size());
}

bool isStandardChromaSiting(const ExtendableType& chromaSiting) {
    return !std::strncmp(chromaSiting.name.c_str(), GRALLOC4_STANDARD_CHROMA_SITING,
                         chromaSiting.name.size());
}

bool isStandardPlaneLayoutComponentType(const ExtendableType& planeLayoutComponentType) {
    return !std::strncmp(planeLayoutComponentType.name.c_str(), GRALLOC4_STANDARD_PLANE_LAYOUT_COMPONENT_TYPE,
                         planeLayoutComponentType.name.size());
}

StandardMetadataType getStandardMetadataTypeValue(const MetadataType& metadataType) {
    return static_cast<StandardMetadataType>(metadataType.value);
}

Compression getStandardCompressionValue(const ExtendableType& compression) {
    return static_cast<Compression>(compression.value);
}

Interlaced getStandardInterlacedValue(const ExtendableType& interlaced) {
    return static_cast<Interlaced>(interlaced.value);
}

ChromaSiting getStandardChromaSitingValue(const ExtendableType& chromaSiting) {
    return static_cast<ChromaSiting>(chromaSiting.value);
}

PlaneLayoutComponentType getStandardPlaneLayoutComponentTypeValue(
        const ExtendableType& planeLayoutComponentType) {
    return static_cast<PlaneLayoutComponentType>(planeLayoutComponentType.value);
}

std::string getCompressionName(const ExtendableType& compression) {
    if (!isStandardCompression(compression)) {
        std::ostringstream stream;
        stream << compression.name << "#" << compression.value;
        return stream.str();
    }
    switch (getStandardCompressionValue(compression)) {
        case Compression::NONE:
            return "None";
        case Compression::DISPLAY_STREAM_COMPRESSION:
            return "DisplayStreamCompression";
    }
}

std::string getInterlacedName(const ExtendableType& interlaced) {
    if (!isStandardInterlaced(interlaced)) {
        std::ostringstream stream;
        stream << interlaced.name << "#" << interlaced.value;
        return stream.str();
    }
    switch (getStandardInterlacedValue(interlaced)) {
        case Interlaced::NONE:
            return "None";
        case Interlaced::TOP_BOTTOM:
            return "TopBottom";
        case Interlaced::RIGHT_LEFT:
            return "RightLeft";
    }
}

std::string getChromaSitingName(const ExtendableType& chromaSiting) {
    if (!isStandardChromaSiting(chromaSiting)) {
        std::ostringstream stream;
        stream << chromaSiting.name << "#" << chromaSiting.value;
        return stream.str();
    }
    switch (getStandardChromaSitingValue(chromaSiting)) {
        case ChromaSiting::NONE:
            return "None";
        case ChromaSiting::UNKNOWN:
            return "Unknown";
        case ChromaSiting::SITED_INTERSTITIAL:
            return "SitedInterstitial";
        case ChromaSiting::COSITED_HORIZONTAL:
            return "CositedHorizontal";
    }
}

std::string getPlaneLayoutComponentTypeName(const ExtendableType& planeLayoutComponentType) {
    if (!isStandardPlaneLayoutComponentType(planeLayoutComponentType)) {
        std::ostringstream stream;
        stream << planeLayoutComponentType.name << "#" << planeLayoutComponentType.value;
        return stream.str();
    }
    switch (getStandardPlaneLayoutComponentTypeValue(planeLayoutComponentType)) {
        case PlaneLayoutComponentType::Y:
            return "Y";
        case PlaneLayoutComponentType::CB:
            return "Cb";
        case PlaneLayoutComponentType::CR:
            return "Cr";
        case PlaneLayoutComponentType::R:
            return "R";
        case PlaneLayoutComponentType::G:
            return "G";
        case PlaneLayoutComponentType::B:
            return "B";
        case PlaneLayoutComponentType::RAW:
            return "RAW";
        case PlaneLayoutComponentType::A:
            return "A";
    }
}

} // namespace gralloc4

} // namespace android
