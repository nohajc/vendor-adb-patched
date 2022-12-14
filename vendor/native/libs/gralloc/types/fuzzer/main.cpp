/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define FUZZ_LOG_TAG "main"

#include "gralloctypes.h"
#include "util.h"

#include <android-base/logging.h>
#include <log/log.h>

#include <cstdlib>
#include <ctime>

using MetadataType = android::hardware::graphics::mapper::V4_0::IMapper::MetadataType;

void doFuzz(
        const std::vector<GrallocTypesDecode>& decodes, uint8_t instruction,
        const std::vector<uint8_t>& input) {

    ::android::hardware::hidl_vec<uint8_t> vec;
    vec.setToExternal(const_cast<uint8_t*>(input.data()), input.size(), false /*shouldOwn*/);

    // since we are only using a byte to index
    CHECK(decodes.size() <= 255) << decodes.size();
    uint8_t decodeIdx = instruction % decodes.size();

    FUZZ_LOG() << "Instruction: " << instruction << " idx: " << static_cast<size_t>(decodeIdx)
               << " size: " << vec.size();

    decodes[decodeIdx](vec);
}

size_t fillInMetadataType(const std::vector<uint8_t>& input, MetadataType* outMetadataType) {
    if (input.size() < sizeof(outMetadataType->value) + 1) {
        return 0;
    }
    size_t size = 0;

    outMetadataType->value = *(reinterpret_cast<const int64_t*>(input.data()));
    size += sizeof(outMetadataType->value);

    uint8_t nameLen = *(input.data() + size);
    size += 1;

    if (input.size() < size + nameLen) {
        return 0;
    }
    std::string name(reinterpret_cast<const char*>(input.data()) + size, nameLen);
    outMetadataType->name = name;
    return size + nameLen;
}

void doFuzzVendorHelper(
        const std::vector<GrallocTypesVendorHelperDecode>& decodes, uint8_t instruction,
        const std::vector<uint8_t>& input) {

    MetadataType metadataType;
    size_t sizeUsed  = fillInMetadataType(input, &metadataType);
    if (sizeUsed <= 0) {
        return;
    }

    ::android::hardware::hidl_vec<uint8_t> vec;
    vec.setToExternal(const_cast<uint8_t*>(input.data() + sizeUsed), input.size() - sizeUsed,
                      false /*shouldOwn*/);

    // since we are only using a byte to index
    CHECK(decodes.size() <= 255) << decodes.size();
    uint8_t decodeIdx = instruction % decodes.size();

    FUZZ_LOG() << "Vendor Helper instruction: " << instruction << " idx: "
               << static_cast<size_t>(decodeIdx) << " size: " << vec.size();

    decodes[decodeIdx](metadataType, vec);
}

void fuzz(uint8_t options, uint8_t instruction, const std::vector<uint8_t>& input) {
    uint8_t option = options & 0x1;

    switch (option) {
        case 0x0:
            doFuzz(GRALLOCTYPES_DECODE_FUNCTIONS, instruction, input);
            break;
        case 0x1:
            doFuzzVendorHelper(GRALLOCTYPES_DECODE_VENDOR_HELPER_FUNCTIONS, instruction, input);
            break;
        default:
            LOG_ALWAYS_FATAL("unknown gralloc types %d", static_cast<int>(option));
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size <= 1) return 0;  // no use

    uint8_t options = *data;
    data++;
    size--;

    uint8_t instruction = *data;
    data++;
    size--;

    std::vector<uint8_t> input(data, data + size);

    FUZZ_LOG() << "input: " << hexString(input);

    fuzz(options, instruction, input);
    return 0;
}
