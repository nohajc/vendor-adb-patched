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

#include "ColorSpaces.h"

namespace android {
namespace renderengine {
namespace skia {

sk_sp<SkColorSpace> toSkColorSpace(ui::Dataspace dataspace) {
    skcms_Matrix3x3 gamut;
    switch (dataspace & HAL_DATASPACE_STANDARD_MASK) {
        case HAL_DATASPACE_STANDARD_BT709:
            gamut = SkNamedGamut::kSRGB;
            break;
        case HAL_DATASPACE_STANDARD_BT2020:
            gamut = SkNamedGamut::kRec2020;
            break;
        case HAL_DATASPACE_STANDARD_DCI_P3:
            gamut = SkNamedGamut::kDisplayP3;
            break;
        default:
            gamut = SkNamedGamut::kSRGB;
            break;
    }

    switch (dataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_LINEAR:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kLinear, gamut);
        case HAL_DATASPACE_TRANSFER_SRGB:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, gamut);
        case HAL_DATASPACE_TRANSFER_ST2084:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kPQ, gamut);
        case HAL_DATASPACE_TRANSFER_HLG:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kHLG, gamut);
        default:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, gamut);
    }
}

} // namespace skia
} // namespace renderengine
} // namespace android