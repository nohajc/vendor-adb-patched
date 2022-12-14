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

// please keep in sync with hwui/utils/Color.cpp
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
        case HAL_DATASPACE_STANDARD_ADOBE_RGB:
            gamut = SkNamedGamut::kAdobeRGB;
            break;
        case HAL_DATASPACE_STANDARD_BT601_625:
        case HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED:
        case HAL_DATASPACE_STANDARD_BT601_525:
        case HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED:
        case HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE:
        case HAL_DATASPACE_STANDARD_BT470M:
        case HAL_DATASPACE_STANDARD_FILM:
        case HAL_DATASPACE_STANDARD_UNSPECIFIED:
        default:
            gamut = SkNamedGamut::kSRGB;
            break;
    }

    switch (dataspace & HAL_DATASPACE_TRANSFER_MASK) {
        case HAL_DATASPACE_TRANSFER_LINEAR:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kLinear, gamut);
        case HAL_DATASPACE_TRANSFER_SRGB:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, gamut);
        case HAL_DATASPACE_TRANSFER_GAMMA2_2:
            return SkColorSpace::MakeRGB({2.2f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f}, gamut);
        case HAL_DATASPACE_TRANSFER_GAMMA2_6:
            return SkColorSpace::MakeRGB({2.6f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f}, gamut);
        case HAL_DATASPACE_TRANSFER_GAMMA2_8:
            return SkColorSpace::MakeRGB({2.8f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f}, gamut);
        case HAL_DATASPACE_TRANSFER_ST2084:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kPQ, gamut);
        case HAL_DATASPACE_TRANSFER_SMPTE_170M:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kRec2020, gamut);
        case HAL_DATASPACE_TRANSFER_HLG:
            // return HLG transfer but scale by 1/12
            skcms_TransferFunction hlgFn;
            if (skcms_TransferFunction_makeScaledHLGish(&hlgFn, 1.f / 12.f, 2.f, 2.f,
                                                        1.f / 0.17883277f, 0.28466892f,
                                                        0.55991073f)) {
                return SkColorSpace::MakeRGB(hlgFn, gamut);
            } else {
                return SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, gamut);
            }
        case HAL_DATASPACE_TRANSFER_UNSPECIFIED:
        default:
            return SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, gamut);
    }
}

} // namespace skia
} // namespace renderengine
} // namespace android