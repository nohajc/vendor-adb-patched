/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <ui/GraphicTypes.h>
using namespace android;

constexpr ui::Dataspace kDataspaces[] = {
        ui::Dataspace::UNKNOWN,
        ui::Dataspace::ARBITRARY,
        ui::Dataspace::STANDARD_UNSPECIFIED,
        ui::Dataspace::STANDARD_BT709,
        ui::Dataspace::STANDARD_BT601_625,
        ui::Dataspace::STANDARD_BT601_625_UNADJUSTED,
        ui::Dataspace::STANDARD_BT601_525,
        ui::Dataspace::STANDARD_BT601_525_UNADJUSTED,
        ui::Dataspace::STANDARD_BT2020,
        ui::Dataspace::STANDARD_BT2020_CONSTANT_LUMINANCE,
        ui::Dataspace::STANDARD_BT470M,
        ui::Dataspace::STANDARD_FILM,
        ui::Dataspace::STANDARD_DCI_P3,
        ui::Dataspace::STANDARD_ADOBE_RGB,
        ui::Dataspace::TRANSFER_UNSPECIFIED,
        ui::Dataspace::TRANSFER_LINEAR,
        ui::Dataspace::TRANSFER_SRGB,
        ui::Dataspace::TRANSFER_SMPTE_170M,
        ui::Dataspace::TRANSFER_GAMMA2_2,
        ui::Dataspace::TRANSFER_GAMMA2_6,
        ui::Dataspace::TRANSFER_GAMMA2_8,
        ui::Dataspace::TRANSFER_ST2084,
        ui::Dataspace::TRANSFER_HLG,
        ui::Dataspace::RANGE_UNSPECIFIED,
        ui::Dataspace::RANGE_FULL,
        ui::Dataspace::RANGE_LIMITED,
        ui::Dataspace::RANGE_EXTENDED,
        ui::Dataspace::SRGB_LINEAR,
        ui::Dataspace::V0_SRGB_LINEAR,
        ui::Dataspace::V0_SCRGB_LINEAR,
        ui::Dataspace::SRGB,
        ui::Dataspace::V0_SRGB,
        ui::Dataspace::V0_SCRGB,
        ui::Dataspace::JFIF,
        ui::Dataspace::V0_JFIF,
        ui::Dataspace::BT601_625,
        ui::Dataspace::V0_BT601_625,
        ui::Dataspace::BT601_525,
        ui::Dataspace::V0_BT601_525,
        ui::Dataspace::BT709,
        ui::Dataspace::V0_BT709,
        ui::Dataspace::DCI_P3_LINEAR,
        ui::Dataspace::DCI_P3,
        ui::Dataspace::DISPLAY_P3_LINEAR,
        ui::Dataspace::DISPLAY_P3,
        ui::Dataspace::ADOBE_RGB,
        ui::Dataspace::BT2020_LINEAR,
        ui::Dataspace::BT2020,
        ui::Dataspace::BT2020_PQ,
        ui::Dataspace::DEPTH,
        ui::Dataspace::SENSOR,
        ui::Dataspace::BT2020_ITU,
        ui::Dataspace::BT2020_ITU_PQ,
        ui::Dataspace::BT2020_ITU_HLG,
        ui::Dataspace::BT2020_HLG,
        ui::Dataspace::DISPLAY_BT2020,
        ui::Dataspace::DYNAMIC_DEPTH,
        ui::Dataspace::JPEG_APP_SEGMENTS,
        ui::Dataspace::HEIF,
};
