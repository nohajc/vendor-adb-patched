/*
 * Copyright 2018 The Android Open Source Project
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

#include <aidl/android/hardware/graphics/common/BlendMode.h>
#include <aidl/android/hardware/graphics/common/ChromaSiting.h>
#include <aidl/android/hardware/graphics/common/Compression.h>
#include <aidl/android/hardware/graphics/common/Cta861_3.h>
#include <aidl/android/hardware/graphics/common/Interlaced.h>
#include <aidl/android/hardware/graphics/common/PlaneLayout.h>
#include <aidl/android/hardware/graphics/common/Smpte2086.h>
#include <android/hardware/graphics/common/1.1/types.h>
#include <android/hardware/graphics/common/1.2/types.h>
#include <system/graphics.h>

namespace android {

/**
 * android::ui::* in this header file will alias different types as
 * the HIDL and stable AIDL interfaces are updated.
 */
namespace ui {

/**
 * The following HIDL types should be moved to their stable AIDL
 * equivalents when composer moves to stable AIDL.
 */
using android::hardware::graphics::common::V1_1::RenderIntent;
using android::hardware::graphics::common::V1_2::ColorMode;
using android::hardware::graphics::common::V1_2::Dataspace;
using android::hardware::graphics::common::V1_2::Hdr;
using android::hardware::graphics::common::V1_2::PixelFormat;

/**
 * Stable AIDL types
 */
using aidl::android::hardware::graphics::common::BlendMode;
using aidl::android::hardware::graphics::common::Cta861_3;
using aidl::android::hardware::graphics::common::PlaneLayout;
using aidl::android::hardware::graphics::common::Smpte2086;

/**
 * The following stable AIDL types below have standard platform definitions
 * that can be extended by vendors. The extensions are not defined here
 * because they cannot be understood by the framework.
 */
using ChromaSiting = aidl::android::hardware::graphics::common::ChromaSiting;
using Compression = aidl::android::hardware::graphics::common::Compression;
using Interlaced = aidl::android::hardware::graphics::common::Interlaced;

}  // namespace ui
}  // namespace android
