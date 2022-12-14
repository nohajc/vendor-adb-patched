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

#include <ui/PixelFormat.h>
#include <aidl/android/hardware/graphics/common/PixelFormat.h>

// Ideally, PIXEL_FORMAT_R_8 would simply be defined to match the aidl PixelFormat, but
// PixelFormat.h (where PIXEL_FORMAT_R_8 is defined) is pulled in by builds for
// which there is no aidl build (e.g. Windows).
static_assert(android::PIXEL_FORMAT_R_8 ==static_cast<int32_t>(
                                  aidl::android::hardware::graphics::common::PixelFormat::R_8));
