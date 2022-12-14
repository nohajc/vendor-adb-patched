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

#include "SkColorSpace.h"
#include "ui/GraphicTypes.h"

namespace android {
namespace renderengine {
namespace skia {

// Converts an android dataspace to a supported SkColorSpace
// Supported dataspaces are
// 1. sRGB
// 2. Display P3
// 3. BT2020 PQ
// 4. BT2020 HLG
// Unknown primaries are mapped to BT709, and unknown transfer functions
// are mapped to sRGB.
sk_sp<SkColorSpace> toSkColorSpace(ui::Dataspace dataspace);

} // namespace skia
} // namespace renderengine
} // namespace android