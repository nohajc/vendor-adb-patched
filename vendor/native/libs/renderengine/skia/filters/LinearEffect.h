/*
 * Copyright 2020 The Android Open Source Project
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

#include <math/mat4.h>

#include <optional>

#include <shaders/shaders.h>
#include "SkRuntimeEffect.h"
#include "SkShader.h"
#include "ui/GraphicTypes.h"

namespace android {
namespace renderengine {
namespace skia {

sk_sp<SkRuntimeEffect> buildRuntimeEffect(const shaders::LinearEffect& linearEffect);

// Generates a shader resulting from applying the a linear effect created from
// LinearEffectArgs::buildEffect to an inputShader.
// Optionally, a color transform may also be provided, which combines with the
// matrix transforming from linear XYZ to linear RGB immediately before OETF.
// We also provide additional HDR metadata upon creating the shader:
// * The max display luminance is the max luminance of the physical display in nits
// * The current luminance of the physical display in nits
// * The max luminance is provided as the max luminance for the buffer, either from the SMPTE 2086
// or as the max light level from the CTA 861.3 standard.
// * An AHardwareBuffer for implementations that support gralloc4 metadata for
// communicating any HDR metadata.
// * A RenderIntent that communicates the downstream renderintent for a physical display, for image
// quality compensation.
sk_sp<SkShader> createLinearEffectShader(
        sk_sp<SkShader> inputShader, const shaders::LinearEffect& linearEffect,
        sk_sp<SkRuntimeEffect> runtimeEffect, const mat4& colorTransform, float maxDisplayLuminance,
        float currentDisplayLuminanceNits, float maxLuminance, AHardwareBuffer* buffer,
        aidl::android::hardware::graphics::composer3::RenderIntent renderIntent);
} // namespace skia
} // namespace renderengine
} // namespace android
