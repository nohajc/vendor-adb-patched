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

#include "LinearEffect.h"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <SkString.h>
#include <log/log.h>
#include <shaders/shaders.h>
#include <utils/Trace.h>

#include <math/mat4.h>

namespace android {
namespace renderengine {
namespace skia {

sk_sp<SkRuntimeEffect> buildRuntimeEffect(const shaders::LinearEffect& linearEffect) {
    ATRACE_CALL();
    SkString shaderString = SkString(shaders::buildLinearEffectSkSL(linearEffect));

    auto [shader, error] = SkRuntimeEffect::MakeForShader(shaderString);
    if (!shader) {
        LOG_ALWAYS_FATAL("LinearColorFilter construction error: %s", error.c_str());
    }
    return shader;
}

sk_sp<SkShader> createLinearEffectShader(
        sk_sp<SkShader> shader, const shaders::LinearEffect& linearEffect,
        sk_sp<SkRuntimeEffect> runtimeEffect, const mat4& colorTransform, float maxDisplayLuminance,
        float currentDisplayLuminanceNits, float maxLuminance, AHardwareBuffer* buffer,
        aidl::android::hardware::graphics::composer3::RenderIntent renderIntent) {
    ATRACE_CALL();
    SkRuntimeShaderBuilder effectBuilder(runtimeEffect);

    effectBuilder.child("child") = shader;

    const auto uniforms =
            shaders::buildLinearEffectUniforms(linearEffect, colorTransform, maxDisplayLuminance,
                                               currentDisplayLuminanceNits, maxLuminance, buffer,
                                               renderIntent);

    for (const auto& uniform : uniforms) {
        effectBuilder.uniform(uniform.name.c_str()).set(uniform.value.data(), uniform.value.size());
    }

    return effectBuilder.makeShader();
}

} // namespace skia
} // namespace renderengine
} // namespace android
