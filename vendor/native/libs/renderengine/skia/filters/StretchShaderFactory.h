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

#include <SkImage.h>
#include <SkRuntimeEffect.h>
#include <SkShader.h>
#include <ui/StretchEffect.h>

namespace android {
namespace renderengine {
namespace skia {
class StretchShaderFactory {
public:
    sk_sp<SkShader> createSkShader(const sk_sp<SkShader>& inputShader,
                                   const StretchEffect& stretchEffect);

private:
    std::unique_ptr<SkRuntimeShaderBuilder> mBuilder;
};
} // namespace skia
} // namespace renderengine
} // namespace android