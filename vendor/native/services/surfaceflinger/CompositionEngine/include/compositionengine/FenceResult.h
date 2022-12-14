/*
 * Copyright 2022 The Android Open Source Project
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

#include <android-base/expected.h>
#include <utils/Errors.h>
#include <utils/StrongPointer.h>

// TODO(b/232535621): Pull this file to <ui/FenceResult.h> so that RenderEngine::drawLayers returns
// FenceResult rather than RenderEngineResult.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#include <renderengine/RenderEngine.h>
#pragma clang diagnostic pop

namespace android {

class Fence;

using FenceResult = base::expected<sp<Fence>, status_t>;

// TODO(b/232535621): Prevent base::unexpected(NO_ERROR) from being a valid FenceResult.
inline status_t fenceStatus(const FenceResult& fenceResult) {
    return fenceResult.ok() ? NO_ERROR : fenceResult.error();
}

inline FenceResult toFenceResult(renderengine::RenderEngineResult&& result) {
    if (auto [status, fence] = std::move(result); fence.ok()) {
        return sp<Fence>::make(std::move(fence));
    } else {
        return base::unexpected(status);
    }
}

} // namespace android
