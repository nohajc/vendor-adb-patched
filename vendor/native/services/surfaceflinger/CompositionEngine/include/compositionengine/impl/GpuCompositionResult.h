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

#include <android-base/unique_fd.h>
#include <ui/GraphicBuffer.h>

namespace android::compositionengine::impl {

struct GpuCompositionResult {
    // Composition ready fence.
    base::unique_fd fence{};

    // Buffer to be used for gpu composition. If gpu composition was not successful,
    // then we want to reuse the buffer instead of dequeuing another buffer.
    std::shared_ptr<renderengine::ExternalTexture> buffer = nullptr;

    bool bufferAvailable() const { return buffer != nullptr; };
};

} // namespace android::compositionengine::impl
