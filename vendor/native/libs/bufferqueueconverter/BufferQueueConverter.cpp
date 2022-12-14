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

#include <gui/Surface.h>
#include <gui/bufferqueue/2.0/H2BGraphicBufferProducer.h>

#include "include/bufferqueueconverter/BufferQueueConverter.h"


using ::android::Surface;
using ::android::IGraphicBufferProducer;
using ::android::hardware::graphics::bufferqueue::V2_0::utils::H2BGraphicBufferProducer;


namespace android {

struct SurfaceHolder {
    sp<Surface> surface;
    SurfaceHolder(const sp<Surface>& s) : surface(s) {}
};

/**
 * Custom deleter for SurfaceHolder unique pointer
 */
void destroySurfaceHolder(SurfaceHolder* surfaceHolder) {
    delete surfaceHolder;
}


SurfaceHolderUniquePtr getSurfaceFromHGBP(const sp<HGraphicBufferProducer>& token) {
    if (token == nullptr) {
        ALOGE("Passed IGraphicBufferProducer handle is invalid.");
        return SurfaceHolderUniquePtr(nullptr, nullptr);
    }

    sp<IGraphicBufferProducer> bufferProducer = new H2BGraphicBufferProducer(token);
    if (bufferProducer == nullptr) {
        ALOGE("Failed to get IGraphicBufferProducer.");
        return SurfaceHolderUniquePtr(nullptr, nullptr);
    }

    sp<Surface> newSurface(new Surface(bufferProducer, true));
    if (newSurface == nullptr) {
        ALOGE("Failed to create Surface from HGBP.");
        return SurfaceHolderUniquePtr(nullptr, nullptr);
    }

    return SurfaceHolderUniquePtr(new SurfaceHolder(newSurface), destroySurfaceHolder);
}


ANativeWindow* getNativeWindow(SurfaceHolder* handle) {
    if (handle == nullptr) {
        ALOGE("SurfaceHolder is invalid.");
        return nullptr;
    }

    return static_cast<ANativeWindow*>(handle->surface.get());
}

} // namespace android
