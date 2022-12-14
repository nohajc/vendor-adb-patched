/*
 * Copyright 2019 The Android Open Source Project
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

#include <cstdint>
#include <memory>

#include <compositionengine/DisplaySurface.h>
#include <utils/StrongPointer.h>

struct ANativeWindow;

namespace android::compositionengine {

/**
 * A parameter object for creating RenderSurface instances
 */
struct RenderSurfaceCreationArgs {
    // The initial width of the surface
    int32_t displayWidth = -1;

    // The initial height of the surface
    int32_t displayHeight = -1;

    // The ANativeWindow for the buffer queue for this surface
    sp<ANativeWindow> nativeWindow;

    // The DisplaySurface for this surface
    sp<DisplaySurface> displaySurface;

    // The maximum size of the renderengine::ExternalTexture cache
    size_t maxTextureCacheSize = 0;

private:
    friend class RenderSurfaceCreationArgsBuilder;

    // Not defaulted to disable aggregate initialization.
    RenderSurfaceCreationArgs() {}
};

class RenderSurfaceCreationArgsBuilder {
public:
    RenderSurfaceCreationArgs build() { return std::move(mArgs); }

    RenderSurfaceCreationArgsBuilder& setDisplayWidth(int32_t displayWidth) {
        mArgs.displayWidth = displayWidth;
        return *this;
    }
    RenderSurfaceCreationArgsBuilder& setDisplayHeight(int32_t displayHeight) {
        mArgs.displayHeight = displayHeight;
        return *this;
    }
    RenderSurfaceCreationArgsBuilder& setNativeWindow(sp<ANativeWindow> nativeWindow) {
        mArgs.nativeWindow = std::move(nativeWindow);
        return *this;
    }
    RenderSurfaceCreationArgsBuilder& setDisplaySurface(sp<DisplaySurface> displaySurface) {
        mArgs.displaySurface = std::move(displaySurface);
        return *this;
    }

    RenderSurfaceCreationArgsBuilder& setMaxTextureCacheSize(size_t maxTextureCacheSize) {
        mArgs.maxTextureCacheSize = maxTextureCacheSize;
        return *this;
    }

private:
    RenderSurfaceCreationArgs mArgs;
};

} // namespace android::compositionengine
