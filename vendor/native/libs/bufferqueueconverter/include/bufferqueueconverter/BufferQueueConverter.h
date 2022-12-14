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

#ifndef ANDROID_BUFFER_QUEUE_CONVERTER_H
#define ANDROID_BUFFER_QUEUE_CONVERTER_H

#include <gui/IGraphicBufferProducer.h>
#include <android/native_window.h>

using ::android::sp;
using HGraphicBufferProducer =
      ::android::hardware::graphics::bufferqueue::V2_0::IGraphicBufferProducer;

namespace android {
    /**
     * Opaque handle for a data structure holding Surface.
     */
    typedef struct SurfaceHolder SurfaceHolder;

    /**
     * SurfaceHolder unique pointer type
     */
    using SurfaceHolderUniquePtr = std::unique_ptr<SurfaceHolder, void(*)(SurfaceHolder*)>;

    /**
     * Returns a SurfaceHolder that wraps a Surface generated from a given HGBP.
     *
     * @param  token         Hardware IGraphicBufferProducer to create a
     *                       Surface.
     * @return SurfaceHolder Unique pointer to created SurfaceHolder object.
     */
    SurfaceHolderUniquePtr getSurfaceFromHGBP(const sp<HGraphicBufferProducer>& token);

    /**
     * Returns ANativeWindow pointer from a given SurfaceHolder.  Returned
     * pointer is valid only while the containing SurfaceHolder is alive.
     *
     * @param  surfaceHolder  SurfaceHolder to generate a native window.
     * @return ANativeWindow* a pointer to a generated native window.
     */
    ANativeWindow* getNativeWindow(SurfaceHolder* surfaceHolder);

} // namespace android

#endif // ANDROID_BUFFER_QUEUE_CONVERTER_H
