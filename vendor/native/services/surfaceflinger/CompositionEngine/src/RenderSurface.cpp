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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <android-base/stringprintf.h>
#include <android/native_window.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/Display.h>
#include <compositionengine/DisplaySurface.h>
#include <compositionengine/RenderSurfaceCreationArgs.h>
#include <compositionengine/impl/DumpHelpers.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/RenderSurface.h>
#include <log/log.h>
#include <renderengine/ExternalTexture.h>
#include <renderengine/RenderEngine.h>
#include <system/window.h>
#include <ui/GraphicBuffer.h>
#include <ui/Rect.h>
#include <utils/Trace.h>

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include "DisplayHardware/HWComposer.h"

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"

namespace android::compositionengine {

RenderSurface::~RenderSurface() = default;

namespace impl {

constexpr auto DEFAULT_USAGE = GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;

std::unique_ptr<compositionengine::RenderSurface> createRenderSurface(
        const compositionengine::CompositionEngine& compositionEngine,
        compositionengine::Display& display,
        const compositionengine::RenderSurfaceCreationArgs& args) {
    return std::make_unique<RenderSurface>(compositionEngine, display, args);
}

RenderSurface::RenderSurface(const CompositionEngine& compositionEngine, Display& display,
                             const RenderSurfaceCreationArgs& args)
      : mCompositionEngine(compositionEngine),
        mDisplay(display),
        mNativeWindow(args.nativeWindow),
        mDisplaySurface(args.displaySurface),
        mSize(args.displayWidth, args.displayHeight),
        mMaxTextureCacheSize(args.maxTextureCacheSize) {
    LOG_ALWAYS_FATAL_IF(!mNativeWindow);
}

RenderSurface::~RenderSurface() {
    ANativeWindow* const window = mNativeWindow.get();
    native_window_api_disconnect(window, NATIVE_WINDOW_API_EGL);
}

bool RenderSurface::isValid() const {
    return mSize.isValid();
}

void RenderSurface::initialize() {
    ANativeWindow* const window = mNativeWindow.get();

    int status = native_window_api_connect(window, NATIVE_WINDOW_API_EGL);
    ALOGE_IF(status != NO_ERROR, "Unable to connect BQ producer: %d", status);
    status = native_window_set_buffers_format(window, HAL_PIXEL_FORMAT_RGBA_8888);
    ALOGE_IF(status != NO_ERROR, "Unable to set BQ format to RGBA888: %d", status);
    status = native_window_set_usage(window, DEFAULT_USAGE);
    ALOGE_IF(status != NO_ERROR, "Unable to set BQ usage bits for GPU rendering: %d", status);
}

const ui::Size& RenderSurface::getSize() const {
    return mSize;
}

const sp<Fence>& RenderSurface::getClientTargetAcquireFence() const {
    return mDisplaySurface->getClientTargetAcquireFence();
}

void RenderSurface::setDisplaySize(const ui::Size& size) {
    mDisplaySurface->resizeBuffers(size);
    mSize = size;
}

void RenderSurface::setBufferDataspace(ui::Dataspace dataspace) {
    native_window_set_buffers_data_space(mNativeWindow.get(),
                                         static_cast<android_dataspace>(dataspace));
}

void RenderSurface::setBufferPixelFormat(ui::PixelFormat pixelFormat) {
    native_window_set_buffers_format(mNativeWindow.get(), static_cast<int32_t>(pixelFormat));
}

void RenderSurface::setProtected(bool useProtected) {
    uint64_t usageFlags = DEFAULT_USAGE;
    if (useProtected) {
        usageFlags |= GRALLOC_USAGE_PROTECTED;
    }
    const int status = native_window_set_usage(mNativeWindow.get(), usageFlags);
    ALOGE_IF(status != NO_ERROR, "Unable to set BQ usage bits for protected content: %d", status);
    if (status == NO_ERROR) {
        mProtected = useProtected;
    }
}

status_t RenderSurface::beginFrame(bool mustRecompose) {
    return mDisplaySurface->beginFrame(mustRecompose);
}

void RenderSurface::prepareFrame(bool usesClientComposition, bool usesDeviceComposition) {
    DisplaySurface::CompositionType compositionType;
    if (usesClientComposition && usesDeviceComposition) {
        compositionType = DisplaySurface::COMPOSITION_MIXED;
    } else if (usesClientComposition) {
        compositionType = DisplaySurface::COMPOSITION_GPU;
    } else if (usesDeviceComposition) {
        compositionType = DisplaySurface::COMPOSITION_HWC;
    } else {
        // Nothing to do -- when turning the screen off we get a frame like
        // this. Call it a HWC frame since we won't be doing any GPU work but
        // will do a prepare/set cycle.
        compositionType = DisplaySurface::COMPOSITION_HWC;
    }

    if (status_t result = mDisplaySurface->prepareFrame(compositionType); result != NO_ERROR) {
        ALOGE("updateCompositionType failed for %s: %d (%s)", mDisplay.getName().c_str(), result,
              strerror(-result));
    }
}

std::shared_ptr<renderengine::ExternalTexture> RenderSurface::dequeueBuffer(
        base::unique_fd* bufferFence) {
    ATRACE_CALL();
    int fd = -1;
    ANativeWindowBuffer* buffer = nullptr;

    status_t result = mNativeWindow->dequeueBuffer(mNativeWindow.get(), &buffer, &fd);

    if (result != NO_ERROR) {
        ALOGE("ANativeWindow::dequeueBuffer failed for display [%s] with error: %d",
              mDisplay.getName().c_str(), result);
        // Return fast here as we can't do much more - any rendering we do
        // now will just be wrong.
        return mTexture;
    }

    ALOGW_IF(mTexture != nullptr, "Clobbering a non-null pointer to a buffer [%p].",
             mTexture->getBuffer()->getNativeBuffer()->handle);

    sp<GraphicBuffer> newBuffer = GraphicBuffer::from(buffer);

    std::shared_ptr<renderengine::ExternalTexture> texture;

    for (auto it = mTextureCache.begin(); it != mTextureCache.end(); it++) {
        const auto& cachedTexture = *it;
        if (cachedTexture->getBuffer()->getId() == newBuffer->getId()) {
            texture = cachedTexture;
            mTextureCache.erase(it);
            break;
        }
    }

    if (texture) {
        mTexture = texture;
    } else {
        mTexture = std::make_shared<
                renderengine::ExternalTexture>(GraphicBuffer::from(buffer),
                                               mCompositionEngine.getRenderEngine(),
                                               renderengine::ExternalTexture::Usage::WRITEABLE);
    }
    mTextureCache.push_back(mTexture);
    if (mTextureCache.size() > mMaxTextureCacheSize) {
        mTextureCache.erase(mTextureCache.begin());
    }

    *bufferFence = base::unique_fd(fd);

    return mTexture;
}

void RenderSurface::queueBuffer(base::unique_fd readyFence) {
    auto& state = mDisplay.getState();

    if (state.usesClientComposition || state.flipClientTarget) {
        // hasFlipClientTargetRequest could return true even if we haven't
        // dequeued a buffer before. Try dequeueing one if we don't have a
        // buffer ready.
        if (mTexture == nullptr) {
            ALOGI("Attempting to queue a client composited buffer without one "
                  "previously dequeued for display [%s]. Attempting to dequeue "
                  "a scratch buffer now",
                  mDisplay.getName().c_str());
            // We shouldn't deadlock here, since mTexture == nullptr only
            // after a successful call to queueBuffer, or if dequeueBuffer has
            // never been called.
            base::unique_fd unused;
            dequeueBuffer(&unused);
        }

        if (mTexture == nullptr) {
            ALOGE("No buffer is ready for display [%s]", mDisplay.getName().c_str());
        } else {
            status_t result = mNativeWindow->queueBuffer(mNativeWindow.get(),
                                                         mTexture->getBuffer()->getNativeBuffer(),
                                                         dup(readyFence));
            if (result != NO_ERROR) {
                ALOGE("Error when queueing buffer for display [%s]: %d", mDisplay.getName().c_str(),
                      result);
                // We risk blocking on dequeueBuffer if the primary display failed
                // to queue up its buffer, so crash here.
                if (!mDisplay.isVirtual()) {
                    LOG_ALWAYS_FATAL("ANativeWindow::queueBuffer failed with error: %d", result);
                } else {
                    mNativeWindow->cancelBuffer(mNativeWindow.get(),
                                                mTexture->getBuffer()->getNativeBuffer(),
                                                dup(readyFence));
                }
            }

            mTexture = nullptr;
        }
    }

    status_t result = mDisplaySurface->advanceFrame();
    if (result != NO_ERROR) {
        ALOGE("[%s] failed pushing new frame to HWC: %d", mDisplay.getName().c_str(), result);
    }
}

void RenderSurface::onPresentDisplayCompleted() {
    mDisplaySurface->onFrameCommitted();
}

void RenderSurface::flip() {
    mPageFlipCount++;
}

void RenderSurface::dump(std::string& out) const {
    using android::base::StringAppendF;

    out.append("   Composition RenderSurface State:");

    out.append("\n   ");

    dumpVal(out, "size", mSize);
    StringAppendF(&out, "ANativeWindow=%p (format %d) ", mNativeWindow.get(),
                  ANativeWindow_getFormat(mNativeWindow.get()));
    dumpVal(out, "flips", mPageFlipCount);
    out.append("\n");

    String8 surfaceDump;
    mDisplaySurface->dumpAsString(surfaceDump);
    out.append(surfaceDump);
}

std::uint32_t RenderSurface::getPageFlipCount() const {
    return mPageFlipCount;
}

void RenderSurface::setPageFlipCountForTest(std::uint32_t count) {
    mPageFlipCount = count;
}

void RenderSurface::setSizeForTest(const ui::Size& size) {
    mSize = size;
}

std::shared_ptr<renderengine::ExternalTexture>& RenderSurface::mutableTextureForTest() {
    return mTexture;
}

} // namespace impl
} // namespace android::compositionengine
