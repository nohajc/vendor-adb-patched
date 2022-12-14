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

#include "SkiaCapture.h"

#undef LOG_TAG
#define LOG_TAG "RenderEngine"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <renderengine/RenderEngine.h>
#include <utils/Trace.h>

#include "CommonPool.h"
#include "src/utils/SkMultiPictureDocument.h"

namespace android {
namespace renderengine {
namespace skia {

// The root of the filename to write a recorded SKP to. In order for this file to
// be written to /data/user/, user must run 'adb shell setenforce 0' on the device.
static const std::string CAPTURED_FILENAME_BASE = "/data/user/re_skiacapture";

SkiaCapture::~SkiaCapture() {
    mTimer.stop();
}

SkCanvas* SkiaCapture::tryCapture(SkSurface* surface) NO_THREAD_SAFETY_ANALYSIS {
    ATRACE_CALL();

    // If we are not running yet, set up.
    if (CC_LIKELY(!mCaptureRunning)) {
        mTimerInterval = std::chrono::milliseconds(
                base::GetIntProperty(PROPERTY_DEBUG_RENDERENGINE_CAPTURE_SKIA_MS, 0));
        // Set up the multi-frame capture. If we fail to set it up, then just return canvas.
        // If interval is 0, return surface.
        if (CC_LIKELY(mTimerInterval == 0ms || !setupMultiFrameCapture())) {
            return surface->getCanvas();
        }
        // Start the new timer. When timer expires, write to file.
        mTimer.setTimeout(
                [this] {
                    const std::scoped_lock lock(mMutex);
                    LOG_ALWAYS_FATAL_IF(mCurrentPageCanvas != nullptr);
                    writeToFile();
                    // To avoid going in circles, set the flag to 0. This way the capture can be
                    // restarted just by setting the flag and without restarting the process.
                    base::SetProperty(PROPERTY_DEBUG_RENDERENGINE_CAPTURE_SKIA_MS, "0");
                },
                mTimerInterval);
    }

    mMutex.lock();

    // Create a canvas pointer, fill it.
    mCurrentPageCanvas = mMultiPic->beginPage(surface->width(), surface->height());

    // Setting up an nway canvas is common to any kind of capture.
    mNwayCanvas = std::make_unique<SkNWayCanvas>(surface->width(), surface->height());
    mNwayCanvas->addCanvas(surface->getCanvas());
    mNwayCanvas->addCanvas(mCurrentPageCanvas);

    return mNwayCanvas.get();
}

void SkiaCapture::endCapture() NO_THREAD_SAFETY_ANALYSIS {
    ATRACE_CALL();
    // Don't end anything if we are not running.
    if (CC_LIKELY(!mCaptureRunning)) {
        return;
    }
    // Reset the canvas pointer.
    mCurrentPageCanvas = nullptr;
    mNwayCanvas.reset();
    // End page.
    if (mMultiPic) {
        mMultiPic->endPage();
    }
    mMutex.unlock();
}

SkCanvas* SkiaCapture::tryOffscreenCapture(SkSurface* surface, OffscreenState* state) {
    ATRACE_CALL();
    // Don't start anything if we are not running.
    if (CC_LIKELY(!mCaptureRunning)) {
        return surface->getCanvas();
    }

    // Create a canvas pointer, fill it.
    state->offscreenRecorder = std::make_unique<SkPictureRecorder>();
    SkCanvas* pictureCanvas =
            state->offscreenRecorder->beginRecording(surface->width(), surface->height());

    // Setting up an nway canvas is common to any kind of capture.
    state->offscreenCanvas = std::make_unique<SkNWayCanvas>(surface->width(), surface->height());
    state->offscreenCanvas->addCanvas(surface->getCanvas());
    state->offscreenCanvas->addCanvas(pictureCanvas);

    return state->offscreenCanvas.get();
}

uint64_t SkiaCapture::endOffscreenCapture(OffscreenState* state) {
    ATRACE_CALL();
    // Don't end anything if we are not running.
    if (CC_LIKELY(!mCaptureRunning)) {
        return 0;
    }

    // compute the uniqueID for this capture
    static std::atomic<uint64_t> nextID{1};
    const uint64_t uniqueID = nextID.fetch_add(1, std::memory_order_relaxed);

    // Reset the canvas pointer as we are no longer drawing into it
    state->offscreenCanvas.reset();

    // Record the offscreen as a picture in the currently active page.
    SkRect bounds =
            SkRect::Make(state->offscreenRecorder->getRecordingCanvas()->imageInfo().dimensions());
    mCurrentPageCanvas
            ->drawAnnotation(bounds,
                             String8::format("OffscreenLayerDraw|%" PRId64, uniqueID).c_str(),
                             nullptr);
    mCurrentPageCanvas->drawPicture(state->offscreenRecorder->finishRecordingAsPicture());

    // Reset the offscreen picture recorder
    state->offscreenRecorder.reset();

    return uniqueID;
}

void SkiaCapture::writeToFile() {
    ATRACE_CALL();
    // Pass mMultiPic and mOpenMultiPicStream to a background thread, which will
    // handle the heavyweight serialization work and destroy them.
    // mOpenMultiPicStream is released to a bare pointer because keeping it in
    // a smart pointer makes the lambda non-copyable. The lambda is only called
    // once, so this is safe.
    SkFILEWStream* stream = mOpenMultiPicStream.release();
    CommonPool::post([doc = std::move(mMultiPic), stream, name = std::move(mCaptureFile)] {
        ALOGD("Finalizing multi frame SKP");
        doc->close();
        delete stream;
        ALOGD("Multi frame SKP saved to %s.", name.c_str());
        base::SetProperty(PROPERTY_DEBUG_RENDERENGINE_CAPTURE_FILENAME, name);
    });
    mCaptureRunning = false;
}

bool SkiaCapture::setupMultiFrameCapture() {
    ATRACE_CALL();
    ALOGD("Set up multi-frame capture, ms = %llu", mTimerInterval.count());
    base::SetProperty(PROPERTY_DEBUG_RENDERENGINE_CAPTURE_FILENAME, "");
    const std::scoped_lock lock(mMutex);

    // Attach a timestamp to the file.
    mCaptureFile.clear();
    base::StringAppendF(&mCaptureFile, "%s_%lld.mskp", CAPTURED_FILENAME_BASE.c_str(),
                        std::chrono::steady_clock::now().time_since_epoch().count());
    auto stream = std::make_unique<SkFILEWStream>(mCaptureFile.c_str());
    // We own this stream and need to hold it until close() finishes.
    if (stream->isValid()) {
        mOpenMultiPicStream = std::move(stream);
        mSerialContext.reset(new SkSharingSerialContext());
        SkSerialProcs procs;
        procs.fImageProc = SkSharingSerialContext::serializeImage;
        procs.fImageCtx = mSerialContext.get();
        procs.fTypefaceProc = [](SkTypeface* tf, void* ctx) {
            return tf->serialize(SkTypeface::SerializeBehavior::kDoIncludeData);
        };
        // SkDocuments don't take ownership of the streams they write.
        // we need to keep it until after mMultiPic.close()
        // procs is passed as a pointer, but just as a method of having an optional default.
        // procs doesn't need to outlive this Make call
        // The last argument is a callback for the endPage behavior.
        // See SkSharingProc.h for more explanation of this callback.
        mMultiPic = SkMakeMultiPictureDocument(
                mOpenMultiPicStream.get(), &procs,
                [sharingCtx = mSerialContext.get()](const SkPicture* pic) {
                    SkSharingSerialContext::collectNonTextureImagesFromPicture(pic, sharingCtx);
                });
        mCaptureRunning = true;
        return true;
    } else {
        ALOGE("Could not open \"%s\" for writing.", mCaptureFile.c_str());
        return false;
    }
}

} // namespace skia
} // namespace renderengine
} // namespace android
