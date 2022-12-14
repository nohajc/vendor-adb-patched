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

#include <SkDocument.h>
#include <SkNWayCanvas.h>
#include <SkPictureRecorder.h>
#include <SkSurface.h>

#include <chrono>
#include <mutex>

#include "CaptureTimer.h"
#include "tools/SkSharingProc.h"

namespace android {
namespace renderengine {
namespace skia {

using namespace std::chrono_literals;

/**
 * Class that captures frames that are sent to Skia in Render Engine. It sets up
 * a multi frame capture and writes it into a file on the device. The capture is
 * done based on a timer.
 */
class SkiaCapture {
    using Interval = std::chrono::milliseconds;

public:
    SkiaCapture() {}
    virtual ~SkiaCapture();
    // Called every frame. Normally returns early with screen canvas.
    // But when capture is enabled, returns an nwaycanvas where commands are also recorded.
    SkCanvas* tryCapture(SkSurface* surface);
    // Called at the end of every frame.
    void endCapture();
    // Returns whether the capture is running.
    bool isCaptureRunning() { return mCaptureRunning; }

    // Offscreen state member variables are private to SkiaCapture, but the allocation
    // and lifetime is managed by the caller. This enables nested offscreen
    // captures to occur.
    struct OffscreenState {
        std::unique_ptr<SkPictureRecorder> offscreenRecorder;
        std::unique_ptr<SkNWayCanvas> offscreenCanvas;
    };
    SkCanvas* tryOffscreenCapture(SkSurface* surface, OffscreenState* state);
    uint64_t endOffscreenCapture(OffscreenState* state);

private:
    // Performs the first-frame work of a multi frame SKP capture. Returns true if successful.
    bool setupMultiFrameCapture();

    // Closes the recording and serializes sequence to a file.
    void writeToFile();

    // Multi frame serialization stream and writer used when serializing more than one frame.
    std::unique_ptr<SkFILEWStream> mOpenMultiPicStream;
    sk_sp<SkDocument> mMultiPic;
    std::unique_ptr<SkSharingSerialContext> mSerialContext;
    std::unique_ptr<SkNWayCanvas> mNwayCanvas;

    SkCanvas* mCurrentPageCanvas = nullptr;

    // Capturing and interval control.
    bool mCaptureRunning = false;
    CaptureTimer mTimer;
    Interval mTimerInterval = 0ms;

    // Mutex to ensure that a frame in progress when the timer fires is allowed to run to
    // completion before we write the file to disk.
    std::mutex mMutex;

    std::string mCaptureFile;
};

} // namespace skia
} // namespace renderengine
} // namespace android
