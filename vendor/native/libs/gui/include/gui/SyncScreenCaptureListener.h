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

#include <android/gui/BnScreenCaptureListener.h>
#include <gui/SurfaceComposerClient.h>
#include <future>

namespace android {

using gui::ScreenCaptureResults;

struct SyncScreenCaptureListener : gui::BnScreenCaptureListener {
public:
    binder::Status onScreenCaptureCompleted(const ScreenCaptureResults& captureResults) override {
        resultsPromise.set_value(captureResults);
        return binder::Status::ok();
    }

    ScreenCaptureResults waitForResults() {
        std::future<ScreenCaptureResults> resultsFuture = resultsPromise.get_future();
        const auto screenCaptureResults = resultsFuture.get();
        screenCaptureResults.fence->waitForever("");
        return screenCaptureResults;
    }

private:
    std::promise<ScreenCaptureResults> resultsPromise;
};

} // namespace android