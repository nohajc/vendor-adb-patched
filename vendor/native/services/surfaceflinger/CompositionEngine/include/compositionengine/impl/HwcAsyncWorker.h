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

#include <android-base/thread_annotations.h>
#include <future>
#include <optional>
#include <thread>

#include "DisplayHardware/HWComposer.h"

namespace android::compositionengine::impl {

// HWC Validate call may take multiple milliseconds to complete and can account for
// a signification amount of time in the display hotpath. This helper class allows
// us to run the hwc validate function on a real time thread if we can predict what
// the composition strategy will be and if composition includes client composition.
// While the hwc validate runs, client composition is kicked off with the prediction.
// When the worker returns with a value, the composition continues if the prediction
// was successful otherwise the client composition is re-executed.
//
// Note: This does not alter the sequence between HWC and surfaceflinger.
class HwcAsyncWorker final {
public:
    HwcAsyncWorker();
    ~HwcAsyncWorker();
    // Runs the provided function which calls hwc validate and returns the requested
    // device changes as a future.
    std::future<bool> send(std::function<bool()>);

private:
    std::mutex mMutex;
    std::condition_variable mCv GUARDED_BY(mMutex);
    bool mDone GUARDED_BY(mMutex) = false;
    bool mTaskRequested GUARDED_BY(mMutex) = false;
    std::packaged_task<bool()> mTask GUARDED_BY(mMutex);
    std::thread mThread;
    void run();
};

} // namespace android::compositionengine::impl
