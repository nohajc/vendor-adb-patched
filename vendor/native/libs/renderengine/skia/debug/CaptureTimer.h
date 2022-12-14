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

#include <chrono>
#include <functional>

namespace android {
namespace renderengine {
namespace skia {

/**
 * Simple timer that times out after a given delay and executes a void
 * callback function.
 */
class CaptureTimer {
    bool clear = false;

public:
    using TimeoutCallback = std::function<void()>;
    // Start the timeout.
    void setTimeout(TimeoutCallback function, std::chrono::milliseconds delay);
    // Stop and clean up.
    void stop();
};

} // namespace skia
} // namespace renderengine
} // namespace android