/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <log/log.h>
#include <unwindstack/AndroidUnwinder.h>

#include <memory>

class CallStack {
public:
    // Create a callstack with the current thread's stack trace.
    // Immediately dump it to logcat using the given logtag.
    static void log(const char* logtag) noexcept {
        unwindstack::AndroidLocalUnwinder unwinder;
        unwindstack::AndroidUnwinderData data;
        if (unwinder.Unwind(data)) {
            for (size_t i = 2, c = data.frames.size(); i < c; i++) {
                auto& frame = data.frames[i];
                // Trim the first two frames.
                frame.num -= 2;
                __android_log_print(ANDROID_LOG_DEBUG, logtag, "%s",
                                    unwinder.FormatFrame(frame).c_str());
            }
        }
    }
};
