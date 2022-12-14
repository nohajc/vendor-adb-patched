/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef _UI_INPUT_INPUTDISPATCHER_MONITOR_H
#define _UI_INPUT_INPUTDISPATCHER_MONITOR_H

#include <input/InputTransport.h>

namespace android::inputdispatcher {

struct Monitor {
    std::shared_ptr<InputChannel> inputChannel; // never null

    int32_t pid;

    explicit Monitor(const std::shared_ptr<InputChannel>& inputChannel, int32_t pid);
};

// For tracking the offsets we need to apply when adding gesture monitor targets.
struct TouchedMonitor {
    Monitor monitor;
    float xOffset = 0.f;
    float yOffset = 0.f;

    explicit TouchedMonitor(const Monitor& monitor, float xOffset, float yOffset);
};

} // namespace android::inputdispatcher

#endif // _UI_INPUT_INPUTDISPATCHER_MONITOR_H
