/*
 * Copyright 2021 The Android Open Source Project
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

#include <stdint.h>

#include <binder/Parcel.h>

namespace android {

struct FrameTimelineInfo {
    // Needs to be in sync with android.graphics.FrameInfo.INVALID_VSYNC_ID in java
    static constexpr int64_t INVALID_VSYNC_ID = -1;

    // The vsync id that was used to start the transaction
    int64_t vsyncId = INVALID_VSYNC_ID;

    // The id of the input event that caused this buffer
    // Default is android::os::IInputConstants::INVALID_INPUT_EVENT_ID = 0
    // We copy the value of the input event ID instead of including the header, because libgui
    // header libraries containing FrameTimelineInfo must be available to vendors, but libinput is
    // not directly vendor available.
    int32_t inputEventId = 0;

    status_t write(Parcel& output) const;
    status_t read(const Parcel& input);

    void merge(const FrameTimelineInfo& other);
    void clear();
};

} // namespace android
