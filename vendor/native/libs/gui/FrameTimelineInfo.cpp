/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "FrameTimelineInfo"

#include <inttypes.h>

#include <android/os/IInputConstants.h>
#include <gui/FrameTimelineInfo.h>
#include <gui/LayerState.h>
#include <private/gui/ParcelUtils.h>
#include <utils/Errors.h>

#include <cmath>

using android::os::IInputConstants;

namespace android {

status_t FrameTimelineInfo::write(Parcel& output) const {
    SAFE_PARCEL(output.writeInt64, vsyncId);
    SAFE_PARCEL(output.writeInt32, inputEventId);
    return NO_ERROR;
}

status_t FrameTimelineInfo::read(const Parcel& input) {
    SAFE_PARCEL(input.readInt64, &vsyncId);
    SAFE_PARCEL(input.readInt32, &inputEventId);
    return NO_ERROR;
}

void FrameTimelineInfo::merge(const FrameTimelineInfo& other) {
    // When merging vsync Ids we take the oldest valid one
    if (vsyncId != INVALID_VSYNC_ID && other.vsyncId != INVALID_VSYNC_ID) {
        if (other.vsyncId > vsyncId) {
            vsyncId = other.vsyncId;
            inputEventId = other.inputEventId;
        }
    } else if (vsyncId == INVALID_VSYNC_ID) {
        vsyncId = other.vsyncId;
        inputEventId = other.inputEventId;
    }
}

void FrameTimelineInfo::clear() {
    vsyncId = INVALID_VSYNC_ID;
    inputEventId = IInputConstants::INVALID_INPUT_EVENT_ID;
}

}; // namespace android
