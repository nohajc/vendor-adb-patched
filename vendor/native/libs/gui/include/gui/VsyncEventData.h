/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <gui/FrameTimelineInfo.h>

#include <array>

namespace android::gui {
// Plain Old Data (POD) vsync data structure. For example, it can be easily used in the
// DisplayEventReceiver::Event union.
struct VsyncEventData {
    // Max amount of frame timelines is arbitrarily set to be reasonable.
    static constexpr int64_t kFrameTimelinesLength = 7;

    // The current frame interval in ns when this frame was scheduled.
    int64_t frameInterval;

    // Index into the frameTimelines that represents the platform's preferred frame timeline.
    uint32_t preferredFrameTimelineIndex;

    struct alignas(8) FrameTimeline {
        // The Vsync Id corresponsing to this vsync event. This will be used to
        // populate ISurfaceComposer::setFrameTimelineVsync and
        // SurfaceComposerClient::setFrameTimelineVsync
        int64_t vsyncId;

        // The deadline in CLOCK_MONOTONIC in nanos that the app needs to complete its
        // frame by (both on the CPU and the GPU).
        int64_t deadlineTimestamp;

        // The anticipated Vsync presentation time in nanos.
        int64_t expectedPresentationTime;
    } frameTimelines[kFrameTimelinesLength]; // Sorted possible frame timelines.

    // Gets the preferred frame timeline's vsync ID.
    int64_t preferredVsyncId() const;

    // Gets the preferred frame timeline's deadline timestamp.
    int64_t preferredDeadlineTimestamp() const;

    // Gets the preferred frame timeline's expected vsync timestamp.
    int64_t preferredExpectedPresentationTime() const;
};

struct ParcelableVsyncEventData : public Parcelable {
    VsyncEventData vsync;

    status_t readFromParcel(const Parcel*) override;
    status_t writeToParcel(Parcel*) const override;
};
} // namespace android::gui
