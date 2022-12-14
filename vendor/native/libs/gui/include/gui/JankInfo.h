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

namespace android {

// Jank information tracked by SurfaceFlinger(SF) for perfetto tracing and telemetry.
enum JankType {
    // No Jank
    None = 0x0,
    // Jank that occurs in the layers below SurfaceFlinger
    DisplayHAL = 0x1,
    // SF took too long on the CPU
    SurfaceFlingerCpuDeadlineMissed = 0x2,
    // SF took too long on the GPU
    SurfaceFlingerGpuDeadlineMissed = 0x4,
    // Either App or GPU took too long on the frame
    AppDeadlineMissed = 0x8,
    // Vsync predictions have drifted beyond the threshold from the actual HWVsync
    PredictionError = 0x10,
    // Janks caused due to the time SF was scheduled to work on the frame
    // Example: SF woke up too early and latched a buffer resulting in an early present
    SurfaceFlingerScheduling = 0x20,
    // A buffer is said to be stuffed if it was expected to be presented on a vsync but was
    // presented later because the previous buffer was presented in its expected vsync. This
    // usually happens if there is an unexpectedly long frame causing the rest of the buffers
    // to enter a stuffed state.
    BufferStuffing = 0x40,
    // Jank due to unknown reasons.
    Unknown = 0x80,
    // SF is said to be stuffed if the previous frame ran longer than expected resulting in the case
    // where the previous frame was presented in the current frame's expected vsync. This pushes the
    // current frame to the next vsync. The behavior is similar to BufferStuffing.
    SurfaceFlingerStuffing = 0x100,
};

} // namespace android
