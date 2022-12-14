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

#include <stdint.h>

#ifdef __cplusplus
#include <type_traits>

namespace android {
namespace gpuwork {
#endif

typedef struct  {
    uint32_t gpu_id;
    uint32_t uid;
} GpuIdUid;

typedef struct {
    // The end time of the previous period where the GPU was active for the UID,
    // in nanoseconds.
    uint64_t previous_active_end_time_ns;

    // The total amount of time the GPU has spent running work for the UID, in
    // nanoseconds.
    uint64_t total_active_duration_ns;

    // The total amount of time of the "gaps" between "continuous" GPU work for
    // the UID, in nanoseconds. This is estimated by ignoring large gaps between
    // GPU work for this UID.
    uint64_t total_inactive_duration_ns;

    // The number of errors detected due to |GpuWorkPeriodEvent| events for the
    // UID violating the specification in some way. E.g. periods with a zero or
    // negative duration.
    uint32_t error_count;

    // Needed to make 32-bit arch struct size match 64-bit BPF arch struct size.
    uint32_t padding0;
} UidTrackingInfo;

typedef struct {
    // We cannot query the number of entries in BPF map |gpu_work_map|. We track
    // the number of entries (approximately) using a counter so we can check if
    // the map is nearly full.
    uint64_t num_map_entries;
} GlobalData;

// The maximum number of tracked GPU ID and UID pairs (|GpuIdUid|).
static const uint32_t kMaxTrackedGpuIdUids = 512;

#ifdef __cplusplus
} // namespace gpuwork
} // namespace android
#endif
