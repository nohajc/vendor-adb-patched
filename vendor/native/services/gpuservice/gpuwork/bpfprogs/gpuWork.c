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

#include "include/gpuwork/gpuWork.h"

#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>

#ifdef MOCK_BPF
#include <test/mock_bpf_helpers.h>
#else
#include <bpf_helpers.h>
#endif

#define S_IN_NS (1000000000)
#define SMALL_TIME_GAP_LIMIT_NS (S_IN_NS)

// A map from GpuIdUid (GPU ID and application UID) to |UidTrackingInfo|.
DEFINE_BPF_MAP_GRW(gpu_work_map, HASH, GpuIdUid, UidTrackingInfo, kMaxTrackedGpuIdUids,
                   AID_GRAPHICS);

// A map containing a single entry of |GlobalData|.
DEFINE_BPF_MAP_GRW(gpu_work_global_data, ARRAY, uint32_t, GlobalData, 1, AID_GRAPHICS);

// Defines the structure of the kernel tracepoint:
//
//  /sys/kernel/tracing/events/power/gpu_work_period/
//
// Drivers must define an appropriate gpu_work_period kernel tracepoint (for
// example, using the DECLARE_EVENT_CLASS and DEFINE_EVENT macros) such that the
// arguments/fields match the fields of |GpuWorkPeriodEvent|, excluding the
// initial "common" field. Drivers must invoke the tracepoint (also referred to
// as emitting the event) as described below. Note that the description below
// assumes a single physical GPU and its driver; for devices with multiple GPUs,
// each GPU and its driver should emit events independently, using a different
// value for |gpu_id| per GPU.
//
// |GpuWorkPeriodEvent| defines a non-overlapping, non-zero period of time from
// |start_time_ns| (inclusive) until |end_time_ns| (exclusive) for a given
// |uid|, and includes details of how much work the GPU was performing for |uid|
// during the period. When GPU work for a given |uid| runs on the GPU, the
// driver must track one or more periods that cover the time where the work was
// running, and emit events soon after. The driver should try to emit the event
// for a period at most 1 second after |end_time_ns|, and must emit the event at
// most 2 seconds after |end_time_ns|. A period's duration (|end_time_ns| -
// |start_time_ns|) must be at most 1 second. Periods for different |uids| can
// overlap, but periods for the same |uid| must not overlap. The driver must
// emit events for the same |uid| in strictly increasing order of
// |start_time_ns|, such that it is guaranteed that the tracepoint call for a
// period for |uid| has returned before the tracepoint call for the next period
// for |uid| is made. Note that synchronization may be necessary if the driver
// emits events for the same |uid| from different threads/contexts. Note that
// |end_time_ns| for a period for a |uid| may equal the |start_time_ns| of the
// next period for |uid|. The driver should try to avoid emitting a large number
// of events in a short time period (e.g. 1000 events per second) for a given
// |uid|.
//
// The |total_active_duration_ns| must be set to the approximate total amount of
// time the GPU spent running work for |uid| within the period, without
// "double-counting" parallel GPU work on the same GPU for the same |uid|. Note
// that even if the parallel GPU work was submitted from several different
// processes (i.e. different PIDs) with the same UID, this overlapping work must
// not be double-counted, as it still came from a single |uid|. "GPU work"
// should correspond to the "GPU slices" shown in the AGI (Android GPU
// Inspector) tool, and so should include work such as fragment and non-fragment
// work/shaders running on the shader cores of the GPU. For example, given the
// following for a single |uid|:
//  - A period has:
//    - |start_time_ns|: 100,000,000 ns
//    - |end_time_ns|:   800,000,000 ns
//  - Some GPU vertex work (A):
//    - started at:      200,000,000 ns
//    - ended at:        400,000,000 ns
//  - Some GPU fragment work (B):
//    - started at:      300,000,000 ns
//    - ended at:        500,000,000 ns
//  - Some GPU fragment work (C):
//    - started at:      300,000,000 ns
//    - ended at:        400,000,000 ns
//  - Some GPU fragment work (D):
//    - started at:      600,000,000 ns
//    - ended at:        700,000,000 ns
//
// The |total_active_duration_ns| would be 400,000,000 ns, because GPU work for
// |uid| was executing:
//  - from 200,000,000 ns to 500,000,000 ns, giving a duration of 300,000,000 ns
//    (encompassing GPU work A, B, and C)
//  - from 600,000,000 ns to 700,000,000 ns, giving a duration of 100,000,000 ns
//    (GPU work D)
//
// Thus, the |total_active_duration_ns| is the sum of these two
// (non-overlapping) durations. Drivers may not have efficient access to the
// exact start and end times of all GPU work, as shown above, but drivers should
// try to approximate/aggregate the value of |total_active_duration_ns| as
// accurately as possible within the limitations of the hardware, without
// double-counting parallel GPU work for the same |uid|. The
// |total_active_duration_ns| value must be less than or equal to the period
// duration (|end_time_ns| - |start_time_ns|); if the aggregation approach might
// violate this requirement then the driver must clamp
// |total_active_duration_ns| to be at most the period duration.
//
// Protected mode: protected GPU work must not be reported. Periods must be
// emitted, and the |total_active_duration_ns| value set, as if the protected
// GPU work did not occur.
//
// Note that the above description allows for a certain amount of flexibility in
// how the driver tracks periods and emits the events. We list a few examples of
// how drivers might implement the above:
//
// - 1: The driver could track periods for all |uid| values at fixed intervals
//   of 1 second. Thus, every period duration would be exactly 1 second, and
//   periods from different |uid|s that overlap would have the same
//   |start_time_ns| and |end_time_ns| values.
//
// - 2: The driver could track periods with many different durations (up to 1
//   second), as needed in order to cover the GPU work for each |uid|.
//   Overlapping periods for different |uid|s may have very different durations,
//   as well as different |start_time_ns| and |end_time_ns| values.
//
// - 3: The driver could track fine-grained periods with different durations
//   that precisely cover the time where GPU work is running for each |uid|.
//   Thus, |total_active_duration_ns| would always equal the period duration.
//   For example, if a game was running at 60 frames per second, the driver
//   would most likely emit _at least_ 60 events per second (probably more, as
//   there would likely be multiple "chunks" of GPU work per frame, with gaps
//   between each chunk). However, the driver may sometimes need to resort to
//   more coarse-grained periods to avoid emitting thousands of events per
//   second for a |uid|, where |total_active_duration_ns| would then be less
//   than the period duration.
typedef struct {
    // Actual fields start at offset 8.
    uint64_t common;

    // A value that uniquely identifies the GPU within the system.
    uint32_t gpu_id;

    // The UID of the application (i.e. persistent, unique ID of the Android
    // app) that submitted work to the GPU.
    uint32_t uid;

    // The start time of the period in nanoseconds. The clock must be
    // CLOCK_MONOTONIC_RAW, as returned by the ktime_get_raw_ns(void) function.
    uint64_t start_time_ns;

    // The end time of the period in nanoseconds. The clock must be
    // CLOCK_MONOTONIC_RAW, as returned by the ktime_get_raw_ns(void) function.
    uint64_t end_time_ns;

    // The amount of time the GPU was running GPU work for |uid| during the
    // period, in nanoseconds, without double-counting parallel GPU work for the
    // same |uid|. For example, this might include the amount of time the GPU
    // spent performing shader work (vertex work, fragment work, etc.) for
    // |uid|.
    uint64_t total_active_duration_ns;

} GpuWorkPeriodEvent;

_Static_assert(offsetof(GpuWorkPeriodEvent, gpu_id) == 8 &&
                       offsetof(GpuWorkPeriodEvent, uid) == 12 &&
                       offsetof(GpuWorkPeriodEvent, start_time_ns) == 16 &&
                       offsetof(GpuWorkPeriodEvent, end_time_ns) == 24 &&
                       offsetof(GpuWorkPeriodEvent, total_active_duration_ns) == 32,
               "Field offsets of struct GpuWorkPeriodEvent must not be changed because they "
               "must match the tracepoint field offsets found via adb shell cat "
               "/sys/kernel/tracing/events/power/gpu_work_period/format");

DEFINE_BPF_PROG("tracepoint/power/gpu_work_period", AID_ROOT, AID_GRAPHICS, tp_gpu_work_period)
(GpuWorkPeriodEvent* const period) {
    // Note: In eBPF programs, |__sync_fetch_and_add| is translated to an atomic
    // add.

    // Return 1 to avoid blocking simpleperf from receiving events.
    const int ALLOW = 1;

    GpuIdUid gpu_id_and_uid;
    __builtin_memset(&gpu_id_and_uid, 0, sizeof(gpu_id_and_uid));
    gpu_id_and_uid.gpu_id = period->gpu_id;
    gpu_id_and_uid.uid = period->uid;

    // Get |UidTrackingInfo|.
    UidTrackingInfo* uid_tracking_info = bpf_gpu_work_map_lookup_elem(&gpu_id_and_uid);
    if (!uid_tracking_info) {
        // There was no existing entry, so we add a new one.
        UidTrackingInfo initial_info;
        __builtin_memset(&initial_info, 0, sizeof(initial_info));
        if (0 == bpf_gpu_work_map_update_elem(&gpu_id_and_uid, &initial_info, BPF_NOEXIST)) {
            // We added an entry to the map, so we increment our entry counter in
            // |GlobalData|.
            const uint32_t zero = 0;
            // Get the |GlobalData|.
            GlobalData* global_data = bpf_gpu_work_global_data_lookup_elem(&zero);
            // Getting the global data never fails because it is an |ARRAY| map,
            // but we need to keep the verifier happy.
            if (global_data) {
                __sync_fetch_and_add(&global_data->num_map_entries, 1);
            }
        }
        uid_tracking_info = bpf_gpu_work_map_lookup_elem(&gpu_id_and_uid);
        if (!uid_tracking_info) {
            // This should never happen, unless entries are getting deleted at
            // this moment. If so, we just give up.
            return ALLOW;
        }
    }

    if (
            // The period duration must be non-zero.
            period->start_time_ns >= period->end_time_ns ||
            // The period duration must be at most 1 second.
            (period->end_time_ns - period->start_time_ns) > S_IN_NS) {
        __sync_fetch_and_add(&uid_tracking_info->error_count, 1);
        return ALLOW;
    }

    // If |total_active_duration_ns| is 0 then no GPU work occurred and there is
    // nothing to do.
    if (period->total_active_duration_ns == 0) {
        return ALLOW;
    }

    // Update |uid_tracking_info->total_active_duration_ns|.
    __sync_fetch_and_add(&uid_tracking_info->total_active_duration_ns,
                         period->total_active_duration_ns);

    // |small_gap_time_ns| is the time gap between the current and previous
    // active period, which could be 0. If the gap is more than
    // |SMALL_TIME_GAP_LIMIT_NS| then |small_gap_time_ns| will be set to 0
    // because we want to estimate the small gaps between "continuous" GPU work.
    uint64_t small_gap_time_ns = 0;
    if (uid_tracking_info->previous_active_end_time_ns > period->start_time_ns) {
        // The current period appears to have occurred before the previous
        // active period, which must not happen because per-UID periods must not
        // overlap and must be emitted in strictly increasing order of
        // |start_time_ns|.
        __sync_fetch_and_add(&uid_tracking_info->error_count, 1);
    } else {
        // The current period appears to have been emitted after the previous
        // active period, as expected, so we can calculate the gap between the
        // current and previous active period.
        small_gap_time_ns = period->start_time_ns - uid_tracking_info->previous_active_end_time_ns;

        // Update |previous_active_end_time_ns|.
        uid_tracking_info->previous_active_end_time_ns = period->end_time_ns;

        // We want to estimate the small gaps between "continuous" GPU work; if
        // the gap is more than |SMALL_TIME_GAP_LIMIT_NS| then we don't consider
        // this "continuous" GPU work.
        if (small_gap_time_ns > SMALL_TIME_GAP_LIMIT_NS) {
            small_gap_time_ns = 0;
        }
    }

    uint64_t period_total_inactive_time_ns = 0;
    const uint64_t period_duration_ns = period->end_time_ns - period->start_time_ns;
    // |period->total_active_duration_ns| is the active time within the period duration, so
    // it must not be larger than |period_duration_ns|.
    if (period->total_active_duration_ns > period_duration_ns) {
        __sync_fetch_and_add(&uid_tracking_info->error_count, 1);
    } else {
        period_total_inactive_time_ns = period_duration_ns - period->total_active_duration_ns;
    }

    // Update |uid_tracking_info->total_inactive_duration_ns| by adding the
    // inactive time from this period, plus the small gap between the current
    // and previous active period. Either or both of these values could be 0.
    if (small_gap_time_ns > 0 || period_total_inactive_time_ns > 0) {
        __sync_fetch_and_add(&uid_tracking_info->total_inactive_duration_ns,
                             small_gap_time_ns + period_total_inactive_time_ns);
    }

    return ALLOW;
}

LICENSE("Apache 2.0");
