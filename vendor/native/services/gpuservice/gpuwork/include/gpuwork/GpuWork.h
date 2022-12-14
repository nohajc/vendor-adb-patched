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

#include <bpf/BpfMap.h>
#include <stats_pull_atom_callback.h>
#include <utils/Mutex.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <thread>

#include "gpuwork/gpuWork.h"

namespace android {
namespace gpuwork {

class GpuWork {
public:
    using Uid = uint32_t;

    GpuWork() = default;
    ~GpuWork();

    void initialize();

    // Dumps the GPU work information.
    void dump(const Vector<String16>& args, std::string* result);

private:
    // Attaches tracepoint |tracepoint_group|/|tracepoint_name| to BPF program at path
    // |program_path|. The tracepoint is also enabled.
    static bool attachTracepoint(const char* program_path, const char* tracepoint_group,
                                 const char* tracepoint_name);

    // Native atom puller callback registered in statsd.
    static AStatsManager_PullAtomCallbackReturn pullAtomCallback(int32_t atomTag,
                                                                 AStatsEventList* data,
                                                                 void* cookie);

    AStatsManager_PullAtomCallbackReturn pullWorkAtoms(AStatsEventList* data);

    // Periodically calls |clearMapIfNeeded| to clear the |mGpuWorkMap| map, if
    // needed.
    //
    // Thread safety analysis is skipped because we need to use
    // |std::unique_lock|, which is not currently supported by thread safety
    // analysis.
    void periodicallyClearMap() NO_THREAD_SAFETY_ANALYSIS;

    // Checks whether the |mGpuWorkMap| map is nearly full and, if so, clears
    // it.
    void clearMapIfNeeded() REQUIRES(mMutex);

    // Clears the |mGpuWorkMap| map.
    void clearMap() REQUIRES(mMutex);

    // Waits for required permissions to become set. This seems to be needed
    // because platform service permissions might not be set when a service
    // first starts. See b/214085769.
    void waitForPermissions();

    // Indicates whether our eBPF components have been initialized.
    std::atomic<bool> mInitialized = false;

    // A thread that periodically checks whether |mGpuWorkMap| is nearly full
    // and, if so, clears it.
    std::thread mMapClearerThread;

    // Mutex for |mGpuWorkMap| and a few other fields.
    std::mutex mMutex;

    // BPF map for per-UID GPU work.
    bpf::BpfMap<GpuIdUid, UidTrackingInfo> mGpuWorkMap GUARDED_BY(mMutex);

    // BPF map containing a single element for global data.
    bpf::BpfMap<uint32_t, GlobalData> mGpuWorkGlobalDataMap GUARDED_BY(mMutex);

    // When true, we are being destructed, so |mMapClearerThread| should stop.
    bool mIsTerminating GUARDED_BY(mMutex);

    // A condition variable for |mIsTerminating|.
    std::condition_variable mIsTerminatingConditionVariable GUARDED_BY(mMutex);

    // 30 second timeout for trying to attach a BPF program to a tracepoint.
    static constexpr int kGpuWaitTimeoutSeconds = 30;

    // The wait duration for the map clearer thread; the thread checks the map
    // every ~1 hour.
    static constexpr uint32_t kMapClearerWaitDurationSeconds = 60 * 60;

    // Whether our |pullAtomCallback| function is registered.
    bool mStatsdRegistered GUARDED_BY(mMutex) = false;

    // The number of randomly chosen (i.e. sampled) UIDs to log stats for.
    static constexpr size_t kNumSampledUids = 10;

    // A "large" number of GPUs. If we observe more GPUs than this limit then
    // we reduce the amount of stats we log.
    static constexpr size_t kNumGpusSoftLimit = 4;

    // A "very large" number of GPUs. If we observe more GPUs than this limit
    // then we don't log any stats.
    static constexpr size_t kNumGpusHardLimit = 32;

    // The minimum GPU time needed to actually log stats for a UID.
    static constexpr uint64_t kMinGpuTimeNanoseconds = 30U * 1000000000U; // 30 seconds.

    // The previous time point at which |mGpuWorkMap| was cleared.
    std::chrono::steady_clock::time_point mPreviousMapClearTimePoint GUARDED_BY(mMutex);

    // Permission to register a statsd puller.
    static constexpr char16_t kPermissionRegisterStatsPullAtom[] =
            u"android.permission.REGISTER_STATS_PULL_ATOM";

    // Time limit for waiting for permissions.
    static constexpr int kPermissionsWaitTimeoutSeconds = 30;
};

} // namespace gpuwork
} // namespace android
