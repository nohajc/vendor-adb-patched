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

#undef LOG_TAG
#define LOG_TAG "GpuWork"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "gpuwork/GpuWork.h"

#include <android-base/stringprintf.h>
#include <binder/PermissionCache.h>
#include <bpf/WaitForProgsLoaded.h>
#include <libbpf.h>
#include <log/log.h>
#include <random>
#include <stats_event.h>
#include <statslog.h>
#include <unistd.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <bit>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "gpuwork/gpuWork.h"

#define ONE_MS_IN_NS (10000000)

namespace android {
namespace gpuwork {

namespace {

bool lessThanGpuIdUid(const android::gpuwork::GpuIdUid& l, const android::gpuwork::GpuIdUid& r) {
    return std::tie(l.gpu_id, l.uid) < std::tie(r.gpu_id, r.uid);
}

size_t hashGpuIdUid(const android::gpuwork::GpuIdUid& gpuIdUid) {
    return static_cast<size_t>((gpuIdUid.gpu_id << 5U) + gpuIdUid.uid);
}

bool equalGpuIdUid(const android::gpuwork::GpuIdUid& l, const android::gpuwork::GpuIdUid& r) {
    return std::tie(l.gpu_id, l.uid) == std::tie(r.gpu_id, r.uid);
}

// Gets a BPF map from |mapPath|.
template <class Key, class Value>
bool getBpfMap(const char* mapPath, bpf::BpfMap<Key, Value>* out) {
    errno = 0;
    auto map = bpf::BpfMap<Key, Value>(mapPath);
    if (!map.isValid()) {
        ALOGW("Failed to create bpf map from %s [%d(%s)]", mapPath, errno, strerror(errno));
        return false;
    }
    *out = std::move(map);
    return true;
}

template <typename SourceType>
inline int32_t cast_int32(SourceType) = delete;

template <typename SourceType>
inline int32_t bitcast_int32(SourceType) = delete;

template <>
inline int32_t bitcast_int32<uint32_t>(uint32_t source) {
    int32_t result;
    memcpy(&result, &source, sizeof(result));
    return result;
}

} // namespace

using base::StringAppendF;

GpuWork::~GpuWork() {
    // If we created our clearer thread, then we must stop it and join it.
    if (mMapClearerThread.joinable()) {
        // Tell the thread to terminate.
        {
            std::scoped_lock<std::mutex> lock(mMutex);
            mIsTerminating = true;
            mIsTerminatingConditionVariable.notify_all();
        }

        // Now, we can join it.
        mMapClearerThread.join();
    }

    {
        std::scoped_lock<std::mutex> lock(mMutex);
        if (mStatsdRegistered) {
            AStatsManager_clearPullAtomCallback(android::util::GPU_WORK_PER_UID);
        }
    }

    bpf_detach_tracepoint("power", "gpu_work_period");
}

void GpuWork::initialize() {
    // Make sure BPF programs are loaded.
    bpf::waitForProgsLoaded();

    waitForPermissions();

    // Get the BPF maps before trying to attach the BPF program; if we can't get
    // the maps then there is no point in attaching the BPF program.
    {
        std::lock_guard<std::mutex> lock(mMutex);

        if (!getBpfMap("/sys/fs/bpf/map_gpuWork_gpu_work_map", &mGpuWorkMap)) {
            return;
        }

        if (!getBpfMap("/sys/fs/bpf/map_gpuWork_gpu_work_global_data", &mGpuWorkGlobalDataMap)) {
            return;
        }

        mPreviousMapClearTimePoint = std::chrono::steady_clock::now();
    }

    // Attach the tracepoint.
    if (!attachTracepoint("/sys/fs/bpf/prog_gpuWork_tracepoint_power_gpu_work_period", "power",
                          "gpu_work_period")) {
        return;
    }

    // Create the map clearer thread, and store it to |mMapClearerThread|.
    std::thread thread([this]() { periodicallyClearMap(); });

    mMapClearerThread.swap(thread);

    {
        std::lock_guard<std::mutex> lock(mMutex);
        AStatsManager_setPullAtomCallback(int32_t{android::util::GPU_WORK_PER_UID}, nullptr,
                                          GpuWork::pullAtomCallback, this);
        mStatsdRegistered = true;
    }

    ALOGI("Initialized!");

    mInitialized.store(true);
}

void GpuWork::dump(const Vector<String16>& /* args */, std::string* result) {
    if (!mInitialized.load()) {
        result->append("GPU work information is not available.\n");
        return;
    }

    // Ordered map ensures output data is sorted.
    std::map<GpuIdUid, UidTrackingInfo, decltype(lessThanGpuIdUid)*> dumpMap(&lessThanGpuIdUid);

    {
        std::lock_guard<std::mutex> lock(mMutex);

        if (!mGpuWorkMap.isValid()) {
            result->append("GPU work map is not available.\n");
            return;
        }

        // Iteration of BPF hash maps can be unreliable (no data races, but elements
        // may be repeated), as the map is typically being modified by other
        // threads. The buckets are all preallocated. Our eBPF program only updates
        // entries (in-place) or adds entries. |GpuWork| only iterates or clears the
        // map while holding |mMutex|. Given this, we should be able to iterate over
        // all elements reliably. Nevertheless, we copy into a map to avoid
        // duplicates.

        // Note that userspace reads of BPF maps make a copy of the value, and
        // thus the returned value is not being concurrently accessed by the BPF
        // program (no atomic reads needed below).

        mGpuWorkMap.iterateWithValue(
                [&dumpMap](const GpuIdUid& key, const UidTrackingInfo& value,
                           const android::bpf::BpfMap<GpuIdUid, UidTrackingInfo>&)
                        -> base::Result<void> {
                    dumpMap[key] = value;
                    return {};
                });
    }

    // Dump work information.
    // E.g.
    // GPU work information.
    // gpu_id uid total_active_duration_ns total_inactive_duration_ns
    // 0 1000 0 0
    // 0 1003 1234 123
    // [errors:3]0 1006 4567 456

    // Header.
    result->append("GPU work information.\ngpu_id uid total_active_duration_ns "
                   "total_inactive_duration_ns\n");

    for (const auto& idToUidInfo : dumpMap) {
        if (idToUidInfo.second.error_count) {
            StringAppendF(result, "[errors:%" PRIu32 "]", idToUidInfo.second.error_count);
        }
        StringAppendF(result, "%" PRIu32 " %" PRIu32 " %" PRIu64 " %" PRIu64 "\n",
                      idToUidInfo.first.gpu_id, idToUidInfo.first.uid,
                      idToUidInfo.second.total_active_duration_ns,
                      idToUidInfo.second.total_inactive_duration_ns);
    }
}

bool GpuWork::attachTracepoint(const char* programPath, const char* tracepointGroup,
                               const char* tracepointName) {
    errno = 0;
    base::unique_fd fd(bpf::retrieveProgram(programPath));
    if (fd < 0) {
        ALOGW("Failed to retrieve pinned program from %s [%d(%s)]", programPath, errno,
              strerror(errno));
        return false;
    }

    // Attach the program to the tracepoint. The tracepoint is automatically enabled.
    errno = 0;
    int count = 0;
    while (bpf_attach_tracepoint(fd.get(), tracepointGroup, tracepointName) < 0) {
        if (++count > kGpuWaitTimeoutSeconds) {
            ALOGW("Failed to attach bpf program to %s/%s tracepoint [%d(%s)]", tracepointGroup,
                  tracepointName, errno, strerror(errno));
            return false;
        }
        // Retry until GPU driver loaded or timeout.
        sleep(1);
        errno = 0;
    }

    return true;
}

AStatsManager_PullAtomCallbackReturn GpuWork::pullAtomCallback(int32_t atomTag,
                                                               AStatsEventList* data,
                                                               void* cookie) {
    ATRACE_CALL();

    GpuWork* gpuWork = reinterpret_cast<GpuWork*>(cookie);
    if (atomTag == android::util::GPU_WORK_PER_UID) {
        return gpuWork->pullWorkAtoms(data);
    }

    return AStatsManager_PULL_SKIP;
}

AStatsManager_PullAtomCallbackReturn GpuWork::pullWorkAtoms(AStatsEventList* data) {
    ATRACE_CALL();

    if (!data || !mInitialized.load()) {
        return AStatsManager_PULL_SKIP;
    }

    std::lock_guard<std::mutex> lock(mMutex);

    if (!mGpuWorkMap.isValid()) {
        return AStatsManager_PULL_SKIP;
    }

    std::unordered_map<GpuIdUid, UidTrackingInfo, decltype(hashGpuIdUid)*, decltype(equalGpuIdUid)*>
            workMap(32, &hashGpuIdUid, &equalGpuIdUid);

    // Iteration of BPF hash maps can be unreliable (no data races, but elements
    // may be repeated), as the map is typically being modified by other
    // threads. The buckets are all preallocated. Our eBPF program only updates
    // entries (in-place) or adds entries. |GpuWork| only iterates or clears the
    // map while holding |mMutex|. Given this, we should be able to iterate over
    // all elements reliably. Nevertheless, we copy into a map to avoid
    // duplicates.

    // Note that userspace reads of BPF maps make a copy of the value, and thus
    // the returned value is not being concurrently accessed by the BPF program
    // (no atomic reads needed below).

    mGpuWorkMap.iterateWithValue([&workMap](const GpuIdUid& key, const UidTrackingInfo& value,
                                            const android::bpf::BpfMap<GpuIdUid, UidTrackingInfo>&)
                                         -> base::Result<void> {
        workMap[key] = value;
        return {};
    });

    // Get a list of just the UIDs; the order does not matter.
    std::vector<Uid> uids;
    // Get a list of the GPU IDs, in order.
    std::set<uint32_t> gpuIds;
    {
        // To avoid adding duplicate UIDs.
        std::unordered_set<Uid> addedUids;

        for (const auto& workInfo : workMap) {
            if (addedUids.insert(workInfo.first.uid).second) {
                // Insertion was successful.
                uids.push_back(workInfo.first.uid);
            }
            gpuIds.insert(workInfo.first.gpu_id);
        }
    }

    ALOGI("pullWorkAtoms: uids.size() == %zu", uids.size());
    ALOGI("pullWorkAtoms: gpuIds.size() == %zu", gpuIds.size());

    if (gpuIds.size() > kNumGpusHardLimit) {
        // If we observe a very high number of GPUs then something has probably
        // gone wrong, so don't log any atoms.
        return AStatsManager_PULL_SKIP;
    }

    size_t numSampledUids = kNumSampledUids;

    if (gpuIds.size() > kNumGpusSoftLimit) {
        // If we observe a high number of GPUs then we just sample 1 UID.
        numSampledUids = 1;
    }

    // Remove all UIDs that do not have at least |kMinGpuTimeNanoseconds| on at
    // least one GPU.
    {
        auto uidIt = uids.begin();
        while (uidIt != uids.end()) {
            bool hasEnoughGpuTime = false;
            for (uint32_t gpuId : gpuIds) {
                auto infoIt = workMap.find(GpuIdUid{gpuId, *uidIt});
                if (infoIt == workMap.end()) {
                    continue;
                }
                if (infoIt->second.total_active_duration_ns +
                            infoIt->second.total_inactive_duration_ns >=
                    kMinGpuTimeNanoseconds) {
                    hasEnoughGpuTime = true;
                    break;
                }
            }
            if (hasEnoughGpuTime) {
                ++uidIt;
            } else {
                uidIt = uids.erase(uidIt);
            }
        }
    }

    ALOGI("pullWorkAtoms: after removing uids with very low GPU time: uids.size() == %zu",
          uids.size());

    std::random_device device;
    std::default_random_engine random_engine(device());

    // If we have more than |numSampledUids| UIDs, choose |numSampledUids|
    // random UIDs. We swap them to the front of the list. Given the list
    // indices 0..i..n-1, we have the following inclusive-inclusive ranges:
    // - [0, i-1] == the randomly chosen elements.
    // - [i, n-1] == the remaining unchosen elements.
    if (uids.size() > numSampledUids) {
        for (size_t i = 0; i < numSampledUids; ++i) {
            std::uniform_int_distribution<size_t> uniform_dist(i, uids.size() - 1);
            size_t random_index = uniform_dist(random_engine);
            std::swap(uids[i], uids[random_index]);
        }
        // Only keep the front |numSampledUids| elements.
        uids.resize(numSampledUids);
    }

    ALOGI("pullWorkAtoms: after random selection: uids.size() == %zu", uids.size());

    auto now = std::chrono::steady_clock::now();
    long long duration =
            std::chrono::duration_cast<std::chrono::seconds>(now - mPreviousMapClearTimePoint)
                    .count();
    if (duration > std::numeric_limits<int32_t>::max() || duration < 0) {
        // This is essentially impossible. If it does somehow happen, give up,
        // but still clear the map.
        clearMap();
        return AStatsManager_PULL_SKIP;
    }

    // Log an atom for each (gpu id, uid) pair for which we have data.
    for (uint32_t gpuId : gpuIds) {
        for (Uid uid : uids) {
            auto it = workMap.find(GpuIdUid{gpuId, uid});
            if (it == workMap.end()) {
                continue;
            }
            const UidTrackingInfo& info = it->second;

            uint64_t total_active_duration_ms = info.total_active_duration_ns / ONE_MS_IN_NS;
            uint64_t total_inactive_duration_ms = info.total_inactive_duration_ns / ONE_MS_IN_NS;

            // Skip this atom if any numbers are out of range. |duration| is
            // already checked above.
            if (total_active_duration_ms > std::numeric_limits<int32_t>::max() ||
                total_inactive_duration_ms > std::numeric_limits<int32_t>::max()) {
                continue;
            }

            ALOGI("pullWorkAtoms: adding stats for GPU ID %" PRIu32 "; UID %" PRIu32, gpuId, uid);
            android::util::addAStatsEvent(data, int32_t{android::util::GPU_WORK_PER_UID},
                                          // uid
                                          bitcast_int32(uid),
                                          // gpu_id
                                          bitcast_int32(gpuId),
                                          // time_duration_seconds
                                          static_cast<int32_t>(duration),
                                          // total_active_duration_millis
                                          static_cast<int32_t>(total_active_duration_ms),
                                          // total_inactive_duration_millis
                                          static_cast<int32_t>(total_inactive_duration_ms));
        }
    }
    clearMap();
    return AStatsManager_PULL_SUCCESS;
}

void GpuWork::periodicallyClearMap() {
    std::unique_lock<std::mutex> lock(mMutex);

    auto previousTime = std::chrono::steady_clock::now();

    while (true) {
        if (mIsTerminating) {
            break;
        }
        auto nextTime = std::chrono::steady_clock::now();
        auto differenceSeconds =
                std::chrono::duration_cast<std::chrono::seconds>(nextTime - previousTime);
        if (differenceSeconds.count() > kMapClearerWaitDurationSeconds) {
            // It has been >1 hour, so clear the map, if needed.
            clearMapIfNeeded();
            // We only update |previousTime| if we actually checked the map.
            previousTime = nextTime;
        }
        // Sleep for ~1 hour. It does not matter if we don't check the map for 2
        // hours.
        mIsTerminatingConditionVariable.wait_for(lock,
                                                 std::chrono::seconds{
                                                         kMapClearerWaitDurationSeconds});
    }
}

void GpuWork::clearMapIfNeeded() {
    if (!mInitialized.load() || !mGpuWorkMap.isValid() || !mGpuWorkGlobalDataMap.isValid()) {
        ALOGW("Map clearing could not occur because we are not initialized properly");
        return;
    }

    base::Result<GlobalData> globalData = mGpuWorkGlobalDataMap.readValue(0);
    if (!globalData.ok()) {
        ALOGW("Could not read BPF global data map entry");
        return;
    }

    // Note that userspace reads of BPF maps make a copy of the value, and thus
    // the return value is not being concurrently accessed by the BPF program
    // (no atomic reads needed below).

    uint64_t numEntries = globalData.value().num_map_entries;

    // If the map is <=75% full, we do nothing.
    if (numEntries <= (kMaxTrackedGpuIdUids / 4) * 3) {
        return;
    }

    clearMap();
}

void GpuWork::clearMap() {
    if (!mInitialized.load() || !mGpuWorkMap.isValid() || !mGpuWorkGlobalDataMap.isValid()) {
        ALOGW("Map clearing could not occur because we are not initialized properly");
        return;
    }

    base::Result<GlobalData> globalData = mGpuWorkGlobalDataMap.readValue(0);
    if (!globalData.ok()) {
        ALOGW("Could not read BPF global data map entry");
        return;
    }

    // Iterating BPF maps to delete keys is tricky. If we just repeatedly call
    // |getFirstKey()| and delete that, we may loop forever (or for a long time)
    // because our BPF program might be repeatedly re-adding keys. Also, even if
    // we limit the number of elements we try to delete, we might only delete
    // new entries, leaving old entries in the map. If we delete a key A and
    // then call |getNextKey(A)|, the first key in the map is returned, so we
    // have the same issue.
    //
    // Thus, we instead get the next key and then delete the previous key. We
    // also limit the number of deletions we try, just in case.

    base::Result<GpuIdUid> key = mGpuWorkMap.getFirstKey();

    for (size_t i = 0; i < kMaxTrackedGpuIdUids; ++i) {
        if (!key.ok()) {
            break;
        }
        base::Result<GpuIdUid> previousKey = key;
        key = mGpuWorkMap.getNextKey(previousKey.value());
        mGpuWorkMap.deleteValue(previousKey.value());
    }

    // Reset our counter; |globalData| is a copy of the data, so we have to use
    // |writeValue|.
    globalData.value().num_map_entries = 0;
    mGpuWorkGlobalDataMap.writeValue(0, globalData.value(), BPF_ANY);

    // Update |mPreviousMapClearTimePoint| so we know when we started collecting
    // the stats.
    mPreviousMapClearTimePoint = std::chrono::steady_clock::now();
}

void GpuWork::waitForPermissions() {
    const String16 permissionRegisterStatsPullAtom(kPermissionRegisterStatsPullAtom);
    int count = 0;
    while (!PermissionCache::checkPermission(permissionRegisterStatsPullAtom, getpid(), getuid())) {
        if (++count > kPermissionsWaitTimeoutSeconds) {
            ALOGW("Timed out waiting for android.permission.REGISTER_STATS_PULL_ATOM");
            return;
        }
        // Retry.
        sleep(1);
    }
}

} // namespace gpuwork
} // namespace android
