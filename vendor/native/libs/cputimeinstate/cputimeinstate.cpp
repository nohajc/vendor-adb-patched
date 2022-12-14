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

#define LOG_TAG "libtimeinstate"

#include "cputimeinstate.h"
#include <bpf_timeinstate.h>

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/sysinfo.h>

#include <mutex>
#include <numeric>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bpf/BpfMap.h>
#include <libbpf.h>
#include <log/log.h>

using android::base::StringPrintf;
using android::base::unique_fd;

namespace android {
namespace bpf {

static std::mutex gInitializedMutex;
static bool gInitialized = false;
static std::mutex gTrackingMutex;
static bool gTracking = false;
static uint32_t gNPolicies = 0;
static uint32_t gNCpus = 0;
static std::vector<std::vector<uint32_t>> gPolicyFreqs;
static std::vector<std::vector<uint32_t>> gPolicyCpus;
static std::vector<uint32_t> gCpuIndexMap;
static std::set<uint32_t> gAllFreqs;
static unique_fd gTisTotalMapFd;
static unique_fd gTisMapFd;
static unique_fd gConcurrentMapFd;
static unique_fd gUidLastUpdateMapFd;
static unique_fd gPidTisMapFd;

static std::optional<std::vector<uint32_t>> readNumbersFromFile(const std::string &path) {
    std::string data;

    if (!android::base::ReadFileToString(path, &data)) return {};

    auto strings = android::base::Split(data, " \n");
    std::vector<uint32_t> ret;
    for (const auto &s : strings) {
        if (s.empty()) continue;
        uint32_t n;
        if (!android::base::ParseUint(s, &n)) return {};
        ret.emplace_back(n);
    }
    return ret;
}

static int isPolicyFile(const struct dirent *d) {
    return android::base::StartsWith(d->d_name, "policy");
}

static int comparePolicyFiles(const struct dirent **d1, const struct dirent **d2) {
    uint32_t policyN1, policyN2;
    if (sscanf((*d1)->d_name, "policy%" SCNu32 "", &policyN1) != 1 ||
        sscanf((*d2)->d_name, "policy%" SCNu32 "", &policyN2) != 1)
        return 0;
    return policyN1 - policyN2;
}

static bool initGlobals() {
    std::lock_guard<std::mutex> guard(gInitializedMutex);
    if (gInitialized) return true;

    gNCpus = get_nprocs_conf();

    struct dirent **dirlist;
    const char basepath[] = "/sys/devices/system/cpu/cpufreq";
    int ret = scandir(basepath, &dirlist, isPolicyFile, comparePolicyFiles);
    if (ret == -1 || ret == 0) return false;
    gNPolicies = ret;

    std::vector<std::string> policyFileNames;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        policyFileNames.emplace_back(dirlist[i]->d_name);
        free(dirlist[i]);
    }
    free(dirlist);
    uint32_t max_cpu_number = 0;
    for (const auto &policy : policyFileNames) {
        std::vector<uint32_t> freqs;
        for (const auto &name : {"available", "boost"}) {
            std::string path =
                    StringPrintf("%s/%s/scaling_%s_frequencies", basepath, policy.c_str(), name);
            auto nums = readNumbersFromFile(path);
            if (!nums) continue;
            freqs.insert(freqs.end(), nums->begin(), nums->end());
        }
        if (freqs.empty()) return false;
        std::sort(freqs.begin(), freqs.end());
        gPolicyFreqs.emplace_back(freqs);

        for (auto freq : freqs) gAllFreqs.insert(freq);

        std::string path = StringPrintf("%s/%s/%s", basepath, policy.c_str(), "related_cpus");
        auto cpus = readNumbersFromFile(path);
        if (!cpus) return false;
        for (auto cpu : *cpus) {
            if(cpu > max_cpu_number)
                max_cpu_number = cpu;
        }
        gPolicyCpus.emplace_back(*cpus);
    }
    gCpuIndexMap = std::vector<uint32_t>(max_cpu_number+1, -1);
    uint32_t cpuorder = 0;
    for (const auto &cpuList : gPolicyCpus) {
        for (auto cpu : cpuList) {
            gCpuIndexMap[cpu] = cpuorder++;
        }
    }

    gTisTotalMapFd =
            unique_fd{bpf_obj_get(BPF_FS_PATH "map_timeInState_total_time_in_state_map")};
    if (gTisTotalMapFd < 0) return false;

    gTisMapFd = unique_fd{bpf_obj_get(BPF_FS_PATH "map_timeInState_uid_time_in_state_map")};
    if (gTisMapFd < 0) return false;

    gConcurrentMapFd =
            unique_fd{bpf_obj_get(BPF_FS_PATH "map_timeInState_uid_concurrent_times_map")};
    if (gConcurrentMapFd < 0) return false;

    gUidLastUpdateMapFd =
            unique_fd{bpf_obj_get(BPF_FS_PATH "map_timeInState_uid_last_update_map")};
    if (gUidLastUpdateMapFd < 0) return false;

    gPidTisMapFd = unique_fd{mapRetrieveRO(BPF_FS_PATH "map_timeInState_pid_time_in_state_map")};
    if (gPidTisMapFd < 0) return false;

    unique_fd trackedPidMapFd(mapRetrieveWO(BPF_FS_PATH "map_timeInState_pid_tracked_map"));
    if (trackedPidMapFd < 0) return false;

    gInitialized = true;
    return true;
}

static int retrieveProgramFd(const std::string &eventType, const std::string &eventName) {
    std::string path = StringPrintf(BPF_FS_PATH "prog_timeInState_tracepoint_%s_%s",
                                    eventType.c_str(), eventName.c_str());
    return retrieveProgram(path.c_str());
}

static bool attachTracepointProgram(const std::string &eventType, const std::string &eventName) {
    int prog_fd = retrieveProgramFd(eventType, eventName);
    if (prog_fd < 0) return false;
    return bpf_attach_tracepoint(prog_fd, eventType.c_str(), eventName.c_str()) >= 0;
}

static std::optional<uint32_t> getPolicyFreqIdx(uint32_t policy) {
    auto path = StringPrintf("/sys/devices/system/cpu/cpufreq/policy%u/scaling_cur_freq",
                             gPolicyCpus[policy][0]);
    auto freqVec = readNumbersFromFile(path);
    if (!freqVec.has_value() || freqVec->size() != 1) return {};
    for (uint32_t idx = 0; idx < gPolicyFreqs[policy].size(); ++idx) {
        if ((*freqVec)[0] == gPolicyFreqs[policy][idx]) return idx + 1;
    }
    return {};
}

// Check if tracking is expected to work without activating it.
bool isTrackingUidTimesSupported() {
    auto freqs = getCpuFreqs();
    if (!freqs || freqs->empty()) return false;
    if (gTracking) return true;
    if (retrieveProgramFd("sched", "sched_switch") < 0) return false;
    if (retrieveProgramFd("power", "cpu_frequency") < 0) return false;
    if (retrieveProgramFd("sched", "sched_process_free") < 0) return false;
    return true;
}

// Start tracking and aggregating data to be reported by getUidCpuFreqTimes and getUidsCpuFreqTimes.
// Returns true on success, false otherwise.
// Tracking is active only once a live process has successfully called this function; if the calling
// process dies then it must be called again to resume tracking.
// This function should *not* be called while tracking is already active; doing so is unnecessary
// and can lead to accounting errors.
bool startTrackingUidTimes() {
    std::lock_guard<std::mutex> guard(gTrackingMutex);
    if (!initGlobals()) return false;
    if (gTracking) return true;

    unique_fd cpuPolicyFd(mapRetrieveWO(BPF_FS_PATH "map_timeInState_cpu_policy_map"));
    if (cpuPolicyFd < 0) return false;

    for (uint32_t i = 0; i < gPolicyCpus.size(); ++i) {
        for (auto &cpu : gPolicyCpus[i]) {
            if (writeToMapEntry(cpuPolicyFd, &cpu, &i, BPF_ANY)) return false;
        }
    }

    unique_fd freqToIdxFd(mapRetrieveWO(BPF_FS_PATH "map_timeInState_freq_to_idx_map"));
    if (freqToIdxFd < 0) return false;
    freq_idx_key_t key;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        key.policy = i;
        for (uint32_t j = 0; j < gPolicyFreqs[i].size(); ++j) {
            key.freq = gPolicyFreqs[i][j];
            // Start indexes at 1 so that uninitialized state is distinguishable from lowest freq.
            // The uid_times map still uses 0-based indexes, and the sched_switch program handles
            // conversion between them, so this does not affect our map reading code.
            uint32_t idx = j + 1;
            if (writeToMapEntry(freqToIdxFd, &key, &idx, BPF_ANY)) return false;
        }
    }

    unique_fd cpuLastUpdateFd(mapRetrieveWO(BPF_FS_PATH "map_timeInState_cpu_last_update_map"));
    if (cpuLastUpdateFd < 0) return false;
    std::vector<uint64_t> zeros(get_nprocs_conf(), 0);
    uint32_t zero = 0;
    if (writeToMapEntry(cpuLastUpdateFd, &zero, zeros.data(), BPF_ANY)) return false;

    unique_fd nrActiveFd(mapRetrieveWO(BPF_FS_PATH "map_timeInState_nr_active_map"));
    if (nrActiveFd < 0) return false;
    if (writeToMapEntry(nrActiveFd, &zero, &zero, BPF_ANY)) return false;

    unique_fd policyNrActiveFd(mapRetrieveWO(BPF_FS_PATH "map_timeInState_policy_nr_active_map"));
    if (policyNrActiveFd < 0) return false;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        if (writeToMapEntry(policyNrActiveFd, &i, &zero, BPF_ANY)) return false;
    }

    unique_fd policyFreqIdxFd(mapRetrieveWO(BPF_FS_PATH "map_timeInState_policy_freq_idx_map"));
    if (policyFreqIdxFd < 0) return false;
    for (uint32_t i = 0; i < gNPolicies; ++i) {
        auto freqIdx = getPolicyFreqIdx(i);
        if (!freqIdx.has_value()) return false;
        if (writeToMapEntry(policyFreqIdxFd, &i, &(*freqIdx), BPF_ANY)) return false;
    }

    gTracking = attachTracepointProgram("sched", "sched_switch") &&
            attachTracepointProgram("power", "cpu_frequency") &&
            attachTracepointProgram("sched", "sched_process_free");
    return gTracking;
}

std::optional<std::vector<std::vector<uint32_t>>> getCpuFreqs() {
    if (!gInitialized && !initGlobals()) return {};
    return gPolicyFreqs;
}

std::optional<std::vector<std::vector<uint64_t>>> getTotalCpuFreqTimes() {
    if (!gInitialized && !initGlobals()) return {};

    std::vector<std::vector<uint64_t>> out;
    uint32_t maxFreqCount = 0;
    for (const auto &freqList : gPolicyFreqs) {
        if (freqList.size() > maxFreqCount) maxFreqCount = freqList.size();
        out.emplace_back(freqList.size(), 0);
    }

    std::vector<uint64_t> vals(gNCpus);
    const uint32_t freqCount = maxFreqCount <= MAX_FREQS_FOR_TOTAL ? maxFreqCount :
            MAX_FREQS_FOR_TOTAL;
    for (uint32_t freqIdx = 0; freqIdx < freqCount; ++freqIdx) {
        if (findMapEntry(gTisTotalMapFd, &freqIdx, vals.data())) return {};
        for (uint32_t policyIdx = 0; policyIdx < gNPolicies; ++policyIdx) {
            if (freqIdx >= gPolicyFreqs[policyIdx].size()) continue;
            for (const auto &cpu : gPolicyCpus[policyIdx]) {
                out[policyIdx][freqIdx] += vals[gCpuIndexMap[cpu]];
            }
        }
    }

    return out;
}
// Retrieve the times in ns that uid spent running at each CPU frequency.
// Return contains no value on error, otherwise it contains a vector of vectors using the format:
// [[t0_0, t0_1, ...],
//  [t1_0, t1_1, ...], ...]
// where ti_j is the ns that uid spent running on the ith cluster at that cluster's jth lowest freq.
std::optional<std::vector<std::vector<uint64_t>>> getUidCpuFreqTimes(uint32_t uid) {
    if (!gInitialized && !initGlobals()) return {};

    std::vector<std::vector<uint64_t>> out;
    uint32_t maxFreqCount = 0;
    for (const auto &freqList : gPolicyFreqs) {
        if (freqList.size() > maxFreqCount) maxFreqCount = freqList.size();
        out.emplace_back(freqList.size(), 0);
    }

    std::vector<tis_val_t> vals(gNCpus);
    for (uint32_t i = 0; i <= (maxFreqCount - 1) / FREQS_PER_ENTRY; ++i) {
        const time_key_t key = {.uid = uid, .bucket = i};
        if (findMapEntry(gTisMapFd, &key, vals.data())) {
            time_key_t tmpKey;
            if (errno != ENOENT || getFirstMapKey(gTisMapFd, &tmpKey)) return {};
            continue;
        }

        auto offset = i * FREQS_PER_ENTRY;
        auto nextOffset = (i + 1) * FREQS_PER_ENTRY;
        for (uint32_t j = 0; j < gNPolicies; ++j) {
            if (offset >= gPolicyFreqs[j].size()) continue;
            auto begin = out[j].begin() + offset;
            auto end = nextOffset < gPolicyFreqs[j].size() ? begin + FREQS_PER_ENTRY : out[j].end();

            for (const auto &cpu : gPolicyCpus[j]) {
                std::transform(begin, end, std::begin(vals[gCpuIndexMap[cpu]].ar), begin,
                               std::plus<uint64_t>());
            }
        }
    }

    return out;
}

static std::optional<bool> uidUpdatedSince(uint32_t uid, uint64_t lastUpdate,
                                           uint64_t *newLastUpdate) {
    uint64_t uidLastUpdate;
    if (findMapEntry(gUidLastUpdateMapFd, &uid, &uidLastUpdate)) return {};
    // Updates that occurred during the previous read may have been missed. To mitigate
    // this, don't ignore entries updated up to 1s before *lastUpdate
    constexpr uint64_t NSEC_PER_SEC = 1000000000;
    if (uidLastUpdate + NSEC_PER_SEC < lastUpdate) return false;
    if (uidLastUpdate > *newLastUpdate) *newLastUpdate = uidLastUpdate;
    return true;
}

// Retrieve the times in ns that each uid spent running at each CPU freq.
// Return contains no value on error, otherwise it contains a map from uids to vectors of vectors
// using the format:
// { uid0 -> [[t0_0_0, t0_0_1, ...], [t0_1_0, t0_1_1, ...], ...],
//   uid1 -> [[t1_0_0, t1_0_1, ...], [t1_1_0, t1_1_1, ...], ...], ... }
// where ti_j_k is the ns uid i spent running on the jth cluster at the cluster's kth lowest freq.
std::optional<std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>>>
getUidsCpuFreqTimes() {
    return getUidsUpdatedCpuFreqTimes(nullptr);
}

// Retrieve the times in ns that each uid spent running at each CPU freq, excluding UIDs that have
// not run since before lastUpdate.
// Return format is the same as getUidsCpuFreqTimes()
std::optional<std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>>>
getUidsUpdatedCpuFreqTimes(uint64_t *lastUpdate) {
    if (!gInitialized && !initGlobals()) return {};
    time_key_t key, prevKey;
    std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>> map;
    if (getFirstMapKey(gTisMapFd, &key)) {
        if (errno == ENOENT) return map;
        return std::nullopt;
    }

    std::vector<std::vector<uint64_t>> mapFormat;
    for (const auto &freqList : gPolicyFreqs) mapFormat.emplace_back(freqList.size(), 0);

    uint64_t newLastUpdate = lastUpdate ? *lastUpdate : 0;
    std::vector<tis_val_t> vals(gNCpus);
    do {
        if (lastUpdate) {
            auto uidUpdated = uidUpdatedSince(key.uid, *lastUpdate, &newLastUpdate);
            if (!uidUpdated.has_value()) return {};
            if (!*uidUpdated) continue;
        }
        if (findMapEntry(gTisMapFd, &key, vals.data())) return {};
        if (map.find(key.uid) == map.end()) map.emplace(key.uid, mapFormat);

        auto offset = key.bucket * FREQS_PER_ENTRY;
        auto nextOffset = (key.bucket + 1) * FREQS_PER_ENTRY;
        for (uint32_t i = 0; i < gNPolicies; ++i) {
            if (offset >= gPolicyFreqs[i].size()) continue;
            auto begin = map[key.uid][i].begin() + offset;
            auto end = nextOffset < gPolicyFreqs[i].size() ? begin + FREQS_PER_ENTRY :
                map[key.uid][i].end();
            for (const auto &cpu : gPolicyCpus[i]) {
                std::transform(begin, end, std::begin(vals[gCpuIndexMap[cpu]].ar), begin,
                               std::plus<uint64_t>());
            }
        }
        prevKey = key;
    } while (prevKey = key, !getNextMapKey(gTisMapFd, &prevKey, &key));
    if (errno != ENOENT) return {};
    if (lastUpdate && newLastUpdate > *lastUpdate) *lastUpdate = newLastUpdate;
    return map;
}

static bool verifyConcurrentTimes(const concurrent_time_t &ct) {
    uint64_t activeSum = std::accumulate(ct.active.begin(), ct.active.end(), (uint64_t)0);
    uint64_t policySum = 0;
    for (const auto &vec : ct.policy) {
        policySum += std::accumulate(vec.begin(), vec.end(), (uint64_t)0);
    }
    return activeSum == policySum;
}

// Retrieve the times in ns that uid spent running concurrently with each possible number of other
// tasks on each cluster (policy times) and overall (active times).
// Return contains no value on error, otherwise it contains a concurrent_time_t with the format:
// {.active = [a0, a1, ...], .policy = [[p0_0, p0_1, ...], [p1_0, p1_1, ...], ...]}
// where ai is the ns spent running concurrently with tasks on i other cpus and pi_j is the ns spent
// running on the ith cluster, concurrently with tasks on j other cpus in the same cluster
std::optional<concurrent_time_t> getUidConcurrentTimes(uint32_t uid, bool retry) {
    if (!gInitialized && !initGlobals()) return {};
    concurrent_time_t ret = {.active = std::vector<uint64_t>(gNCpus, 0)};
    for (const auto &cpuList : gPolicyCpus) ret.policy.emplace_back(cpuList.size(), 0);
    std::vector<concurrent_val_t> vals(gNCpus);
    for (uint32_t i = 0; i <= (gNCpus - 1) / CPUS_PER_ENTRY; ++i) {
        const time_key_t key = {.uid = uid, .bucket = i};
        if (findMapEntry(gConcurrentMapFd, &key, vals.data())) {
            time_key_t tmpKey;
            if (errno != ENOENT || getFirstMapKey(gConcurrentMapFd, &tmpKey)) return {};
            continue;
        }
        auto offset = key.bucket * CPUS_PER_ENTRY;
        auto nextOffset = (key.bucket + 1) * CPUS_PER_ENTRY;

        auto activeBegin = ret.active.begin() + offset;
        auto activeEnd = nextOffset < gNCpus ? activeBegin + CPUS_PER_ENTRY : ret.active.end();

        for (uint32_t cpu = 0; cpu < gNCpus; ++cpu) {
            std::transform(activeBegin, activeEnd, std::begin(vals[cpu].active), activeBegin,
                           std::plus<uint64_t>());
        }

        for (uint32_t policy = 0; policy < gNPolicies; ++policy) {
            if (offset >= gPolicyCpus[policy].size()) continue;
            auto policyBegin = ret.policy[policy].begin() + offset;
            auto policyEnd = nextOffset < gPolicyCpus[policy].size() ? policyBegin + CPUS_PER_ENTRY
                                                                     : ret.policy[policy].end();

            for (const auto &cpu : gPolicyCpus[policy]) {
                std::transform(policyBegin, policyEnd, std::begin(vals[gCpuIndexMap[cpu]].policy),
                               policyBegin, std::plus<uint64_t>());
            }
        }
    }
    if (!verifyConcurrentTimes(ret) && retry)  return getUidConcurrentTimes(uid, false);
    return ret;
}

// Retrieve the times in ns that each uid spent running concurrently with each possible number of
// other tasks on each cluster (policy times) and overall (active times).
// Return contains no value on error, otherwise it contains a map from uids to concurrent_time_t's
// using the format:
// { uid0 -> {.active = [a0, a1, ...], .policy = [[p0_0, p0_1, ...], [p1_0, p1_1, ...], ...] }, ...}
// where ai is the ns spent running concurrently with tasks on i other cpus and pi_j is the ns spent
// running on the ith cluster, concurrently with tasks on j other cpus in the same cluster.
std::optional<std::unordered_map<uint32_t, concurrent_time_t>> getUidsConcurrentTimes() {
    return getUidsUpdatedConcurrentTimes(nullptr);
}

// Retrieve the times in ns that each uid spent running concurrently with each possible number of
// other tasks on each cluster (policy times) and overall (active times), excluding UIDs that have
// not run since before lastUpdate.
// Return format is the same as getUidsConcurrentTimes()
std::optional<std::unordered_map<uint32_t, concurrent_time_t>> getUidsUpdatedConcurrentTimes(
        uint64_t *lastUpdate) {
    if (!gInitialized && !initGlobals()) return {};
    time_key_t key, prevKey;
    std::unordered_map<uint32_t, concurrent_time_t> ret;
    if (getFirstMapKey(gConcurrentMapFd, &key)) {
        if (errno == ENOENT) return ret;
        return {};
    }

    concurrent_time_t retFormat = {.active = std::vector<uint64_t>(gNCpus, 0)};
    for (const auto &cpuList : gPolicyCpus) retFormat.policy.emplace_back(cpuList.size(), 0);

    std::vector<concurrent_val_t> vals(gNCpus);
    std::vector<uint64_t>::iterator activeBegin, activeEnd, policyBegin, policyEnd;

    uint64_t newLastUpdate = lastUpdate ? *lastUpdate : 0;
    do {
        if (key.bucket > (gNCpus - 1) / CPUS_PER_ENTRY) return {};
        if (lastUpdate) {
            auto uidUpdated = uidUpdatedSince(key.uid, *lastUpdate, &newLastUpdate);
            if (!uidUpdated.has_value()) return {};
            if (!*uidUpdated) continue;
        }
        if (findMapEntry(gConcurrentMapFd, &key, vals.data())) return {};
        if (ret.find(key.uid) == ret.end()) ret.emplace(key.uid, retFormat);

        auto offset = key.bucket * CPUS_PER_ENTRY;
        auto nextOffset = (key.bucket + 1) * CPUS_PER_ENTRY;

        activeBegin = ret[key.uid].active.begin();
        activeEnd = nextOffset < gNCpus ? activeBegin + CPUS_PER_ENTRY : ret[key.uid].active.end();

        for (uint32_t cpu = 0; cpu < gNCpus; ++cpu) {
            std::transform(activeBegin, activeEnd, std::begin(vals[cpu].active), activeBegin,
                           std::plus<uint64_t>());
        }

        for (uint32_t policy = 0; policy < gNPolicies; ++policy) {
            if (offset >= gPolicyCpus[policy].size()) continue;
            policyBegin = ret[key.uid].policy[policy].begin() + offset;
            policyEnd = nextOffset < gPolicyCpus[policy].size() ? policyBegin + CPUS_PER_ENTRY
                                                                : ret[key.uid].policy[policy].end();

            for (const auto &cpu : gPolicyCpus[policy]) {
                std::transform(policyBegin, policyEnd, std::begin(vals[gCpuIndexMap[cpu]].policy),
                               policyBegin, std::plus<uint64_t>());
            }
        }
    } while (prevKey = key, !getNextMapKey(gConcurrentMapFd, &prevKey, &key));
    if (errno != ENOENT) return {};
    for (const auto &[key, value] : ret) {
        if (!verifyConcurrentTimes(value)) {
            auto val = getUidConcurrentTimes(key, false);
            if (val.has_value()) ret[key] = val.value();
        }
    }
    if (lastUpdate && newLastUpdate > *lastUpdate) *lastUpdate = newLastUpdate;
    return ret;
}

// Clear all time in state data for a given uid. Returns false on error, true otherwise.
// This is only suitable for clearing data when an app is uninstalled; if called on a UID with
// running tasks it will cause time in state vs. concurrent time totals to be inconsistent for that
// UID.
bool clearUidTimes(uint32_t uid) {
    if (!gInitialized && !initGlobals()) return false;

    time_key_t key = {.uid = uid};

    uint32_t maxFreqCount = 0;
    for (const auto &freqList : gPolicyFreqs) {
        if (freqList.size() > maxFreqCount) maxFreqCount = freqList.size();
    }

    tis_val_t zeros = {0};
    std::vector<tis_val_t> vals(gNCpus, zeros);
    for (key.bucket = 0; key.bucket <= (maxFreqCount - 1) / FREQS_PER_ENTRY; ++key.bucket) {
        if (writeToMapEntry(gTisMapFd, &key, vals.data(), BPF_EXIST) && errno != ENOENT)
            return false;
        if (deleteMapEntry(gTisMapFd, &key) && errno != ENOENT) return false;
    }

    concurrent_val_t czeros = { .active = {0}, .policy = {0}, };
    std::vector<concurrent_val_t> cvals(gNCpus, czeros);
    for (key.bucket = 0; key.bucket <= (gNCpus - 1) / CPUS_PER_ENTRY; ++key.bucket) {
        if (writeToMapEntry(gConcurrentMapFd, &key, cvals.data(), BPF_EXIST) && errno != ENOENT)
            return false;
        if (deleteMapEntry(gConcurrentMapFd, &key) && errno != ENOENT) return false;
    }

    if (deleteMapEntry(gUidLastUpdateMapFd, &uid) && errno != ENOENT) return false;
    return true;
}

bool startTrackingProcessCpuTimes(pid_t pid) {
    if (!gInitialized && !initGlobals()) return false;

    unique_fd trackedPidHashMapFd(
            mapRetrieveWO(BPF_FS_PATH "map_timeInState_pid_tracked_hash_map"));
    if (trackedPidHashMapFd < 0) return false;

    unique_fd trackedPidMapFd(mapRetrieveWO(BPF_FS_PATH "map_timeInState_pid_tracked_map"));
    if (trackedPidMapFd < 0) return false;

    for (uint32_t index = 0; index < MAX_TRACKED_PIDS; index++) {
        // Find first available [index, pid] entry in the pid_tracked_hash_map map
        if (writeToMapEntry(trackedPidHashMapFd, &index, &pid, BPF_NOEXIST) != 0) {
            if (errno != EEXIST) {
                return false;
            }
            continue; // This index is already taken
        }

        tracked_pid_t tracked_pid = {.pid = pid, .state = TRACKED_PID_STATE_ACTIVE};
        if (writeToMapEntry(trackedPidMapFd, &index, &tracked_pid, BPF_ANY) != 0) {
            return false;
        }
        return true;
    }
    return false;
}

// Marks the specified task identified by its PID (aka TID) for CPU time-in-state tracking
// aggregated with other tasks sharing the same TGID and aggregation key.
bool startAggregatingTaskCpuTimes(pid_t pid, uint16_t aggregationKey) {
    if (!gInitialized && !initGlobals()) return false;

    unique_fd taskAggregationMapFd(
            mapRetrieveWO(BPF_FS_PATH "map_timeInState_pid_task_aggregation_map"));
    if (taskAggregationMapFd < 0) return false;

    return writeToMapEntry(taskAggregationMapFd, &pid, &aggregationKey, BPF_ANY) == 0;
}

// Retrieves the times in ns that each thread spent running at each CPU freq, aggregated by
// aggregation key.
// Return contains no value on error, otherwise it contains a map from aggregation keys
// to vectors of vectors using the format:
// { aggKey0 -> [[t0_0_0, t0_0_1, ...], [t0_1_0, t0_1_1, ...], ...],
//   aggKey1 -> [[t1_0_0, t1_0_1, ...], [t1_1_0, t1_1_1, ...], ...], ... }
// where ti_j_k is the ns tid i spent running on the jth cluster at the cluster's kth lowest freq.
std::optional<std::unordered_map<uint16_t, std::vector<std::vector<uint64_t>>>>
getAggregatedTaskCpuFreqTimes(pid_t tgid, const std::vector<uint16_t> &aggregationKeys) {
    if (!gInitialized && !initGlobals()) return {};

    uint32_t maxFreqCount = 0;
    std::vector<std::vector<uint64_t>> mapFormat;
    for (const auto &freqList : gPolicyFreqs) {
        if (freqList.size() > maxFreqCount) maxFreqCount = freqList.size();
        mapFormat.emplace_back(freqList.size(), 0);
    }

    bool dataCollected = false;
    std::unordered_map<uint16_t, std::vector<std::vector<uint64_t>>> map;
    std::vector<tis_val_t> vals(gNCpus);
    for (uint16_t aggregationKey : aggregationKeys) {
        map.emplace(aggregationKey, mapFormat);

        aggregated_task_tis_key_t key{.tgid = tgid, .aggregation_key = aggregationKey};
        for (key.bucket = 0; key.bucket <= (maxFreqCount - 1) / FREQS_PER_ENTRY; ++key.bucket) {
            if (findMapEntry(gPidTisMapFd, &key, vals.data()) != 0) {
                if (errno != ENOENT) {
                    return {};
                }
                continue;
            } else {
                dataCollected = true;
            }

            // Combine data by aggregating time-in-state data grouped by CPU cluster aka policy.
            uint32_t offset = key.bucket * FREQS_PER_ENTRY;
            uint32_t nextOffset = offset + FREQS_PER_ENTRY;
            for (uint32_t j = 0; j < gNPolicies; ++j) {
                if (offset >= gPolicyFreqs[j].size()) continue;
                auto begin = map[key.aggregation_key][j].begin() + offset;
                auto end = nextOffset < gPolicyFreqs[j].size() ? begin + FREQS_PER_ENTRY
                                                               : map[key.aggregation_key][j].end();
                for (const auto &cpu : gPolicyCpus[j]) {
                    std::transform(begin, end, std::begin(vals[gCpuIndexMap[cpu]].ar), begin,
                                   std::plus<uint64_t>());
                }
            }
        }
    }

    if (!dataCollected) {
        // Check if eBPF is supported on this device. If it is, gTisMap should not be empty.
        time_key_t key;
        if (getFirstMapKey(gTisMapFd, &key) != 0) {
            return {};
        }
    }
    return map;
}

} // namespace bpf
} // namespace android
