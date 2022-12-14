/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <unordered_map>
#include <vector>

namespace android {
namespace bpf {

bool isTrackingUidTimesSupported();
bool startTrackingUidTimes();
std::optional<std::vector<std::vector<uint64_t>>> getTotalCpuFreqTimes();
std::optional<std::vector<std::vector<uint64_t>>> getUidCpuFreqTimes(uint32_t uid);
std::optional<std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>>>
    getUidsCpuFreqTimes();
std::optional<std::unordered_map<uint32_t, std::vector<std::vector<uint64_t>>>>
    getUidsUpdatedCpuFreqTimes(uint64_t *lastUpdate);
std::optional<std::vector<std::vector<uint32_t>>> getCpuFreqs();

struct concurrent_time_t {
    std::vector<uint64_t> active;
    std::vector<std::vector<uint64_t>> policy;
};

std::optional<concurrent_time_t> getUidConcurrentTimes(uint32_t uid, bool retry = true);
std::optional<std::unordered_map<uint32_t, concurrent_time_t>> getUidsConcurrentTimes();
std::optional<std::unordered_map<uint32_t, concurrent_time_t>>
    getUidsUpdatedConcurrentTimes(uint64_t *lastUpdate);
bool clearUidTimes(unsigned int uid);

bool startTrackingProcessCpuTimes(pid_t pid);
bool startAggregatingTaskCpuTimes(pid_t pid, uint16_t aggregationKey);
std::optional<std::unordered_map<uint16_t, std::vector<std::vector<uint64_t>>>>
getAggregatedTaskCpuFreqTimes(pid_t pid, const std::vector<uint16_t> &aggregationKeys);

} // namespace bpf
} // namespace android
