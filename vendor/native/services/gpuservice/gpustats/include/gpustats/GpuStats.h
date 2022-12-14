/*
 * Copyright 2019 The Android Open Source Project
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

#include <graphicsenv/GpuStatsInfo.h>
#include <graphicsenv/GraphicsEnv.h>
#include <stats_pull_atom_callback.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include <mutex>
#include <unordered_map>
#include <vector>

namespace android {

class GpuStats {
public:
    ~GpuStats();

    // Insert new gpu driver stats into global stats and app stats.
    void insertDriverStats(const std::string& driverPackageName,
                           const std::string& driverVersionName, uint64_t driverVersionCode,
                           int64_t driverBuildTime, const std::string& appPackageName,
                           const int32_t vulkanVersion, GpuStatsInfo::Driver driver,
                           bool isDriverLoaded, int64_t driverLoadingTime);
    // Insert target stats into app stats or potentially global stats as well.
    void insertTargetStats(const std::string& appPackageName, const uint64_t driverVersionCode,
                           const GpuStatsInfo::Stats stats, const uint64_t value);
    // dumpsys interface
    void dump(const Vector<String16>& args, std::string* result);

    // This limits the worst case number of loading times tracked.
    static const size_t MAX_NUM_LOADING_TIMES = 50;

private:
    // Friend class for testing.
    friend class TestableGpuStats;

    // Native atom puller callback registered in statsd.
    static AStatsManager_PullAtomCallbackReturn pullAtomCallback(int32_t atomTag,
                                                                 AStatsEventList* data,
                                                                 void* cookie);
    // Pull global into into global atom.
    AStatsManager_PullAtomCallbackReturn pullGlobalInfoAtom(AStatsEventList* data);
    // Pull app into into app atom.
    AStatsManager_PullAtomCallbackReturn pullAppInfoAtom(AStatsEventList* data);
    // Dump global stats
    void dumpGlobalLocked(std::string* result);
    // Dump app stats
    void dumpAppLocked(std::string* result);
    // Append cpuVulkanVersion and glesVersion to system driver stats
    void interceptSystemDriverStatsLocked();
    // Registers statsd callbacks if they have not already been registered
    void registerStatsdCallbacksIfNeeded();

    // Below limits the memory usage of GpuStats to be less than 10KB. This is
    // the preferred number for statsd while maintaining nice data quality.
    static const size_t MAX_NUM_APP_RECORDS = 100;
    // GpuStats access should be guarded by mLock.
    std::mutex mLock;
    // True if statsd callbacks have been registered.
    bool mStatsdRegistered = false;
    // Key is driver version code.
    std::unordered_map<uint64_t, GpuStatsGlobalInfo> mGlobalStats;
    // Key is <app package name>+<driver version code>.
    std::unordered_map<std::string, GpuStatsAppInfo> mAppStats;
};

} // namespace android
