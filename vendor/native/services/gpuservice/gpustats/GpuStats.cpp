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
#undef LOG_TAG
#define LOG_TAG "GpuStats"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "gpustats/GpuStats.h"

#include <android/util/ProtoOutputStream.h>
#include <cutils/properties.h>
#include <log/log.h>
#include <stats_event.h>
#include <statslog.h>
#include <utils/Trace.h>

#include <unordered_set>

namespace android {

GpuStats::~GpuStats() {
    if (mStatsdRegistered) {
        AStatsManager_clearPullAtomCallback(android::util::GPU_STATS_GLOBAL_INFO);
        AStatsManager_clearPullAtomCallback(android::util::GPU_STATS_APP_INFO);
    }
}

static void addLoadingCount(GpuStatsInfo::Driver driver, bool isDriverLoaded,
                            GpuStatsGlobalInfo* const outGlobalInfo) {
    switch (driver) {
        case GpuStatsInfo::Driver::GL:
        case GpuStatsInfo::Driver::GL_UPDATED:
            outGlobalInfo->glLoadingCount++;
            if (!isDriverLoaded) outGlobalInfo->glLoadingFailureCount++;
            break;
        case GpuStatsInfo::Driver::VULKAN:
        case GpuStatsInfo::Driver::VULKAN_UPDATED:
            outGlobalInfo->vkLoadingCount++;
            if (!isDriverLoaded) outGlobalInfo->vkLoadingFailureCount++;
            break;
        case GpuStatsInfo::Driver::ANGLE:
            outGlobalInfo->angleLoadingCount++;
            if (!isDriverLoaded) outGlobalInfo->angleLoadingFailureCount++;
            break;
        default:
            break;
    }
}

static void addLoadingTime(GpuStatsInfo::Driver driver, int64_t driverLoadingTime,
                           GpuStatsAppInfo* const outAppInfo) {
    switch (driver) {
        case GpuStatsInfo::Driver::GL:
        case GpuStatsInfo::Driver::GL_UPDATED:
            if (outAppInfo->glDriverLoadingTime.size() < GpuStats::MAX_NUM_LOADING_TIMES) {
                outAppInfo->glDriverLoadingTime.emplace_back(driverLoadingTime);
            }
            break;
        case GpuStatsInfo::Driver::VULKAN:
        case GpuStatsInfo::Driver::VULKAN_UPDATED:
            if (outAppInfo->vkDriverLoadingTime.size() < GpuStats::MAX_NUM_LOADING_TIMES) {
                outAppInfo->vkDriverLoadingTime.emplace_back(driverLoadingTime);
            }
            break;
        case GpuStatsInfo::Driver::ANGLE:
            if (outAppInfo->angleDriverLoadingTime.size() < GpuStats::MAX_NUM_LOADING_TIMES) {
                outAppInfo->angleDriverLoadingTime.emplace_back(driverLoadingTime);
            }
            break;
        default:
            break;
    }
}

void GpuStats::purgeOldDriverStats() {
    ALOG_ASSERT(mAppStats.size() == MAX_NUM_APP_RECORDS);

    struct GpuStatsApp {
        // Key is <app package name>+<driver version code>.
        const std::string *appStatsKey = nullptr;
        const std::chrono::time_point<std::chrono::system_clock> *lastAccessTime = nullptr;
    };
    std::vector<GpuStatsApp> gpuStatsApps(MAX_NUM_APP_RECORDS);

    // Create a list of pointers to package names and their last access times.
    int index = 0;
    for (const auto & [appStatsKey, gpuStatsAppInfo] : mAppStats) {
        GpuStatsApp &gpuStatsApp = gpuStatsApps[index];
        gpuStatsApp.appStatsKey = &appStatsKey;
        gpuStatsApp.lastAccessTime = &gpuStatsAppInfo.lastAccessTime;
        ++index;
    }

    // Sort the list with the oldest access times at the front.
    std::sort(gpuStatsApps.begin(), gpuStatsApps.end(), [](GpuStatsApp a, GpuStatsApp b) -> bool {
        return *a.lastAccessTime < *b.lastAccessTime;
    });

    // Remove the oldest packages from mAppStats to make room for new apps.
    for (int i = 0; i < APP_RECORD_HEADROOM; ++i) {
        mAppStats.erase(*gpuStatsApps[i].appStatsKey);
        gpuStatsApps[i].appStatsKey = nullptr;
        gpuStatsApps[i].lastAccessTime = nullptr;
    }
}

void GpuStats::insertDriverStats(const std::string& driverPackageName,
                                 const std::string& driverVersionName, uint64_t driverVersionCode,
                                 int64_t driverBuildTime, const std::string& appPackageName,
                                 const int32_t vulkanVersion, GpuStatsInfo::Driver driver,
                                 bool isDriverLoaded, int64_t driverLoadingTime) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mLock);
    registerStatsdCallbacksIfNeeded();
    ALOGV("Received:\n"
          "\tdriverPackageName[%s]\n"
          "\tdriverVersionName[%s]\n"
          "\tdriverVersionCode[%" PRIu64 "]\n"
          "\tdriverBuildTime[%" PRId64 "]\n"
          "\tappPackageName[%s]\n"
          "\tvulkanVersion[%d]\n"
          "\tdriver[%d]\n"
          "\tisDriverLoaded[%d]\n"
          "\tdriverLoadingTime[%" PRId64 "]",
          driverPackageName.c_str(), driverVersionName.c_str(), driverVersionCode, driverBuildTime,
          appPackageName.c_str(), vulkanVersion, static_cast<int32_t>(driver), isDriverLoaded,
          driverLoadingTime);

    if (!mGlobalStats.count(driverVersionCode)) {
        GpuStatsGlobalInfo globalInfo;
        addLoadingCount(driver, isDriverLoaded, &globalInfo);
        globalInfo.driverPackageName = driverPackageName;
        globalInfo.driverVersionName = driverVersionName;
        globalInfo.driverVersionCode = driverVersionCode;
        globalInfo.driverBuildTime = driverBuildTime;
        globalInfo.vulkanVersion = vulkanVersion;
        mGlobalStats.insert({driverVersionCode, globalInfo});
    } else {
        addLoadingCount(driver, isDriverLoaded, &mGlobalStats[driverVersionCode]);
    }

    const std::string appStatsKey = appPackageName + std::to_string(driverVersionCode);
    if (!mAppStats.count(appStatsKey)) {
        if (mAppStats.size() >= MAX_NUM_APP_RECORDS) {
            ALOGV("GpuStatsAppInfo has reached maximum size. Removing old stats to make room.");
            purgeOldDriverStats();
        }

        GpuStatsAppInfo appInfo;
        addLoadingTime(driver, driverLoadingTime, &appInfo);
        appInfo.appPackageName = appPackageName;
        appInfo.driverVersionCode = driverVersionCode;
        appInfo.angleInUse = driverPackageName == "angle";
        appInfo.lastAccessTime = std::chrono::system_clock::now();
        mAppStats.insert({appStatsKey, appInfo});
    } else {
        mAppStats[appStatsKey].angleInUse = driverPackageName == "angle";
        addLoadingTime(driver, driverLoadingTime, &mAppStats[appStatsKey]);
        mAppStats[appStatsKey].lastAccessTime = std::chrono::system_clock::now();
    }
}

void GpuStats::insertTargetStats(const std::string& appPackageName,
                                 const uint64_t driverVersionCode, const GpuStatsInfo::Stats stats,
                                 const uint64_t /*value*/) {
    ATRACE_CALL();

    const std::string appStatsKey = appPackageName + std::to_string(driverVersionCode);

    std::lock_guard<std::mutex> lock(mLock);
    registerStatsdCallbacksIfNeeded();
    if (!mAppStats.count(appStatsKey)) {
        return;
    }

    switch (stats) {
        case GpuStatsInfo::Stats::CPU_VULKAN_IN_USE:
            mAppStats[appStatsKey].cpuVulkanInUse = true;
            break;
        case GpuStatsInfo::Stats::FALSE_PREROTATION:
            mAppStats[appStatsKey].falsePrerotation = true;
            break;
        case GpuStatsInfo::Stats::GLES_1_IN_USE:
            mAppStats[appStatsKey].gles1InUse = true;
            break;
        default:
            break;
    }
}

void GpuStats::interceptSystemDriverStatsLocked() {
    // Append cpuVulkanVersion and glesVersion to system driver stats
    if (!mGlobalStats.count(0) || mGlobalStats[0].glesVersion) {
        return;
    }

    mGlobalStats[0].cpuVulkanVersion = property_get_int32("ro.cpuvulkan.version", 0);
    mGlobalStats[0].glesVersion = property_get_int32("ro.opengles.version", 0);
}

void GpuStats::registerStatsdCallbacksIfNeeded() {
    if (!mStatsdRegistered) {
        AStatsManager_setPullAtomCallback(android::util::GPU_STATS_GLOBAL_INFO, nullptr,
                                         GpuStats::pullAtomCallback, this);
        AStatsManager_setPullAtomCallback(android::util::GPU_STATS_APP_INFO, nullptr,
                                         GpuStats::pullAtomCallback, this);
        mStatsdRegistered = true;
    }
}

void GpuStats::dump(const Vector<String16>& args, std::string* result) {
    ATRACE_CALL();

    if (!result) {
        ALOGE("Dump result shouldn't be nullptr.");
        return;
    }

    std::lock_guard<std::mutex> lock(mLock);
    bool dumpAll = true;

    std::unordered_set<std::string> argsSet;
    for (size_t i = 0; i < args.size(); i++) {
        argsSet.insert(String8(args[i]).c_str());
    }

    const bool dumpGlobal = argsSet.count("--global") != 0;
    if (dumpGlobal) {
        dumpGlobalLocked(result);
        dumpAll = false;
    }

    const bool dumpApp = argsSet.count("--app") != 0;
    if (dumpApp) {
        dumpAppLocked(result);
        dumpAll = false;
    }

    if (dumpAll) {
        dumpGlobalLocked(result);
        dumpAppLocked(result);
    }

    if (argsSet.count("--clear")) {
        bool clearAll = true;

        if (dumpGlobal) {
            mGlobalStats.clear();
            clearAll = false;
        }

        if (dumpApp) {
            mAppStats.clear();
            clearAll = false;
        }

        if (clearAll) {
            mGlobalStats.clear();
            mAppStats.clear();
        }
    }
}

void GpuStats::dumpGlobalLocked(std::string* result) {
    interceptSystemDriverStatsLocked();

    for (const auto& ele : mGlobalStats) {
        result->append(ele.second.toString());
        result->append("\n");
    }
}

void GpuStats::dumpAppLocked(std::string* result) {
    for (const auto& ele : mAppStats) {
        result->append(ele.second.toString());
        result->append("\n");
    }
}

static std::string protoOutputStreamToByteString(android::util::ProtoOutputStream& proto) {
    if (!proto.size()) return "";

    std::string byteString;
    sp<android::util::ProtoReader> reader = proto.data();
    while (reader->readBuffer() != nullptr) {
        const size_t toRead = reader->currentToRead();
        byteString.append((char*)reader->readBuffer(), toRead);
        reader->move(toRead);
    }

    if (byteString.size() != proto.size()) return "";

    return byteString;
}

static std::string int64VectorToProtoByteString(const std::vector<int64_t>& value) {
    if (value.empty()) return "";

    android::util::ProtoOutputStream proto;
    for (const auto& ele : value) {
        proto.write(android::util::FIELD_TYPE_INT64 | android::util::FIELD_COUNT_REPEATED |
                            1 /* field id */,
                    (long long)ele);
    }

    return protoOutputStreamToByteString(proto);
}

AStatsManager_PullAtomCallbackReturn GpuStats::pullAppInfoAtom(AStatsEventList* data) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mLock);

    if (data) {
        for (const auto& ele : mAppStats) {
            std::string glDriverBytes = int64VectorToProtoByteString(
                ele.second.glDriverLoadingTime);
            std::string vkDriverBytes = int64VectorToProtoByteString(
                ele.second.vkDriverLoadingTime);
            std::string angleDriverBytes = int64VectorToProtoByteString(
                ele.second.angleDriverLoadingTime);

            android::util::addAStatsEvent(
                    data,
                    android::util::GPU_STATS_APP_INFO,
                    ele.second.appPackageName.c_str(),
                    ele.second.driverVersionCode,
                    android::util::BytesField(glDriverBytes.c_str(),
                                              glDriverBytes.length()),
                    android::util::BytesField(vkDriverBytes.c_str(),
                                              vkDriverBytes.length()),
                    android::util::BytesField(angleDriverBytes.c_str(),
                                              angleDriverBytes.length()),
                    ele.second.cpuVulkanInUse,
                    ele.second.falsePrerotation,
                    ele.second.gles1InUse,
                    ele.second.angleInUse);
        }
    }

    mAppStats.clear();

    return AStatsManager_PULL_SUCCESS;
}

AStatsManager_PullAtomCallbackReturn GpuStats::pullGlobalInfoAtom(AStatsEventList* data) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mLock);
    // flush cpuVulkanVersion and glesVersion to builtin driver stats
    interceptSystemDriverStatsLocked();

    if (data) {
        for (const auto& ele : mGlobalStats) {
          android::util::addAStatsEvent(
                  data,
                  android::util::GPU_STATS_GLOBAL_INFO,
                  ele.second.driverPackageName.c_str(),
                  ele.second.driverVersionName.c_str(),
                  ele.second.driverVersionCode,
                  ele.second.driverBuildTime,
                  ele.second.glLoadingCount,
                  ele.second.glLoadingFailureCount,
                  ele.second.vkLoadingCount,
                  ele.second.vkLoadingFailureCount,
                  ele.second.vulkanVersion,
                  ele.second.cpuVulkanVersion,
                  ele.second.glesVersion,
                  ele.second.angleLoadingCount,
                  ele.second.angleLoadingFailureCount);
        }
    }

    mGlobalStats.clear();

    return AStatsManager_PULL_SUCCESS;
}

AStatsManager_PullAtomCallbackReturn GpuStats::pullAtomCallback(int32_t atomTag,
                                                                AStatsEventList* data,
                                                                void* cookie) {
    ATRACE_CALL();

    GpuStats* pGpuStats = reinterpret_cast<GpuStats*>(cookie);
    if (atomTag == android::util::GPU_STATS_GLOBAL_INFO) {
        return pGpuStats->pullGlobalInfoAtom(data);
    } else if (atomTag == android::util::GPU_STATS_APP_INFO) {
        return pGpuStats->pullAppInfoAtom(data);
    }

    return AStatsManager_PULL_SKIP;
}

} // namespace android
