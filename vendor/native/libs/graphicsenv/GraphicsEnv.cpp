/*
 * Copyright 2017 The Android Open Source Project
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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

//#define LOG_NDEBUG 1
#define LOG_TAG "GraphicsEnv"

#include <graphicsenv/GraphicsEnv.h>

#include <dlfcn.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/dlext.h>
#include <binder/IServiceManager.h>
#include <graphicsenv/IGpuService.h>
#include <log/log.h>
#include <nativeloader/dlext_namespaces.h>
#include <sys/prctl.h>
#include <utils/Trace.h>

#include <memory>
#include <string>
#include <thread>

// TODO(b/159240322): Extend this to x86 ABI.
#if defined(__LP64__)
#define UPDATABLE_DRIVER_ABI "arm64-v8a"
#else
#define UPDATABLE_DRIVER_ABI "armeabi-v7a"
#endif // defined(__LP64__)

// TODO(ianelliott@): Get the following from an ANGLE header:
#define CURRENT_ANGLE_API_VERSION 2 // Current API verion we are targetting
// Version-2 API:
typedef bool (*fpANGLEGetFeatureSupportUtilAPIVersion)(unsigned int* versionToUse);
typedef bool (*fpANGLEAndroidParseRulesString)(const char* rulesString, void** rulesHandle,
                                               int* rulesVersion);
typedef bool (*fpANGLEGetSystemInfo)(void** handle);
typedef bool (*fpANGLEAddDeviceInfoToSystemInfo)(const char* deviceMfr, const char* deviceModel,
                                                 void* handle);
typedef bool (*fpANGLEShouldBeUsedForApplication)(void* rulesHandle, int rulesVersion,
                                                  void* systemInfoHandle, const char* appName);
typedef bool (*fpANGLEFreeRulesHandle)(void* handle);
typedef bool (*fpANGLEFreeSystemInfoHandle)(void* handle);

namespace android {

enum NativeLibrary {
    LLNDK = 0,
    VNDKSP = 1,
};

static constexpr const char* kNativeLibrariesSystemConfigPath[] =
        {"/apex/com.android.vndk.v{}/etc/llndk.libraries.{}.txt",
         "/apex/com.android.vndk.v{}/etc/vndksp.libraries.{}.txt"};

static std::string vndkVersionStr() {
#ifdef __BIONIC__
    return base::GetProperty("ro.vndk.version", "");
#endif
    return "";
}

static void insertVndkVersionStr(std::string* fileName) {
    LOG_ALWAYS_FATAL_IF(!fileName, "fileName should never be nullptr");
    std::string version = vndkVersionStr();
    size_t pos = fileName->find("{}");
    while (pos != std::string::npos) {
        fileName->replace(pos, 2, version);
        pos = fileName->find("{}", pos + version.size());
    }
}

static bool readConfig(const std::string& configFile, std::vector<std::string>* soNames) {
    // Read list of public native libraries from the config file.
    std::string fileContent;
    if (!base::ReadFileToString(configFile, &fileContent)) {
        return false;
    }

    std::vector<std::string> lines = base::Split(fileContent, "\n");

    for (auto& line : lines) {
        auto trimmedLine = base::Trim(line);
        if (!trimmedLine.empty()) {
            soNames->push_back(trimmedLine);
        }
    }

    return true;
}

static const std::string getSystemNativeLibraries(NativeLibrary type) {
    std::string nativeLibrariesSystemConfig = kNativeLibrariesSystemConfigPath[type];
    insertVndkVersionStr(&nativeLibrariesSystemConfig);

    std::vector<std::string> soNames;
    if (!readConfig(nativeLibrariesSystemConfig, &soNames)) {
        ALOGE("Failed to retrieve library names from %s", nativeLibrariesSystemConfig.c_str());
        return "";
    }

    return base::Join(soNames, ':');
}

/*static*/ GraphicsEnv& GraphicsEnv::getInstance() {
    static GraphicsEnv env;
    return env;
}

bool GraphicsEnv::isDebuggable() {
    // This flag determines if the application is marked debuggable
    bool appDebuggable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) > 0;

    // This flag is set only in `debuggable` builds of the platform
#if defined(ANDROID_DEBUGGABLE)
    bool platformDebuggable = true;
#else
    bool platformDebuggable = false;
#endif

    ALOGV("GraphicsEnv::isDebuggable returning appDebuggable=%s || platformDebuggable=%s",
          appDebuggable ? "true" : "false", platformDebuggable ? "true" : "false");

    return appDebuggable || platformDebuggable;
}

void GraphicsEnv::setDriverPathAndSphalLibraries(const std::string path,
                                                 const std::string sphalLibraries) {
    if (!mDriverPath.empty() || !mSphalLibraries.empty()) {
        ALOGV("ignoring attempt to change driver path from '%s' to '%s' or change sphal libraries "
              "from '%s' to '%s'",
              mDriverPath.c_str(), path.c_str(), mSphalLibraries.c_str(), sphalLibraries.c_str());
        return;
    }
    ALOGV("setting driver path to '%s' and sphal libraries to '%s'", path.c_str(),
          sphalLibraries.c_str());
    mDriverPath = path;
    mSphalLibraries = sphalLibraries;
}

void GraphicsEnv::hintActivityLaunch() {
    ATRACE_CALL();

    {
        std::lock_guard<std::mutex> lock(mStatsLock);
        if (mActivityLaunched) return;
        mActivityLaunched = true;
    }

    std::thread trySendGpuStatsThread([this]() {
        // If there's already graphics driver preloaded in the process, just send
        // the stats info to GpuStats directly through async binder.
        std::lock_guard<std::mutex> lock(mStatsLock);
        if (mGpuStats.glDriverToSend) {
            mGpuStats.glDriverToSend = false;
            sendGpuStatsLocked(GpuStatsInfo::Api::API_GL, true, mGpuStats.glDriverLoadingTime);
        }
        if (mGpuStats.vkDriverToSend) {
            mGpuStats.vkDriverToSend = false;
            sendGpuStatsLocked(GpuStatsInfo::Api::API_VK, true, mGpuStats.vkDriverLoadingTime);
        }
    });
    trySendGpuStatsThread.detach();
}

void GraphicsEnv::setGpuStats(const std::string& driverPackageName,
                              const std::string& driverVersionName, uint64_t driverVersionCode,
                              int64_t driverBuildTime, const std::string& appPackageName,
                              const int vulkanVersion) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mStatsLock);
    ALOGV("setGpuStats:\n"
          "\tdriverPackageName[%s]\n"
          "\tdriverVersionName[%s]\n"
          "\tdriverVersionCode[%" PRIu64 "]\n"
          "\tdriverBuildTime[%" PRId64 "]\n"
          "\tappPackageName[%s]\n"
          "\tvulkanVersion[%d]\n",
          driverPackageName.c_str(), driverVersionName.c_str(), driverVersionCode, driverBuildTime,
          appPackageName.c_str(), vulkanVersion);

    mGpuStats.driverPackageName = driverPackageName;
    mGpuStats.driverVersionName = driverVersionName;
    mGpuStats.driverVersionCode = driverVersionCode;
    mGpuStats.driverBuildTime = driverBuildTime;
    mGpuStats.appPackageName = appPackageName;
    mGpuStats.vulkanVersion = vulkanVersion;
}

void GraphicsEnv::setDriverToLoad(GpuStatsInfo::Driver driver) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mStatsLock);
    switch (driver) {
        case GpuStatsInfo::Driver::GL:
        case GpuStatsInfo::Driver::GL_UPDATED:
        case GpuStatsInfo::Driver::ANGLE: {
            if (mGpuStats.glDriverToLoad == GpuStatsInfo::Driver::NONE ||
                mGpuStats.glDriverToLoad == GpuStatsInfo::Driver::GL) {
                mGpuStats.glDriverToLoad = driver;
                break;
            }

            if (mGpuStats.glDriverFallback == GpuStatsInfo::Driver::NONE) {
                mGpuStats.glDriverFallback = driver;
            }
            break;
        }
        case GpuStatsInfo::Driver::VULKAN:
        case GpuStatsInfo::Driver::VULKAN_UPDATED: {
            if (mGpuStats.vkDriverToLoad == GpuStatsInfo::Driver::NONE ||
                mGpuStats.vkDriverToLoad == GpuStatsInfo::Driver::VULKAN) {
                mGpuStats.vkDriverToLoad = driver;
                break;
            }

            if (mGpuStats.vkDriverFallback == GpuStatsInfo::Driver::NONE) {
                mGpuStats.vkDriverFallback = driver;
            }
            break;
        }
        default:
            break;
    }
}

void GraphicsEnv::setDriverLoaded(GpuStatsInfo::Api api, bool isDriverLoaded,
                                  int64_t driverLoadingTime) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mStatsLock);
    if (api == GpuStatsInfo::Api::API_GL) {
        mGpuStats.glDriverToSend = true;
        mGpuStats.glDriverLoadingTime = driverLoadingTime;
    } else {
        mGpuStats.vkDriverToSend = true;
        mGpuStats.vkDriverLoadingTime = driverLoadingTime;
    }

    sendGpuStatsLocked(api, isDriverLoaded, driverLoadingTime);
}

static sp<IGpuService> getGpuService() {
    static const sp<IBinder> binder = defaultServiceManager()->checkService(String16("gpu"));
    if (!binder) {
        ALOGE("Failed to get gpu service");
        return nullptr;
    }

    return interface_cast<IGpuService>(binder);
}

bool GraphicsEnv::readyToSendGpuStatsLocked() {
    // Only send stats for processes having at least one activity launched and that process doesn't
    // skip the GraphicsEnvironment setup.
    return mActivityLaunched && !mGpuStats.appPackageName.empty();
}

void GraphicsEnv::setTargetStats(const GpuStatsInfo::Stats stats, const uint64_t value) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lock(mStatsLock);
    if (!readyToSendGpuStatsLocked()) return;

    const sp<IGpuService> gpuService = getGpuService();
    if (gpuService) {
        gpuService->setTargetStats(mGpuStats.appPackageName, mGpuStats.driverVersionCode, stats,
                                   value);
    }
}

void GraphicsEnv::sendGpuStatsLocked(GpuStatsInfo::Api api, bool isDriverLoaded,
                                     int64_t driverLoadingTime) {
    ATRACE_CALL();

    if (!readyToSendGpuStatsLocked()) return;

    ALOGV("sendGpuStats:\n"
          "\tdriverPackageName[%s]\n"
          "\tdriverVersionName[%s]\n"
          "\tdriverVersionCode[%" PRIu64 "]\n"
          "\tdriverBuildTime[%" PRId64 "]\n"
          "\tappPackageName[%s]\n"
          "\tvulkanVersion[%d]\n"
          "\tapi[%d]\n"
          "\tisDriverLoaded[%d]\n"
          "\tdriverLoadingTime[%" PRId64 "]",
          mGpuStats.driverPackageName.c_str(), mGpuStats.driverVersionName.c_str(),
          mGpuStats.driverVersionCode, mGpuStats.driverBuildTime, mGpuStats.appPackageName.c_str(),
          mGpuStats.vulkanVersion, static_cast<int32_t>(api), isDriverLoaded, driverLoadingTime);

    GpuStatsInfo::Driver driver = GpuStatsInfo::Driver::NONE;
    bool isIntendedDriverLoaded = false;
    if (api == GpuStatsInfo::Api::API_GL) {
        driver = mGpuStats.glDriverToLoad;
        isIntendedDriverLoaded =
                isDriverLoaded && (mGpuStats.glDriverFallback == GpuStatsInfo::Driver::NONE);
    } else {
        driver = mGpuStats.vkDriverToLoad;
        isIntendedDriverLoaded =
                isDriverLoaded && (mGpuStats.vkDriverFallback == GpuStatsInfo::Driver::NONE);
    }

    const sp<IGpuService> gpuService = getGpuService();
    if (gpuService) {
        gpuService->setGpuStats(mGpuStats.driverPackageName, mGpuStats.driverVersionName,
                                mGpuStats.driverVersionCode, mGpuStats.driverBuildTime,
                                mGpuStats.appPackageName, mGpuStats.vulkanVersion, driver,
                                isIntendedDriverLoaded, driverLoadingTime);
    }
}

bool GraphicsEnv::setInjectLayersPrSetDumpable() {
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        return false;
    }
    return true;
}

void* GraphicsEnv::loadLibrary(std::string name) {
    const android_dlextinfo dlextinfo = {
            .flags = ANDROID_DLEXT_USE_NAMESPACE,
            .library_namespace = getAngleNamespace(),
    };

    std::string libName = std::string("lib") + name + "_angle.so";

    void* so = android_dlopen_ext(libName.c_str(), RTLD_LOCAL | RTLD_NOW, &dlextinfo);

    if (so) {
        ALOGD("dlopen_ext from APK (%s) success at %p", libName.c_str(), so);
        return so;
    } else {
        ALOGE("dlopen_ext(\"%s\") failed: %s", libName.c_str(), dlerror());
    }

    return nullptr;
}

bool GraphicsEnv::shouldUseAngle(std::string appName) {
    if (appName != mAngleAppName) {
        // Make sure we are checking the app we were init'ed for
        ALOGE("App name does not match: expected '%s', got '%s'", mAngleAppName.c_str(),
              appName.c_str());
        return false;
    }

    return shouldUseAngle();
}

bool GraphicsEnv::shouldUseAngle() {
    // Make sure we are init'ed
    if (mAngleAppName.empty()) {
        ALOGV("App name is empty. setAngleInfo() has not been called to enable ANGLE.");
        return false;
    }

    return (mUseAngle == YES) ? true : false;
}

bool GraphicsEnv::angleIsSystemDriver() {
    // Make sure we are init'ed
    if (mAngleAppName.empty()) {
        ALOGV("App name is empty. setAngleInfo() has not been called to enable ANGLE.");
        return false;
    }

    return (mAngleIsSystemDriver == YES) ? true : false;
}

bool GraphicsEnv::shouldForceLegacyDriver() {
    // Make sure we are init'ed
    if (mAngleAppName.empty()) {
        ALOGV("App name is empty. setAngleInfo() has not been called to enable ANGLE.");
        return false;
    }

    return (mAngleIsSystemDriver == YES && mUseAngle == NO) ? true : false;
}

std::string GraphicsEnv::getLegacySuffix() {
    return mLegacyDriverSuffix;
}

void GraphicsEnv::updateUseAngle() {
    mUseAngle = NO;

    const char* ANGLE_PREFER_ANGLE = "angle";
    const char* ANGLE_PREFER_LEGACY = "legacy";
    // The following is a deprecated version of "legacy"
    const char* ANGLE_PREFER_NATIVE = "native";

    mUseAngle = NO;
    if (mAngleDeveloperOptIn == ANGLE_PREFER_ANGLE) {
        ALOGI("Using ANGLE, the %s GLES driver for package '%s'",
              mAngleIsSystemDriver == YES ? "system" : "optional", mAngleAppName.c_str());
        mUseAngle = YES;
    } else if (mAngleDeveloperOptIn == ANGLE_PREFER_LEGACY ||
               mAngleDeveloperOptIn == ANGLE_PREFER_NATIVE) {
        ALOGI("Using the (%s) Legacy GLES driver for package '%s'",
              mAngleIsSystemDriver == YES ? "optional" : "system", mAngleAppName.c_str());
    } else {
        ALOGV("User set invalid \"Developer Options\": '%s'", mAngleDeveloperOptIn.c_str());
    }
}

void GraphicsEnv::setAngleInfo(const std::string path, const std::string appName,
                               const bool angleIsSystemDriver, const std::string developerOptIn,
                               const std::vector<std::string> eglFeatures) {
    // Set whether ANGLE is the system driver:
    mAngleIsSystemDriver = angleIsSystemDriver ? YES : NO;

    // Note: Given the current logic and lack of the old rules file processing,
    // there seems to be little chance that mUseAngle != UNKNOWN.  Leave this
    // for now, even though it seems outdated.
    if (mUseAngle != UNKNOWN) {
        // We've already figured out an answer for this app, so just return.
        ALOGV("Already evaluated the rules file for '%s': use ANGLE = %s", appName.c_str(),
              (mUseAngle == YES) ? "true" : "false");
        return;
    }

    mAngleEglFeatures = std::move(eglFeatures);

    ALOGV("setting ANGLE path to '%s'", path.c_str());
    mAnglePath = path;
    ALOGV("setting ANGLE app name to '%s'", appName.c_str());
    mAngleAppName = appName;
    ALOGV("setting ANGLE application opt-in to '%s'", developerOptIn.c_str());
    mAngleDeveloperOptIn = developerOptIn;

    // Update the current status of whether we should use ANGLE or not
    updateUseAngle();
}

void GraphicsEnv::setLegacyDriverInfo(const std::string appName, const bool angleIsSystemDriver,
                                      const std::string legacyDriverName) {
    ALOGV("setting legacy app name to '%s'", appName.c_str());
    mAngleAppName = appName;

    // Force the use of the legacy driver instead of ANGLE
    const char* ANGLE_PREFER_LEGACY = "legacy";
    mAngleDeveloperOptIn = ANGLE_PREFER_LEGACY;
    ALOGV("setting ANGLE application opt-in to 'legacy'");

    // Set whether ANGLE is the system driver:
    mAngleIsSystemDriver = angleIsSystemDriver ? YES : NO;

    mLegacyDriverSuffix = legacyDriverName;

    // Update the current status of whether we should use ANGLE or not
    updateUseAngle();
}

void GraphicsEnv::setLayerPaths(NativeLoaderNamespace* appNamespace, const std::string layerPaths) {
    if (mLayerPaths.empty()) {
        mLayerPaths = layerPaths;
        mAppNamespace = appNamespace;
    } else {
        ALOGV("Vulkan layer search path already set, not clobbering with '%s' for namespace %p'",
              layerPaths.c_str(), appNamespace);
    }
}

NativeLoaderNamespace* GraphicsEnv::getAppNamespace() {
    return mAppNamespace;
}

std::string& GraphicsEnv::getAngleAppName() {
    return mAngleAppName;
}

const std::vector<std::string>& GraphicsEnv::getAngleEglFeatures() {
    return mAngleEglFeatures;
}

const std::string& GraphicsEnv::getLayerPaths() {
    return mLayerPaths;
}

const std::string& GraphicsEnv::getDebugLayers() {
    return mDebugLayers;
}

const std::string& GraphicsEnv::getDebugLayersGLES() {
    return mDebugLayersGLES;
}

void GraphicsEnv::setDebugLayers(const std::string layers) {
    mDebugLayers = layers;
}

void GraphicsEnv::setDebugLayersGLES(const std::string layers) {
    mDebugLayersGLES = layers;
}

// Return true if all the required libraries from vndk and sphal namespace are
// linked to the updatable gfx driver namespace correctly.
bool GraphicsEnv::linkDriverNamespaceLocked(android_namespace_t* vndkNamespace) {
    const std::string llndkLibraries = getSystemNativeLibraries(NativeLibrary::LLNDK);
    if (llndkLibraries.empty()) {
        return false;
    }
    if (!android_link_namespaces(mDriverNamespace, nullptr, llndkLibraries.c_str())) {
        ALOGE("Failed to link default namespace[%s]", dlerror());
        return false;
    }

    const std::string vndkspLibraries = getSystemNativeLibraries(NativeLibrary::VNDKSP);
    if (vndkspLibraries.empty()) {
        return false;
    }
    if (!android_link_namespaces(mDriverNamespace, vndkNamespace, vndkspLibraries.c_str())) {
        ALOGE("Failed to link vndk namespace[%s]", dlerror());
        return false;
    }

    if (mSphalLibraries.empty()) {
        return true;
    }

    // Make additional libraries in sphal to be accessible
    auto sphalNamespace = android_get_exported_namespace("sphal");
    if (!sphalNamespace) {
        ALOGE("Depend on these libraries[%s] in sphal, but failed to get sphal namespace",
              mSphalLibraries.c_str());
        return false;
    }

    if (!android_link_namespaces(mDriverNamespace, sphalNamespace, mSphalLibraries.c_str())) {
        ALOGE("Failed to link sphal namespace[%s]", dlerror());
        return false;
    }

    return true;
}

android_namespace_t* GraphicsEnv::getDriverNamespace() {
    std::lock_guard<std::mutex> lock(mNamespaceMutex);

    if (mDriverNamespace) {
        return mDriverNamespace;
    }

    if (mDriverPath.empty()) {
        // For an application process, driver path is empty means this application is not opted in
        // to use updatable driver. Application process doesn't have the ability to set up
        // environment variables and hence before `getenv` call will return.
        // For a process that is not an application process, if it's run from an environment,
        // for example shell, where environment variables can be set, then it can opt into using
        // udpatable driver by setting UPDATABLE_GFX_DRIVER to 1. By setting to 1 the developer
        // driver will be used currently.
        // TODO(b/159240322) Support the production updatable driver.
        const char* id = getenv("UPDATABLE_GFX_DRIVER");
        if (id == nullptr || std::strcmp(id, "1")) {
            return nullptr;
        }
        const sp<IGpuService> gpuService = getGpuService();
        if (!gpuService) {
            return nullptr;
        }
        mDriverPath = gpuService->getUpdatableDriverPath();
        if (mDriverPath.empty()) {
            return nullptr;
        }
        mDriverPath.append(UPDATABLE_DRIVER_ABI);
        ALOGI("Driver path is setup via UPDATABLE_GFX_DRIVER: %s", mDriverPath.c_str());
    }

    auto vndkNamespace = android_get_exported_namespace("vndk");
    if (!vndkNamespace) {
        return nullptr;
    }

    mDriverNamespace = android_create_namespace("gfx driver",
                                                mDriverPath.c_str(), // ld_library_path
                                                mDriverPath.c_str(), // default_library_path
                                                ANDROID_NAMESPACE_TYPE_ISOLATED,
                                                nullptr, // permitted_when_isolated_path
                                                nullptr);

    if (!linkDriverNamespaceLocked(vndkNamespace)) {
        mDriverNamespace = nullptr;
    }

    return mDriverNamespace;
}

std::string GraphicsEnv::getDriverPath() const {
    return mDriverPath;
}

android_namespace_t* GraphicsEnv::getAngleNamespace() {
    std::lock_guard<std::mutex> lock(mNamespaceMutex);

    if (mAngleNamespace) {
        return mAngleNamespace;
    }

    if (mAnglePath.empty()) {
        ALOGV("mAnglePath is empty, not creating ANGLE namespace");
        return nullptr;
    }

    mAngleNamespace = android_create_namespace("ANGLE",
                                               nullptr,            // ld_library_path
                                               mAnglePath.c_str(), // default_library_path
                                               ANDROID_NAMESPACE_TYPE_SHARED_ISOLATED,
                                               nullptr, // permitted_when_isolated_path
                                               nullptr);

    ALOGD_IF(!mAngleNamespace, "Could not create ANGLE namespace from default");

    return mAngleNamespace;
}

} // namespace android
