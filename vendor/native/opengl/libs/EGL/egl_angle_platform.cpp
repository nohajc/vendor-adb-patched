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

#if defined(__ANDROID__)

#include "egl_angle_platform.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <EGL/Platform.h>
#pragma GCC diagnostic pop

#include <android-base/properties.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <graphicsenv/GraphicsEnv.h>
#include <log/log.h>
#include <time.h>
#include <vndksupport/linker.h>

#include "Loader.h"

namespace angle {

constexpr int kAngleDlFlags = RTLD_LOCAL | RTLD_NOW;

static GetDisplayPlatformFunc angleGetDisplayPlatform = nullptr;
static ResetDisplayPlatformFunc angleResetDisplayPlatform = nullptr;

static time_t startTime = time(nullptr);

static const unsigned char* getTraceCategoryEnabledFlag(PlatformMethods* /*platform*/,
                                                        const char* /*categoryName*/) {
    // Returning ptr to 'g' (non-zero) to ALWAYS enable tracing initially.
    // This ptr is what will be passed into "category_group_enabled" of addTraceEvent
    static const unsigned char traceEnabled = 'g';
    return &traceEnabled;
}

static double monotonicallyIncreasingTime(PlatformMethods* /*platform*/) {
    return difftime(time(nullptr), startTime);
}

static void logError(PlatformMethods* /*platform*/, const char* errorMessage) {
    ALOGE("ANGLE Error:%s", errorMessage);
}

static void logWarning(PlatformMethods* /*platform*/, const char* warningMessage) {
    ALOGW("ANGLE Warn:%s", warningMessage);
}

static void logInfo(PlatformMethods* /*platform*/, const char* infoMessage) {
    ALOGD("ANGLE Info:%s", infoMessage);
}

static TraceEventHandle addTraceEvent(
        PlatformMethods* /**platform*/, char phase, const unsigned char* /*category_group_enabled*/,
        const char* name, unsigned long long /*id*/, double /*timestamp*/, int /*num_args*/,
        const char** /*arg_names*/, const unsigned char* /*arg_types*/,
        const unsigned long long* /*arg_values*/, unsigned char /*flags*/) {
    switch (phase) {
        case 'B': {
            ATRACE_BEGIN(name);
            break;
        }
        case 'E': {
            ATRACE_END();
            break;
        }
        case 'I': {
            ATRACE_NAME(name);
            break;
        }
        default:
            // Could handle other event types here
            break;
    }
    // Return any non-zero handle to avoid assert in ANGLE
    TraceEventHandle result = 1.0;
    return result;
}

static void assignAnglePlatformMethods(PlatformMethods* platformMethods) {
    platformMethods->addTraceEvent = addTraceEvent;
    platformMethods->getTraceCategoryEnabledFlag = getTraceCategoryEnabledFlag;
    platformMethods->monotonicallyIncreasingTime = monotonicallyIncreasingTime;
    platformMethods->logError = logError;
    platformMethods->logWarning = logWarning;
    platformMethods->logInfo = logInfo;
}

// Initialize function ptrs for ANGLE PlatformMethods struct, used for systrace
bool initializeAnglePlatform(EGLDisplay dpy) {
    // Since we're inside libEGL, use dlsym to lookup fptr for ANGLEGetDisplayPlatform
    android_namespace_t* ns = android::GraphicsEnv::getInstance().getAngleNamespace();
    void* so = nullptr;
    if (ns) {
        // Loading from an APK, so hard-code the suffix to "_angle".
        constexpr char kAngleEs2Lib[] = "libGLESv2_angle.so";
        const android_dlextinfo dlextinfo = {
                .flags = ANDROID_DLEXT_USE_NAMESPACE,
                .library_namespace = ns,
        };
        so = android_dlopen_ext(kAngleEs2Lib, kAngleDlFlags, &dlextinfo);
        if (so) {
            ALOGD("dlopen_ext from APK (%s) success at %p", kAngleEs2Lib, so);
        } else {
            ALOGE("dlopen_ext(\"%s\") failed: %s", kAngleEs2Lib, dlerror());
            return false;
        }
    } else {
        // If we are here, ANGLE is loaded as built-in gl driver in the sphal.
        // Get the specified ANGLE library filename suffix.
        std::string angleEs2LibSuffix = android::base::GetProperty("ro.hardware.egl", "");
        if (angleEs2LibSuffix.empty()) {
            ALOGE("%s failed to get valid ANGLE library filename suffix!", __FUNCTION__);
            return false;
        }

        std::string angleEs2LibName = "libGLESv2_" + angleEs2LibSuffix + ".so";
        so = android_load_sphal_library(angleEs2LibName.c_str(), kAngleDlFlags);
        if (so) {
            ALOGD("dlopen (%s) success at %p", angleEs2LibName.c_str(), so);
        } else {
            ALOGE("%s failed to dlopen %s!", __FUNCTION__, angleEs2LibName.c_str());
            return false;
        }
    }

    angleGetDisplayPlatform =
            reinterpret_cast<GetDisplayPlatformFunc>(dlsym(so, "ANGLEGetDisplayPlatform"));

    if (!angleGetDisplayPlatform) {
        ALOGE("dlsym lookup of ANGLEGetDisplayPlatform in libEGL_angle failed!");
        return false;
    }

    angleResetDisplayPlatform =
            reinterpret_cast<ResetDisplayPlatformFunc>(dlsym(so, "ANGLEResetDisplayPlatform"));

    PlatformMethods* platformMethods = nullptr;
    if (!((angleGetDisplayPlatform)(dpy, g_PlatformMethodNames, g_NumPlatformMethods, nullptr,
                                    &platformMethods))) {
        ALOGE("ANGLEGetDisplayPlatform call failed!");
        return false;
    }
    if (platformMethods) {
        assignAnglePlatformMethods(platformMethods);
    } else {
        ALOGE("In initializeAnglePlatform() platformMethods struct ptr is NULL. Not assigning "
              "tracing function ptrs!");
    }
    return true;
}

void resetAnglePlatform(EGLDisplay dpy) {
    if (angleResetDisplayPlatform) {
        angleResetDisplayPlatform(dpy);
    }
}

}; // namespace angle

#endif // __ANDROID__
