/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef __ANDROID_VNDK__

#include <android/app/ProcessStateEnum.h>
#include <binder/IActivityManager.h>
#include <utils/Mutex.h>

// ---------------------------------------------------------------------------
namespace android {

#define DECLARE_PROCESS_STATE(name) \
    PROCESS_STATE_##name = (int32_t) app::ProcessStateEnum::name

class ActivityManager
{
public:
    enum {
        // Flag for registerUidObserver: report uid state changed
        UID_OBSERVER_PROCSTATE = 1 << 0,
        // Flag for registerUidObserver: report uid gone
        UID_OBSERVER_GONE = 1 << 1,
        // Flag for registerUidObserver: report uid has become idle
        UID_OBSERVER_IDLE = 1 << 2,
        // Flag for registerUidObserver: report uid has become active
        UID_OBSERVER_ACTIVE = 1 << 3,
        // Flag for registerUidObserver: report uid cached state has changed
        UID_OBSERVER_CACHED = 1 << 4,
        // Flag for registerUidObserver: report uid capability has changed
        UID_OBSERVER_CAPABILITY = 1 << 5,
        // Flag for registerUidObserver: report pid oom adj has changed
        UID_OBSERVER_PROC_OOM_ADJ = 1 << 6,
    };

    // PROCESS_STATE_* must come from frameworks/base/core/java/android/app/ProcessStateEnum.aidl.
    // This is to make sure that Java side uses the same values as native.
    enum {
        DECLARE_PROCESS_STATE(UNKNOWN),
        DECLARE_PROCESS_STATE(PERSISTENT),
        DECLARE_PROCESS_STATE(PERSISTENT_UI),
        DECLARE_PROCESS_STATE(TOP),
        DECLARE_PROCESS_STATE(BOUND_TOP),
        DECLARE_PROCESS_STATE(FOREGROUND_SERVICE),
        DECLARE_PROCESS_STATE(BOUND_FOREGROUND_SERVICE),
        DECLARE_PROCESS_STATE(IMPORTANT_FOREGROUND),
        DECLARE_PROCESS_STATE(IMPORTANT_BACKGROUND),
        DECLARE_PROCESS_STATE(TRANSIENT_BACKGROUND),
        DECLARE_PROCESS_STATE(BACKUP),
        DECLARE_PROCESS_STATE(SERVICE),
        DECLARE_PROCESS_STATE(RECEIVER),
        DECLARE_PROCESS_STATE(TOP_SLEEPING),
        DECLARE_PROCESS_STATE(HEAVY_WEIGHT),
        DECLARE_PROCESS_STATE(HOME),
        DECLARE_PROCESS_STATE(LAST_ACTIVITY),
        DECLARE_PROCESS_STATE(CACHED_ACTIVITY),
        DECLARE_PROCESS_STATE(CACHED_ACTIVITY_CLIENT),
        DECLARE_PROCESS_STATE(CACHED_RECENT),
        DECLARE_PROCESS_STATE(CACHED_EMPTY),
        DECLARE_PROCESS_STATE(NONEXISTENT),
    };

    ActivityManager();

    int openContentUri(const String16& stringUri);
    status_t registerUidObserver(const sp<IUidObserver>& observer,
                             const int32_t event,
                             const int32_t cutpoint,
                             const String16& callingPackage);
    status_t unregisterUidObserver(const sp<IUidObserver>& observer);
    bool isUidActive(const uid_t uid, const String16& callingPackage);
    int getUidProcessState(const uid_t uid, const String16& callingPackage);
    status_t checkPermission(const String16& permission, const pid_t pid, const uid_t uid, int32_t* outResult);

    status_t linkToDeath(const sp<IBinder::DeathRecipient>& recipient);
    status_t unlinkToDeath(const sp<IBinder::DeathRecipient>& recipient);

private:
    Mutex mLock;
    sp<IActivityManager> mService;
    sp<IActivityManager> getService();
};


} // namespace android
// ---------------------------------------------------------------------------
#else // __ANDROID_VNDK__
#error "This header is not visible to vendors"
#endif // __ANDROID_VNDK__
