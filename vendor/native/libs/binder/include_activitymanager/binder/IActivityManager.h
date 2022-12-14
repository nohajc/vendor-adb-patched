/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <binder/IUidObserver.h>
#include <binder/IInterface.h>

namespace android {

// ------------------------------------------------------------------------------------

class IActivityManager : public IInterface
{
public:
    DECLARE_META_INTERFACE(ActivityManager)

    virtual int openContentUri(const String16& stringUri) = 0;
    virtual status_t registerUidObserver(const sp<IUidObserver>& observer,
                                     const int32_t event,
                                     const int32_t cutpoint,
                                     const String16& callingPackage) = 0;
    virtual status_t unregisterUidObserver(const sp<IUidObserver>& observer) = 0;
    virtual bool isUidActive(const uid_t uid, const String16& callingPackage) = 0;
    virtual int32_t getUidProcessState(const uid_t uid, const String16& callingPackage) = 0;
    virtual status_t checkPermission(const String16& permission,
                                    const pid_t pid,
                                    const uid_t uid,
                                    int32_t* outResult) = 0;

    enum {
        OPEN_CONTENT_URI_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION,
        REGISTER_UID_OBSERVER_TRANSACTION,
        UNREGISTER_UID_OBSERVER_TRANSACTION,
        IS_UID_ACTIVE_TRANSACTION,
        GET_UID_PROCESS_STATE_TRANSACTION,
        CHECK_PERMISSION_TRANSACTION,
    };
};

// ------------------------------------------------------------------------------------

} // namespace android

#else // __ANDROID_VNDK__
#error "This header is not visible to vendors"
#endif // __ANDROID_VNDK__
