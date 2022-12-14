/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <binder/IAppOpsCallback.h>
#include <binder/IInterface.h>

#include <optional>

#ifdef __ANDROID_VNDK__
#error "This header is not visible to vendors"
#endif

namespace android {

// ----------------------------------------------------------------------

class IAppOpsService : public IInterface
{
public:
    DECLARE_META_INTERFACE(AppOpsService)

    virtual int32_t checkOperation(int32_t code, int32_t uid, const String16& packageName) = 0;
    virtual int32_t noteOperation(int32_t code, int32_t uid, const String16& packageName,
            const std::optional<String16>& attributionTag, bool shouldCollectAsyncNotedOp,
            const String16& message) = 0;
    virtual int32_t startOperation(const sp<IBinder>& token, int32_t code, int32_t uid,
            const String16& packageName, const std::optional<String16>& attributionTag,
            bool startIfModeDefault, bool shouldCollectAsyncNotedOp, const String16& message) = 0;
    virtual void finishOperation(const sp<IBinder>& token, int32_t code, int32_t uid,
            const String16& packageName, const std::optional<String16>& attributionTag) = 0;
    virtual void startWatchingMode(int32_t op, const String16& packageName,
            const sp<IAppOpsCallback>& callback) = 0;
    virtual void stopWatchingMode(const sp<IAppOpsCallback>& callback) = 0;
    virtual int32_t permissionToOpCode(const String16& permission) = 0;
    virtual int32_t checkAudioOperation(int32_t code, int32_t usage,int32_t uid,
            const String16& packageName) = 0;
    virtual void setCameraAudioRestriction(int32_t mode) = 0;
    virtual bool shouldCollectNotes(int32_t opCode) = 0;

    enum {
        CHECK_OPERATION_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION,
        NOTE_OPERATION_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+1,
        START_OPERATION_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+2,
        FINISH_OPERATION_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+3,
        START_WATCHING_MODE_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+4,
        STOP_WATCHING_MODE_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+5,
        PERMISSION_TO_OP_CODE_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+6,
        CHECK_AUDIO_OPERATION_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+7,
        SHOULD_COLLECT_NOTES_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+8,
        SET_CAMERA_AUDIO_RESTRICTION_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION+9,
    };

    enum {
        MODE_ALLOWED = 0,
        MODE_IGNORED = 1,
        MODE_ERRORED = 2
    };
};

// ----------------------------------------------------------------------

class BnAppOpsService : public BnInterface<IAppOpsService>
{
public:
    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t    onTransact( uint32_t code,
                                    const Parcel& data,
                                    Parcel* reply,
                                    uint32_t flags = 0);
};

// ----------------------------------------------------------------------

} // namespace android
