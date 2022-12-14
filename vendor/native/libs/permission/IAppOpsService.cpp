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

#define LOG_TAG "AppOpsService"

#include <binder/IAppOpsService.h>

#include <utils/Log.h>
#include <binder/Parcel.h>
#include <utils/String8.h>

#include <optional>

namespace android {

// ----------------------------------------------------------------------

class BpAppOpsService : public BpInterface<IAppOpsService>
{
public:
    explicit BpAppOpsService(const sp<IBinder>& impl)
        : BpInterface<IAppOpsService>(impl)
    {
    }

    virtual int32_t checkOperation(int32_t code, int32_t uid, const String16& packageName) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeInt32(code);
        data.writeInt32(uid);
        data.writeString16(packageName);
        remote()->transact(CHECK_OPERATION_TRANSACTION, data, &reply);
        // fail on exception
        if (reply.readExceptionCode() != 0) return MODE_ERRORED;
        return reply.readInt32();
    }

    virtual int32_t noteOperation(int32_t code, int32_t uid, const String16& packageName,
                const std::optional<String16>& attributionTag, bool shouldCollectAsyncNotedOp,
                const String16& message) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeInt32(code);
        data.writeInt32(uid);
        data.writeString16(packageName);
        data.writeString16(attributionTag);
        data.writeInt32(shouldCollectAsyncNotedOp ? 1 : 0);
        data.writeString16(message);
        remote()->transact(NOTE_OPERATION_TRANSACTION, data, &reply);
        // fail on exception
        if (reply.readExceptionCode() != 0) return MODE_ERRORED;
        return reply.readInt32();
    }

    virtual int32_t startOperation(const sp<IBinder>& token, int32_t code, int32_t uid,
                const String16& packageName, const std::optional<String16>& attributionTag,
                bool startIfModeDefault, bool shouldCollectAsyncNotedOp, const String16& message) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        data.writeInt32(code);
        data.writeInt32(uid);
        data.writeString16(packageName);
        data.writeString16(attributionTag);
        data.writeInt32(startIfModeDefault ? 1 : 0);
        data.writeInt32(shouldCollectAsyncNotedOp ? 1 : 0);
        data.writeString16(message);
        remote()->transact(START_OPERATION_TRANSACTION, data, &reply);
        // fail on exception
        if (reply.readExceptionCode() != 0) return MODE_ERRORED;
        return reply.readInt32();
    }

    virtual void finishOperation(const sp<IBinder>& token, int32_t code, int32_t uid,
            const String16& packageName, const std::optional<String16>& attributionTag) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        data.writeInt32(code);
        data.writeInt32(uid);
        data.writeString16(packageName);
        data.writeString16(attributionTag);
        remote()->transact(FINISH_OPERATION_TRANSACTION, data, &reply);
    }

    virtual void startWatchingMode(int32_t op, const String16& packageName,
            const sp<IAppOpsCallback>& callback) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeInt32(op);
        data.writeString16(packageName);
        data.writeStrongBinder(IInterface::asBinder(callback));
        remote()->transact(START_WATCHING_MODE_TRANSACTION, data, &reply);
    }

    virtual void stopWatchingMode(const sp<IAppOpsCallback>& callback) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeStrongBinder(IInterface::asBinder(callback));
        remote()->transact(STOP_WATCHING_MODE_TRANSACTION, data, &reply);
    }

    virtual int32_t permissionToOpCode(const String16& permission) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeString16(permission);
        remote()->transact(PERMISSION_TO_OP_CODE_TRANSACTION, data, &reply);
        // fail on exception
        if (reply.readExceptionCode() != 0) return -1;
        return reply.readInt32();
    }

    virtual int32_t checkAudioOperation(int32_t code, int32_t usage,
            int32_t uid, const String16& packageName) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeInt32(code);
        data.writeInt32(usage);
        data.writeInt32(uid);
        data.writeString16(packageName);
        remote()->transact(CHECK_AUDIO_OPERATION_TRANSACTION, data, &reply);
        // fail on exception
        if (reply.readExceptionCode() != 0) {
            return MODE_ERRORED;
        }
        return reply.readInt32();
    }

    virtual void setCameraAudioRestriction(int32_t mode) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeInt32(mode);
        remote()->transact(SET_CAMERA_AUDIO_RESTRICTION_TRANSACTION, data, &reply);
    }

    virtual bool shouldCollectNotes(int32_t opCode) {
        Parcel data, reply;
        data.writeInterfaceToken(IAppOpsService::getInterfaceDescriptor());
        data.writeInt32(opCode);
        remote()->transact(SHOULD_COLLECT_NOTES_TRANSACTION, data, &reply);
        // fail on exception
        if (reply.readExceptionCode() != 0) {
            return false;
        }
        return reply.readBool();
    }
};

IMPLEMENT_META_INTERFACE(AppOpsService, "com.android.internal.app.IAppOpsService")

// ----------------------------------------------------------------------

// NOLINTNEXTLINE(google-default-arguments)
status_t BnAppOpsService::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    //printf("AppOpsService received: "); data.print();
    switch(code) {
        case CHECK_OPERATION_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            int32_t code = data.readInt32();
            int32_t uid = data.readInt32();
            String16 packageName = data.readString16();
            int32_t res = checkOperation(code, uid, packageName);
            reply->writeNoException();
            reply->writeInt32(res);
            return NO_ERROR;
        } break;
        case NOTE_OPERATION_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            int32_t code = data.readInt32();
            int32_t uid = data.readInt32();
            String16 packageName = data.readString16();
            std::optional<String16> attributionTag;
            data.readString16(&attributionTag);
            bool shouldCollectAsyncNotedOp = data.readInt32() == 1;
            String16 message = data.readString16();
            int32_t res = noteOperation(code, uid, packageName, attributionTag,
                    shouldCollectAsyncNotedOp, message);
            reply->writeNoException();
            reply->writeInt32(res);
            return NO_ERROR;
        } break;
        case START_OPERATION_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            sp<IBinder> token = data.readStrongBinder();
            int32_t code = data.readInt32();
            int32_t uid = data.readInt32();
            String16 packageName = data.readString16();
            std::optional<String16> attributionTag;
            data.readString16(&attributionTag);
            bool startIfModeDefault = data.readInt32() == 1;
            bool shouldCollectAsyncNotedOp = data.readInt32() == 1;
            String16 message = data.readString16();
            int32_t res = startOperation(token, code, uid, packageName, attributionTag,
                    startIfModeDefault, shouldCollectAsyncNotedOp, message);
            reply->writeNoException();
            reply->writeInt32(res);
            return NO_ERROR;
        } break;
        case FINISH_OPERATION_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            sp<IBinder> token = data.readStrongBinder();
            int32_t code = data.readInt32();
            int32_t uid = data.readInt32();
            String16 packageName = data.readString16();
            std::optional<String16> attributionTag;
            data.readString16(&attributionTag);
            finishOperation(token, code, uid, packageName, attributionTag);
            reply->writeNoException();
            return NO_ERROR;
        } break;
        case START_WATCHING_MODE_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            int32_t op = data.readInt32();
            String16 packageName = data.readString16();
            sp<IAppOpsCallback> callback = interface_cast<IAppOpsCallback>(data.readStrongBinder());
            startWatchingMode(op, packageName, callback);
            reply->writeNoException();
            return NO_ERROR;
        } break;
        case STOP_WATCHING_MODE_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            sp<IAppOpsCallback> callback = interface_cast<IAppOpsCallback>(data.readStrongBinder());
            stopWatchingMode(callback);
            reply->writeNoException();
            return NO_ERROR;
        } break;
        case PERMISSION_TO_OP_CODE_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            String16 permission = data.readString16();
            const int32_t opCode = permissionToOpCode(permission);
            reply->writeNoException();
            reply->writeInt32(opCode);
            return NO_ERROR;
        } break;
        case CHECK_AUDIO_OPERATION_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            const int32_t code = data.readInt32();
            const int32_t usage = data.readInt32();
            const int32_t uid = data.readInt32();
            const String16 packageName = data.readString16();
            const int32_t res = checkAudioOperation(code, usage, uid, packageName);
            reply->writeNoException();
            reply->writeInt32(res);
            return NO_ERROR;
        } break;
        case SET_CAMERA_AUDIO_RESTRICTION_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            const int32_t mode = data.readInt32();
            setCameraAudioRestriction(mode);
            reply->writeNoException();
            return NO_ERROR;
        } break;
        case SHOULD_COLLECT_NOTES_TRANSACTION: {
            CHECK_INTERFACE(IAppOpsService, data, reply);
            int32_t opCode = data.readInt32();
            bool shouldCollect = shouldCollectNotes(opCode);
            reply->writeNoException();
            reply->writeBool(shouldCollect);
            return NO_ERROR;
        } break;
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

} // namespace android
