/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <mutex>
#include <include/android/permission/PermissionChecker.h>
#include <binder/Binder.h>
#include <binder/IServiceManager.h>

#include <utils/SystemClock.h>

#include <sys/types.h>
#include <private/android_filesystem_config.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "PermissionChecker"

namespace android::permission {

using android::content::AttributionSourceState;

PermissionChecker::PermissionChecker()
{
}

sp<android::permission::IPermissionChecker> PermissionChecker::getService()
{
    static String16 permission_checker("permission_checker");

    std::lock_guard<Mutex> scoped_lock(mLock);
    int64_t startTime = 0;
    sp<IPermissionChecker> service = mService;
    while (service == nullptr || !IInterface::asBinder(service)->isBinderAlive()) {
        sp<IBinder> binder = defaultServiceManager()->checkService(permission_checker);
        if (binder == nullptr) {
            // Wait for the permission checker service to come back...
            if (startTime == 0) {
                startTime = uptimeMillis();
                ALOGW("Waiting for permission checker service");
            } else if ((uptimeMillis() - startTime) > 10000) {
                ALOGE("Waiting too long for permission checker service, giving up");
                service = nullptr;
                break;
            }
            sleep(1);
        } else {
            mService = interface_cast<IPermissionChecker>(binder);
            break;
        }
    }
    return mService;
}

PermissionChecker::PermissionResult PermissionChecker::checkPermissionForDataDeliveryFromDatasource(
        const String16& permission, const AttributionSourceState& attributionSource,
        const String16& message, int32_t attributedOpCode)
{
    return checkPermission(permission, attributionSource, message, /*forDataDelivery*/ true,
            /*startDataDelivery*/ false,/*fromDatasource*/ true, attributedOpCode);
}

PermissionChecker::PermissionResult
        PermissionChecker::checkPermissionForStartDataDeliveryFromDatasource(
        const String16& permission, const AttributionSourceState& attributionSource,
        const String16& message, int32_t attributedOpCode)
{
    return checkPermission(permission, attributionSource, message, /*forDataDelivery*/ true,
            /*startDataDelivery*/ true, /*fromDatasource*/ true, attributedOpCode);
}

PermissionChecker::PermissionResult PermissionChecker::checkPermissionForPreflight(
        const String16& permission, const AttributionSourceState& attributionSource,
        const String16& message, int32_t attributedOpCode)
{
    return checkPermission(permission, attributionSource, message, /*forDataDelivery*/ false,
            /*startDataDelivery*/ false, /*fromDatasource*/ false, attributedOpCode);
}

PermissionChecker::PermissionResult PermissionChecker::checkPermissionForPreflightFromDatasource(
        const String16& permission, const AttributionSourceState& attributionSource,
        const String16& message, int32_t attributedOpCode)
{
    return checkPermission(permission, attributionSource, message, /*forDataDelivery*/ false,
            /*startDataDelivery*/ false, /*fromDatasource*/ true, attributedOpCode);
}

void PermissionChecker::finishDataDeliveryFromDatasource(int32_t op,
        const AttributionSourceState& attributionSource)
{
    sp<IPermissionChecker> service = getService();
    if (service != nullptr) {
        binder::Status status = service->finishDataDelivery(op, attributionSource,
                /*fromDatasource*/ true);
        if (!status.isOk()) {
            ALOGE("finishDataDelivery failed: %s", status.exceptionMessage().c_str());
        }
    }
}

PermissionChecker::PermissionResult PermissionChecker::checkPermission(const String16& permission,
        const AttributionSourceState& attributionSource, const String16& message,
        bool forDataDelivery, bool startDataDelivery, bool fromDatasource,
        int32_t attributedOpCode)
{
    sp<IPermissionChecker> service = getService();
    if (service != nullptr) {
        int32_t result;
        binder::Status status = service->checkPermission(permission, attributionSource, message,
                forDataDelivery, startDataDelivery, fromDatasource, attributedOpCode, &result);
        if (status.isOk()) {
            return static_cast<PermissionResult>(result);
        }
        ALOGE("checkPermission failed: %s", status.exceptionMessage().c_str());
    }
    return PERMISSION_HARD_DENIED;
}

} // namespace android::permission
