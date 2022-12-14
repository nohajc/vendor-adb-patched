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

#pragma once

#include <android/content/AttributionSourceState.h>
#include <android/permission/IPermissionChecker.h>

#include <utils/threads.h>

#include <optional>

#ifdef __ANDROID_VNDK__
#error "This header is not visible to vendors"
#endif

// ---------------------------------------------------------------------------
namespace android {

namespace permission {

using android::content::AttributionSourceState;
using android::permission::IPermissionChecker;

class PermissionChecker
{
public:

    enum PermissionResult {

        /**
         * The permission is granted.
         */
        PERMISSION_GRANTED = IPermissionChecker::PERMISSION_GRANTED,

        /**
         * The permission is denied. Applicable only to runtime and app op permissions.
         *
         * Returned when:
         *   - the runtime permission is granted, but the corresponding app op is denied
         *       for runtime permissions.
         *   - the app ops is ignored for app op permissions.
         *
         */
        PERMISSION_SOFT_DENIED = IPermissionChecker::PERMISSION_SOFT_DENIED,

        /**
         * The permission is denied.
         *
         * Returned when:
         *  - the permission is denied for non app op permissions.
         *  - the app op is denied or app op is AppOpsManager#MODE_DEFAULT and permission is denied.
         */
        PERMISSION_HARD_DENIED = IPermissionChecker::PERMISSION_HARD_DENIED
    };

    PermissionChecker();

    /**
     * Checks whether a given data access chain described by the given attribution source
     * has a given permission and whether the app op that corresponds to this permission
     * is allowed. Call this method if you are the datasource which would not blame you for
     * access to the data since you are the data.  Use this API if you are the datasource of
     * the protected state.
     *
     * NOTE: The attribution source should be for yourself with its next attribution
     * source being the app that would receive the data from you.
     *
     * NOTE: Use this method only for permission checks at the point where you will deliver
     * the permission protected data to clients.
     *
     * @param permission The permission to check.
     * @param attributionSource The attribution chain to check.
     * @param message A message describing the reason the permission was checked.
     * @param attributedOpCode The op code towards which to blame the access. If this
     *     is a valid app op the op corresponding to the checked permission (if such)
     *     would only be checked to ensure it is allowed and if that succeeds the
     *     noting would be against the attributed op.
     * @return The permission check result which is either PERMISSION_GRANTED,
     *     or PERMISSION_SOFT_DENIED or PERMISSION_HARD_DENIED.
     */
    PermissionChecker::PermissionResult checkPermissionForDataDeliveryFromDatasource(
            const String16& permission, const AttributionSourceState& attributionSource,
            const String16& message, int32_t attributedOpCode);

   /**
     * Checks whether a given data access chain described by the given attribution source
     * has a given permission and whether the app op that corresponds to this permission
     * is allowed. The app ops are not noted/started.
     *
     * NOTE: Use this method only for permission checks at the preflight point where you
     * will not deliver the permission protected data to clients but schedule permission
     * data delivery, apps register listeners, etc.
     *
     * @param permission The permission to check.
     * @param attributionSource The attribution chain to check.
     * @param message A message describing the reason the permission was checked.
     * @param attributedOpCode The op code towards which to blame the access. If this
     *     is a valid app op the op corresponding to the checked permission (if such)
     *     would only be checked to ensure it is allowed and if that succeeds the
     *     starting would be against the attributed op.
     * @return The permission check result which is either PERMISSION_GRANTED,
     *     or PERMISSION_SOFT_DENIED or PERMISSION_HARD_DENIED.
     */
    PermissionResult checkPermissionForPreflight(
            const String16& permission, const AttributionSourceState& attributionSource,
            const String16& message, int32_t attributedOpCode);

   /**
     * Checks whether a given data access chain described by the given attribution source
     * has a given permission and whether the app op that corresponds to this permission
     * is allowed. The app ops are not noted/started.
     *
     * NOTE: The attribution source should be for yourself with its next attribution
     * source being the app that would receive the data from you.
     *
     * NOTE: Use this method only for permission checks at the preflight point where you
     * will not deliver the permission protected data to clients but schedule permission
     * data delivery, apps register listeners, etc.
     *
     * @param permission The permission to check.
     * @param attributionSource The attribution chain to check.
     * @param message A message describing the reason the permission was checked.
     * @param attributedOpCode The op code towards which to blame the access. If this
     *     is a valid app op the op corresponding to the checked permission (if such)
     *     would only be checked to ensure it is allowed and if that succeeds the
     *     starting would be against the attributed op.
     * @return The permission check result which is either PERMISSION_GRANTED,
     *     or PERMISSION_SOFT_DENIED or PERMISSION_HARD_DENIED.
     */
    PermissionResult checkPermissionForPreflightFromDatasource(
            const String16& permission, const AttributionSourceState& attributionSource,
            const String16& message, int32_t attributedOpCode);

   /**
     * Checks whether a given data access chain described by the given attribution source
     * has a given permission and whether the app op that corresponds to this permission
     * is allowed. The app ops are also marked as started. This is useful for long running
     * permissions like camera and microphone. Use this API if you are the datasource of
     * the protected state.
     *
     * NOTE: The attribution source should be for yourself with its next attribution
     * source being the app that would receive the data from you.
     *
     * NOTE: Use this method only for permission checks at the point where you will deliver
     * the permission protected data to clients.
     *
     * @param permission The permission to check.
     * @param attributionSource The attribution chain to check.
     * @param message A message describing the reason the permission was checked.
     * @param attributedOpCode The op code towards which to blame the access. If this
     *     is a valid app op the op corresponding to the checked permission (if such)
     *     would only be checked to ensure it is allowed and if that succeeds the
     *     starting would be against the attributed op.
     * @return The permission check result which is either PERMISSION_GRANTED,
     *     or PERMISSION_SOFT_DENIED or PERMISSION_HARD_DENIED.
     */
    PermissionResult checkPermissionForStartDataDeliveryFromDatasource(
            const String16& permission, const AttributionSourceState& attributionSource,
            const String16& message, int32_t attributedOpCode);

    /**
     * Finishes an ongoing op for data access chain described by the given
     * attribution source. Use this API if you are the datasource of the protected
     * state. Use this API if you are the datasource of the protected state.
     *
     * NOTE: The attribution source should be for yourself with its next attribution
     * source being the app that would receive the data from you.
     *
     * @param op The op to finish.
     * @param attributionSource The attribution chain for which to finish data delivery.
     * @param attributedOpCode The op code towards which to blame the access. If this
     *     is a valid app op it is the op that would be finished.
     */
    void finishDataDeliveryFromDatasource(int32_t op,
            const AttributionSourceState& attributionSource);

private:
    Mutex mLock;
    sp<IPermissionChecker> mService;
    sp<IPermissionChecker> getService();

    PermissionResult checkPermission(const String16& permission,
            const AttributionSourceState& attributionSource,
            const String16& message, bool forDataDelivery, bool startDataDelivery,
            bool fromDatasource, int32_t attributedOpCode);
};

} // namespace permission

} // namespace android

// ---------------------------------------------------------------------------
