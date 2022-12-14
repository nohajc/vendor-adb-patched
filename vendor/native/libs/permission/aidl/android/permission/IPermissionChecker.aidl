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

package android.permission;

import android.content.AttributionSourceState;

/**
 * Interface to communicate directly with the permission checker service.
 */
interface IPermissionChecker {
    const int PERMISSION_GRANTED = 0;
    const int PERMISSION_SOFT_DENIED = 1;
    const int PERMISSION_HARD_DENIED = 2;

    int checkPermission(String permission, in AttributionSourceState attributionSource,
            @nullable String message, boolean forDataDelivery, boolean startDataDelivery,
            boolean fromDatasource, int attributedOp);

    void finishDataDelivery(int op, in AttributionSourceState attributionSource,
            boolean fromDatasource);

    int checkOp(int op, in AttributionSourceState attributionSource,
            String message, boolean forDataDelivery, boolean startDataDelivery);
}
