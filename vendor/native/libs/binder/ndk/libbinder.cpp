/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <android/binder_libbinder.h>

#include "ibinder_internal.h"
#include "parcel_internal.h"

using ::android::IBinder;
using ::android::Parcel;
using ::android::sp;

sp<IBinder> AIBinder_toPlatformBinder(AIBinder* binder) {
    if (binder == nullptr) return nullptr;
    return binder->getBinder();
}

AIBinder* AIBinder_fromPlatformBinder(const sp<IBinder>& binder) {
    sp<AIBinder> ndkBinder = ABpBinder::lookupOrCreateFromBinder(binder);
    AIBinder_incStrong(ndkBinder.get());
    return ndkBinder.get();
}

Parcel* AParcel_viewPlatformParcel(AParcel* parcel) {
    return parcel->get();
}

const Parcel* AParcel_viewPlatformParcel(const AParcel* parcel) {
    return parcel->get();
}
