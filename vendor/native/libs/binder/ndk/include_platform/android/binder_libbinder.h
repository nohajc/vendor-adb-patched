/*
 * Copyright (C) 2020 The Android Open Source Project
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

#if !defined(__ANDROID_APEX__) && !defined(__ANDROID_VNDK__)

#include <android/binder_ibinder.h>
#include <binder/IBinder.h>

/**
 * Get libbinder version of binder from AIBinder.
 *
 * WARNING: function calls to a local object on the other side of this function
 * will parcel. When converting between binders, keep in mind it is not as
 * efficient as a direct function call.
 *
 * \param binder binder with ownership retained by the client
 * \return platform binder object
 */
android::sp<android::IBinder> AIBinder_toPlatformBinder(AIBinder* binder);

/**
 * Get libbinder_ndk version of binder from platform binder.
 *
 * WARNING: function calls to a local object on the other side of this function
 * will parcel. When converting between binders, keep in mind it is not as
 * efficient as a direct function call.
 *
 * \param binder platform binder which may be from anywhere (doesn't have to be
 * created with libbinder_ndK)
 * \return binder with one reference count of ownership given to the client. See
 * AIBinder_decStrong
 */
AIBinder* AIBinder_fromPlatformBinder(const android::sp<android::IBinder>& binder);

#endif
