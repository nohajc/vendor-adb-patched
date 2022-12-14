/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <android/binder_stability.h>

#include <binder/Stability.h>
#include "ibinder_internal.h"

#include <log/log.h>

using ::android::internal::Stability;

#ifdef __ANDROID_VNDK__
#error libbinder_ndk should only be built in a system context
#endif

#ifdef __ANDROID_NDK__
#error libbinder_ndk should only be built in a system context
#endif

// explicit extern because symbol is only declared in header when __ANDROID_VENDOR__
extern "C" void AIBinder_markVendorStability(AIBinder* binder) {
    Stability::markVndk(binder->getBinder().get());
}

void AIBinder_markSystemStability(AIBinder* binder) {
    Stability::markCompilationUnit(binder->getBinder().get());
}

void AIBinder_markVintfStability(AIBinder* binder) {
    Stability::markVintf(binder->getBinder().get());
}

// explicit extern because symbol is only declared in header when __ANDROID_VENDOR__
extern "C" void AIBinder_forceDowngradeToVendorStability(AIBinder* binder) {
    Stability::forceDowngradeToVendorStability(binder->getBinder());
}

void AIBinder_forceDowngradeToSystemStability(AIBinder* binder) {
    Stability::forceDowngradeToSystemStability(binder->getBinder());
}
