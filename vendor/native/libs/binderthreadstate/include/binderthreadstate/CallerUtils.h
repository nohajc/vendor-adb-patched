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

// WARNING: DO NOT USE THIS
// You should:
// - have code know how it is handling things. Pass in caller information rather
//   than assuming that code is running in a specific global context
// - use AIDL exclusively in your stack (HIDL is no longer required anywhere)

#include <binder/IPCThreadState.h>
#include <hwbinder/IPCThreadState.h>

namespace android {

enum class BinderCallType {
    NONE,
    BINDER,
    HWBINDER,
};

// Based on where we are in recursion of nested binder/hwbinder calls, determine
// which one we are closer to.
inline static BinderCallType getCurrentServingCall() {
    auto* hwState = android::hardware::IPCThreadState::selfOrNull();
    auto* state = android::IPCThreadState::selfOrNull();

    // getServingStackPointer can also return nullptr
    const void* hwbinderSp = hwState ? hwState->getServingStackPointer() : nullptr;
    const void* binderSp = state ? state->getServingStackPointer() : nullptr;

    if (hwbinderSp == nullptr && binderSp == nullptr) return BinderCallType::NONE;
    if (hwbinderSp == nullptr) return BinderCallType::BINDER;
    if (binderSp == nullptr) return BinderCallType::HWBINDER;

    if (hwbinderSp < binderSp) return BinderCallType::HWBINDER;
    return BinderCallType::BINDER;
}

} // namespace android
