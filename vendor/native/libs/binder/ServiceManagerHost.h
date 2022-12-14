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

#include <android-base/macros.h>
#include <android/os/IServiceManager.h>

namespace android {

struct RpcDelegateServiceManagerOptions;

// Get a service on device by running servicedispatcher with the given args, e.g.
//     getDeviceService({"foo"});
// Return nullptr on any error.
// When the returned binder object is destroyed, remove adb forwarding and kills
// the long-running servicedispatcher process.
sp<IBinder> getDeviceService(std::vector<std::string>&& serviceDispatcherArgs,
                             const RpcDelegateServiceManagerOptions& options);

} // namespace android
