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

#define LOG_TAG "PowerHalLoader"

#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/IPower.h>
#include <binder/IServiceManager.h>
#include <hardware/power.h>
#include <hardware_legacy/power.h>
#include <powermanager/PowerHalLoader.h>

using namespace android::hardware::power;

namespace android {

namespace power {

// -------------------------------------------------------------------------------------------------

template <typename T, typename F>
sp<T> loadHal(bool& exists, sp<T>& hal, F& loadFn, const char* halName) {
    if (!exists) {
        return nullptr;
    }
    if (hal) {
        return hal;
    }
    hal = loadFn();
    if (hal) {
        ALOGV("Successfully connected to Power HAL %s service.", halName);
    } else {
        ALOGV("Power HAL %s service not available.", halName);
        exists = false;
    }
    return hal;
}

// -------------------------------------------------------------------------------------------------

std::mutex PowerHalLoader::gHalMutex;
sp<IPower> PowerHalLoader::gHalAidl = nullptr;
sp<V1_0::IPower> PowerHalLoader::gHalHidlV1_0 = nullptr;
sp<V1_1::IPower> PowerHalLoader::gHalHidlV1_1 = nullptr;

void PowerHalLoader::unloadAll() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    gHalAidl = nullptr;
    gHalHidlV1_0 = nullptr;
    gHalHidlV1_1 = nullptr;
}

sp<IPower> PowerHalLoader::loadAidl() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    static bool gHalExists = true;
    static auto loadFn = []() { return waitForVintfService<IPower>(); };
    return loadHal<IPower>(gHalExists, gHalAidl, loadFn, "AIDL");
}

sp<V1_0::IPower> PowerHalLoader::loadHidlV1_0() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    return loadHidlV1_0Locked();
}

sp<V1_1::IPower> PowerHalLoader::loadHidlV1_1() {
    std::lock_guard<std::mutex> lock(gHalMutex);
    static bool gHalExists = true;
    static auto loadFn = []() { return V1_1::IPower::castFrom(loadHidlV1_0Locked()); };
    return loadHal<V1_1::IPower>(gHalExists, gHalHidlV1_1, loadFn, "HIDL v1.1");
}

sp<V1_0::IPower> PowerHalLoader::loadHidlV1_0Locked() {
    static bool gHalExists = true;
    static auto loadFn = []() { return V1_0::IPower::getService(); };
    return loadHal<V1_0::IPower>(gHalExists, gHalHidlV1_0, loadFn, "HIDL v1.0");
}

// -------------------------------------------------------------------------------------------------

} // namespace power

} // namespace android
