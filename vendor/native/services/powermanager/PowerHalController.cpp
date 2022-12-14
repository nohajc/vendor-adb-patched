/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *                        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "PowerHalController"
#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/IPowerHintSession.h>
#include <android/hardware/power/Mode.h>
#include <powermanager/PowerHalController.h>
#include <powermanager/PowerHalLoader.h>
#include <utils/Log.h>

using namespace android::hardware::power;

namespace android {

namespace power {

// -------------------------------------------------------------------------------------------------

std::unique_ptr<HalWrapper> HalConnector::connect() {
    sp<IPower> halAidl = PowerHalLoader::loadAidl();
    if (halAidl) {
        return std::make_unique<AidlHalWrapper>(halAidl);
    }
    sp<V1_0::IPower> halHidlV1_0 = PowerHalLoader::loadHidlV1_0();
    sp<V1_1::IPower> halHidlV1_1 = PowerHalLoader::loadHidlV1_1();
    if (halHidlV1_1) {
        return std::make_unique<HidlHalWrapperV1_1>(halHidlV1_0, halHidlV1_1);
    }
    if (halHidlV1_0) {
        return std::make_unique<HidlHalWrapperV1_0>(halHidlV1_0);
    }
    return nullptr;
}

void HalConnector::reset() {
    PowerHalLoader::unloadAll();
}

// -------------------------------------------------------------------------------------------------

void PowerHalController::init() {
    initHal();
}

// Check validity of current handle to the power HAL service, and create a new
// one if necessary.
std::shared_ptr<HalWrapper> PowerHalController::initHal() {
    std::lock_guard<std::mutex> lock(mConnectedHalMutex);
    if (mConnectedHal == nullptr) {
        mConnectedHal = mHalConnector->connect();
        if (mConnectedHal == nullptr) {
            // Unable to connect to Power HAL service. Fallback to default.
            return mDefaultHal;
        }
    }
    return mConnectedHal;
}

// Check if a call to Power HAL function failed; if so, log the failure and
// invalidate the current Power HAL handle.
template <typename T>
HalResult<T> PowerHalController::processHalResult(HalResult<T> result, const char* fnName) {
    if (result.isFailed()) {
        ALOGE("%s failed: %s", fnName, result.errorMessage());
        std::lock_guard<std::mutex> lock(mConnectedHalMutex);
        // Drop Power HAL handle. This will force future api calls to reconnect.
        mConnectedHal = nullptr;
        mHalConnector->reset();
    }
    return result;
}

HalResult<void> PowerHalController::setBoost(Boost boost, int32_t durationMs) {
    std::shared_ptr<HalWrapper> handle = initHal();
    auto result = handle->setBoost(boost, durationMs);
    return processHalResult(result, "setBoost");
}

HalResult<void> PowerHalController::setMode(Mode mode, bool enabled) {
    std::shared_ptr<HalWrapper> handle = initHal();
    auto result = handle->setMode(mode, enabled);
    return processHalResult(result, "setMode");
}

HalResult<sp<IPowerHintSession>> PowerHalController::createHintSession(
        int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds, int64_t durationNanos) {
    std::shared_ptr<HalWrapper> handle = initHal();
    auto result = handle->createHintSession(tgid, uid, threadIds, durationNanos);
    return processHalResult(result, "createHintSession");
}

HalResult<int64_t> PowerHalController::getHintSessionPreferredRate() {
    std::shared_ptr<HalWrapper> handle = initHal();
    auto result = handle->getHintSessionPreferredRate();
    return processHalResult(result, "getHintSessionPreferredRate");
}

} // namespace power

} // namespace android
