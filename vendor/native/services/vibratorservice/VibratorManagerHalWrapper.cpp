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

#define LOG_TAG "VibratorManagerHalWrapper"

#include <utils/Log.h>

#include <vibratorservice/VibratorManagerHalWrapper.h>

namespace Aidl = android::hardware::vibrator;

namespace android {

namespace vibrator {

constexpr int32_t SINGLE_VIBRATOR_ID = 0;
const constexpr char* MISSING_VIBRATOR_MESSAGE_PREFIX = "No vibrator with id=";

HalResult<void> LegacyManagerHalWrapper::ping() {
    auto pingFn = [](HalWrapper* hal) { return hal->ping(); };
    return mController->doWithRetry<void>(pingFn, "ping");
}

void LegacyManagerHalWrapper::tryReconnect() {
    mController->tryReconnect();
}

HalResult<ManagerCapabilities> LegacyManagerHalWrapper::getCapabilities() {
    return HalResult<ManagerCapabilities>::ok(ManagerCapabilities::NONE);
}

HalResult<std::vector<int32_t>> LegacyManagerHalWrapper::getVibratorIds() {
    if (mController->init()) {
        return HalResult<std::vector<int32_t>>::ok(std::vector<int32_t>(1, SINGLE_VIBRATOR_ID));
    }
    // Controller.init did not connect to any vibrator HAL service, so the device has no vibrator.
    return HalResult<std::vector<int32_t>>::ok(std::vector<int32_t>());
}

HalResult<std::shared_ptr<HalController>> LegacyManagerHalWrapper::getVibrator(int32_t id) {
    if (id == SINGLE_VIBRATOR_ID && mController->init()) {
        return HalResult<std::shared_ptr<HalController>>::ok(mController);
    }
    // Controller.init did not connect to any vibrator HAL service, so the device has no vibrator.
    return HalResult<std::shared_ptr<HalController>>::failed(MISSING_VIBRATOR_MESSAGE_PREFIX +
                                                             std::to_string(id));
}

HalResult<void> LegacyManagerHalWrapper::prepareSynced(const std::vector<int32_t>&) {
    return HalResult<void>::unsupported();
}

HalResult<void> LegacyManagerHalWrapper::triggerSynced(const std::function<void()>&) {
    return HalResult<void>::unsupported();
}

HalResult<void> LegacyManagerHalWrapper::cancelSynced() {
    return HalResult<void>::unsupported();
}

// -------------------------------------------------------------------------------------------------

std::shared_ptr<HalWrapper> AidlManagerHalWrapper::connectToVibrator(
        int32_t vibratorId, std::shared_ptr<CallbackScheduler> callbackScheduler) {
    std::function<HalResult<sp<Aidl::IVibrator>>()> reconnectFn = [=]() {
        sp<Aidl::IVibrator> vibrator;
        auto result = this->getHal()->getVibrator(vibratorId, &vibrator);
        return HalResult<sp<Aidl::IVibrator>>::fromStatus(result, vibrator);
    };
    auto result = reconnectFn();
    if (!result.isOk()) {
        return nullptr;
    }
    auto vibrator = result.value();
    if (!vibrator) {
        return nullptr;
    }
    return std::move(std::make_unique<AidlHalWrapper>(std::move(callbackScheduler),
                                                      std::move(vibrator), reconnectFn));
}

HalResult<void> AidlManagerHalWrapper::ping() {
    return HalResult<void>::fromStatus(IInterface::asBinder(getHal())->pingBinder());
}

void AidlManagerHalWrapper::tryReconnect() {
    sp<Aidl::IVibratorManager> newHandle = checkVintfService<Aidl::IVibratorManager>();
    if (newHandle) {
        std::lock_guard<std::mutex> lock(mHandleMutex);
        mHandle = std::move(newHandle);
    }
}

HalResult<ManagerCapabilities> AidlManagerHalWrapper::getCapabilities() {
    std::lock_guard<std::mutex> lock(mCapabilitiesMutex);
    if (mCapabilities.has_value()) {
        // Return copy of cached value.
        return HalResult<ManagerCapabilities>::ok(*mCapabilities);
    }
    int32_t cap = 0;
    auto result = getHal()->getCapabilities(&cap);
    auto ret = HalResult<ManagerCapabilities>::fromStatus(result,
                                                          static_cast<ManagerCapabilities>(cap));
    if (ret.isOk()) {
        // Cache copy of returned value.
        mCapabilities.emplace(ret.value());
    }
    return ret;
}

HalResult<std::vector<int32_t>> AidlManagerHalWrapper::getVibratorIds() {
    std::lock_guard<std::mutex> lock(mVibratorsMutex);
    if (mVibratorIds.has_value()) {
        // Return copy of cached values.
        return HalResult<std::vector<int32_t>>::ok(*mVibratorIds);
    }
    std::vector<int32_t> ids;
    auto result = getHal()->getVibratorIds(&ids);
    auto ret = HalResult<std::vector<int32_t>>::fromStatus(result, ids);
    if (ret.isOk()) {
        // Cache copy of returned value and the individual controllers.
        mVibratorIds.emplace(ret.value());
        for (auto& id : ids) {
            HalController::Connector connector = [&, id](auto scheduler) {
                return this->connectToVibrator(id, scheduler);
            };
            auto controller = std::make_unique<HalController>(mCallbackScheduler, connector);
            mVibrators[id] = std::move(controller);
        }
    }
    return ret;
}

HalResult<std::shared_ptr<HalController>> AidlManagerHalWrapper::getVibrator(int32_t id) {
    // Make sure we cache vibrator ids and initialize the individual controllers.
    getVibratorIds();
    std::lock_guard<std::mutex> lock(mVibratorsMutex);
    auto it = mVibrators.find(id);
    if (it != mVibrators.end()) {
        return HalResult<std::shared_ptr<HalController>>::ok(it->second);
    }
    return HalResult<std::shared_ptr<HalController>>::failed(MISSING_VIBRATOR_MESSAGE_PREFIX +
                                                             std::to_string(id));
}

HalResult<void> AidlManagerHalWrapper::prepareSynced(const std::vector<int32_t>& ids) {
    auto ret = HalResult<void>::fromStatus(getHal()->prepareSynced(ids));
    if (ret.isOk()) {
        // Force reload of all vibrator controllers that were prepared for a sync operation here.
        // This will trigger calls to getVibrator(id) on each controller, so they can use the
        // latest service provided by this manager.
        std::lock_guard<std::mutex> lock(mVibratorsMutex);
        for (auto& id : ids) {
            auto it = mVibrators.find(id);
            if (it != mVibrators.end()) {
                it->second->tryReconnect();
            }
        }
    }
    return ret;
}

HalResult<void> AidlManagerHalWrapper::triggerSynced(
        const std::function<void()>& completionCallback) {
    HalResult<ManagerCapabilities> capabilities = getCapabilities();
    bool supportsCallback = capabilities.isOk() &&
            static_cast<int32_t>(capabilities.value() & ManagerCapabilities::TRIGGER_CALLBACK);
    auto cb = supportsCallback ? new HalCallbackWrapper(completionCallback) : nullptr;
    return HalResult<void>::fromStatus(getHal()->triggerSynced(cb));
}

HalResult<void> AidlManagerHalWrapper::cancelSynced() {
    auto ret = HalResult<void>::fromStatus(getHal()->cancelSynced());
    if (ret.isOk()) {
        // Force reload of all vibrator controllers that were prepared for a sync operation before.
        // This will trigger calls to getVibrator(id) on each controller, so they can use the
        // latest service provided by this manager.
        std::lock_guard<std::mutex> lock(mVibratorsMutex);
        for (auto& entry : mVibrators) {
            entry.second->tryReconnect();
        }
    }
    return ret;
}

sp<Aidl::IVibratorManager> AidlManagerHalWrapper::getHal() {
    std::lock_guard<std::mutex> lock(mHandleMutex);
    return mHandle;
}

}; // namespace vibrator

}; // namespace android
