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

#ifndef ANDROID_OS_VIBRATOR_MANAGER_HAL_CONTROLLER_H
#define ANDROID_OS_VIBRATOR_MANAGER_HAL_CONTROLLER_H

#include <android/hardware/vibrator/IVibratorManager.h>
#include <vibratorservice/VibratorHalController.h>
#include <vibratorservice/VibratorManagerHalWrapper.h>
#include <unordered_map>

namespace android {

namespace vibrator {

std::shared_ptr<ManagerHalWrapper> connectManagerHal(std::shared_ptr<CallbackScheduler> scheduler);

// Controller for VibratorManager HAL handle.
class ManagerHalController : public ManagerHalWrapper {
public:
    using Connector =
            std::function<std::shared_ptr<ManagerHalWrapper>(std::shared_ptr<CallbackScheduler>)>;

    ManagerHalController()
          : ManagerHalController(std::make_shared<CallbackScheduler>(), &connectManagerHal) {}
    ManagerHalController(std::shared_ptr<CallbackScheduler> callbackScheduler, Connector connector)
          : mConnector(connector), mCallbackScheduler(callbackScheduler), mConnectedHal(nullptr) {}
    virtual ~ManagerHalController() = default;

    /* Connects to the HAL service, possibly waiting for the registered service to
     * become available. This will automatically be called at the first API usage if it was not
     * manually called beforehand. Calling this manually during the setup phase can avoid slowing
     * the first API call later on. This will fallback to a legacy manager implementation if the
     * service is not available.
     */
    virtual void init();

    /* reloads HAL service instance without waiting. This relies on the HAL found by init()
     * to rapidly reconnect to the specific HAL service, or defers to init() if it was never called.
     */
    void tryReconnect() override final;

    HalResult<void> ping() override final;

    HalResult<ManagerCapabilities> getCapabilities() override final;
    HalResult<std::vector<int32_t>> getVibratorIds() override final;
    HalResult<std::shared_ptr<HalController>> getVibrator(int32_t id) override final;

    HalResult<void> prepareSynced(const std::vector<int32_t>& ids) override final;
    HalResult<void> triggerSynced(const std::function<void()>& completionCallback) override final;
    HalResult<void> cancelSynced() override final;

private:
    Connector mConnector;
    std::shared_ptr<CallbackScheduler> mCallbackScheduler;
    std::mutex mConnectedHalMutex;
    // Shared pointer to allow local copies to be used by different threads.
    std::shared_ptr<ManagerHalWrapper> mConnectedHal GUARDED_BY(mConnectedHalMutex);

    template <typename T>
    HalResult<T> processHalResult(HalResult<T> result, const char* functionName);

    template <typename T>
    using hal_fn = std::function<HalResult<T>(std::shared_ptr<ManagerHalWrapper>)>;

    template <typename T>
    HalResult<T> apply(hal_fn<T>& halFn, const char* functionName);
};

}; // namespace vibrator

}; // namespace android

#endif // ANDROID_OS_VIBRATOR_MANAGER_HAL_CONTROLLER_H
