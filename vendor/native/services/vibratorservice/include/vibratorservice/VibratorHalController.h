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

#ifndef ANDROID_OS_VIBRATORHALCONTROLLER_H
#define ANDROID_OS_VIBRATORHALCONTROLLER_H

#include <android-base/thread_annotations.h>
#include <android/hardware/vibrator/IVibrator.h>

#include <vibratorservice/VibratorCallbackScheduler.h>
#include <vibratorservice/VibratorHalWrapper.h>

namespace android {

namespace vibrator {

std::shared_ptr<HalWrapper> connectHal(std::shared_ptr<CallbackScheduler> scheduler);

template <typename T>
using HalFunction = std::function<T(HalWrapper*)>;

// Controller for Vibrator HAL handle.
// This relies on a given Connector to connect to the underlying Vibrator HAL service and reconnects
// after each failed api call. This also ensures connecting to the service is thread-safe.
class HalController {
public:
    using Connector =
            std::function<std::shared_ptr<HalWrapper>(std::shared_ptr<CallbackScheduler>)>;

    HalController() : HalController(std::make_shared<CallbackScheduler>(), &connectHal) {}
    HalController(std::shared_ptr<CallbackScheduler> callbackScheduler, Connector connector)
          : mConnector(connector),
            mConnectedHal(nullptr),
            mCallbackScheduler(std::move(callbackScheduler)) {}
    virtual ~HalController() = default;

    /* Connects to the newest HAL version available, possibly waiting for the registered service to
     * become available. This will automatically be called at the first API usage if it was not
     * manually called beforehand. Calling this manually during the setup phase can avoid slowing
     * the first API call later on. Returns true if any HAL version is available, false otherwise.
     */
    virtual bool init();

    /* Reloads HAL service instance without waiting. This relies on the HAL version found by init()
     * to rapidly reconnect to the specific HAL service, or defers to init() if it was never called.
     */
    virtual void tryReconnect();

    /* Returns info loaded from the connected HAL. This allows partial results to be returned if any
     * of the Info fields has failed, but also retried on any failure.
     */
    Info getInfo() {
        static Info sDefaultInfo = InfoCache().get();
        return apply<Info>([](HalWrapper* hal) { return hal->getInfo(); }, sDefaultInfo, "getInfo");
    }

    /* Calls given HAL function, applying automatic retries to reconnect with the HAL when the
     * result has failed. Parameter functionName is for logging purposes.
     */
    template <typename T>
    HalResult<T> doWithRetry(const HalFunction<HalResult<T>>& halFn, const char* functionName) {
        return apply(halFn, HalResult<T>::unsupported(), functionName);
    }

private:
    static constexpr int MAX_RETRIES = 1;

    Connector mConnector;
    std::mutex mConnectedHalMutex;
    // Shared pointer to allow local copies to be used by different threads.
    std::shared_ptr<HalWrapper> mConnectedHal GUARDED_BY(mConnectedHalMutex);
    // Shared pointer to allow copies to be passed to possible recreated mConnectedHal instances.
    std::shared_ptr<CallbackScheduler> mCallbackScheduler;

    /* Calls given HAL function, applying automatic retries to reconnect with the HAL when the
     * result has failed. Given default value is returned when no HAL is available, and given
     * function name is for logging purposes.
     */
    template <typename T>
    T apply(const HalFunction<T>& halFn, T defaultValue, const char* functionName) {
        if (!init()) {
            ALOGV("Skipped %s because Vibrator HAL is not available", functionName);
            return defaultValue;
        }
        std::shared_ptr<HalWrapper> hal;
        {
            std::lock_guard<std::mutex> lock(mConnectedHalMutex);
            hal = mConnectedHal;
        }

        for (int i = 0; i < MAX_RETRIES; i++) {
            T result = halFn(hal.get());
            if (result.checkAndLogFailure(functionName)) {
                tryReconnect();
            } else {
                return result;
            }
        }

        return halFn(hal.get());
    }
};

}; // namespace vibrator

}; // namespace android

#endif // ANDROID_OS_VIBRATORHALCONTROLLER_H
