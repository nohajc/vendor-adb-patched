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

#ifndef ANDROID_POWERHALCONTROLLER_H
#define ANDROID_POWERHALCONTROLLER_H

#include <android-base/thread_annotations.h>
#include <android/hardware/power/Boost.h>
#include <android/hardware/power/IPower.h>
#include <android/hardware/power/IPowerHintSession.h>
#include <android/hardware/power/Mode.h>
#include <powermanager/PowerHalWrapper.h>

namespace android {

namespace power {

// -------------------------------------------------------------------------------------------------

// Connects to underlying Power HAL handles.
class HalConnector {
public:
    HalConnector() = default;
    virtual ~HalConnector() = default;

    virtual std::unique_ptr<HalWrapper> connect();
    virtual void reset();
};

// -------------------------------------------------------------------------------------------------

// Controller for Power HAL handle.
// This relies on HalConnector to connect to the underlying Power HAL
// service and reconnects to it after each failed api call. This also ensures
// connecting to the service is thread-safe.
class PowerHalController : public HalWrapper {
public:
    PowerHalController() : PowerHalController(std::make_unique<HalConnector>()) {}
    explicit PowerHalController(std::unique_ptr<HalConnector> connector)
          : mHalConnector(std::move(connector)) {}
    virtual ~PowerHalController() = default;

    void init();

    virtual HalResult<void> setBoost(hardware::power::Boost boost, int32_t durationMs) override;
    virtual HalResult<void> setMode(hardware::power::Mode mode, bool enabled) override;
    virtual HalResult<sp<hardware::power::IPowerHintSession>> createHintSession(
            int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
            int64_t durationNanos) override;
    virtual HalResult<int64_t> getHintSessionPreferredRate() override;

private:
    std::mutex mConnectedHalMutex;
    std::unique_ptr<HalConnector> mHalConnector;

    // Shared pointers to keep global pointer and allow local copies to be used in
    // different threads
    std::shared_ptr<HalWrapper> mConnectedHal GUARDED_BY(mConnectedHalMutex) = nullptr;
    const std::shared_ptr<HalWrapper> mDefaultHal = std::make_shared<EmptyHalWrapper>();

    std::shared_ptr<HalWrapper> initHal();
    template <typename T>
    HalResult<T> processHalResult(HalResult<T> result, const char* functionName);
};

// -------------------------------------------------------------------------------------------------

}; // namespace power

}; // namespace android

#endif // ANDROID_POWERHALCONTROLLER_H
