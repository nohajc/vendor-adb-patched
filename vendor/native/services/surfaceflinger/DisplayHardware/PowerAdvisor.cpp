/*
 * Copyright 2018 The Android Open Source Project
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

//#define LOG_NDEBUG 0

#undef LOG_TAG
#define LOG_TAG "PowerAdvisor"

#include <cinttypes>

#include <android-base/properties.h>
#include <utils/Log.h>
#include <utils/Mutex.h>

#include <android/hardware/power/1.3/IPower.h>
#include <android/hardware/power/IPower.h>
#include <binder/IServiceManager.h>

#include "../SurfaceFlingerProperties.h"

#include "PowerAdvisor.h"

namespace android {
namespace Hwc2 {

PowerAdvisor::~PowerAdvisor() = default;

namespace impl {

namespace V1_0 = android::hardware::power::V1_0;
namespace V1_3 = android::hardware::power::V1_3;
using V1_3::PowerHint;

using android::hardware::power::Boost;
using android::hardware::power::IPower;
using android::hardware::power::Mode;
using base::GetIntProperty;
using scheduler::OneShotTimer;

PowerAdvisor::~PowerAdvisor() = default;

namespace {
int32_t getUpdateTimeout() {
    // Default to a timeout of 80ms if nothing else is specified
    static int32_t timeout = sysprop::display_update_imminent_timeout_ms(80);
    return timeout;
}

} // namespace

PowerAdvisor::PowerAdvisor()
      : mUseUpdateImminentTimer(getUpdateTimeout() > 0),
        mUpdateImminentTimer(
                OneShotTimer::Interval(getUpdateTimeout()),
                /* resetCallback */ [this] { mSendUpdateImminent.store(false); },
                /* timeoutCallback */ [this] { mSendUpdateImminent.store(true); }) {
    if (mUseUpdateImminentTimer) {
        mUpdateImminentTimer.start();
    }
}

void PowerAdvisor::onBootFinished() {
    mBootFinished.store(true);
}

void PowerAdvisor::setExpensiveRenderingExpected(DisplayId displayId, bool expected) {
    if (expected) {
        mExpensiveDisplays.insert(displayId);
    } else {
        mExpensiveDisplays.erase(displayId);
    }

    const bool expectsExpensiveRendering = !mExpensiveDisplays.empty();
    if (mNotifiedExpensiveRendering != expectsExpensiveRendering) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper == nullptr) {
            return;
        }

        if (!halWrapper->setExpensiveRendering(expectsExpensiveRendering)) {
            // The HAL has become unavailable; attempt to reconnect later
            mReconnectPowerHal = true;
            return;
        }

        mNotifiedExpensiveRendering = expectsExpensiveRendering;
    }
}

void PowerAdvisor::notifyDisplayUpdateImminent() {
    // Only start sending this notification once the system has booted so we don't introduce an
    // early-boot dependency on Power HAL
    if (!mBootFinished.load()) {
        return;
    }

    if (mSendUpdateImminent.load()) {
        std::lock_guard lock(mPowerHalMutex);
        HalWrapper* const halWrapper = getPowerHal();
        if (halWrapper == nullptr) {
            return;
        }

        if (!halWrapper->notifyDisplayUpdateImminent()) {
            // The HAL has become unavailable; attempt to reconnect later
            mReconnectPowerHal = true;
            return;
        }
    }

    if (mUseUpdateImminentTimer) {
        mUpdateImminentTimer.reset();
    }
}

class HidlPowerHalWrapper : public PowerAdvisor::HalWrapper {
public:
    HidlPowerHalWrapper(sp<V1_3::IPower> powerHal) : mPowerHal(std::move(powerHal)) {}

    ~HidlPowerHalWrapper() override = default;

    static std::unique_ptr<HalWrapper> connect() {
        // Power HAL 1.3 is not guaranteed to be available, thus we need to query
        // Power HAL 1.0 first and try to cast it to Power HAL 1.3.
        sp<V1_3::IPower> powerHal = nullptr;
        sp<V1_0::IPower> powerHal_1_0 = V1_0::IPower::getService();
        if (powerHal_1_0 != nullptr) {
            // Try to cast to Power HAL 1.3
            powerHal = V1_3::IPower::castFrom(powerHal_1_0);
            if (powerHal == nullptr) {
                ALOGW("No Power HAL 1.3 service in system, disabling PowerAdvisor");
            } else {
                ALOGI("Loaded Power HAL 1.3 service");
            }
        } else {
            ALOGW("No Power HAL found, disabling PowerAdvisor");
        }

        if (powerHal == nullptr) {
            return nullptr;
        }

        return std::make_unique<HidlPowerHalWrapper>(std::move(powerHal));
    }

    bool setExpensiveRendering(bool enabled) override {
        ALOGV("HIDL setExpensiveRendering %s", enabled ? "T" : "F");
        auto ret = mPowerHal->powerHintAsync_1_3(PowerHint::EXPENSIVE_RENDERING, enabled);
        return ret.isOk();
    }

    bool notifyDisplayUpdateImminent() override {
        // Power HAL 1.x doesn't have a notification for this
        ALOGV("HIDL notifyUpdateImminent received but can't send");
        return true;
    }

private:
    const sp<V1_3::IPower> mPowerHal = nullptr;
};

class AidlPowerHalWrapper : public PowerAdvisor::HalWrapper {
public:
    AidlPowerHalWrapper(sp<IPower> powerHal) : mPowerHal(std::move(powerHal)) {
        auto ret = mPowerHal->isModeSupported(Mode::EXPENSIVE_RENDERING, &mHasExpensiveRendering);
        if (!ret.isOk()) {
            mHasExpensiveRendering = false;
        }

        ret = mPowerHal->isBoostSupported(Boost::DISPLAY_UPDATE_IMMINENT,
                                          &mHasDisplayUpdateImminent);
        if (!ret.isOk()) {
            mHasDisplayUpdateImminent = false;
        }
    }

    ~AidlPowerHalWrapper() override = default;

    static std::unique_ptr<HalWrapper> connect() {
        // This only waits if the service is actually declared
        sp<IPower> powerHal = waitForVintfService<IPower>();
        if (powerHal == nullptr) {
            return nullptr;
        }
        ALOGI("Loaded AIDL Power HAL service");

        return std::make_unique<AidlPowerHalWrapper>(std::move(powerHal));
    }

    bool setExpensiveRendering(bool enabled) override {
        ALOGV("AIDL setExpensiveRendering %s", enabled ? "T" : "F");
        if (!mHasExpensiveRendering) {
            ALOGV("Skipped sending EXPENSIVE_RENDERING because HAL doesn't support it");
            return true;
        }

        auto ret = mPowerHal->setMode(Mode::EXPENSIVE_RENDERING, enabled);
        return ret.isOk();
    }

    bool notifyDisplayUpdateImminent() override {
        ALOGV("AIDL notifyDisplayUpdateImminent");
        if (!mHasDisplayUpdateImminent) {
            ALOGV("Skipped sending DISPLAY_UPDATE_IMMINENT because HAL doesn't support it");
            return true;
        }

        auto ret = mPowerHal->setBoost(Boost::DISPLAY_UPDATE_IMMINENT, 0);
        return ret.isOk();
    }

private:
    const sp<IPower> mPowerHal = nullptr;
    bool mHasExpensiveRendering = false;
    bool mHasDisplayUpdateImminent = false;
};

PowerAdvisor::HalWrapper* PowerAdvisor::getPowerHal() {
    static std::unique_ptr<HalWrapper> sHalWrapper = nullptr;
    static bool sHasHal = true;

    if (!sHasHal) {
        return nullptr;
    }

    // If we used to have a HAL, but it stopped responding, attempt to reconnect
    if (mReconnectPowerHal) {
        sHalWrapper = nullptr;
        mReconnectPowerHal = false;
    }

    if (sHalWrapper != nullptr) {
        return sHalWrapper.get();
    }

    // First attempt to connect to the AIDL Power HAL
    sHalWrapper = AidlPowerHalWrapper::connect();

    // If that didn't succeed, attempt to connect to the HIDL Power HAL
    if (sHalWrapper == nullptr) {
        sHalWrapper = HidlPowerHalWrapper::connect();
    }

    // If we make it to this point and still don't have a HAL, it's unlikely we
    // will, so stop trying
    if (sHalWrapper == nullptr) {
        sHasHal = false;
    }

    return sHalWrapper.get();
}

} // namespace impl
} // namespace Hwc2
} // namespace android
