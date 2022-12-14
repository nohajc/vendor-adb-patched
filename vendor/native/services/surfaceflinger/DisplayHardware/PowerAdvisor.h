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

#pragma once

#include <atomic>
#include <unordered_set>

#include <utils/Mutex.h>

#include "../Scheduler/OneShotTimer.h"
#include "DisplayIdentification.h"

namespace android {
namespace Hwc2 {

class PowerAdvisor {
public:
    virtual ~PowerAdvisor();

    virtual void onBootFinished() = 0;
    virtual void setExpensiveRenderingExpected(DisplayId displayId, bool expected) = 0;
    virtual void notifyDisplayUpdateImminent() = 0;
};

namespace impl {

// PowerAdvisor is a wrapper around IPower HAL which takes into account the
// full state of the system when sending out power hints to things like the GPU.
class PowerAdvisor final : public Hwc2::PowerAdvisor {
public:
    class HalWrapper {
    public:
        virtual ~HalWrapper() = default;

        virtual bool setExpensiveRendering(bool enabled) = 0;
        virtual bool notifyDisplayUpdateImminent() = 0;
    };

    PowerAdvisor();
    ~PowerAdvisor() override;

    void onBootFinished() override;
    void setExpensiveRenderingExpected(DisplayId displayId, bool expected) override;
    void notifyDisplayUpdateImminent() override;

private:
    HalWrapper* getPowerHal() REQUIRES(mPowerHalMutex);
    bool mReconnectPowerHal GUARDED_BY(mPowerHalMutex) = false;
    std::mutex mPowerHalMutex;

    std::atomic_bool mBootFinished = false;

    std::unordered_set<DisplayId> mExpensiveDisplays;
    bool mNotifiedExpensiveRendering = false;

    const bool mUseUpdateImminentTimer;
    std::atomic_bool mSendUpdateImminent = true;
    scheduler::OneShotTimer mUpdateImminentTimer;
};

} // namespace impl
} // namespace Hwc2
} // namespace android
