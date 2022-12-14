/*
 * Copyright 2021 The Android Open Source Project
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

#include <utils/Condition.h>
#include <chrono>
#include <vector>

#include <android/hardware/graphics/composer/2.4/IComposer.h>
#include <composer-hal/2.1/ComposerClient.h>
#include <composer-hal/2.2/ComposerClient.h>
#include <composer-hal/2.3/ComposerClient.h>
#include <composer-hal/2.4/ComposerClient.h>

#include "DisplayHardware/HWC2.h"
#include "surfaceflinger_fuzzers_utils.h"

namespace {
class LayerImpl;
class Frame;
class DelayedEventGenerator;
} // namespace

namespace android {
class SurfaceComposerClient;
} // namespace android

namespace android::hardware::graphics::composer::hal {

using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::HWC2::ComposerCallback;

class ComposerCallbackBridge : public IComposerCallback {
public:
    ComposerCallbackBridge(ComposerCallback* callback, bool vsyncSwitchingSupported)
          : mCallback(callback), mVsyncSwitchingSupported(vsyncSwitchingSupported) {}

    Return<void> onHotplug(HWDisplayId display, Connection connection) override {
        mCallback->onComposerHalHotplug(display, connection);
        return Void();
    }

    Return<void> onRefresh(HWDisplayId display) override {
        mCallback->onComposerHalRefresh(display);
        return Void();
    }

    Return<void> onVsync(HWDisplayId display, int64_t timestamp) override {
        if (!mVsyncSwitchingSupported) {
            mCallback->onComposerHalVsync(display, timestamp, std::nullopt);
        }
        return Void();
    }

    Return<void> onVsync_2_4(HWDisplayId display, int64_t timestamp,
                             VsyncPeriodNanos vsyncPeriodNanos) override {
        if (mVsyncSwitchingSupported) {
            mCallback->onComposerHalVsync(display, timestamp, vsyncPeriodNanos);
        }
        return Void();
    }

    Return<void> onVsyncPeriodTimingChanged(HWDisplayId display,
                                            const VsyncPeriodChangeTimeline& timeline) override {
        mCallback->onComposerHalVsyncPeriodTimingChanged(display, timeline);
        return Void();
    }

    Return<void> onSeamlessPossible(HWDisplayId display) override {
        mCallback->onComposerHalSeamlessPossible(display);
        return Void();
    }

private:
    ComposerCallback* const mCallback;
    const bool mVsyncSwitchingSupported;
};

struct TestHWC2ComposerCallback : public HWC2::ComposerCallback {
    virtual ~TestHWC2ComposerCallback() = default;
    void onComposerHalHotplug(HWDisplayId, Connection){};
    void onComposerHalRefresh(HWDisplayId) {}
    void onComposerHalVsync(HWDisplayId, int64_t, std::optional<VsyncPeriodNanos>) {}
    void onComposerHalVsyncPeriodTimingChanged(HWDisplayId, const VsyncPeriodChangeTimeline&) {}
    void onComposerHalSeamlessPossible(HWDisplayId) {}
    void onComposerHalVsyncIdle(HWDisplayId) {}
};

} // namespace android::hardware::graphics::composer::hal
