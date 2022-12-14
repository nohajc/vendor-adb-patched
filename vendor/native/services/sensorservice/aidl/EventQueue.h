/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "SensorManagerAidl.h"

#include <aidl/android/frameworks/sensorservice/BnEventQueue.h>
#include <sensor/SensorManager.h>

namespace android {
namespace frameworks {
namespace sensorservice {
namespace implementation {

struct EventQueue final : public aidl::android::frameworks::sensorservice::BnEventQueue {
    EventQueue(
            std::shared_ptr<aidl::android::frameworks::sensorservice::IEventQueueCallback> callback,
            sp<::android::Looper> looper, sp<::android::SensorEventQueue> internalQueue);
    ~EventQueue();

    ndk::ScopedAStatus enableSensor(int32_t in_sensorHandle, int32_t in_samplingPeriodUs,
                                    int64_t in_maxBatchReportLatencyUs) override;
    ndk::ScopedAStatus disableSensor(int32_t sensorHandle) override;

private:
    friend class EventQueueLooperCallback;
    sp<::android::Looper> mLooper;
    sp<::android::SensorEventQueue> mInternalQueue;
};

} // namespace implementation
} // namespace sensorservice
} // namespace frameworks
} // namespace android
