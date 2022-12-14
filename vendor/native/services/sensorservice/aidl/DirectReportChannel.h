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

#include <aidl/android/frameworks/sensorservice/BnDirectReportChannel.h>
#include <aidl/android/hardware/sensors/ISensors.h>
#include <sensor/SensorManager.h>

namespace android {
namespace frameworks {
namespace sensorservice {
namespace implementation {

class DirectReportChannel final
      : public ::aidl::android::frameworks::sensorservice::BnDirectReportChannel {
public:
    DirectReportChannel(::android::SensorManager& manager, int channelId);
    ~DirectReportChannel();

    ndk::ScopedAStatus configure(int32_t sensorHandle,
                                 ::aidl::android::hardware::sensors::ISensors::RateLevel rate,
                                 int32_t* _aidl_return) override;

private:
    ::android::SensorManager& mManager;
    const int mId;
};

} // namespace implementation
} // namespace sensorservice
} // namespace frameworks
} // namespace android
