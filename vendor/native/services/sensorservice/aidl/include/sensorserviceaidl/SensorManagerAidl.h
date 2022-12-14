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

#include <aidl/android/frameworks/sensorservice/BnSensorManager.h>
#include <jni.h>
#include <sensor/SensorManager.h>
#include <utils/Looper.h>
#include <mutex>
#include <thread>

namespace android {
namespace frameworks {
namespace sensorservice {
namespace implementation {

class SensorManagerAidl : public ::aidl::android::frameworks::sensorservice::BnSensorManager {
public:
    explicit SensorManagerAidl(JavaVM* vm);
    ~SensorManagerAidl();

    ::ndk::ScopedAStatus createAshmemDirectChannel(
            const ::aidl::android::hardware::common::Ashmem& in_mem, int64_t in_size,
            std::shared_ptr<::aidl::android::frameworks::sensorservice::IDirectReportChannel>*
                    _aidl_return) override;
    ::ndk::ScopedAStatus createEventQueue(
            const std::shared_ptr<::aidl::android::frameworks::sensorservice::IEventQueueCallback>&
                    in_callback,
            std::shared_ptr<::aidl::android::frameworks::sensorservice::IEventQueue>* _aidl_return)
            override;
    ::ndk::ScopedAStatus createGrallocDirectChannel(
            const ::ndk::ScopedFileDescriptor& in_buffer, int64_t in_size,
            std::shared_ptr<::aidl::android::frameworks::sensorservice::IDirectReportChannel>*
                    _aidl_return) override;
    ::ndk::ScopedAStatus getDefaultSensor(
            ::aidl::android::hardware::sensors::SensorType in_type,
            ::aidl::android::hardware::sensors::SensorInfo* _aidl_return) override;
    ::ndk::ScopedAStatus getSensorList(
            std::vector<::aidl::android::hardware::sensors::SensorInfo>* _aidl_return) override;

private:
    // Block until ::android::SensorManager is initialized.
    ::android::SensorManager& getInternalManager();
    sp<Looper> getLooper();

    std::mutex mInternalManagerMutex;
    ::android::SensorManager* mInternalManager = nullptr; // does not own
    sp<Looper> mLooper;

    volatile bool mStopThread;
    std::mutex mThreadMutex; // protects mPollThread
    std::thread mPollThread;

    JavaVM* mJavaVm;
};

} // namespace implementation
} // namespace sensorservice
} // namespace frameworks
} // namespace android
