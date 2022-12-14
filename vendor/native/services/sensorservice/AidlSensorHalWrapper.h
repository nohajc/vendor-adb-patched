/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_AIDL_SENSOR_HAL_WRAPPER_H
#define ANDROID_AIDL_SENSOR_HAL_WRAPPER_H

#include "ISensorHalWrapper.h"

#include <aidl/android/hardware/sensors/ISensors.h>
#include <fmq/AidlMessageQueue.h>
#include <sensor/SensorEventQueue.h>

namespace android {

class AidlSensorHalWrapper : public ISensorHalWrapper {
public:
    AidlSensorHalWrapper();

    ~AidlSensorHalWrapper() override {
        if (mEventQueueFlag != nullptr) {
            ::android::hardware::EventFlag::deleteEventFlag(&mEventQueueFlag);
            mEventQueueFlag = nullptr;
        }
        if (mWakeLockQueueFlag != nullptr) {
            ::android::hardware::EventFlag::deleteEventFlag(&mWakeLockQueueFlag);
            mWakeLockQueueFlag = nullptr;
        }
    }

    virtual bool connect(SensorDeviceCallback *callback) override;

    virtual void prepareForReconnect() override;

    virtual bool supportsPolling() override;

    virtual bool supportsMessageQueues() override;

    virtual ssize_t poll(sensors_event_t *buffer, size_t count) override;

    virtual ssize_t pollFmq(sensors_event_t *buffer, size_t count) override;

    virtual std::vector<sensor_t> getSensorsList() override;

    virtual status_t setOperationMode(SensorService::Mode mode) override;

    virtual status_t activate(int32_t sensorHandle, bool enabled) override;

    virtual status_t batch(int32_t sensorHandle, int64_t samplingPeriodNs,
                           int64_t maxReportLatencyNs) override;

    virtual status_t flush(int32_t sensorHandle) override;

    virtual status_t injectSensorData(const sensors_event_t *event) override;

    virtual status_t registerDirectChannel(const sensors_direct_mem_t *memory,
                                           int32_t *channelHandle) override;

    virtual status_t unregisterDirectChannel(int32_t channelHandle) override;

    virtual status_t configureDirectChannel(int32_t sensorHandle, int32_t channelHandle,
                                            const struct sensors_direct_cfg_t *config) override;

    virtual void writeWakeLockHandled(uint32_t count) override;

private:
    std::shared_ptr<aidl::android::hardware::sensors::ISensors> mSensors;
    std::shared_ptr<::aidl::android::hardware::sensors::ISensorsCallback> mCallback;
    std::unique_ptr<::android::AidlMessageQueue<::aidl::android::hardware::sensors::Event,
                                                SynchronizedReadWrite>>
            mEventQueue;
    std::unique_ptr<::android::AidlMessageQueue<int, SynchronizedReadWrite>> mWakeLockQueue;
    ::android::hardware::EventFlag *mEventQueueFlag;
    ::android::hardware::EventFlag *mWakeLockQueueFlag;
    SensorDeviceCallback *mSensorDeviceCallback;
    std::array<::aidl::android::hardware::sensors::Event,
               ::android::SensorEventQueue::MAX_RECEIVE_BUFFER_EVENT_COUNT>
            mEventBuffer;

    ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
};

} // namespace android

#endif // ANDROID_AIDL_SENSOR_HAL_WRAPPER_H
