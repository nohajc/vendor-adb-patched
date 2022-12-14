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

#ifndef ANDROID_HIDL_SENSOR_HAL_WRAPPER_H
#define ANDROID_HIDL_SENSOR_HAL_WRAPPER_H

#include <sensor/SensorEventQueue.h>
#include <utils/Singleton.h>

#include "ISensorHalWrapper.h"

#include "ISensorsWrapper.h"
#include "SensorDeviceUtils.h"

namespace android {

using android::hardware::sensors::V1_0::Result;
using android::hardware::sensors::V2_1::Event;
using android::hardware::sensors::V2_1::SensorInfo;

class HidlTransportErrorLog {
public:
    HidlTransportErrorLog() {
        mTs = 0;
        mCount = 0;
    }

    HidlTransportErrorLog(time_t ts, int count) {
        mTs = ts;
        mCount = count;
    }

    String8 toString() const {
        String8 result;
        struct tm* timeInfo = localtime(&mTs);
        result.appendFormat("%02d:%02d:%02d :: %d", timeInfo->tm_hour, timeInfo->tm_min,
                            timeInfo->tm_sec, mCount);
        return result;
    }

private:
    time_t mTs; // timestamp of the error
    int mCount; // number of transport errors observed
};

class SensorsHalDeathReceiver : public android::hardware::hidl_death_recipient {
public:
    SensorsHalDeathReceiver(ISensorHalWrapper* wrapper) : mHidlSensorHalWrapper(wrapper) {}

    virtual void serviceDied(uint64_t cookie,
                             const wp<::android::hidl::base::V1_0::IBase>& service) override;

private:
    ISensorHalWrapper* mHidlSensorHalWrapper;
};

class HidlSensorHalWrapper : public ISensorHalWrapper {
public:
    HidlSensorHalWrapper()
          : mHidlTransportErrors(20),
            mTotalHidlTransportErrors(0),
            mRestartWaiter(new SensorDeviceUtils::HidlServiceRegistrationWaiter()),
            mEventQueueFlag(nullptr),
            mWakeLockQueueFlag(nullptr) {}

    ~HidlSensorHalWrapper() override {
        if (mEventQueueFlag != nullptr) {
            hardware::EventFlag::deleteEventFlag(&mEventQueueFlag);
            mEventQueueFlag = nullptr;
        }
        if (mWakeLockQueueFlag != nullptr) {
            hardware::EventFlag::deleteEventFlag(&mWakeLockQueueFlag);
            mWakeLockQueueFlag = nullptr;
        }
    }
    virtual bool connect(SensorDeviceCallback* callback) override;

    virtual void prepareForReconnect() override;

    virtual bool supportsPolling() override;

    virtual bool supportsMessageQueues() override;

    virtual ssize_t poll(sensors_event_t* buffer, size_t count) override;

    virtual ssize_t pollFmq(sensors_event_t* buffer, size_t count) override;

    virtual std::vector<sensor_t> getSensorsList() override;

    virtual status_t setOperationMode(SensorService::Mode mode) override;

    virtual status_t activate(int32_t sensorHandle, bool enabled) override;

    virtual status_t batch(int32_t sensorHandle, int64_t samplingPeriodNs,
                           int64_t maxReportLatencyNs) override;

    virtual status_t flush(int32_t sensorHandle) override;

    virtual status_t injectSensorData(const sensors_event_t* event) override;

    virtual status_t registerDirectChannel(const sensors_direct_mem_t* memory,
                                           int32_t* outChannelHandle) override;

    virtual status_t unregisterDirectChannel(int32_t channelHandle) override;

    virtual status_t configureDirectChannel(int32_t sensorHandle, int32_t channelHandle,
                                            const struct sensors_direct_cfg_t* config) override;

    virtual void writeWakeLockHandled(uint32_t count) override;

private:
    sp<::android::hardware::sensors::V2_1::implementation::ISensorsWrapperBase> mSensors;
    sp<::android::hardware::sensors::V2_1::ISensorsCallback> mCallback;

    // Keep track of any hidl transport failures
    SensorServiceUtil::RingBuffer<HidlTransportErrorLog> mHidlTransportErrors;
    int mTotalHidlTransportErrors;

    SensorDeviceCallback* mSensorDeviceCallback = nullptr;

    // TODO(b/67425500): remove waiter after bug is resolved.
    sp<SensorDeviceUtils::HidlServiceRegistrationWaiter> mRestartWaiter;

    template <typename T>
    void checkReturn(const hardware::Return<T>& ret) {
        if (!ret.isOk()) {
            handleHidlDeath(ret.description());
        }
    }

    status_t checkReturnAndGetStatus(const hardware::Return<Result>& ret);

    void handleHidlDeath(const std::string& detail);

    void convertToSensorEvent(const Event& src, sensors_event_t* dst);

    void convertToSensorEvents(const hardware::hidl_vec<Event>& src,
                               const hardware::hidl_vec<SensorInfo>& dynamicSensorsAdded,
                               sensors_event_t* dst);

    bool connectHidlService();

    HalConnectionStatus connectHidlServiceV1_0();
    HalConnectionStatus connectHidlServiceV2_0();
    HalConnectionStatus connectHidlServiceV2_1();
    HalConnectionStatus initializeHidlServiceV2_X();

    typedef hardware::MessageQueue<uint32_t, hardware::kSynchronizedReadWrite> WakeLockQueue;
    std::unique_ptr<WakeLockQueue> mWakeLockQueue;

    hardware::EventFlag* mEventQueueFlag;
    hardware::EventFlag* mWakeLockQueueFlag;

    std::array<Event, SensorEventQueue::MAX_RECEIVE_BUFFER_EVENT_COUNT> mEventBuffer;

    sp<SensorsHalDeathReceiver> mSensorsHalDeathReceiver;
};

} // namespace android

#endif // ANDROID_HIDL_SENSOR_HAL_WRAPPER_H
