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

#include "AidlSensorHalWrapper.h"
#include "ISensorsWrapper.h"
#include "SensorDeviceUtils.h"
#include "android/hardware/sensors/2.0/types.h"

#include <aidl/android/hardware/sensors/BnSensorsCallback.h>
#include <aidlcommonsupport/NativeHandle.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <aidl/sensors/convert.h>

using ::aidl::android::hardware::sensors::AdditionalInfo;
using ::aidl::android::hardware::sensors::DynamicSensorInfo;
using ::aidl::android::hardware::sensors::Event;
using ::aidl::android::hardware::sensors::ISensors;
using ::aidl::android::hardware::sensors::SensorInfo;
using ::aidl::android::hardware::sensors::SensorStatus;
using ::aidl::android::hardware::sensors::SensorType;
using ::android::AidlMessageQueue;
using ::android::hardware::EventFlag;
using ::android::hardware::sensors::V2_1::implementation::MAX_RECEIVE_BUFFER_EVENT_COUNT;
using ::android::hardware::sensors::implementation::convertToStatus;
using ::android::hardware::sensors::implementation::convertToSensor;
using ::android::hardware::sensors::implementation::convertToSensorEvent;
using ::android::hardware::sensors::implementation::convertFromSensorEvent;


namespace android {

namespace {

void serviceDied(void *cookie) {
    ALOGW("Sensors HAL died, attempting to reconnect.");
    ((AidlSensorHalWrapper *)cookie)->prepareForReconnect();
}

template <typename EnumType>
constexpr typename std::underlying_type<EnumType>::type asBaseType(EnumType value) {
    return static_cast<typename std::underlying_type<EnumType>::type>(value);
}

enum EventQueueFlagBitsInternal : uint32_t {
    INTERNAL_WAKE = 1 << 16,
};

} // anonymous namespace

class AidlSensorsCallback : public ::aidl::android::hardware::sensors::BnSensorsCallback {
public:
    AidlSensorsCallback(AidlSensorHalWrapper::SensorDeviceCallback *sensorDeviceCallback)
          : mSensorDeviceCallback(sensorDeviceCallback) {}

    ::ndk::ScopedAStatus onDynamicSensorsConnected(
            const std::vector<SensorInfo> &sensorInfos) override {
        std::vector<sensor_t> sensors;
        for (const SensorInfo &sensorInfo : sensorInfos) {
            sensor_t sensor;
            convertToSensor(sensorInfo, &sensor);
            sensors.push_back(sensor);
        }

        mSensorDeviceCallback->onDynamicSensorsConnected(sensors);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onDynamicSensorsDisconnected(
            const std::vector<int32_t> &sensorHandles) override {
        mSensorDeviceCallback->onDynamicSensorsDisconnected(sensorHandles);
        return ::ndk::ScopedAStatus::ok();
    }

private:
    ISensorHalWrapper::SensorDeviceCallback *mSensorDeviceCallback;
};

AidlSensorHalWrapper::AidlSensorHalWrapper()
      : mEventQueueFlag(nullptr),
        mWakeLockQueueFlag(nullptr),
        mDeathRecipient(AIBinder_DeathRecipient_new(serviceDied)) {}

bool AidlSensorHalWrapper::supportsPolling() {
    return false;
}

bool AidlSensorHalWrapper::supportsMessageQueues() {
    return true;
}

bool AidlSensorHalWrapper::connect(SensorDeviceCallback *callback) {
    mSensorDeviceCallback = callback;
    mSensors = nullptr;

    auto aidlServiceName = std::string() + ISensors::descriptor + "/default";
    if (AServiceManager_isDeclared(aidlServiceName.c_str())) {
        if (mSensors != nullptr) {
            AIBinder_unlinkToDeath(mSensors->asBinder().get(), mDeathRecipient.get(), this);
        }

        ndk::SpAIBinder binder(AServiceManager_waitForService(aidlServiceName.c_str()));
        if (binder.get() != nullptr) {
            mSensors = ISensors::fromBinder(binder);
            mEventQueue = std::make_unique<AidlMessageQueue<
                    Event, SynchronizedReadWrite>>(MAX_RECEIVE_BUFFER_EVENT_COUNT,
                                                   /*configureEventFlagWord=*/true);

            mWakeLockQueue = std::make_unique<AidlMessageQueue<
                    int32_t, SynchronizedReadWrite>>(MAX_RECEIVE_BUFFER_EVENT_COUNT,
                                                     /*configureEventFlagWord=*/true);
            if (mEventQueueFlag != nullptr) {
                EventFlag::deleteEventFlag(&mEventQueueFlag);
            }
            EventFlag::createEventFlag(mEventQueue->getEventFlagWord(), &mEventQueueFlag);
            if (mWakeLockQueueFlag != nullptr) {
                EventFlag::deleteEventFlag(&mWakeLockQueueFlag);
            }
            EventFlag::createEventFlag(mWakeLockQueue->getEventFlagWord(), &mWakeLockQueueFlag);

            CHECK(mEventQueue != nullptr && mEventQueueFlag != nullptr &&
                  mWakeLockQueue != nullptr && mWakeLockQueueFlag != nullptr);

            mCallback = ndk::SharedRefBase::make<AidlSensorsCallback>(mSensorDeviceCallback);
            mSensors->initialize(mEventQueue->dupeDesc(), mWakeLockQueue->dupeDesc(), mCallback);

            AIBinder_linkToDeath(mSensors->asBinder().get(), mDeathRecipient.get(), this);
        } else {
            ALOGE("Could not connect to declared sensors AIDL HAL");
        }
    }

    return mSensors != nullptr;
}

void AidlSensorHalWrapper::prepareForReconnect() {
    mReconnecting = true;
    if (mEventQueueFlag != nullptr) {
        mEventQueueFlag->wake(asBaseType(INTERNAL_WAKE));
    }
}

ssize_t AidlSensorHalWrapper::poll(sensors_event_t * /* buffer */, size_t /* count */) {
    return 0;
}

ssize_t AidlSensorHalWrapper::pollFmq(sensors_event_t *buffer, size_t maxNumEventsToRead) {
    ssize_t eventsRead = 0;
    size_t availableEvents = mEventQueue->availableToRead();

    if (availableEvents == 0) {
        uint32_t eventFlagState = 0;

        // Wait for events to become available. This is necessary so that the Event FMQ's read() is
        // able to be called with the correct number of events to read. If the specified number of
        // events is not available, then read() would return no events, possibly introducing
        // additional latency in delivering events to applications.
        if (mEventQueueFlag != nullptr) {
            mEventQueueFlag->wait(asBaseType(ISensors::EVENT_QUEUE_FLAG_BITS_READ_AND_PROCESS) |
                                          asBaseType(INTERNAL_WAKE),
                                  &eventFlagState);
        }
        availableEvents = mEventQueue->availableToRead();

        if ((eventFlagState & asBaseType(INTERNAL_WAKE)) && mReconnecting) {
            ALOGD("Event FMQ internal wake, returning from poll with no events");
            return DEAD_OBJECT;
        }
    }

    size_t eventsToRead = std::min({availableEvents, maxNumEventsToRead, mEventBuffer.size()});
    if (eventsToRead > 0) {
        if (mEventQueue->read(mEventBuffer.data(), eventsToRead)) {
            // Notify the Sensors HAL that sensor events have been read. This is required to support
            // the use of writeBlocking by the Sensors HAL.
            if (mEventQueueFlag != nullptr) {
                mEventQueueFlag->wake(asBaseType(ISensors::EVENT_QUEUE_FLAG_BITS_EVENTS_READ));
            }

            for (size_t i = 0; i < eventsToRead; i++) {
                convertToSensorEvent(mEventBuffer[i], &buffer[i]);
            }
            eventsRead = eventsToRead;
        } else {
            ALOGW("Failed to read %zu events, currently %zu events available", eventsToRead,
                  availableEvents);
        }
    }

    return eventsRead;
}

std::vector<sensor_t> AidlSensorHalWrapper::getSensorsList() {
    std::vector<sensor_t> sensorsFound;

    if (mSensors != nullptr) {
        std::vector<SensorInfo> list;
        mSensors->getSensorsList(&list);
        for (size_t i = 0; i < list.size(); i++) {
            sensor_t sensor;
            convertToSensor(list[i], &sensor);
            sensorsFound.push_back(sensor);
        }
    }

    return sensorsFound;
}

status_t AidlSensorHalWrapper::setOperationMode(SensorService::Mode mode) {
    if (mSensors == nullptr) return NO_INIT;
    return convertToStatus(mSensors->setOperationMode(static_cast<ISensors::OperationMode>(mode)));
}

status_t AidlSensorHalWrapper::activate(int32_t sensorHandle, bool enabled) {
    if (mSensors == nullptr) return NO_INIT;
    return convertToStatus(mSensors->activate(sensorHandle, enabled));
}

status_t AidlSensorHalWrapper::batch(int32_t sensorHandle, int64_t samplingPeriodNs,
                                     int64_t maxReportLatencyNs) {
    if (mSensors == nullptr) return NO_INIT;
    return convertToStatus(mSensors->batch(sensorHandle, samplingPeriodNs, maxReportLatencyNs));
}

status_t AidlSensorHalWrapper::flush(int32_t sensorHandle) {
    if (mSensors == nullptr) return NO_INIT;
    return convertToStatus(mSensors->flush(sensorHandle));
}

status_t AidlSensorHalWrapper::injectSensorData(const sensors_event_t *event) {
    if (mSensors == nullptr) return NO_INIT;

    Event ev;
    convertFromSensorEvent(*event, &ev);
    return convertToStatus(mSensors->injectSensorData(ev));
}

status_t AidlSensorHalWrapper::registerDirectChannel(const sensors_direct_mem_t *memory,
                                                     int32_t *channelHandle) {
    if (mSensors == nullptr) return NO_INIT;

    ISensors::SharedMemInfo::SharedMemType type;
    switch (memory->type) {
        case SENSOR_DIRECT_MEM_TYPE_ASHMEM:
            type = ISensors::SharedMemInfo::SharedMemType::ASHMEM;
            break;
        case SENSOR_DIRECT_MEM_TYPE_GRALLOC:
            type = ISensors::SharedMemInfo::SharedMemType::GRALLOC;
            break;
        default:
            return BAD_VALUE;
    }

    if (memory->format != SENSOR_DIRECT_FMT_SENSORS_EVENT) {
        return BAD_VALUE;
    }
    ISensors::SharedMemInfo::SharedMemFormat format =
            ISensors::SharedMemInfo::SharedMemFormat::SENSORS_EVENT;

    ISensors::SharedMemInfo mem = {
            .type = type,
            .format = format,
            .size = static_cast<int32_t>(memory->size),
            .memoryHandle = dupToAidl(memory->handle),
    };

    return convertToStatus(mSensors->registerDirectChannel(mem, channelHandle));
}

status_t AidlSensorHalWrapper::unregisterDirectChannel(int32_t channelHandle) {
    if (mSensors == nullptr) return NO_INIT;
    return convertToStatus(mSensors->unregisterDirectChannel(channelHandle));
}

status_t AidlSensorHalWrapper::configureDirectChannel(int32_t sensorHandle, int32_t channelHandle,
                                                      const struct sensors_direct_cfg_t *config) {
    if (mSensors == nullptr) return NO_INIT;

    ISensors::RateLevel rate;
    switch (config->rate_level) {
        case SENSOR_DIRECT_RATE_STOP:
            rate = ISensors::RateLevel::STOP;
            break;
        case SENSOR_DIRECT_RATE_NORMAL:
            rate = ISensors::RateLevel::NORMAL;
            break;
        case SENSOR_DIRECT_RATE_FAST:
            rate = ISensors::RateLevel::FAST;
            break;
        case SENSOR_DIRECT_RATE_VERY_FAST:
            rate = ISensors::RateLevel::VERY_FAST;
            break;
        default:
            return BAD_VALUE;
    }

    int32_t token;
    mSensors->configDirectReport(sensorHandle, channelHandle, rate, &token);
    return token;
}

void AidlSensorHalWrapper::writeWakeLockHandled(uint32_t count) {
    int signedCount = (int)count;
    if (mWakeLockQueue->write(&signedCount)) {
        mWakeLockQueueFlag->wake(asBaseType(ISensors::WAKE_LOCK_QUEUE_FLAG_BITS_DATA_WRITTEN));
    } else {
        ALOGW("Failed to write wake lock handled");
    }
}

} // namespace android
