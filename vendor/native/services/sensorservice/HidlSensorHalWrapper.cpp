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

#include "HidlSensorHalWrapper.h"
#include "android/hardware/sensors/2.0/types.h"
#include "android/hardware/sensors/2.1/ISensorsCallback.h"
#include "android/hardware/sensors/2.1/types.h"
#include "convertV2_1.h"

#include <android-base/logging.h>

using android::hardware::hidl_vec;
using android::hardware::sensors::V1_0::RateLevel;
using android::hardware::sensors::V1_0::Result;
using android::hardware::sensors::V1_0::SharedMemFormat;
using android::hardware::sensors::V1_0::SharedMemInfo;
using android::hardware::sensors::V1_0::SharedMemType;
using android::hardware::sensors::V2_0::EventQueueFlagBits;
using android::hardware::sensors::V2_0::WakeLockQueueFlagBits;
using android::hardware::sensors::V2_1::Event;
using android::hardware::sensors::V2_1::ISensorsCallback;
using android::hardware::sensors::V2_1::implementation::convertFromSensorEvent;
using android::hardware::sensors::V2_1::implementation::convertToNewEvents;
using android::hardware::sensors::V2_1::implementation::convertToNewSensorInfos;
using android::hardware::sensors::V2_1::implementation::convertToSensor;
using android::hardware::sensors::V2_1::implementation::ISensorsWrapperV1_0;
using android::hardware::sensors::V2_1::implementation::ISensorsWrapperV2_0;
using android::hardware::sensors::V2_1::implementation::ISensorsWrapperV2_1;

namespace android {

namespace {

status_t statusFromResult(Result result) {
    switch (result) {
        case Result::OK:
            return OK;
        case Result::BAD_VALUE:
            return BAD_VALUE;
        case Result::PERMISSION_DENIED:
            return PERMISSION_DENIED;
        case Result::INVALID_OPERATION:
            return INVALID_OPERATION;
        case Result::NO_MEMORY:
            return NO_MEMORY;
    }
}

template <typename EnumType>
constexpr typename std::underlying_type<EnumType>::type asBaseType(EnumType value) {
    return static_cast<typename std::underlying_type<EnumType>::type>(value);
}

enum EventQueueFlagBitsInternal : uint32_t {
    INTERNAL_WAKE = 1 << 16,
};

} // anonymous namespace

void SensorsHalDeathReceiver::serviceDied(
        uint64_t /* cookie */, const wp<::android::hidl::base::V1_0::IBase>& /* service */) {
    ALOGW("Sensors HAL died, attempting to reconnect.");
    mHidlSensorHalWrapper->prepareForReconnect();
}

struct HidlSensorsCallback : public ISensorsCallback {
    using Result = ::android::hardware::sensors::V1_0::Result;
    using SensorInfo = ::android::hardware::sensors::V2_1::SensorInfo;

    HidlSensorsCallback(ISensorHalWrapper::SensorDeviceCallback* sensorDeviceCallback) {
        mSensorDeviceCallback = sensorDeviceCallback;
    }

    Return<void> onDynamicSensorsConnected_2_1(
            const hidl_vec<SensorInfo>& dynamicSensorsAdded) override {
        std::vector<sensor_t> sensors;
        for (const android::hardware::sensors::V2_1::SensorInfo& info : dynamicSensorsAdded) {
            sensor_t sensor;
            convertToSensor(info, &sensor);
            sensors.push_back(sensor);
        }

        mSensorDeviceCallback->onDynamicSensorsConnected(sensors);
        return Return<void>();
    }

    Return<void> onDynamicSensorsConnected(
            const hidl_vec<android::hardware::sensors::V1_0::SensorInfo>& dynamicSensorsAdded)
            override {
        return onDynamicSensorsConnected_2_1(convertToNewSensorInfos(dynamicSensorsAdded));
    }

    Return<void> onDynamicSensorsDisconnected(
            const hidl_vec<int32_t>& dynamicSensorHandlesRemoved) override {
        mSensorDeviceCallback->onDynamicSensorsDisconnected(dynamicSensorHandlesRemoved);
        return Return<void>();
    }

private:
    ISensorHalWrapper::SensorDeviceCallback* mSensorDeviceCallback;
};

bool HidlSensorHalWrapper::supportsPolling() {
    return mSensors->supportsPolling();
}

bool HidlSensorHalWrapper::supportsMessageQueues() {
    return mSensors->supportsMessageQueues();
}

bool HidlSensorHalWrapper::connect(SensorDeviceCallback* callback) {
    mSensorDeviceCallback = callback;
    bool ret = connectHidlService();
    if (mEventQueueFlag != nullptr) {
        mEventQueueFlag->wake(asBaseType(INTERNAL_WAKE));
    }
    return ret;
}

void HidlSensorHalWrapper::prepareForReconnect() {
    mReconnecting = true;
    if (mEventQueueFlag != nullptr) {
        mEventQueueFlag->wake(asBaseType(INTERNAL_WAKE));
    }
}

ssize_t HidlSensorHalWrapper::poll(sensors_event_t* buffer, size_t count) {
    ssize_t err;
    int numHidlTransportErrors = 0;
    bool hidlTransportError = false;

    do {
        auto ret = mSensors->poll(count,
                                  [&](auto result, const auto& events,
                                      const auto& dynamicSensorsAdded) {
                                      if (result == Result::OK) {
                                          convertToSensorEvents(convertToNewEvents(events),
                                                                convertToNewSensorInfos(
                                                                        dynamicSensorsAdded),
                                                                buffer);
                                          err = (ssize_t)events.size();
                                      } else {
                                          err = statusFromResult(result);
                                      }
                                  });

        if (ret.isOk()) {
            hidlTransportError = false;
        } else {
            hidlTransportError = true;
            numHidlTransportErrors++;
            if (numHidlTransportErrors > 50) {
                // Log error and bail
                ALOGE("Max Hidl transport errors this cycle : %d", numHidlTransportErrors);
                handleHidlDeath(ret.description());
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    } while (hidlTransportError);

    if (numHidlTransportErrors > 0) {
        ALOGE("Saw %d Hidl transport failures", numHidlTransportErrors);
        HidlTransportErrorLog errLog(time(nullptr), numHidlTransportErrors);
        mHidlTransportErrors.add(errLog);
        mTotalHidlTransportErrors++;
    }

    return err;
}

ssize_t HidlSensorHalWrapper::pollFmq(sensors_event_t* buffer, size_t maxNumEventsToRead) {
    ssize_t eventsRead = 0;
    size_t availableEvents = mSensors->getEventQueue()->availableToRead();

    if (availableEvents == 0) {
        uint32_t eventFlagState = 0;

        // Wait for events to become available. This is necessary so that the Event FMQ's read() is
        // able to be called with the correct number of events to read. If the specified number of
        // events is not available, then read() would return no events, possibly introducing
        // additional latency in delivering events to applications.
        if (mEventQueueFlag != nullptr) {
            mEventQueueFlag->wait(asBaseType(EventQueueFlagBits::READ_AND_PROCESS) |
                                          asBaseType(INTERNAL_WAKE),
                                  &eventFlagState);
        }
        availableEvents = mSensors->getEventQueue()->availableToRead();

        if ((eventFlagState & asBaseType(INTERNAL_WAKE)) && mReconnecting) {
            ALOGD("Event FMQ internal wake, returning from poll with no events");
            return DEAD_OBJECT;
        }
    }

    size_t eventsToRead = std::min({availableEvents, maxNumEventsToRead, mEventBuffer.size()});
    if (eventsToRead > 0) {
        if (mSensors->getEventQueue()->read(mEventBuffer.data(), eventsToRead)) {
            // Notify the Sensors HAL that sensor events have been read. This is required to support
            // the use of writeBlocking by the Sensors HAL.
            if (mEventQueueFlag != nullptr) {
                mEventQueueFlag->wake(asBaseType(EventQueueFlagBits::EVENTS_READ));
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

std::vector<sensor_t> HidlSensorHalWrapper::getSensorsList() {
    std::vector<sensor_t> sensorsFound;
    if (mSensors != nullptr) {
        checkReturn(mSensors->getSensorsList([&](const auto& list) {
            for (size_t i = 0; i < list.size(); i++) {
                sensor_t sensor;
                convertToSensor(list[i], &sensor);
                sensorsFound.push_back(sensor);

                // Only disable all sensors on HAL 1.0 since HAL 2.0
                // handles this in its initialize method
                if (!mSensors->supportsMessageQueues()) {
                    checkReturn(mSensors->activate(list[i].sensorHandle, 0 /* enabled */));
                }
            }
        }));
    }

    return sensorsFound;
}

status_t HidlSensorHalWrapper::setOperationMode(SensorService::Mode mode) {
    if (mSensors == nullptr) return NO_INIT;
    return checkReturnAndGetStatus(
            mSensors->setOperationMode(static_cast<hardware::sensors::V1_0::OperationMode>(mode)));
}

status_t HidlSensorHalWrapper::activate(int32_t sensorHandle, bool enabled) {
    if (mSensors == nullptr) return NO_INIT;
    return checkReturnAndGetStatus(mSensors->activate(sensorHandle, enabled));
}

status_t HidlSensorHalWrapper::batch(int32_t sensorHandle, int64_t samplingPeriodNs,
                                     int64_t maxReportLatencyNs) {
    if (mSensors == nullptr) return NO_INIT;
    return checkReturnAndGetStatus(
            mSensors->batch(sensorHandle, samplingPeriodNs, maxReportLatencyNs));
}

status_t HidlSensorHalWrapper::flush(int32_t sensorHandle) {
    if (mSensors == nullptr) return NO_INIT;
    return checkReturnAndGetStatus(mSensors->flush(sensorHandle));
}

status_t HidlSensorHalWrapper::injectSensorData(const sensors_event_t* event) {
    if (mSensors == nullptr) return NO_INIT;

    Event ev;
    convertFromSensorEvent(*event, &ev);
    return checkReturnAndGetStatus(mSensors->injectSensorData(ev));
}

status_t HidlSensorHalWrapper::registerDirectChannel(const sensors_direct_mem_t* memory,
                                                     int32_t* outChannelHandle) {
    if (mSensors == nullptr) return NO_INIT;

    SharedMemType type;
    switch (memory->type) {
        case SENSOR_DIRECT_MEM_TYPE_ASHMEM:
            type = SharedMemType::ASHMEM;
            break;
        case SENSOR_DIRECT_MEM_TYPE_GRALLOC:
            type = SharedMemType::GRALLOC;
            break;
        default:
            return BAD_VALUE;
    }

    SharedMemFormat format;
    if (memory->format != SENSOR_DIRECT_FMT_SENSORS_EVENT) {
        return BAD_VALUE;
    }
    format = SharedMemFormat::SENSORS_EVENT;

    SharedMemInfo mem = {
            .type = type,
            .format = format,
            .size = static_cast<uint32_t>(memory->size),
            .memoryHandle = memory->handle,
    };

    status_t ret = OK;
    checkReturn(mSensors->registerDirectChannel(mem,
                                                [&ret, &outChannelHandle](auto result,
                                                                          auto channelHandle) {
                                                    if (result == Result::OK) {
                                                        *outChannelHandle = channelHandle;
                                                    } else {
                                                        ret = statusFromResult(result);
                                                    }
                                                }));
    return ret;
}

status_t HidlSensorHalWrapper::unregisterDirectChannel(int32_t channelHandle) {
    if (mSensors == nullptr) return NO_INIT;
    return checkReturnAndGetStatus(mSensors->unregisterDirectChannel(channelHandle));
}

status_t HidlSensorHalWrapper::configureDirectChannel(int32_t sensorHandle, int32_t channelHandle,
                                                      const struct sensors_direct_cfg_t* config) {
    if (mSensors == nullptr) return NO_INIT;

    RateLevel rate;
    switch (config->rate_level) {
        case SENSOR_DIRECT_RATE_STOP:
            rate = RateLevel::STOP;
            break;
        case SENSOR_DIRECT_RATE_NORMAL:
            rate = RateLevel::NORMAL;
            break;
        case SENSOR_DIRECT_RATE_FAST:
            rate = RateLevel::FAST;
            break;
        case SENSOR_DIRECT_RATE_VERY_FAST:
            rate = RateLevel::VERY_FAST;
            break;
        default:
            return BAD_VALUE;
    }

    status_t ret;
    checkReturn(mSensors->configDirectReport(sensorHandle, channelHandle, rate,
                                             [&ret, rate](auto result, auto token) {
                                                 if (rate == RateLevel::STOP) {
                                                     ret = statusFromResult(result);
                                                 } else {
                                                     if (result == Result::OK) {
                                                         ret = token;
                                                     } else {
                                                         ret = statusFromResult(result);
                                                     }
                                                 }
                                             }));

    return ret;
}

void HidlSensorHalWrapper::writeWakeLockHandled(uint32_t count) {
    if (mWakeLockQueue->write(&count)) {
        mWakeLockQueueFlag->wake(asBaseType(WakeLockQueueFlagBits::DATA_WRITTEN));
    } else {
        ALOGW("Failed to write wake lock handled");
    }
}

status_t HidlSensorHalWrapper::checkReturnAndGetStatus(const hardware::Return<Result>& ret) {
    checkReturn(ret);
    return (!ret.isOk()) ? DEAD_OBJECT : statusFromResult(ret);
}

void HidlSensorHalWrapper::handleHidlDeath(const std::string& detail) {
    if (!mSensors->supportsMessageQueues()) {
        // restart is the only option at present.
        LOG_ALWAYS_FATAL("Abort due to ISensors hidl service failure, detail: %s.", detail.c_str());
    } else {
        ALOGD("ISensors HAL died, death recipient will attempt reconnect");
    }
}

bool HidlSensorHalWrapper::connectHidlService() {
    HalConnectionStatus status = connectHidlServiceV2_1();
    if (status == HalConnectionStatus::DOES_NOT_EXIST) {
        status = connectHidlServiceV2_0();
    }

    if (status == HalConnectionStatus::DOES_NOT_EXIST) {
        status = connectHidlServiceV1_0();
    }
    return (status == HalConnectionStatus::CONNECTED);
}

ISensorHalWrapper::HalConnectionStatus HidlSensorHalWrapper::connectHidlServiceV1_0() {
    // SensorDevice will wait for HAL service to start if HAL is declared in device manifest.
    size_t retry = 10;
    HalConnectionStatus connectionStatus = HalConnectionStatus::UNKNOWN;

    while (retry-- > 0) {
        sp<android::hardware::sensors::V1_0::ISensors> sensors =
                android::hardware::sensors::V1_0::ISensors::getService();
        if (sensors == nullptr) {
            // no sensor hidl service found
            connectionStatus = HalConnectionStatus::DOES_NOT_EXIST;
            break;
        }

        mSensors = new ISensorsWrapperV1_0(sensors);
        mRestartWaiter->reset();
        // Poke ISensor service. If it has lingering connection from previous generation of
        // system server, it will kill itself. There is no intention to handle the poll result,
        // which will be done since the size is 0.
        if (mSensors->poll(0, [](auto, const auto&, const auto&) {}).isOk()) {
            // ok to continue
            connectionStatus = HalConnectionStatus::CONNECTED;
            break;
        }

        // hidl service is restarting, pointer is invalid.
        mSensors = nullptr;
        connectionStatus = HalConnectionStatus::FAILED_TO_CONNECT;
        ALOGI("%s unsuccessful, remaining retry %zu.", __FUNCTION__, retry);
        mRestartWaiter->wait();
    }

    return connectionStatus;
}

ISensorHalWrapper::HalConnectionStatus HidlSensorHalWrapper::connectHidlServiceV2_0() {
    HalConnectionStatus connectionStatus = HalConnectionStatus::UNKNOWN;
    sp<android::hardware::sensors::V2_0::ISensors> sensors =
            android::hardware::sensors::V2_0::ISensors::getService();

    if (sensors == nullptr) {
        connectionStatus = HalConnectionStatus::DOES_NOT_EXIST;
    } else {
        mSensors = new ISensorsWrapperV2_0(sensors);
        connectionStatus = initializeHidlServiceV2_X();
    }

    return connectionStatus;
}

ISensorHalWrapper::HalConnectionStatus HidlSensorHalWrapper::connectHidlServiceV2_1() {
    HalConnectionStatus connectionStatus = HalConnectionStatus::UNKNOWN;
    sp<android::hardware::sensors::V2_1::ISensors> sensors =
            android::hardware::sensors::V2_1::ISensors::getService();

    if (sensors == nullptr) {
        connectionStatus = HalConnectionStatus::DOES_NOT_EXIST;
    } else {
        mSensors = new ISensorsWrapperV2_1(sensors);
        connectionStatus = initializeHidlServiceV2_X();
    }

    return connectionStatus;
}

ISensorHalWrapper::HalConnectionStatus HidlSensorHalWrapper::initializeHidlServiceV2_X() {
    HalConnectionStatus connectionStatus = HalConnectionStatus::UNKNOWN;

    mWakeLockQueue =
            std::make_unique<WakeLockQueue>(SensorEventQueue::MAX_RECEIVE_BUFFER_EVENT_COUNT,
                                            true /* configureEventFlagWord */);

    hardware::EventFlag::deleteEventFlag(&mEventQueueFlag);
    hardware::EventFlag::createEventFlag(mSensors->getEventQueue()->getEventFlagWord(),
                                         &mEventQueueFlag);

    hardware::EventFlag::deleteEventFlag(&mWakeLockQueueFlag);
    hardware::EventFlag::createEventFlag(mWakeLockQueue->getEventFlagWord(), &mWakeLockQueueFlag);

    CHECK(mSensors != nullptr && mWakeLockQueue != nullptr && mEventQueueFlag != nullptr &&
          mWakeLockQueueFlag != nullptr);

    mCallback = sp<HidlSensorsCallback>::make(mSensorDeviceCallback);
    status_t status =
            checkReturnAndGetStatus(mSensors->initialize(*mWakeLockQueue->getDesc(), mCallback));

    if (status != NO_ERROR) {
        connectionStatus = HalConnectionStatus::FAILED_TO_CONNECT;
        ALOGE("Failed to initialize Sensors HAL (%s)", strerror(-status));
    } else {
        connectionStatus = HalConnectionStatus::CONNECTED;
        mSensorsHalDeathReceiver = new SensorsHalDeathReceiver(this);
        mSensors->linkToDeath(mSensorsHalDeathReceiver, 0 /* cookie */);
    }

    return connectionStatus;
}

void HidlSensorHalWrapper::convertToSensorEvent(const Event& src, sensors_event_t* dst) {
    android::hardware::sensors::V2_1::implementation::convertToSensorEvent(src, dst);
}

void HidlSensorHalWrapper::convertToSensorEvents(const hidl_vec<Event>& src,
                                                 const hidl_vec<SensorInfo>& dynamicSensorsAdded,
                                                 sensors_event_t* dst) {
    if (dynamicSensorsAdded.size() > 0 && mCallback != nullptr) {
        mCallback->onDynamicSensorsConnected_2_1(dynamicSensorsAdded);
    }

    for (size_t i = 0; i < src.size(); ++i) {
        convertToSensorEvent(src[i], &dst[i]);
    }
}

} // namespace android
