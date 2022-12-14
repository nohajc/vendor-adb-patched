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

#include <math.h>
#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>

#include <hardware/sensors.h>

#include "LimitedAxesImuSensor.h"
#include "SensorDevice.h"
#include "SensorFusion.h"
#include "SensorServiceUtils.h"

namespace android {

namespace {
const sensor_t DUMMY_SENSOR = {.name = "",
                               .vendor = "",
                               .stringType = "",
                               .requiredPermission = ""};
} // unnamed namespace

LimitedAxesImuSensor::LimitedAxesImuSensor(sensor_t const* list, size_t count,
                                           int32_t imu3dSensorType)
      : BaseSensor(DUMMY_SENSOR) {
    for (size_t i = 0; i < count; i++) {
        if (list[i].type == imu3dSensorType) {
            mImu3dSensor = Sensor(list + i);
            break;
        }
    }

    const int32_t imuLimitedAxesSensorType = convertImu3dToLimitedAxesSensorType(imu3dSensorType);

    const sensor_t sensor = {
            .name = convertLimitedAxesSensorTypeToName(imuLimitedAxesSensorType),
            .vendor = "AOSP",
            .version = 1,
            .handle = convertLimitedAxesSensorTypeToHandle(imuLimitedAxesSensorType),
            .type = imuLimitedAxesSensorType,
            .maxRange = mImu3dSensor.getMaxValue(),
            .resolution = mImu3dSensor.getResolution(),
            .power = mImu3dSensor.getPowerUsage(),
            .minDelay = mImu3dSensor.getMinDelay(),
    };
    mSensor = Sensor(&sensor);
}

bool LimitedAxesImuSensor::process(sensors_event_t* outEvent, const sensors_event_t& event) {
    if (event.type == mImu3dSensor.getType()) {
        *outEvent = event;
        size_t imu3dDataSize = SensorServiceUtil::eventSizeBySensorType(mImu3dSensor.getType());
        outEvent->data[0 + imu3dDataSize] = 1;
        outEvent->data[1 + imu3dDataSize] = 1;
        outEvent->data[2 + imu3dDataSize] = 1;
        outEvent->sensor = mSensor.getHandle();
        outEvent->type = mSensor.getType();
        return true;
    }
    return false;
}

status_t LimitedAxesImuSensor::activate(void* ident, bool enabled) {
    return mSensorDevice.activate(ident, mImu3dSensor.getHandle(), enabled);
}

status_t LimitedAxesImuSensor::setDelay(void* ident, int /*handle*/, int64_t ns) {
    return mSensorDevice.setDelay(ident, mImu3dSensor.getHandle(), ns);
}

int32_t LimitedAxesImuSensor::convertImu3dToLimitedAxesSensorType(int32_t imu3dSensorType) {
    switch (imu3dSensorType) {
        case SENSOR_TYPE_ACCELEROMETER:
            return SENSOR_TYPE_ACCELEROMETER_LIMITED_AXES;
        case SENSOR_TYPE_GYROSCOPE:
            return SENSOR_TYPE_GYROSCOPE_LIMITED_AXES;
        case SENSOR_TYPE_ACCELEROMETER_UNCALIBRATED:
            return SENSOR_TYPE_ACCELEROMETER_LIMITED_AXES_UNCALIBRATED;
        case SENSOR_TYPE_GYROSCOPE_UNCALIBRATED:
            return SENSOR_TYPE_GYROSCOPE_LIMITED_AXES_UNCALIBRATED;
        default:
            return 0;
    }
}

int32_t LimitedAxesImuSensor::convertLimitedAxesSensorTypeToHandle(
        int32_t imuLimitedAxesSensorType) {
    switch (imuLimitedAxesSensorType) {
        case SENSOR_TYPE_ACCELEROMETER_LIMITED_AXES:
            return '_ala';
        case SENSOR_TYPE_GYROSCOPE_LIMITED_AXES:
            return '_gla';
        case SENSOR_TYPE_ACCELEROMETER_LIMITED_AXES_UNCALIBRATED:
            return '_alc';
        case SENSOR_TYPE_GYROSCOPE_LIMITED_AXES_UNCALIBRATED:
            return '_glc';
        default:
            return 0;
    }
}

const char* LimitedAxesImuSensor::convertLimitedAxesSensorTypeToName(
        int32_t imuLimitedAxesSensorType) {
    switch (imuLimitedAxesSensorType) {
        case SENSOR_TYPE_ACCELEROMETER_LIMITED_AXES:
            return "Accelerometer Limited Axes Sensor";
        case SENSOR_TYPE_GYROSCOPE_LIMITED_AXES:
            return "Gyroscope Limited Axes Sensor";
        case SENSOR_TYPE_ACCELEROMETER_LIMITED_AXES_UNCALIBRATED:
            return "Accelerometer Limited Axes Uncalibrated Sensor";
        case SENSOR_TYPE_GYROSCOPE_LIMITED_AXES_UNCALIBRATED:
            return "Gyroscope Limited Axes Uncalibrated Sensor";
        default:
            return "";
    }
}

}; // namespace android
