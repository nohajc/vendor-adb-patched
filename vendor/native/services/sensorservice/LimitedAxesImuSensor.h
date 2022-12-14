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

#include <stdint.h>
#include <sys/types.h>

#include <sensor/Sensor.h>

#include "SensorInterface.h"

namespace android {

class SensorDevice;

class LimitedAxesImuSensor : public BaseSensor {
    Sensor mImu3dSensor;

public:
    LimitedAxesImuSensor(sensor_t const* list, size_t count, int32_t imuSensorType);
    virtual bool process(sensors_event_t* outEvent, const sensors_event_t& event) override;
    virtual status_t activate(void* ident, bool enabled) override;
    virtual status_t setDelay(void* ident, int handle, int64_t ns) override;
    virtual bool isVirtual() const override { return true; }

private:
    int32_t convertImu3dToLimitedAxesSensorType(int32_t imu3dSensorType);
    int32_t convertLimitedAxesSensorTypeToHandle(int32_t imuLimitedAxesSensorType);
    const char* convertLimitedAxesSensorTypeToName(int32_t imuLimitedAxesSensorType);
};

}; // namespace android