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

#ifndef _UI_INPUTREADER_INPUT_CONTROLLER_H
#define _UI_INPUTREADER_INPUT_CONTROLLER_H

#include "EventHub.h"
#include "InputDevice.h"
#include "InputListener.h"
#include "InputReaderContext.h"

namespace android {

/* A peripheral controller manages the input device peripherals associated with the input device,
 * like the sysfs based battery and light class devices.
 *
 */
class PeripheralControllerInterface {
public:
    PeripheralControllerInterface() {}
    virtual ~PeripheralControllerInterface() {}

    // Interface methods for Battery
    virtual std::optional<int32_t> getBatteryCapacity(int32_t batteryId) = 0;
    virtual std::optional<int32_t> getBatteryStatus(int32_t batteryId) = 0;

    // Interface methods for Light
    virtual bool setLightColor(int32_t lightId, int32_t color) = 0;
    virtual bool setLightPlayerId(int32_t lightId, int32_t playerId) = 0;
    virtual std::optional<int32_t> getLightColor(int32_t lightId) = 0;
    virtual std::optional<int32_t> getLightPlayerId(int32_t lightId) = 0;

    virtual void populateDeviceInfo(InputDeviceInfo* deviceInfo) = 0;
    virtual void dump(std::string& dump) = 0;
};

} // namespace android

#endif // _UI_INPUTREADER_INPUT_CONTROLLER_H
