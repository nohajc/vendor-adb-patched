/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef _UI_INPUTREADER_INPUT_MAPPER_H
#define _UI_INPUTREADER_INPUT_MAPPER_H

#include "EventHub.h"
#include "InputDevice.h"
#include "InputListener.h"
#include "InputReaderContext.h"
#include "StylusState.h"
#include "VibrationElement.h"

namespace android {

/* An input mapper transforms raw input events into cooked event data.
 * A single input device can have multiple associated input mappers in order to interpret
 * different classes of events.
 *
 * InputMapper lifecycle:
 * - create
 * - configure with 0 changes
 * - reset
 * - process, process, process (may occasionally reconfigure with non-zero changes or reset)
 * - reset
 * - destroy
 */
class InputMapper {
public:
    explicit InputMapper(InputDeviceContext& deviceContext);
    virtual ~InputMapper();

    inline int32_t getDeviceId() { return mDeviceContext.getId(); }
    inline InputDeviceContext& getDeviceContext() { return mDeviceContext; }
    inline const std::string getDeviceName() { return mDeviceContext.getName(); }
    inline InputReaderContext* getContext() { return mDeviceContext.getContext(); }
    inline InputReaderPolicyInterface* getPolicy() { return getContext()->getPolicy(); }
    inline InputListenerInterface* getListener() { return getContext()->getListener(); }

    virtual uint32_t getSources() = 0;
    virtual void populateDeviceInfo(InputDeviceInfo* deviceInfo);
    virtual void dump(std::string& dump);
    virtual void configure(nsecs_t when, const InputReaderConfiguration* config, uint32_t changes);
    virtual void reset(nsecs_t when);
    virtual void process(const RawEvent* rawEvent) = 0;
    virtual void timeoutExpired(nsecs_t when);

    virtual int32_t getKeyCodeState(uint32_t sourceMask, int32_t keyCode);
    virtual int32_t getScanCodeState(uint32_t sourceMask, int32_t scanCode);
    virtual int32_t getSwitchState(uint32_t sourceMask, int32_t switchCode);
    virtual bool markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes,
                                       const int32_t* keyCodes, uint8_t* outFlags);
    virtual void vibrate(const VibrationSequence& sequence, ssize_t repeat, int32_t token);
    virtual void cancelVibrate(int32_t token);
    virtual bool isVibrating();
    virtual std::vector<int32_t> getVibratorIds();
    virtual void cancelTouch(nsecs_t when, nsecs_t readTime);
    virtual bool enableSensor(InputDeviceSensorType sensorType,
                              std::chrono::microseconds samplingPeriod,
                              std::chrono::microseconds maxBatchReportLatency);
    virtual void disableSensor(InputDeviceSensorType sensorType);
    virtual void flushSensor(InputDeviceSensorType sensorType);

    virtual std::optional<int32_t> getBatteryCapacity() { return std::nullopt; }
    virtual std::optional<int32_t> getBatteryStatus() { return std::nullopt; }

    virtual bool setLightColor(int32_t lightId, int32_t color) { return true; }
    virtual bool setLightPlayerId(int32_t lightId, int32_t playerId) { return true; }
    virtual std::optional<int32_t> getLightColor(int32_t lightId) { return std::nullopt; }
    virtual std::optional<int32_t> getLightPlayerId(int32_t lightId) { return std::nullopt; }

    virtual int32_t getMetaState();
    virtual void updateMetaState(int32_t keyCode);

    virtual void updateExternalStylusState(const StylusState& state);

    virtual std::optional<int32_t> getAssociatedDisplayId() { return std::nullopt; }
    virtual void updateLedState(bool reset) {}

protected:
    InputDeviceContext& mDeviceContext;

    status_t getAbsoluteAxisInfo(int32_t axis, RawAbsoluteAxisInfo* axisInfo);
    void bumpGeneration();

    static void dumpRawAbsoluteAxisInfo(std::string& dump, const RawAbsoluteAxisInfo& axis,
                                        const char* name);
    static void dumpStylusState(std::string& dump, const StylusState& state);
};

} // namespace android

#endif // _UI_INPUTREADER_INPUT_MAPPER_H
