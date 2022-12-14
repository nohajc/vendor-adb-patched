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

#include "Macros.h"

#include "InputDevice.h"

#include <algorithm>

#include <ftl/flags.h>

#include "CursorInputMapper.h"
#include "ExternalStylusInputMapper.h"
#include "InputReaderContext.h"
#include "JoystickInputMapper.h"
#include "KeyboardInputMapper.h"
#include "MultiTouchInputMapper.h"
#include "PeripheralController.h"
#include "RotaryEncoderInputMapper.h"
#include "SensorInputMapper.h"
#include "SingleTouchInputMapper.h"
#include "SwitchInputMapper.h"
#include "VibratorInputMapper.h"

namespace android {

InputDevice::InputDevice(InputReaderContext* context, int32_t id, int32_t generation,
                         const InputDeviceIdentifier& identifier)
      : mContext(context),
        mId(id),
        mGeneration(generation),
        mControllerNumber(0),
        mIdentifier(identifier),
        mClasses(0),
        mSources(0),
        mIsExternal(false),
        mHasMic(false),
        mDropUntilNextSync(false) {}

InputDevice::~InputDevice() {}

bool InputDevice::isEnabled() {
    if (!hasEventHubDevices()) {
        return false;
    }
    // An input device composed of sub devices can be individually enabled or disabled.
    // If any of the sub device is enabled then the input device is considered as enabled.
    bool enabled = false;
    for_each_subdevice([&enabled](auto& context) { enabled |= context.isDeviceEnabled(); });
    return enabled;
}

void InputDevice::setEnabled(bool enabled, nsecs_t when) {
    if (enabled && mAssociatedDisplayPort && !mAssociatedViewport) {
        ALOGW("Cannot enable input device %s because it is associated with port %" PRIu8 ", "
              "but the corresponding viewport is not found",
              getName().c_str(), *mAssociatedDisplayPort);
        enabled = false;
    }

    if (isEnabled() == enabled) {
        return;
    }

    // When resetting some devices, the driver needs to be queried to ensure that a proper reset is
    // performed. The querying must happen when the device is enabled, so we reset after enabling
    // but before disabling the device. See MultiTouchMotionAccumulator::reset for more information.
    if (enabled) {
        for_each_subdevice([](auto& context) { context.enableDevice(); });
        reset(when);
    } else {
        reset(when);
        for_each_subdevice([](auto& context) { context.disableDevice(); });
    }
    // Must change generation to flag this device as changed
    bumpGeneration();
}

void InputDevice::dump(std::string& dump, const std::string& eventHubDevStr) {
    InputDeviceInfo deviceInfo = getDeviceInfo();

    dump += StringPrintf(INDENT "Device %d: %s\n", deviceInfo.getId(),
                         deviceInfo.getDisplayName().c_str());
    dump += StringPrintf(INDENT "%s", eventHubDevStr.c_str());
    dump += StringPrintf(INDENT2 "Generation: %d\n", mGeneration);
    dump += StringPrintf(INDENT2 "IsExternal: %s\n", toString(mIsExternal));
    dump += StringPrintf(INDENT2 "AssociatedDisplayPort: ");
    if (mAssociatedDisplayPort) {
        dump += StringPrintf("%" PRIu8 "\n", *mAssociatedDisplayPort);
    } else {
        dump += "<none>\n";
    }
    dump += StringPrintf(INDENT2 "AssociatedDisplayUniqueId: ");
    if (mAssociatedDisplayUniqueId) {
        dump += StringPrintf("%s\n", mAssociatedDisplayUniqueId->c_str());
    } else {
        dump += "<none>\n";
    }
    dump += StringPrintf(INDENT2 "HasMic:     %s\n", toString(mHasMic));
    dump += StringPrintf(INDENT2 "Sources: %s\n",
                         inputEventSourceToString(deviceInfo.getSources()).c_str());
    dump += StringPrintf(INDENT2 "KeyboardType: %d\n", deviceInfo.getKeyboardType());
    dump += StringPrintf(INDENT2 "ControllerNum: %d\n", deviceInfo.getControllerNumber());

    const std::vector<InputDeviceInfo::MotionRange>& ranges = deviceInfo.getMotionRanges();
    if (!ranges.empty()) {
        dump += INDENT2 "Motion Ranges:\n";
        for (size_t i = 0; i < ranges.size(); i++) {
            const InputDeviceInfo::MotionRange& range = ranges[i];
            const char* label = InputEventLookup::getAxisLabel(range.axis);
            char name[32];
            if (label) {
                strncpy(name, label, sizeof(name));
                name[sizeof(name) - 1] = '\0';
            } else {
                snprintf(name, sizeof(name), "%d", range.axis);
            }
            dump += StringPrintf(INDENT3
                                 "%s: source=%s, "
                                 "min=%0.3f, max=%0.3f, flat=%0.3f, fuzz=%0.3f, resolution=%0.3f\n",
                                 name, inputEventSourceToString(range.source).c_str(), range.min,
                                 range.max, range.flat, range.fuzz, range.resolution);
        }
    }

    for_each_mapper([&dump](InputMapper& mapper) { mapper.dump(dump); });
    if (mController) {
        mController->dump(dump);
    }
}

void InputDevice::addEventHubDevice(int32_t eventHubId, bool populateMappers) {
    if (mDevices.find(eventHubId) != mDevices.end()) {
        return;
    }
    std::unique_ptr<InputDeviceContext> contextPtr(new InputDeviceContext(*this, eventHubId));
    ftl::Flags<InputDeviceClass> classes = contextPtr->getDeviceClasses();
    std::vector<std::unique_ptr<InputMapper>> mappers;

    // Check if we should skip population
    if (!populateMappers) {
        mDevices.insert({eventHubId, std::make_pair(std::move(contextPtr), std::move(mappers))});
        return;
    }

    // Switch-like devices.
    if (classes.test(InputDeviceClass::SWITCH)) {
        mappers.push_back(std::make_unique<SwitchInputMapper>(*contextPtr));
    }

    // Scroll wheel-like devices.
    if (classes.test(InputDeviceClass::ROTARY_ENCODER)) {
        mappers.push_back(std::make_unique<RotaryEncoderInputMapper>(*contextPtr));
    }

    // Vibrator-like devices.
    if (classes.test(InputDeviceClass::VIBRATOR)) {
        mappers.push_back(std::make_unique<VibratorInputMapper>(*contextPtr));
    }

    // Battery-like devices or light-containing devices.
    // PeripheralController will be created with associated EventHub device.
    if (classes.test(InputDeviceClass::BATTERY) || classes.test(InputDeviceClass::LIGHT)) {
        mController = std::make_unique<PeripheralController>(*contextPtr);
    }

    // Keyboard-like devices.
    uint32_t keyboardSource = 0;
    int32_t keyboardType = AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC;
    if (classes.test(InputDeviceClass::KEYBOARD)) {
        keyboardSource |= AINPUT_SOURCE_KEYBOARD;
    }
    if (classes.test(InputDeviceClass::ALPHAKEY)) {
        keyboardType = AINPUT_KEYBOARD_TYPE_ALPHABETIC;
    }
    if (classes.test(InputDeviceClass::DPAD)) {
        keyboardSource |= AINPUT_SOURCE_DPAD;
    }
    if (classes.test(InputDeviceClass::GAMEPAD)) {
        keyboardSource |= AINPUT_SOURCE_GAMEPAD;
    }

    if (keyboardSource != 0) {
        mappers.push_back(
                std::make_unique<KeyboardInputMapper>(*contextPtr, keyboardSource, keyboardType));
    }

    // Cursor-like devices.
    if (classes.test(InputDeviceClass::CURSOR)) {
        mappers.push_back(std::make_unique<CursorInputMapper>(*contextPtr));
    }

    // Touchscreens and touchpad devices.
    if (classes.test(InputDeviceClass::TOUCH_MT)) {
        mappers.push_back(std::make_unique<MultiTouchInputMapper>(*contextPtr));
    } else if (classes.test(InputDeviceClass::TOUCH)) {
        mappers.push_back(std::make_unique<SingleTouchInputMapper>(*contextPtr));
    }

    // Joystick-like devices.
    if (classes.test(InputDeviceClass::JOYSTICK)) {
        mappers.push_back(std::make_unique<JoystickInputMapper>(*contextPtr));
    }

    // Motion sensor enabled devices.
    if (classes.test(InputDeviceClass::SENSOR)) {
        mappers.push_back(std::make_unique<SensorInputMapper>(*contextPtr));
    }

    // External stylus-like devices.
    if (classes.test(InputDeviceClass::EXTERNAL_STYLUS)) {
        mappers.push_back(std::make_unique<ExternalStylusInputMapper>(*contextPtr));
    }

    // insert the context into the devices set
    mDevices.insert({eventHubId, std::make_pair(std::move(contextPtr), std::move(mappers))});
    // Must change generation to flag this device as changed
    bumpGeneration();
}

void InputDevice::removeEventHubDevice(int32_t eventHubId) {
    if (mController != nullptr && mController->getEventHubId() == eventHubId) {
        // Delete mController, since the corresponding eventhub device is going away
        mController = nullptr;
    }
    mDevices.erase(eventHubId);
}

void InputDevice::configure(nsecs_t when, const InputReaderConfiguration* config,
                            uint32_t changes) {
    mSources = 0;
    mClasses = ftl::Flags<InputDeviceClass>(0);
    mControllerNumber = 0;

    for_each_subdevice([this](InputDeviceContext& context) {
        mClasses |= context.getDeviceClasses();
        int32_t controllerNumber = context.getDeviceControllerNumber();
        if (controllerNumber > 0) {
            if (mControllerNumber && mControllerNumber != controllerNumber) {
                ALOGW("InputDevice::configure(): composite device contains multiple unique "
                      "controller numbers");
            }
            mControllerNumber = controllerNumber;
        }
    });

    mIsExternal = mClasses.test(InputDeviceClass::EXTERNAL);
    mHasMic = mClasses.test(InputDeviceClass::MIC);

    if (!isIgnored()) {
        if (!changes) { // first time only
            mConfiguration.clear();
            for_each_subdevice([this](InputDeviceContext& context) {
                PropertyMap configuration;
                context.getConfiguration(&configuration);
                mConfiguration.addAll(&configuration);
            });
        }

        if (!changes || (changes & InputReaderConfiguration::CHANGE_KEYBOARD_LAYOUTS)) {
            if (!mClasses.test(InputDeviceClass::VIRTUAL)) {
                std::shared_ptr<KeyCharacterMap> keyboardLayout =
                        mContext->getPolicy()->getKeyboardLayoutOverlay(mIdentifier);
                bool shouldBumpGeneration = false;
                for_each_subdevice(
                        [&keyboardLayout, &shouldBumpGeneration](InputDeviceContext& context) {
                            if (context.setKeyboardLayoutOverlay(keyboardLayout)) {
                                shouldBumpGeneration = true;
                            }
                        });
                if (shouldBumpGeneration) {
                    bumpGeneration();
                }
            }
        }

        if (!changes || (changes & InputReaderConfiguration::CHANGE_DEVICE_ALIAS)) {
            if (!(mClasses.test(InputDeviceClass::VIRTUAL))) {
                std::string alias = mContext->getPolicy()->getDeviceAlias(mIdentifier);
                if (mAlias != alias) {
                    mAlias = alias;
                    bumpGeneration();
                }
            }
        }

        if (!changes || (changes & InputReaderConfiguration::CHANGE_ENABLED_STATE)) {
            auto it = config->disabledDevices.find(mId);
            bool enabled = it == config->disabledDevices.end();
            setEnabled(enabled, when);
        }

        if (!changes || (changes & InputReaderConfiguration::CHANGE_DISPLAY_INFO)) {
            // In most situations, no port or name will be specified.
            mAssociatedDisplayPort = std::nullopt;
            mAssociatedDisplayUniqueId = std::nullopt;
            mAssociatedViewport = std::nullopt;
            // Find the display port that corresponds to the current input port.
            const std::string& inputPort = mIdentifier.location;
            if (!inputPort.empty()) {
                const std::unordered_map<std::string, uint8_t>& ports = config->portAssociations;
                const auto& displayPort = ports.find(inputPort);
                if (displayPort != ports.end()) {
                    mAssociatedDisplayPort = std::make_optional(displayPort->second);
                } else {
                    const std::unordered_map<std::string, std::string>& displayUniqueIds =
                            config->uniqueIdAssociations;
                    const auto& displayUniqueId = displayUniqueIds.find(inputPort);
                    if (displayUniqueId != displayUniqueIds.end()) {
                        mAssociatedDisplayUniqueId = displayUniqueId->second;
                    }
                }
            }

            // If the device was explicitly disabled by the user, it would be present in the
            // "disabledDevices" list. If it is associated with a specific display, and it was not
            // explicitly disabled, then enable/disable the device based on whether we can find the
            // corresponding viewport.
            bool enabled = (config->disabledDevices.find(mId) == config->disabledDevices.end());
            if (mAssociatedDisplayPort) {
                mAssociatedViewport = config->getDisplayViewportByPort(*mAssociatedDisplayPort);
                if (!mAssociatedViewport) {
                    ALOGW("Input device %s should be associated with display on port %" PRIu8 ", "
                          "but the corresponding viewport is not found.",
                          getName().c_str(), *mAssociatedDisplayPort);
                    enabled = false;
                }
            } else if (mAssociatedDisplayUniqueId != std::nullopt) {
                mAssociatedViewport =
                        config->getDisplayViewportByUniqueId(*mAssociatedDisplayUniqueId);
                if (!mAssociatedViewport) {
                    ALOGW("Input device %s should be associated with display %s but the "
                          "corresponding viewport cannot be found",
                          getName().c_str(), mAssociatedDisplayUniqueId->c_str());
                    enabled = false;
                }
            }

            if (changes) {
                // For first-time configuration, only allow device to be disabled after mappers have
                // finished configuring. This is because we need to read some of the properties from
                // the device's open fd.
                setEnabled(enabled, when);
            }
        }

        for_each_mapper([this, when, config, changes](InputMapper& mapper) {
            mapper.configure(when, config, changes);
            mSources |= mapper.getSources();
        });

        // If a device is just plugged but it might be disabled, we need to update some info like
        // axis range of touch from each InputMapper first, then disable it.
        if (!changes) {
            setEnabled(config->disabledDevices.find(mId) == config->disabledDevices.end(), when);
        }
    }
}

void InputDevice::reset(nsecs_t when) {
    for_each_mapper([when](InputMapper& mapper) { mapper.reset(when); });

    mContext->updateGlobalMetaState();

    notifyReset(when);
}

void InputDevice::process(const RawEvent* rawEvents, size_t count) {
    // Process all of the events in order for each mapper.
    // We cannot simply ask each mapper to process them in bulk because mappers may
    // have side-effects that must be interleaved.  For example, joystick movement events and
    // gamepad button presses are handled by different mappers but they should be dispatched
    // in the order received.
    for (const RawEvent* rawEvent = rawEvents; count != 0; rawEvent++) {
        if (DEBUG_RAW_EVENTS) {
            ALOGD("Input event: device=%d type=0x%04x code=0x%04x value=0x%08x when=%" PRId64,
                  rawEvent->deviceId, rawEvent->type, rawEvent->code, rawEvent->value,
                  rawEvent->when);
        }

        if (mDropUntilNextSync) {
            if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
                mDropUntilNextSync = false;
                if (DEBUG_RAW_EVENTS) {
                    ALOGD("Recovered from input event buffer overrun.");
                }
            } else {
                if (DEBUG_RAW_EVENTS) {
                    ALOGD("Dropped input event while waiting for next input sync.");
                }
            }
        } else if (rawEvent->type == EV_SYN && rawEvent->code == SYN_DROPPED) {
            ALOGI("Detected input event buffer overrun for device %s.", getName().c_str());
            mDropUntilNextSync = true;
            reset(rawEvent->when);
        } else {
            for_each_mapper_in_subdevice(rawEvent->deviceId, [rawEvent](InputMapper& mapper) {
                mapper.process(rawEvent);
            });
        }
        --count;
    }
}

void InputDevice::timeoutExpired(nsecs_t when) {
    for_each_mapper([when](InputMapper& mapper) { mapper.timeoutExpired(when); });
}

void InputDevice::updateExternalStylusState(const StylusState& state) {
    for_each_mapper([state](InputMapper& mapper) { mapper.updateExternalStylusState(state); });
}

InputDeviceInfo InputDevice::getDeviceInfo() {
    InputDeviceInfo outDeviceInfo;
    outDeviceInfo.initialize(mId, mGeneration, mControllerNumber, mIdentifier, mAlias, mIsExternal,
                             mHasMic);
    for_each_mapper(
            [&outDeviceInfo](InputMapper& mapper) { mapper.populateDeviceInfo(&outDeviceInfo); });

    if (mController) {
        mController->populateDeviceInfo(&outDeviceInfo);
    }
    return outDeviceInfo;
}

int32_t InputDevice::getKeyCodeState(uint32_t sourceMask, int32_t keyCode) {
    return getState(sourceMask, keyCode, &InputMapper::getKeyCodeState);
}

int32_t InputDevice::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    return getState(sourceMask, scanCode, &InputMapper::getScanCodeState);
}

int32_t InputDevice::getSwitchState(uint32_t sourceMask, int32_t switchCode) {
    return getState(sourceMask, switchCode, &InputMapper::getSwitchState);
}

int32_t InputDevice::getState(uint32_t sourceMask, int32_t code, GetStateFunc getStateFunc) {
    int32_t result = AKEY_STATE_UNKNOWN;
    for (auto& deviceEntry : mDevices) {
        auto& devicePair = deviceEntry.second;
        auto& mappers = devicePair.second;
        for (auto& mapperPtr : mappers) {
            InputMapper& mapper = *mapperPtr;
            if (sourcesMatchMask(mapper.getSources(), sourceMask)) {
                // If any mapper reports AKEY_STATE_DOWN or AKEY_STATE_VIRTUAL, return that
                // value.  Otherwise, return AKEY_STATE_UP as long as one mapper reports it.
                int32_t currentResult = (mapper.*getStateFunc)(sourceMask, code);
                if (currentResult >= AKEY_STATE_DOWN) {
                    return currentResult;
                } else if (currentResult == AKEY_STATE_UP) {
                    result = currentResult;
                }
            }
        }
    }
    return result;
}

bool InputDevice::markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes,
                                        const int32_t* keyCodes, uint8_t* outFlags) {
    bool result = false;
    for_each_mapper([&result, sourceMask, numCodes, keyCodes, outFlags](InputMapper& mapper) {
        if (sourcesMatchMask(mapper.getSources(), sourceMask)) {
            result |= mapper.markSupportedKeyCodes(sourceMask, numCodes, keyCodes, outFlags);
        }
    });
    return result;
}

int32_t InputDevice::getKeyCodeForKeyLocation(int32_t locationKeyCode) const {
    std::optional<int32_t> result = first_in_mappers<int32_t>(
            [locationKeyCode](const InputMapper& mapper) -> std::optional<int32_t> const {
                if (sourcesMatchMask(mapper.getSources(), AINPUT_SOURCE_KEYBOARD)) {
                    return std::make_optional(mapper.getKeyCodeForKeyLocation(locationKeyCode));
                }
                return std::nullopt;
            });
    if (!result) {
        ALOGE("Failed to get key code for key location: No matching InputMapper with source mask "
              "KEYBOARD found. The provided input device with id %d has sources %s.",
              getId(), inputEventSourceToString(getSources()).c_str());
        return AKEYCODE_UNKNOWN;
    }
    return *result;
}

void InputDevice::vibrate(const VibrationSequence& sequence, ssize_t repeat, int32_t token) {
    for_each_mapper([sequence, repeat, token](InputMapper& mapper) {
        mapper.vibrate(sequence, repeat, token);
    });
}

void InputDevice::cancelVibrate(int32_t token) {
    for_each_mapper([token](InputMapper& mapper) { mapper.cancelVibrate(token); });
}

bool InputDevice::isVibrating() {
    bool vibrating = false;
    for_each_mapper([&vibrating](InputMapper& mapper) { vibrating |= mapper.isVibrating(); });
    return vibrating;
}

/* There's no guarantee the IDs provided by the different mappers are unique, so if we have two
 * different vibration mappers then we could have duplicate IDs.
 * Alternatively, if we have a merged device that has multiple evdev nodes with FF_* capabilities,
 * we would definitely have duplicate IDs.
 */
std::vector<int32_t> InputDevice::getVibratorIds() {
    std::vector<int32_t> vibrators;
    for_each_mapper([&vibrators](InputMapper& mapper) {
        std::vector<int32_t> devVibs = mapper.getVibratorIds();
        vibrators.reserve(vibrators.size() + devVibs.size());
        vibrators.insert(vibrators.end(), devVibs.begin(), devVibs.end());
    });
    return vibrators;
}

bool InputDevice::enableSensor(InputDeviceSensorType sensorType,
                               std::chrono::microseconds samplingPeriod,
                               std::chrono::microseconds maxBatchReportLatency) {
    bool success = true;
    for_each_mapper(
            [&success, sensorType, samplingPeriod, maxBatchReportLatency](InputMapper& mapper) {
                success &= mapper.enableSensor(sensorType, samplingPeriod, maxBatchReportLatency);
            });
    return success;
}

void InputDevice::disableSensor(InputDeviceSensorType sensorType) {
    for_each_mapper([sensorType](InputMapper& mapper) { mapper.disableSensor(sensorType); });
}

void InputDevice::flushSensor(InputDeviceSensorType sensorType) {
    for_each_mapper([sensorType](InputMapper& mapper) { mapper.flushSensor(sensorType); });
}

void InputDevice::cancelTouch(nsecs_t when, nsecs_t readTime) {
    for_each_mapper([when, readTime](InputMapper& mapper) { mapper.cancelTouch(when, readTime); });
}

bool InputDevice::setLightColor(int32_t lightId, int32_t color) {
    return mController ? mController->setLightColor(lightId, color) : false;
}

bool InputDevice::setLightPlayerId(int32_t lightId, int32_t playerId) {
    return mController ? mController->setLightPlayerId(lightId, playerId) : false;
}

std::optional<int32_t> InputDevice::getLightColor(int32_t lightId) {
    return mController ? mController->getLightColor(lightId) : std::nullopt;
}

std::optional<int32_t> InputDevice::getLightPlayerId(int32_t lightId) {
    return mController ? mController->getLightPlayerId(lightId) : std::nullopt;
}

int32_t InputDevice::getMetaState() {
    int32_t result = 0;
    for_each_mapper([&result](InputMapper& mapper) { result |= mapper.getMetaState(); });
    return result;
}

void InputDevice::updateMetaState(int32_t keyCode) {
    first_in_mappers<bool>([keyCode](InputMapper& mapper) {
        if (sourcesMatchMask(mapper.getSources(), AINPUT_SOURCE_KEYBOARD) &&
            mapper.updateMetaState(keyCode)) {
            return std::make_optional(true);
        }
        return std::optional<bool>();
    });
}

void InputDevice::bumpGeneration() {
    mGeneration = mContext->bumpGeneration();
}

void InputDevice::notifyReset(nsecs_t when) {
    NotifyDeviceResetArgs args(mContext->getNextId(), when, mId);
    mContext->getListener().notifyDeviceReset(&args);
}

std::optional<int32_t> InputDevice::getAssociatedDisplayId() {
    // Check if we had associated to the specific display.
    if (mAssociatedViewport) {
        return mAssociatedViewport->displayId;
    }

    // No associated display port, check if some InputMapper is associated.
    return first_in_mappers<int32_t>(
            [](InputMapper& mapper) { return mapper.getAssociatedDisplayId(); });
}

// returns the number of mappers associated with the device
size_t InputDevice::getMapperCount() {
    size_t count = 0;
    for (auto& deviceEntry : mDevices) {
        auto& devicePair = deviceEntry.second;
        auto& mappers = devicePair.second;
        count += mappers.size();
    }
    return count;
}

void InputDevice::updateLedState(bool reset) {
    for_each_mapper([reset](InputMapper& mapper) { mapper.updateLedState(reset); });
}

std::optional<int32_t> InputDevice::getBatteryEventHubId() const {
    return mController ? std::make_optional(mController->getEventHubId()) : std::nullopt;
}

InputDeviceContext::InputDeviceContext(InputDevice& device, int32_t eventHubId)
      : mDevice(device),
        mContext(device.getContext()),
        mEventHub(device.getContext()->getEventHub()),
        mId(eventHubId),
        mDeviceId(device.getId()) {}

InputDeviceContext::~InputDeviceContext() {}

} // namespace android
