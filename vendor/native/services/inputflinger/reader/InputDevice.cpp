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

#include "CursorInputMapper.h"
#include "ExternalStylusInputMapper.h"
#include "InputReaderContext.h"
#include "JoystickInputMapper.h"
#include "KeyboardInputMapper.h"
#include "MultiTouchInputMapper.h"
#include "RotaryEncoderInputMapper.h"
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
    // devices are either all enabled or all disabled, so we only need to check the first
    auto& devicePair = mDevices.begin()->second;
    auto& contextPtr = devicePair.first;
    return contextPtr->isDeviceEnabled();
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
    InputDeviceInfo deviceInfo;
    getDeviceInfo(&deviceInfo);

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
    dump += StringPrintf(INDENT2 "HasMic:     %s\n", toString(mHasMic));
    dump += StringPrintf(INDENT2 "Sources: 0x%08x\n", deviceInfo.getSources());
    dump += StringPrintf(INDENT2 "KeyboardType: %d\n", deviceInfo.getKeyboardType());
    dump += StringPrintf(INDENT2 "ControllerNum: %d\n", deviceInfo.getControllerNumber());

    const std::vector<InputDeviceInfo::MotionRange>& ranges = deviceInfo.getMotionRanges();
    if (!ranges.empty()) {
        dump += INDENT2 "Motion Ranges:\n";
        for (size_t i = 0; i < ranges.size(); i++) {
            const InputDeviceInfo::MotionRange& range = ranges[i];
            const char* label = getAxisLabel(range.axis);
            char name[32];
            if (label) {
                strncpy(name, label, sizeof(name));
                name[sizeof(name) - 1] = '\0';
            } else {
                snprintf(name, sizeof(name), "%d", range.axis);
            }
            dump += StringPrintf(INDENT3
                                 "%s: source=0x%08x, "
                                 "min=%0.3f, max=%0.3f, flat=%0.3f, fuzz=%0.3f, resolution=%0.3f\n",
                                 name, range.source, range.min, range.max, range.flat, range.fuzz,
                                 range.resolution);
        }
    }

    for_each_mapper([&dump](InputMapper& mapper) { mapper.dump(dump); });
}

void InputDevice::addEventHubDevice(int32_t eventHubId, bool populateMappers) {
    if (mDevices.find(eventHubId) != mDevices.end()) {
        return;
    }
    std::unique_ptr<InputDeviceContext> contextPtr(new InputDeviceContext(*this, eventHubId));
    uint32_t classes = contextPtr->getDeviceClasses();
    std::vector<std::unique_ptr<InputMapper>> mappers;

    // Check if we should skip population
    if (!populateMappers) {
        mDevices.insert({eventHubId, std::make_pair(std::move(contextPtr), std::move(mappers))});
        return;
    }

    // Switch-like devices.
    if (classes & INPUT_DEVICE_CLASS_SWITCH) {
        mappers.push_back(std::make_unique<SwitchInputMapper>(*contextPtr));
    }

    // Scroll wheel-like devices.
    if (classes & INPUT_DEVICE_CLASS_ROTARY_ENCODER) {
        mappers.push_back(std::make_unique<RotaryEncoderInputMapper>(*contextPtr));
    }

    // Vibrator-like devices.
    if (classes & INPUT_DEVICE_CLASS_VIBRATOR) {
        mappers.push_back(std::make_unique<VibratorInputMapper>(*contextPtr));
    }

    // Keyboard-like devices.
    uint32_t keyboardSource = 0;
    int32_t keyboardType = AINPUT_KEYBOARD_TYPE_NON_ALPHABETIC;
    if (classes & INPUT_DEVICE_CLASS_KEYBOARD) {
        keyboardSource |= AINPUT_SOURCE_KEYBOARD;
    }
    if (classes & INPUT_DEVICE_CLASS_ALPHAKEY) {
        keyboardType = AINPUT_KEYBOARD_TYPE_ALPHABETIC;
    }
    if (classes & INPUT_DEVICE_CLASS_DPAD) {
        keyboardSource |= AINPUT_SOURCE_DPAD;
    }
    if (classes & INPUT_DEVICE_CLASS_GAMEPAD) {
        keyboardSource |= AINPUT_SOURCE_GAMEPAD;
    }

    if (keyboardSource != 0) {
        mappers.push_back(
                std::make_unique<KeyboardInputMapper>(*contextPtr, keyboardSource, keyboardType));
    }

    // Cursor-like devices.
    if (classes & INPUT_DEVICE_CLASS_CURSOR) {
        mappers.push_back(std::make_unique<CursorInputMapper>(*contextPtr));
    }

    // Touchscreens and touchpad devices.
    if (classes & INPUT_DEVICE_CLASS_TOUCH_MT) {
        mappers.push_back(std::make_unique<MultiTouchInputMapper>(*contextPtr));
    } else if (classes & INPUT_DEVICE_CLASS_TOUCH) {
        mappers.push_back(std::make_unique<SingleTouchInputMapper>(*contextPtr));
    }

    // Joystick-like devices.
    if (classes & INPUT_DEVICE_CLASS_JOYSTICK) {
        mappers.push_back(std::make_unique<JoystickInputMapper>(*contextPtr));
    }

    // External stylus-like devices.
    if (classes & INPUT_DEVICE_CLASS_EXTERNAL_STYLUS) {
        mappers.push_back(std::make_unique<ExternalStylusInputMapper>(*contextPtr));
    }

    // insert the context into the devices set
    mDevices.insert({eventHubId, std::make_pair(std::move(contextPtr), std::move(mappers))});
    // Must change generation to flag this device as changed
    bumpGeneration();
}

void InputDevice::removeEventHubDevice(int32_t eventHubId) {
    mDevices.erase(eventHubId);
}

void InputDevice::configure(nsecs_t when, const InputReaderConfiguration* config,
                            uint32_t changes) {
    mSources = 0;
    mClasses = 0;
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

    mIsExternal = !!(mClasses & INPUT_DEVICE_CLASS_EXTERNAL);
    mHasMic = !!(mClasses & INPUT_DEVICE_CLASS_MIC);

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
            if (!(mClasses & INPUT_DEVICE_CLASS_VIRTUAL)) {
                sp<KeyCharacterMap> keyboardLayout =
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
            if (!(mClasses & INPUT_DEVICE_CLASS_VIRTUAL)) {
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
            // In most situations, no port will be specified.
            mAssociatedDisplayPort = std::nullopt;
            mAssociatedViewport = std::nullopt;
            // Find the display port that corresponds to the current input port.
            const std::string& inputPort = mIdentifier.location;
            if (!inputPort.empty()) {
                const std::unordered_map<std::string, uint8_t>& ports = config->portAssociations;
                const auto& displayPort = ports.find(inputPort);
                if (displayPort != ports.end()) {
                    mAssociatedDisplayPort = std::make_optional(displayPort->second);
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
#if DEBUG_RAW_EVENTS
        ALOGD("Input event: device=%d type=0x%04x code=0x%04x value=0x%08x when=%" PRId64,
              rawEvent->deviceId, rawEvent->type, rawEvent->code, rawEvent->value, rawEvent->when);
#endif

        if (mDropUntilNextSync) {
            if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
                mDropUntilNextSync = false;
#if DEBUG_RAW_EVENTS
                ALOGD("Recovered from input event buffer overrun.");
#endif
            } else {
#if DEBUG_RAW_EVENTS
                ALOGD("Dropped input event while waiting for next input sync.");
#endif
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

void InputDevice::getDeviceInfo(InputDeviceInfo* outDeviceInfo) {
    outDeviceInfo->initialize(mId, mGeneration, mControllerNumber, mIdentifier, mAlias, mIsExternal,
                              mHasMic);
    for_each_mapper(
            [outDeviceInfo](InputMapper& mapper) { mapper.populateDeviceInfo(outDeviceInfo); });
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

void InputDevice::vibrate(const nsecs_t* pattern, size_t patternSize, ssize_t repeat,
                          int32_t token) {
    for_each_mapper([pattern, patternSize, repeat, token](InputMapper& mapper) {
        mapper.vibrate(pattern, patternSize, repeat, token);
    });
}

void InputDevice::cancelVibrate(int32_t token) {
    for_each_mapper([token](InputMapper& mapper) { mapper.cancelVibrate(token); });
}

void InputDevice::cancelTouch(nsecs_t when) {
    for_each_mapper([when](InputMapper& mapper) { mapper.cancelTouch(when); });
}

int32_t InputDevice::getMetaState() {
    int32_t result = 0;
    for_each_mapper([&result](InputMapper& mapper) { result |= mapper.getMetaState(); });
    return result;
}

void InputDevice::updateMetaState(int32_t keyCode) {
    for_each_mapper([keyCode](InputMapper& mapper) { mapper.updateMetaState(keyCode); });
}

void InputDevice::bumpGeneration() {
    mGeneration = mContext->bumpGeneration();
}

void InputDevice::notifyReset(nsecs_t when) {
    NotifyDeviceResetArgs args(mContext->getNextId(), when, mId);
    mContext->getListener()->notifyDeviceReset(&args);
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

InputDeviceContext::InputDeviceContext(InputDevice& device, int32_t eventHubId)
      : mDevice(device),
        mContext(device.getContext()),
        mEventHub(device.getContext()->getEventHub()),
        mId(eventHubId),
        mDeviceId(device.getId()) {}

InputDeviceContext::~InputDeviceContext() {}

} // namespace android
