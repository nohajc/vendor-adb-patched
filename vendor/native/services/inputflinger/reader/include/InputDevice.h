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

#ifndef _UI_INPUTREADER_INPUT_DEVICE_H
#define _UI_INPUTREADER_INPUT_DEVICE_H

#include <input/DisplayViewport.h>
#include <input/InputDevice.h>
#include <input/PropertyMap.h>
#include <stdint.h>

#include <optional>
#include <unordered_map>
#include <vector>

#include "EventHub.h"
#include "InputReaderBase.h"
#include "InputReaderContext.h"

namespace android {

class InputDeviceContext;
class InputMapper;

/* Represents the state of a single input device. */
class InputDevice {
public:
    InputDevice(InputReaderContext* context, int32_t id, int32_t generation,
                const InputDeviceIdentifier& identifier);
    ~InputDevice();

    inline InputReaderContext* getContext() { return mContext; }
    inline int32_t getId() const { return mId; }
    inline int32_t getControllerNumber() const { return mControllerNumber; }
    inline int32_t getGeneration() const { return mGeneration; }
    inline const std::string getName() const { return mIdentifier.name; }
    inline const std::string getDescriptor() { return mIdentifier.descriptor; }
    inline uint32_t getClasses() const { return mClasses; }
    inline uint32_t getSources() const { return mSources; }
    inline bool hasEventHubDevices() const { return !mDevices.empty(); }

    inline bool isExternal() { return mIsExternal; }
    inline std::optional<uint8_t> getAssociatedDisplayPort() const {
        return mAssociatedDisplayPort;
    }
    inline std::optional<DisplayViewport> getAssociatedViewport() const {
        return mAssociatedViewport;
    }
    inline bool hasMic() const { return mHasMic; }

    inline bool isIgnored() { return !getMapperCount(); }

    bool isEnabled();
    void setEnabled(bool enabled, nsecs_t when);

    void dump(std::string& dump, const std::string& eventHubDevStr);
    void addEventHubDevice(int32_t eventHubId, bool populateMappers = true);
    void removeEventHubDevice(int32_t eventHubId);
    void configure(nsecs_t when, const InputReaderConfiguration* config, uint32_t changes);
    void reset(nsecs_t when);
    void process(const RawEvent* rawEvents, size_t count);
    void timeoutExpired(nsecs_t when);
    void updateExternalStylusState(const StylusState& state);

    void getDeviceInfo(InputDeviceInfo* outDeviceInfo);
    int32_t getKeyCodeState(uint32_t sourceMask, int32_t keyCode);
    int32_t getScanCodeState(uint32_t sourceMask, int32_t scanCode);
    int32_t getSwitchState(uint32_t sourceMask, int32_t switchCode);
    bool markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes, const int32_t* keyCodes,
                               uint8_t* outFlags);
    void vibrate(const nsecs_t* pattern, size_t patternSize, ssize_t repeat, int32_t token);
    void cancelVibrate(int32_t token);
    void cancelTouch(nsecs_t when);

    int32_t getMetaState();
    void updateMetaState(int32_t keyCode);

    void bumpGeneration();

    void notifyReset(nsecs_t when);

    inline const PropertyMap& getConfiguration() { return mConfiguration; }
    inline EventHubInterface* getEventHub() { return mContext->getEventHub(); }

    std::optional<int32_t> getAssociatedDisplayId();

    size_t getMapperCount();

    // construct and add a mapper to the input device
    template <class T, typename... Args>
    T& addMapper(int32_t eventHubId, Args... args) {
        // ensure a device entry exists for this eventHubId
        addEventHubDevice(eventHubId, false);

        // create mapper
        auto& devicePair = mDevices[eventHubId];
        auto& deviceContext = devicePair.first;
        auto& mappers = devicePair.second;
        T* mapper = new T(*deviceContext, args...);
        mappers.emplace_back(mapper);
        return *mapper;
    }

private:
    InputReaderContext* mContext;
    int32_t mId;
    int32_t mGeneration;
    int32_t mControllerNumber;
    InputDeviceIdentifier mIdentifier;
    std::string mAlias;
    uint32_t mClasses;

    // map from eventHubId to device context and mappers
    using MapperVector = std::vector<std::unique_ptr<InputMapper>>;
    using DevicePair = std::pair<std::unique_ptr<InputDeviceContext>, MapperVector>;
    std::unordered_map<int32_t, DevicePair> mDevices;

    uint32_t mSources;
    bool mIsExternal;
    std::optional<uint8_t> mAssociatedDisplayPort;
    std::optional<DisplayViewport> mAssociatedViewport;
    bool mHasMic;
    bool mDropUntilNextSync;

    typedef int32_t (InputMapper::*GetStateFunc)(uint32_t sourceMask, int32_t code);
    int32_t getState(uint32_t sourceMask, int32_t code, GetStateFunc getStateFunc);

    PropertyMap mConfiguration;

    // helpers to interate over the devices collection
    // run a function against every mapper on every subdevice
    inline void for_each_mapper(std::function<void(InputMapper&)> f) {
        for (auto& deviceEntry : mDevices) {
            auto& devicePair = deviceEntry.second;
            auto& mappers = devicePair.second;
            for (auto& mapperPtr : mappers) {
                f(*mapperPtr);
            }
        }
    }

    // run a function against every mapper on a specific subdevice
    inline void for_each_mapper_in_subdevice(int32_t eventHubDevice,
                                             std::function<void(InputMapper&)> f) {
        auto deviceIt = mDevices.find(eventHubDevice);
        if (deviceIt != mDevices.end()) {
            auto& devicePair = deviceIt->second;
            auto& mappers = devicePair.second;
            for (auto& mapperPtr : mappers) {
                f(*mapperPtr);
            }
        }
    }

    // run a function against every subdevice
    inline void for_each_subdevice(std::function<void(InputDeviceContext&)> f) {
        for (auto& deviceEntry : mDevices) {
            auto& devicePair = deviceEntry.second;
            auto& contextPtr = devicePair.first;
            f(*contextPtr);
        }
    }

    // return the first value returned by a function over every mapper.
    // if all mappers return nullopt, return nullopt.
    template <typename T>
    inline std::optional<T> first_in_mappers(std::function<std::optional<T>(InputMapper&)> f) {
        for (auto& deviceEntry : mDevices) {
            auto& devicePair = deviceEntry.second;
            auto& mappers = devicePair.second;
            for (auto& mapperPtr : mappers) {
                std::optional<T> ret = f(*mapperPtr);
                if (ret) {
                    return ret;
                }
            }
        }
        return std::nullopt;
    }
};

/* Provides access to EventHub methods, but limits access to the current InputDevice.
 * Essentially an implementation of EventHubInterface, but for a specific device id.
 * Helps hide implementation details of InputDevice and EventHub. Used by mappers to
 * check the status of the associated hardware device
 */
class InputDeviceContext {
public:
    InputDeviceContext(InputDevice& device, int32_t eventHubId);
    ~InputDeviceContext();

    inline InputReaderContext* getContext() { return mContext; }
    inline int32_t getId() { return mDeviceId; }
    inline int32_t getEventHubId() { return mId; }

    inline uint32_t getDeviceClasses() const { return mEventHub->getDeviceClasses(mId); }
    inline InputDeviceIdentifier getDeviceIdentifier() const {
        return mEventHub->getDeviceIdentifier(mId);
    }
    inline int32_t getDeviceControllerNumber() const {
        return mEventHub->getDeviceControllerNumber(mId);
    }
    inline void getConfiguration(PropertyMap* outConfiguration) const {
        return mEventHub->getConfiguration(mId, outConfiguration);
    }
    inline status_t getAbsoluteAxisInfo(int32_t code, RawAbsoluteAxisInfo* axisInfo) const {
        return mEventHub->getAbsoluteAxisInfo(mId, code, axisInfo);
    }
    inline bool hasRelativeAxis(int32_t code) const {
        return mEventHub->hasRelativeAxis(mId, code);
    }
    inline bool hasInputProperty(int property) const {
        return mEventHub->hasInputProperty(mId, property);
    }
    inline status_t mapKey(int32_t scanCode, int32_t usageCode, int32_t metaState,
                           int32_t* outKeycode, int32_t* outMetaState, uint32_t* outFlags) const {
        return mEventHub->mapKey(mId, scanCode, usageCode, metaState, outKeycode, outMetaState,
                                 outFlags);
    }
    inline status_t mapAxis(int32_t scanCode, AxisInfo* outAxisInfo) const {
        return mEventHub->mapAxis(mId, scanCode, outAxisInfo);
    }
    inline std::vector<TouchVideoFrame> getVideoFrames() { return mEventHub->getVideoFrames(mId); }
    inline int32_t getScanCodeState(int32_t scanCode) const {
        return mEventHub->getScanCodeState(mId, scanCode);
    }
    inline int32_t getKeyCodeState(int32_t keyCode) const {
        return mEventHub->getKeyCodeState(mId, keyCode);
    }
    inline int32_t getSwitchState(int32_t sw) const { return mEventHub->getSwitchState(mId, sw); }
    inline status_t getAbsoluteAxisValue(int32_t code, int32_t* outValue) const {
        return mEventHub->getAbsoluteAxisValue(mId, code, outValue);
    }
    inline bool markSupportedKeyCodes(size_t numCodes, const int32_t* keyCodes,
                                      uint8_t* outFlags) const {
        return mEventHub->markSupportedKeyCodes(mId, numCodes, keyCodes, outFlags);
    }
    inline bool hasScanCode(int32_t scanCode) const {
        return mEventHub->hasScanCode(mId, scanCode);
    }
    inline bool hasLed(int32_t led) const { return mEventHub->hasLed(mId, led); }
    inline void setLedState(int32_t led, bool on) { return mEventHub->setLedState(mId, led, on); }
    inline void getVirtualKeyDefinitions(std::vector<VirtualKeyDefinition>& outVirtualKeys) const {
        return mEventHub->getVirtualKeyDefinitions(mId, outVirtualKeys);
    }
    inline sp<KeyCharacterMap> getKeyCharacterMap() const {
        return mEventHub->getKeyCharacterMap(mId);
    }
    inline bool setKeyboardLayoutOverlay(const sp<KeyCharacterMap>& map) {
        return mEventHub->setKeyboardLayoutOverlay(mId, map);
    }
    inline void vibrate(nsecs_t duration) { return mEventHub->vibrate(mId, duration); }
    inline void cancelVibrate() { return mEventHub->cancelVibrate(mId); }

    inline bool hasAbsoluteAxis(int32_t code) const {
        RawAbsoluteAxisInfo info;
        mEventHub->getAbsoluteAxisInfo(mId, code, &info);
        return info.valid;
    }
    inline bool isKeyPressed(int32_t code) const {
        return mEventHub->getScanCodeState(mId, code) == AKEY_STATE_DOWN;
    }
    inline int32_t getAbsoluteAxisValue(int32_t code) const {
        int32_t value;
        mEventHub->getAbsoluteAxisValue(mId, code, &value);
        return value;
    }
    inline bool isDeviceEnabled() { return mEventHub->isDeviceEnabled(mId); }
    inline status_t enableDevice() { return mEventHub->enableDevice(mId); }
    inline status_t disableDevice() { return mEventHub->disableDevice(mId); }

    inline const std::string getName() { return mDevice.getName(); }
    inline const std::string getDescriptor() { return mDevice.getDescriptor(); }
    inline bool isExternal() { return mDevice.isExternal(); }
    inline std::optional<uint8_t> getAssociatedDisplayPort() const {
        return mDevice.getAssociatedDisplayPort();
    }
    inline std::optional<DisplayViewport> getAssociatedViewport() const {
        return mDevice.getAssociatedViewport();
    }
    inline void cancelTouch(nsecs_t when) { mDevice.cancelTouch(when); }
    inline void bumpGeneration() { mDevice.bumpGeneration(); }
    inline const PropertyMap& getConfiguration() { return mDevice.getConfiguration(); }

private:
    InputDevice& mDevice;
    InputReaderContext* mContext;
    EventHubInterface* mEventHub;
    int32_t mId;
    int32_t mDeviceId;
};

} // namespace android

#endif //_UI_INPUTREADER_INPUT_DEVICE_H
