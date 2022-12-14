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

#ifndef _UI_INPUTREADER_KEYBOARD_INPUT_MAPPER_H
#define _UI_INPUTREADER_KEYBOARD_INPUT_MAPPER_H

#include "InputMapper.h"

namespace android {

class KeyboardInputMapper : public InputMapper {
public:
    KeyboardInputMapper(InputDeviceContext& deviceContext, uint32_t source, int32_t keyboardType);
    virtual ~KeyboardInputMapper();

    virtual uint32_t getSources() override;
    virtual void populateDeviceInfo(InputDeviceInfo* deviceInfo) override;
    virtual void dump(std::string& dump) override;
    virtual void configure(nsecs_t when, const InputReaderConfiguration* config,
                           uint32_t changes) override;
    virtual void reset(nsecs_t when) override;
    virtual void process(const RawEvent* rawEvent) override;

    virtual int32_t getKeyCodeState(uint32_t sourceMask, int32_t keyCode) override;
    virtual int32_t getScanCodeState(uint32_t sourceMask, int32_t scanCode) override;
    virtual bool markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes,
                                       const int32_t* keyCodes, uint8_t* outFlags) override;

    virtual int32_t getMetaState() override;
    virtual void updateMetaState(int32_t keyCode) override;
    virtual std::optional<int32_t> getAssociatedDisplayId() override;
    virtual void updateLedState(bool reset);

private:
    // The current viewport.
    std::optional<DisplayViewport> mViewport;

    struct KeyDown {
        int32_t keyCode;
        int32_t scanCode;
    };

    uint32_t mSource;
    int32_t mKeyboardType;

    std::vector<KeyDown> mKeyDowns; // keys that are down
    int32_t mMetaState;
    nsecs_t mDownTime; // time of most recent key down

    int32_t mCurrentHidUsage; // most recent HID usage seen this packet, or 0 if none

    struct LedState {
        bool avail; // led is available
        bool on;    // we think the led is currently on
    };
    LedState mCapsLockLedState;
    LedState mNumLockLedState;
    LedState mScrollLockLedState;

    // Immutable configuration parameters.
    struct Parameters {
        bool orientationAware;
        bool handlesKeyRepeat;
        bool doNotWakeByDefault;
    } mParameters;

    void configureParameters();
    void dumpParameters(std::string& dump);

    int32_t getOrientation();
    int32_t getDisplayId();

    bool isKeyboardOrGamepadKey(int32_t scanCode);
    bool isMediaKey(int32_t keyCode);

    void processKey(nsecs_t when, nsecs_t readTime, bool down, int32_t scanCode, int32_t usageCode);

    bool updateMetaStateIfNeeded(int32_t keyCode, bool down);

    ssize_t findKeyDown(int32_t scanCode);

    void resetLedState();
    void initializeLedState(LedState& ledState, int32_t led);
    void updateLedStateForModifier(LedState& ledState, int32_t led, int32_t modifier, bool reset);
    std::optional<DisplayViewport> findViewport(nsecs_t when,
                                                const InputReaderConfiguration* config);
};

} // namespace android

#endif // _UI_INPUTREADER_KEYBOARD_INPUT_MAPPER_H