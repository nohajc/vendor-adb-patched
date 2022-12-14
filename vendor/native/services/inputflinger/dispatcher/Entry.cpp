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

#include "Entry.h"

#include "Connection.h"

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <cutils/atomic.h>
#include <inttypes.h>

using android::base::GetBoolProperty;
using android::base::StringPrintf;

namespace android::inputdispatcher {

VerifiedKeyEvent verifiedKeyEventFromKeyEntry(const KeyEntry& entry) {
    return {{VerifiedInputEvent::Type::KEY, entry.deviceId, entry.eventTime, entry.source,
             entry.displayId},
            entry.action,
            entry.downTime,
            entry.flags & VERIFIED_KEY_EVENT_FLAGS,
            entry.keyCode,
            entry.scanCode,
            entry.metaState,
            entry.repeatCount};
}

VerifiedMotionEvent verifiedMotionEventFromMotionEntry(const MotionEntry& entry) {
    const float rawX = entry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X);
    const float rawY = entry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y);
    const int actionMasked = entry.action & AMOTION_EVENT_ACTION_MASK;
    return {{VerifiedInputEvent::Type::MOTION, entry.deviceId, entry.eventTime, entry.source,
             entry.displayId},
            rawX,
            rawY,
            actionMasked,
            entry.downTime,
            entry.flags & VERIFIED_MOTION_EVENT_FLAGS,
            entry.metaState,
            entry.buttonState};
}

// --- EventEntry ---

EventEntry::EventEntry(int32_t id, Type type, nsecs_t eventTime, uint32_t policyFlags)
      : id(id),
        refCount(1),
        type(type),
        eventTime(eventTime),
        policyFlags(policyFlags),
        injectionState(nullptr),
        dispatchInProgress(false) {}

EventEntry::~EventEntry() {
    releaseInjectionState();
}

std::string EventEntry::getDescription() const {
    std::string result;
    appendDescription(result);
    return result;
}

void EventEntry::release() {
    refCount -= 1;
    if (refCount == 0) {
        delete this;
    } else {
        ALOG_ASSERT(refCount > 0);
    }
}

void EventEntry::releaseInjectionState() {
    if (injectionState) {
        injectionState->release();
        injectionState = nullptr;
    }
}

// --- ConfigurationChangedEntry ---

ConfigurationChangedEntry::ConfigurationChangedEntry(int32_t id, nsecs_t eventTime)
      : EventEntry(id, Type::CONFIGURATION_CHANGED, eventTime, 0) {}

ConfigurationChangedEntry::~ConfigurationChangedEntry() {}

void ConfigurationChangedEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("ConfigurationChangedEvent(), policyFlags=0x%08x", policyFlags);
}

// --- DeviceResetEntry ---

DeviceResetEntry::DeviceResetEntry(int32_t id, nsecs_t eventTime, int32_t deviceId)
      : EventEntry(id, Type::DEVICE_RESET, eventTime, 0), deviceId(deviceId) {}

DeviceResetEntry::~DeviceResetEntry() {}

void DeviceResetEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("DeviceResetEvent(deviceId=%d), policyFlags=0x%08x", deviceId, policyFlags);
}

// --- FocusEntry ---

// Focus notifications always go to apps, so set the flag POLICY_FLAG_PASS_TO_USER for all entries
FocusEntry::FocusEntry(int32_t id, nsecs_t eventTime, sp<IBinder> connectionToken, bool hasFocus)
      : EventEntry(id, Type::FOCUS, eventTime, POLICY_FLAG_PASS_TO_USER),
        connectionToken(connectionToken),
        hasFocus(hasFocus) {}

FocusEntry::~FocusEntry() {}

void FocusEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("FocusEvent(hasFocus=%s)", hasFocus ? "true" : "false");
}

// --- KeyEntry ---

KeyEntry::KeyEntry(int32_t id, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                   int32_t displayId, uint32_t policyFlags, int32_t action, int32_t flags,
                   int32_t keyCode, int32_t scanCode, int32_t metaState, int32_t repeatCount,
                   nsecs_t downTime)
      : EventEntry(id, Type::KEY, eventTime, policyFlags),
        deviceId(deviceId),
        source(source),
        displayId(displayId),
        action(action),
        flags(flags),
        keyCode(keyCode),
        scanCode(scanCode),
        metaState(metaState),
        repeatCount(repeatCount),
        downTime(downTime),
        syntheticRepeat(false),
        interceptKeyResult(KeyEntry::INTERCEPT_KEY_RESULT_UNKNOWN),
        interceptKeyWakeupTime(0) {}

KeyEntry::~KeyEntry() {}

void KeyEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("KeyEvent");
    if (!GetBoolProperty("ro.debuggable", false)) {
        return;
    }
    msg += StringPrintf("(deviceId=%d, source=0x%08x, displayId=%" PRId32 ", action=%s, "
                        "flags=0x%08x, keyCode=%d, scanCode=%d, metaState=0x%08x, "
                        "repeatCount=%d), policyFlags=0x%08x",
                        deviceId, source, displayId, KeyEvent::actionToString(action), flags,
                        keyCode, scanCode, metaState, repeatCount, policyFlags);
}

void KeyEntry::recycle() {
    releaseInjectionState();

    dispatchInProgress = false;
    syntheticRepeat = false;
    interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_UNKNOWN;
    interceptKeyWakeupTime = 0;
}

// --- MotionEntry ---

MotionEntry::MotionEntry(int32_t id, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                         int32_t displayId, uint32_t policyFlags, int32_t action,
                         int32_t actionButton, int32_t flags, int32_t metaState,
                         int32_t buttonState, MotionClassification classification,
                         int32_t edgeFlags, float xPrecision, float yPrecision,
                         float xCursorPosition, float yCursorPosition, nsecs_t downTime,
                         uint32_t pointerCount, const PointerProperties* pointerProperties,
                         const PointerCoords* pointerCoords, float xOffset, float yOffset)
      : EventEntry(id, Type::MOTION, eventTime, policyFlags),
        eventTime(eventTime),
        deviceId(deviceId),
        source(source),
        displayId(displayId),
        action(action),
        actionButton(actionButton),
        flags(flags),
        metaState(metaState),
        buttonState(buttonState),
        classification(classification),
        edgeFlags(edgeFlags),
        xPrecision(xPrecision),
        yPrecision(yPrecision),
        xCursorPosition(xCursorPosition),
        yCursorPosition(yCursorPosition),
        downTime(downTime),
        pointerCount(pointerCount) {
    for (uint32_t i = 0; i < pointerCount; i++) {
        this->pointerProperties[i].copyFrom(pointerProperties[i]);
        this->pointerCoords[i].copyFrom(pointerCoords[i]);
        if (xOffset || yOffset) {
            this->pointerCoords[i].applyOffset(xOffset, yOffset);
        }
    }
}

MotionEntry::~MotionEntry() {}

void MotionEntry::appendDescription(std::string& msg) const {
    msg += StringPrintf("MotionEvent");
    if (!GetBoolProperty("ro.debuggable", false)) {
        return;
    }
    msg += StringPrintf("(deviceId=%d, source=0x%08x, displayId=%" PRId32
                        ", action=%s, actionButton=0x%08x, flags=0x%08x, metaState=0x%08x, "
                        "buttonState=0x%08x, "
                        "classification=%s, edgeFlags=0x%08x, xPrecision=%.1f, yPrecision=%.1f, "
                        "xCursorPosition=%0.1f, yCursorPosition=%0.1f, pointers=[",
                        deviceId, source, displayId, MotionEvent::actionToString(action),
                        actionButton, flags, metaState, buttonState,
                        motionClassificationToString(classification), edgeFlags, xPrecision,
                        yPrecision, xCursorPosition, yCursorPosition);

    for (uint32_t i = 0; i < pointerCount; i++) {
        if (i) {
            msg += ", ";
        }
        msg += StringPrintf("%d: (%.1f, %.1f)", pointerProperties[i].id, pointerCoords[i].getX(),
                            pointerCoords[i].getY());
    }
    msg += StringPrintf("]), policyFlags=0x%08x", policyFlags);
}

// --- DispatchEntry ---

volatile int32_t DispatchEntry::sNextSeqAtomic;

DispatchEntry::DispatchEntry(EventEntry* eventEntry, int32_t targetFlags, float xOffset,
                             float yOffset, float globalScaleFactor, float windowXScale,
                             float windowYScale)
      : seq(nextSeq()),
        eventEntry(eventEntry),
        targetFlags(targetFlags),
        xOffset(xOffset),
        yOffset(yOffset),
        globalScaleFactor(globalScaleFactor),
        windowXScale(windowXScale),
        windowYScale(windowYScale),
        deliveryTime(0),
        resolvedAction(0),
        resolvedFlags(0) {
    eventEntry->refCount += 1;
}

DispatchEntry::~DispatchEntry() {
    eventEntry->release();
}

uint32_t DispatchEntry::nextSeq() {
    // Sequence number 0 is reserved and will never be returned.
    uint32_t seq;
    do {
        seq = android_atomic_inc(&sNextSeqAtomic);
    } while (!seq);
    return seq;
}

// --- CommandEntry ---

CommandEntry::CommandEntry(Command command)
      : command(command),
        eventTime(0),
        keyEntry(nullptr),
        userActivityEventType(0),
        seq(0),
        handled(false) {}

CommandEntry::~CommandEntry() {}

} // namespace android::inputdispatcher
