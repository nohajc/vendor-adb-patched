/*
 * Copyright (C) 2011 The Android Open Source Project
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

#define LOG_TAG "InputListener"

#define ATRACE_TAG ATRACE_TAG_INPUT

//#define LOG_NDEBUG 0

#include "InputListener.h"

#include <android-base/stringprintf.h>
#include <android/log.h>
#include <math.h>
#include <utils/Trace.h>

using android::base::StringPrintf;

namespace android {

// --- NotifyConfigurationChangedArgs ---

NotifyConfigurationChangedArgs::NotifyConfigurationChangedArgs(int32_t id, nsecs_t eventTime)
      : NotifyArgs(id, eventTime) {}

NotifyConfigurationChangedArgs::NotifyConfigurationChangedArgs(
        const NotifyConfigurationChangedArgs& other)
      : NotifyArgs(other.id, other.eventTime) {}

bool NotifyConfigurationChangedArgs::operator==(const NotifyConfigurationChangedArgs& rhs) const {
    return id == rhs.id && eventTime == rhs.eventTime;
}

void NotifyConfigurationChangedArgs::notify(InputListenerInterface& listener) const {
    listener.notifyConfigurationChanged(this);
}

// --- NotifyKeyArgs ---

NotifyKeyArgs::NotifyKeyArgs(int32_t id, nsecs_t eventTime, nsecs_t readTime, int32_t deviceId,
                             uint32_t source, int32_t displayId, uint32_t policyFlags,
                             int32_t action, int32_t flags, int32_t keyCode, int32_t scanCode,
                             int32_t metaState, nsecs_t downTime)
      : NotifyArgs(id, eventTime),
        deviceId(deviceId),
        source(source),
        displayId(displayId),
        policyFlags(policyFlags),
        action(action),
        flags(flags),
        keyCode(keyCode),
        scanCode(scanCode),
        metaState(metaState),
        downTime(downTime),
        readTime(readTime) {}

NotifyKeyArgs::NotifyKeyArgs(const NotifyKeyArgs& other)
      : NotifyArgs(other.id, other.eventTime),
        deviceId(other.deviceId),
        source(other.source),
        displayId(other.displayId),
        policyFlags(other.policyFlags),
        action(other.action),
        flags(other.flags),
        keyCode(other.keyCode),
        scanCode(other.scanCode),
        metaState(other.metaState),
        downTime(other.downTime),
        readTime(other.readTime) {}

bool NotifyKeyArgs::operator==(const NotifyKeyArgs& rhs) const {
    return id == rhs.id && eventTime == rhs.eventTime && readTime == rhs.readTime &&
            deviceId == rhs.deviceId && source == rhs.source && displayId == rhs.displayId &&
            policyFlags == rhs.policyFlags && action == rhs.action && flags == rhs.flags &&
            keyCode == rhs.keyCode && scanCode == rhs.scanCode && metaState == rhs.metaState &&
            downTime == rhs.downTime;
}

void NotifyKeyArgs::notify(InputListenerInterface& listener) const {
    listener.notifyKey(this);
}

// --- NotifyMotionArgs ---

NotifyMotionArgs::NotifyMotionArgs(
        int32_t id, nsecs_t eventTime, nsecs_t readTime, int32_t deviceId, uint32_t source,
        int32_t displayId, uint32_t policyFlags, int32_t action, int32_t actionButton,
        int32_t flags, int32_t metaState, int32_t buttonState, MotionClassification classification,
        int32_t edgeFlags, uint32_t pointerCount, const PointerProperties* pointerProperties,
        const PointerCoords* pointerCoords, float xPrecision, float yPrecision,
        float xCursorPosition, float yCursorPosition, nsecs_t downTime,
        const std::vector<TouchVideoFrame>& videoFrames)
      : NotifyArgs(id, eventTime),
        deviceId(deviceId),
        source(source),
        displayId(displayId),
        policyFlags(policyFlags),
        action(action),
        actionButton(actionButton),
        flags(flags),
        metaState(metaState),
        buttonState(buttonState),
        classification(classification),
        edgeFlags(edgeFlags),
        pointerCount(pointerCount),
        xPrecision(xPrecision),
        yPrecision(yPrecision),
        xCursorPosition(xCursorPosition),
        yCursorPosition(yCursorPosition),
        downTime(downTime),
        readTime(readTime),
        videoFrames(videoFrames) {
    for (uint32_t i = 0; i < pointerCount; i++) {
        this->pointerProperties[i].copyFrom(pointerProperties[i]);
        this->pointerCoords[i].copyFrom(pointerCoords[i]);
    }
}

NotifyMotionArgs::NotifyMotionArgs(const NotifyMotionArgs& other)
      : NotifyArgs(other.id, other.eventTime),
        deviceId(other.deviceId),
        source(other.source),
        displayId(other.displayId),
        policyFlags(other.policyFlags),
        action(other.action),
        actionButton(other.actionButton),
        flags(other.flags),
        metaState(other.metaState),
        buttonState(other.buttonState),
        classification(other.classification),
        edgeFlags(other.edgeFlags),
        pointerCount(other.pointerCount),
        xPrecision(other.xPrecision),
        yPrecision(other.yPrecision),
        xCursorPosition(other.xCursorPosition),
        yCursorPosition(other.yCursorPosition),
        downTime(other.downTime),
        readTime(other.readTime),
        videoFrames(other.videoFrames) {
    for (uint32_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].copyFrom(other.pointerProperties[i]);
        pointerCoords[i].copyFrom(other.pointerCoords[i]);
    }
}

static inline bool isCursorPositionEqual(float lhs, float rhs) {
    return (isnan(lhs) && isnan(rhs)) || lhs == rhs;
}

bool NotifyMotionArgs::operator==(const NotifyMotionArgs& rhs) const {
    bool equal = id == rhs.id && eventTime == rhs.eventTime && readTime == rhs.readTime &&
            deviceId == rhs.deviceId && source == rhs.source && displayId == rhs.displayId &&
            policyFlags == rhs.policyFlags && action == rhs.action &&
            actionButton == rhs.actionButton && flags == rhs.flags && metaState == rhs.metaState &&
            buttonState == rhs.buttonState && classification == rhs.classification &&
            edgeFlags == rhs.edgeFlags &&
            pointerCount == rhs.pointerCount
            // PointerProperties and PointerCoords are compared separately below
            && xPrecision == rhs.xPrecision && yPrecision == rhs.yPrecision &&
            isCursorPositionEqual(xCursorPosition, rhs.xCursorPosition) &&
            isCursorPositionEqual(yCursorPosition, rhs.yCursorPosition) &&
            downTime == rhs.downTime && videoFrames == rhs.videoFrames;
    if (!equal) {
        return false;
    }

    for (size_t i = 0; i < pointerCount; i++) {
        equal =
                pointerProperties[i] == rhs.pointerProperties[i]
                && pointerCoords[i] == rhs.pointerCoords[i];
        if (!equal) {
            return false;
        }
    }
    return true;
}

std::string NotifyMotionArgs::dump() const {
    std::string coords;
    for (uint32_t i = 0; i < pointerCount; i++) {
        if (!coords.empty()) {
            coords += ", ";
        }
        coords += StringPrintf("{%" PRIu32 ": ", i);
        coords +=
                StringPrintf("id=%" PRIu32 " x=%.1f y=%.1f pressure=%.1f", pointerProperties[i].id,
                             pointerCoords[i].getX(), pointerCoords[i].getY(),
                             pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_PRESSURE));
        const int32_t toolType = pointerProperties[i].toolType;
        if (toolType != AMOTION_EVENT_TOOL_TYPE_FINGER) {
            coords += StringPrintf(" toolType=%s", motionToolTypeToString(toolType));
        }
        const float major = pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR);
        const float minor = pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR);
        const float orientation = pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION);
        if (major != 0 || minor != 0) {
            coords += StringPrintf(" major=%.1f minor=%.1f orientation=%.1f", major, minor,
                                   orientation);
        }
        coords += "}";
    }
    return StringPrintf("NotifyMotionArgs(id=%" PRId32 ", eventTime=%" PRId64 ", deviceId=%" PRId32
                        ", source=%s, action=%s, pointerCount=%" PRIu32
                        " pointers=%s, flags=0x%08x)",
                        id, eventTime, deviceId, inputEventSourceToString(source).c_str(),
                        MotionEvent::actionToString(action).c_str(), pointerCount, coords.c_str(),
                        flags);
}

void NotifyMotionArgs::notify(InputListenerInterface& listener) const {
    listener.notifyMotion(this);
}

// --- NotifySwitchArgs ---

NotifySwitchArgs::NotifySwitchArgs(int32_t id, nsecs_t eventTime, uint32_t policyFlags,
                                   uint32_t switchValues, uint32_t switchMask)
      : NotifyArgs(id, eventTime),
        policyFlags(policyFlags),
        switchValues(switchValues),
        switchMask(switchMask) {}

NotifySwitchArgs::NotifySwitchArgs(const NotifySwitchArgs& other)
      : NotifyArgs(other.id, other.eventTime),
        policyFlags(other.policyFlags),
        switchValues(other.switchValues),
        switchMask(other.switchMask) {}

bool NotifySwitchArgs::operator==(const NotifySwitchArgs rhs) const {
    return id == rhs.id && eventTime == rhs.eventTime && policyFlags == rhs.policyFlags &&
            switchValues == rhs.switchValues && switchMask == rhs.switchMask;
}

void NotifySwitchArgs::notify(InputListenerInterface& listener) const {
    listener.notifySwitch(this);
}

// --- NotifySensorArgs ---

NotifySensorArgs::NotifySensorArgs(int32_t id, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                                   InputDeviceSensorType sensorType,
                                   InputDeviceSensorAccuracy accuracy, bool accuracyChanged,
                                   nsecs_t hwTimestamp, std::vector<float> values)
      : NotifyArgs(id, eventTime),
        deviceId(deviceId),
        source(source),
        sensorType(sensorType),
        accuracy(accuracy),
        accuracyChanged(accuracyChanged),
        hwTimestamp(hwTimestamp),
        values(std::move(values)) {}

NotifySensorArgs::NotifySensorArgs(const NotifySensorArgs& other)
      : NotifyArgs(other.id, other.eventTime),
        deviceId(other.deviceId),
        source(other.source),
        sensorType(other.sensorType),
        accuracy(other.accuracy),
        accuracyChanged(other.accuracyChanged),
        hwTimestamp(other.hwTimestamp),
        values(other.values) {}

bool NotifySensorArgs::operator==(const NotifySensorArgs rhs) const {
    return id == rhs.id && eventTime == rhs.eventTime && sensorType == rhs.sensorType &&
            accuracy == rhs.accuracy && accuracyChanged == rhs.accuracyChanged &&
            hwTimestamp == rhs.hwTimestamp && values == rhs.values;
}

void NotifySensorArgs::notify(InputListenerInterface& listener) const {
    listener.notifySensor(this);
}

// --- NotifyVibratorStateArgs ---

NotifyVibratorStateArgs::NotifyVibratorStateArgs(int32_t id, nsecs_t eventTime, int32_t deviceId,
                                                 bool isOn)
      : NotifyArgs(id, eventTime), deviceId(deviceId), isOn(isOn) {}

NotifyVibratorStateArgs::NotifyVibratorStateArgs(const NotifyVibratorStateArgs& other)
      : NotifyArgs(other.id, other.eventTime), deviceId(other.deviceId), isOn(other.isOn) {}

bool NotifyVibratorStateArgs::operator==(const NotifyVibratorStateArgs rhs) const {
    return id == rhs.id && eventTime == rhs.eventTime && deviceId == rhs.deviceId &&
            isOn == rhs.isOn;
}

void NotifyVibratorStateArgs::notify(InputListenerInterface& listener) const {
    listener.notifyVibratorState(this);
}

// --- NotifyDeviceResetArgs ---

NotifyDeviceResetArgs::NotifyDeviceResetArgs(int32_t id, nsecs_t eventTime, int32_t deviceId)
      : NotifyArgs(id, eventTime), deviceId(deviceId) {}

NotifyDeviceResetArgs::NotifyDeviceResetArgs(const NotifyDeviceResetArgs& other)
      : NotifyArgs(other.id, other.eventTime), deviceId(other.deviceId) {}

bool NotifyDeviceResetArgs::operator==(const NotifyDeviceResetArgs& rhs) const {
    return id == rhs.id && eventTime == rhs.eventTime && deviceId == rhs.deviceId;
}

void NotifyDeviceResetArgs::notify(InputListenerInterface& listener) const {
    listener.notifyDeviceReset(this);
}

// --- NotifyPointerCaptureChangedArgs ---

NotifyPointerCaptureChangedArgs::NotifyPointerCaptureChangedArgs(
        int32_t id, nsecs_t eventTime, const PointerCaptureRequest& request)
      : NotifyArgs(id, eventTime), request(request) {}

NotifyPointerCaptureChangedArgs::NotifyPointerCaptureChangedArgs(
        const NotifyPointerCaptureChangedArgs& other)
      : NotifyArgs(other.id, other.eventTime), request(other.request) {}

bool NotifyPointerCaptureChangedArgs::operator==(const NotifyPointerCaptureChangedArgs& rhs) const {
    return id == rhs.id && eventTime == rhs.eventTime && request == rhs.request;
}

void NotifyPointerCaptureChangedArgs::notify(InputListenerInterface& listener) const {
    listener.notifyPointerCaptureChanged(this);
}

// --- QueuedInputListener ---

static inline void traceEvent(const char* functionName, int32_t id) {
    if (ATRACE_ENABLED()) {
        std::string message = StringPrintf("%s(id=0x%" PRIx32 ")", functionName, id);
        ATRACE_NAME(message.c_str());
    }
}

QueuedInputListener::QueuedInputListener(InputListenerInterface& innerListener)
      : mInnerListener(innerListener) {}

void QueuedInputListener::notifyConfigurationChanged(
        const NotifyConfigurationChangedArgs* args) {
    traceEvent(__func__, args->id);
    mArgsQueue.emplace_back(std::make_unique<NotifyConfigurationChangedArgs>(*args));
}

void QueuedInputListener::notifyKey(const NotifyKeyArgs* args) {
    traceEvent(__func__, args->id);
    mArgsQueue.emplace_back(std::make_unique<NotifyKeyArgs>(*args));
}

void QueuedInputListener::notifyMotion(const NotifyMotionArgs* args) {
    traceEvent(__func__, args->id);
    mArgsQueue.emplace_back(std::make_unique<NotifyMotionArgs>(*args));
}

void QueuedInputListener::notifySwitch(const NotifySwitchArgs* args) {
    traceEvent(__func__, args->id);
    mArgsQueue.emplace_back(std::make_unique<NotifySwitchArgs>(*args));
}

void QueuedInputListener::notifySensor(const NotifySensorArgs* args) {
    traceEvent(__func__, args->id);
    mArgsQueue.emplace_back(std::make_unique<NotifySensorArgs>(*args));
}

void QueuedInputListener::notifyVibratorState(const NotifyVibratorStateArgs* args) {
    traceEvent(__func__, args->id);
    mArgsQueue.emplace_back(std::make_unique<NotifyVibratorStateArgs>(*args));
}

void QueuedInputListener::notifyDeviceReset(const NotifyDeviceResetArgs* args) {
    traceEvent(__func__, args->id);
    mArgsQueue.emplace_back(std::make_unique<NotifyDeviceResetArgs>(*args));
}

void QueuedInputListener::notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs* args) {
    traceEvent(__func__, args->id);
    mArgsQueue.emplace_back(std::make_unique<NotifyPointerCaptureChangedArgs>(*args));
}

void QueuedInputListener::flush() {
    for (const std::unique_ptr<NotifyArgs>& args : mArgsQueue) {
        args->notify(mInnerListener);
    }
    mArgsQueue.clear();
}

} // namespace android
