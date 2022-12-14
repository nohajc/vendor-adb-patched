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

#ifndef _UI_INPUT_LISTENER_H
#define _UI_INPUT_LISTENER_H

#include <vector>

#include <input/Input.h>
#include <input/InputDevice.h>
#include <input/TouchVideoFrame.h>
#include <utils/RefBase.h>

namespace android {

class InputListenerInterface;


/* Superclass of all input event argument objects */
struct NotifyArgs {
    int32_t id;
    nsecs_t eventTime;

    inline NotifyArgs() : id(0), eventTime(0) {}

    inline explicit NotifyArgs(int32_t id, nsecs_t eventTime) : id(id), eventTime(eventTime) {}

    virtual ~NotifyArgs() { }

    virtual void notify(const sp<InputListenerInterface>& listener) const = 0;
};


/* Describes a configuration change event. */
struct NotifyConfigurationChangedArgs : public NotifyArgs {

    inline NotifyConfigurationChangedArgs() { }

    bool operator==(const NotifyConfigurationChangedArgs& rhs) const;

    NotifyConfigurationChangedArgs(int32_t id, nsecs_t eventTime);

    NotifyConfigurationChangedArgs(const NotifyConfigurationChangedArgs& other);

    virtual ~NotifyConfigurationChangedArgs() { }

    virtual void notify(const sp<InputListenerInterface>& listener) const;
};


/* Describes a key event. */
struct NotifyKeyArgs : public NotifyArgs {
    int32_t deviceId;
    uint32_t source;
    int32_t displayId;
    uint32_t policyFlags;
    int32_t action;
    int32_t flags;
    int32_t keyCode;
    int32_t scanCode;
    int32_t metaState;
    nsecs_t downTime;
    nsecs_t readTime;

    inline NotifyKeyArgs() { }

    NotifyKeyArgs(int32_t id, nsecs_t eventTime, nsecs_t readTime, int32_t deviceId,
                  uint32_t source, int32_t displayId, uint32_t policyFlags, int32_t action,
                  int32_t flags, int32_t keyCode, int32_t scanCode, int32_t metaState,
                  nsecs_t downTime);

    bool operator==(const NotifyKeyArgs& rhs) const;

    NotifyKeyArgs(const NotifyKeyArgs& other);

    virtual ~NotifyKeyArgs() { }

    virtual void notify(const sp<InputListenerInterface>& listener) const;
};


/* Describes a motion event. */
struct NotifyMotionArgs : public NotifyArgs {
    int32_t deviceId;
    uint32_t source;
    int32_t displayId;
    uint32_t policyFlags;
    int32_t action;
    int32_t actionButton;
    int32_t flags;
    int32_t metaState;
    int32_t buttonState;
    /**
     * Classification of the current touch gesture
     */
    MotionClassification classification;
    int32_t edgeFlags;

    uint32_t pointerCount;
    PointerProperties pointerProperties[MAX_POINTERS];
    PointerCoords pointerCoords[MAX_POINTERS];
    float xPrecision;
    float yPrecision;
    /**
     * Mouse cursor position when this event is reported relative to the origin of the specified
     * display. Only valid if this is a mouse event (originates from a mouse or from a trackpad in
     * gestures enabled mode.
     */
    float xCursorPosition;
    float yCursorPosition;
    nsecs_t downTime;
    nsecs_t readTime;
    std::vector<TouchVideoFrame> videoFrames;

    inline NotifyMotionArgs() { }

    NotifyMotionArgs(int32_t id, nsecs_t eventTime, nsecs_t readTime, int32_t deviceId,
                     uint32_t source, int32_t displayId, uint32_t policyFlags, int32_t action,
                     int32_t actionButton, int32_t flags, int32_t metaState, int32_t buttonState,
                     MotionClassification classification, int32_t edgeFlags, uint32_t pointerCount,
                     const PointerProperties* pointerProperties, const PointerCoords* pointerCoords,
                     float xPrecision, float yPrecision, float xCursorPosition,
                     float yCursorPosition, nsecs_t downTime,
                     const std::vector<TouchVideoFrame>& videoFrames);

    NotifyMotionArgs(const NotifyMotionArgs& other);

    virtual ~NotifyMotionArgs() { }

    bool operator==(const NotifyMotionArgs& rhs) const;

    virtual void notify(const sp<InputListenerInterface>& listener) const;
};

/* Describes a sensor event. */
struct NotifySensorArgs : public NotifyArgs {
    int32_t deviceId;
    uint32_t source;
    InputDeviceSensorType sensorType;
    InputDeviceSensorAccuracy accuracy;
    bool accuracyChanged;
    nsecs_t hwTimestamp;
    std::vector<float> values;

    inline NotifySensorArgs() {}

    NotifySensorArgs(int32_t id, nsecs_t eventTime, int32_t deviceId, uint32_t source,
                     InputDeviceSensorType sensorType, InputDeviceSensorAccuracy accuracy,
                     bool accuracyChanged, nsecs_t hwTimestamp, std::vector<float> values);

    NotifySensorArgs(const NotifySensorArgs& other);

    bool operator==(const NotifySensorArgs rhs) const;

    ~NotifySensorArgs() override {}

    void notify(const sp<InputListenerInterface>& listener) const override;
};

/* Describes a switch event. */
struct NotifySwitchArgs : public NotifyArgs {
    uint32_t policyFlags;
    uint32_t switchValues;
    uint32_t switchMask;

    inline NotifySwitchArgs() { }

    NotifySwitchArgs(int32_t id, nsecs_t eventTime, uint32_t policyFlags, uint32_t switchValues,
                     uint32_t switchMask);

    NotifySwitchArgs(const NotifySwitchArgs& other);

    bool operator==(const NotifySwitchArgs rhs) const;

    virtual ~NotifySwitchArgs() { }

    virtual void notify(const sp<InputListenerInterface>& listener) const;
};


/* Describes a device reset event, such as when a device is added,
 * reconfigured, or removed. */
struct NotifyDeviceResetArgs : public NotifyArgs {
    int32_t deviceId;

    inline NotifyDeviceResetArgs() { }

    NotifyDeviceResetArgs(int32_t id, nsecs_t eventTime, int32_t deviceId);

    NotifyDeviceResetArgs(const NotifyDeviceResetArgs& other);

    bool operator==(const NotifyDeviceResetArgs& rhs) const;

    virtual ~NotifyDeviceResetArgs() { }

    virtual void notify(const sp<InputListenerInterface>& listener) const;
};

/* Describes a change in the state of Pointer Capture. */
struct NotifyPointerCaptureChangedArgs : public NotifyArgs {
    // The sequence number of the Pointer Capture request, if enabled.
    PointerCaptureRequest request;

    inline NotifyPointerCaptureChangedArgs() {}

    NotifyPointerCaptureChangedArgs(int32_t id, nsecs_t eventTime, const PointerCaptureRequest&);

    NotifyPointerCaptureChangedArgs(const NotifyPointerCaptureChangedArgs& other);

    bool operator==(const NotifyPointerCaptureChangedArgs& rhs) const;

    virtual ~NotifyPointerCaptureChangedArgs() {}

    virtual void notify(const sp<InputListenerInterface>& listener) const;
};

/* Describes a vibrator state event. */
struct NotifyVibratorStateArgs : public NotifyArgs {
    int32_t deviceId;
    bool isOn;

    inline NotifyVibratorStateArgs() {}

    NotifyVibratorStateArgs(int32_t id, nsecs_t eventTIme, int32_t deviceId, bool isOn);

    NotifyVibratorStateArgs(const NotifyVibratorStateArgs& other);

    bool operator==(const NotifyVibratorStateArgs rhs) const;

    virtual ~NotifyVibratorStateArgs() {}

    virtual void notify(const sp<InputListenerInterface>& listener) const;
};

/*
 * The interface used by the InputReader to notify the InputListener about input events.
 */
class InputListenerInterface : public virtual RefBase {
protected:
    InputListenerInterface() { }
    virtual ~InputListenerInterface() { }

public:
    virtual void notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) = 0;
    virtual void notifyKey(const NotifyKeyArgs* args) = 0;
    virtual void notifyMotion(const NotifyMotionArgs* args) = 0;
    virtual void notifySwitch(const NotifySwitchArgs* args) = 0;
    virtual void notifySensor(const NotifySensorArgs* args) = 0;
    virtual void notifyVibratorState(const NotifyVibratorStateArgs* args) = 0;
    virtual void notifyDeviceReset(const NotifyDeviceResetArgs* args) = 0;
    virtual void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs* args) = 0;
};


/*
 * An implementation of the listener interface that queues up and defers dispatch
 * of decoded events until flushed.
 */
class QueuedInputListener : public InputListenerInterface {
protected:
    virtual ~QueuedInputListener();

public:
    explicit QueuedInputListener(const sp<InputListenerInterface>& innerListener);

    virtual void notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) override;
    virtual void notifyKey(const NotifyKeyArgs* args) override;
    virtual void notifyMotion(const NotifyMotionArgs* args) override;
    virtual void notifySwitch(const NotifySwitchArgs* args) override;
    virtual void notifySensor(const NotifySensorArgs* args) override;
    virtual void notifyDeviceReset(const NotifyDeviceResetArgs* args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs* args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs* args) override;

    void flush();

private:
    sp<InputListenerInterface> mInnerListener;
    std::vector<NotifyArgs*> mArgsQueue;
};

} // namespace android

#endif // _UI_INPUT_LISTENER_H
