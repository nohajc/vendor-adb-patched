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

#include "InputCommonConverter.h"

using namespace ::aidl::android::hardware::input;

namespace android {

static common::Source getSource(uint32_t source) {
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_UNKNOWN) == common::Source::UNKNOWN,
                  "SOURCE_UNKNOWN mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_KEYBOARD) == common::Source::KEYBOARD,
                  "SOURCE_KEYBOARD mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_DPAD) == common::Source::DPAD,
                  "SOURCE_DPAD mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_GAMEPAD) == common::Source::GAMEPAD,
                  "SOURCE_GAMEPAD mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_TOUCHSCREEN) ==
                          common::Source::TOUCHSCREEN,
                  "SOURCE_TOUCHSCREEN mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_MOUSE) == common::Source::MOUSE,
                  "SOURCE_MOUSE mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_STYLUS) == common::Source::STYLUS,
                  "SOURCE_STYLUS mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_BLUETOOTH_STYLUS) ==
                          common::Source::BLUETOOTH_STYLUS,
                  "SOURCE_BLUETOOTH_STYLUS mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_TRACKBALL) == common::Source::TRACKBALL,
                  "SOURCE_TRACKBALL mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_MOUSE_RELATIVE) ==
                          common::Source::MOUSE_RELATIVE,
                  "SOURCE_MOUSE_RELATIVE mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_TOUCHPAD) == common::Source::TOUCHPAD,
                  "SOURCE_TOUCHPAD mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_TOUCH_NAVIGATION) ==
                          common::Source::TOUCH_NAVIGATION,
                  "SOURCE_TOUCH_NAVIGATION mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_JOYSTICK) == common::Source::JOYSTICK,
                  "SOURCE_JOYSTICK mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_ROTARY_ENCODER) ==
                          common::Source::ROTARY_ENCODER,
                  "SOURCE_ROTARY_ENCODER mismatch");
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_HDMI) == common::Source::HDMI);
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_SENSOR) == common::Source::SENSOR);
    static_assert(static_cast<common::Source>(AINPUT_SOURCE_ANY) == common::Source::ANY,
                  "SOURCE_ANY mismatch");
    return static_cast<common::Source>(source);
}

static common::Action getAction(int32_t actionMasked) {
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_DOWN) == common::Action::DOWN,
                  "ACTION_DOWN mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_UP) == common::Action::UP,
                  "ACTION_UP mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_MOVE) == common::Action::MOVE,
                  "ACTION_MOVE mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_CANCEL) ==
                          common::Action::CANCEL,
                  "ACTION_CANCEL mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_OUTSIDE) ==
                          common::Action::OUTSIDE,
                  "ACTION_OUTSIDE mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_POINTER_DOWN) ==
                          common::Action::POINTER_DOWN,
                  "ACTION_POINTER_DOWN mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_POINTER_UP) ==
                          common::Action::POINTER_UP,
                  "ACTION_POINTER_UP mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_HOVER_MOVE) ==
                          common::Action::HOVER_MOVE,
                  "ACTION_HOVER_MOVE mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_SCROLL) ==
                          common::Action::SCROLL,
                  "ACTION_SCROLL mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_HOVER_ENTER) ==
                          common::Action::HOVER_ENTER,
                  "ACTION_HOVER_ENTER mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_HOVER_EXIT) ==
                          common::Action::HOVER_EXIT,
                  "ACTION_HOVER_EXIT mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_BUTTON_PRESS) ==
                          common::Action::BUTTON_PRESS,
                  "ACTION_BUTTON_PRESS mismatch");
    static_assert(static_cast<common::Action>(AMOTION_EVENT_ACTION_BUTTON_RELEASE) ==
                          common::Action::BUTTON_RELEASE,
                  "ACTION_BUTTON_RELEASE mismatch");
    return static_cast<common::Action>(actionMasked);
}

static common::Button getActionButton(int32_t actionButton) {
    static_assert(static_cast<common::Button>(0) == common::Button::NONE, "BUTTON_NONE mismatch");
    static_assert(static_cast<common::Button>(AMOTION_EVENT_BUTTON_PRIMARY) ==
                          common::Button::PRIMARY,
                  "BUTTON_PRIMARY mismatch");
    static_assert(static_cast<common::Button>(AMOTION_EVENT_BUTTON_SECONDARY) ==
                          common::Button::SECONDARY,
                  "BUTTON_SECONDARY mismatch");
    static_assert(static_cast<common::Button>(AMOTION_EVENT_BUTTON_TERTIARY) ==
                          common::Button::TERTIARY,
                  "BUTTON_TERTIARY mismatch");
    static_assert(static_cast<common::Button>(AMOTION_EVENT_BUTTON_BACK) == common::Button::BACK,
                  "BUTTON_BACK mismatch");
    static_assert(static_cast<common::Button>(AMOTION_EVENT_BUTTON_FORWARD) ==
                          common::Button::FORWARD,
                  "BUTTON_FORWARD mismatch");
    static_assert(static_cast<common::Button>(AMOTION_EVENT_BUTTON_STYLUS_PRIMARY) ==
                          common::Button::STYLUS_PRIMARY,
                  "BUTTON_STYLUS_PRIMARY mismatch");
    static_assert(static_cast<common::Button>(AMOTION_EVENT_BUTTON_STYLUS_SECONDARY) ==
                          common::Button::STYLUS_SECONDARY,
                  "BUTTON_STYLUS_SECONDARY mismatch");
    return static_cast<common::Button>(actionButton);
}

static common::Flag getFlags(int32_t flags) {
    static_assert(static_cast<common::Flag>(AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED) ==
                  common::Flag::WINDOW_IS_OBSCURED);
    static_assert(static_cast<common::Flag>(AMOTION_EVENT_FLAG_IS_GENERATED_GESTURE) ==
                  common::Flag::IS_GENERATED_GESTURE);
    static_assert(static_cast<common::Flag>(AMOTION_EVENT_FLAG_TAINTED) == common::Flag::TAINTED);
    return static_cast<common::Flag>(flags);
}

static common::PolicyFlag getPolicyFlags(int32_t flags) {
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_WAKE) == common::PolicyFlag::WAKE);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_VIRTUAL) ==
                  common::PolicyFlag::VIRTUAL);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_FUNCTION) ==
                  common::PolicyFlag::FUNCTION);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_GESTURE) ==
                  common::PolicyFlag::GESTURE);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_INJECTED) ==
                  common::PolicyFlag::INJECTED);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_TRUSTED) ==
                  common::PolicyFlag::TRUSTED);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_FILTERED) ==
                  common::PolicyFlag::FILTERED);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_DISABLE_KEY_REPEAT) ==
                  common::PolicyFlag::DISABLE_KEY_REPEAT);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_INTERACTIVE) ==
                  common::PolicyFlag::INTERACTIVE);
    static_assert(static_cast<common::PolicyFlag>(POLICY_FLAG_PASS_TO_USER) ==
                  common::PolicyFlag::PASS_TO_USER);
    return static_cast<common::PolicyFlag>(flags);
}

static common::EdgeFlag getEdgeFlags(int32_t flags) {
    static_assert(static_cast<common::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_NONE) ==
                  common::EdgeFlag::NONE);
    static_assert(static_cast<common::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_TOP) ==
                  common::EdgeFlag::TOP);
    static_assert(static_cast<common::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_BOTTOM) ==
                  common::EdgeFlag::BOTTOM);
    static_assert(static_cast<common::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_LEFT) ==
                  common::EdgeFlag::LEFT);
    static_assert(static_cast<common::EdgeFlag>(AMOTION_EVENT_EDGE_FLAG_RIGHT) ==
                  common::EdgeFlag::RIGHT);
    return static_cast<common::EdgeFlag>(flags);
}

static common::Meta getMetastate(int32_t state) {
    static_assert(static_cast<common::Meta>(AMETA_NONE) == common::Meta::NONE);
    static_assert(static_cast<common::Meta>(AMETA_ALT_ON) == common::Meta::ALT_ON);
    static_assert(static_cast<common::Meta>(AMETA_ALT_LEFT_ON) == common::Meta::ALT_LEFT_ON);
    static_assert(static_cast<common::Meta>(AMETA_ALT_RIGHT_ON) == common::Meta::ALT_RIGHT_ON);
    static_assert(static_cast<common::Meta>(AMETA_SHIFT_ON) == common::Meta::SHIFT_ON);
    static_assert(static_cast<common::Meta>(AMETA_SHIFT_LEFT_ON) == common::Meta::SHIFT_LEFT_ON);
    static_assert(static_cast<common::Meta>(AMETA_SHIFT_RIGHT_ON) == common::Meta::SHIFT_RIGHT_ON);
    static_assert(static_cast<common::Meta>(AMETA_SYM_ON) == common::Meta::SYM_ON);
    static_assert(static_cast<common::Meta>(AMETA_FUNCTION_ON) == common::Meta::FUNCTION_ON);
    static_assert(static_cast<common::Meta>(AMETA_CTRL_ON) == common::Meta::CTRL_ON);
    static_assert(static_cast<common::Meta>(AMETA_CTRL_LEFT_ON) == common::Meta::CTRL_LEFT_ON);
    static_assert(static_cast<common::Meta>(AMETA_CTRL_RIGHT_ON) == common::Meta::CTRL_RIGHT_ON);
    static_assert(static_cast<common::Meta>(AMETA_META_ON) == common::Meta::META_ON);
    static_assert(static_cast<common::Meta>(AMETA_META_LEFT_ON) == common::Meta::META_LEFT_ON);
    static_assert(static_cast<common::Meta>(AMETA_META_RIGHT_ON) == common::Meta::META_RIGHT_ON);
    static_assert(static_cast<common::Meta>(AMETA_CAPS_LOCK_ON) == common::Meta::CAPS_LOCK_ON);
    static_assert(static_cast<common::Meta>(AMETA_NUM_LOCK_ON) == common::Meta::NUM_LOCK_ON);
    static_assert(static_cast<common::Meta>(AMETA_SCROLL_LOCK_ON) == common::Meta::SCROLL_LOCK_ON);
    return static_cast<common::Meta>(state);
}

static common::Button getButtonState(int32_t buttonState) {
    // No need for static_assert here.
    // The button values have already been asserted in getActionButton(..) above
    return static_cast<common::Button>(buttonState);
}

static common::ToolType getToolType(int32_t toolType) {
    static_assert(static_cast<common::ToolType>(AMOTION_EVENT_TOOL_TYPE_UNKNOWN) ==
                  common::ToolType::UNKNOWN);
    static_assert(static_cast<common::ToolType>(AMOTION_EVENT_TOOL_TYPE_FINGER) ==
                  common::ToolType::FINGER);
    static_assert(static_cast<common::ToolType>(AMOTION_EVENT_TOOL_TYPE_STYLUS) ==
                  common::ToolType::STYLUS);
    static_assert(static_cast<common::ToolType>(AMOTION_EVENT_TOOL_TYPE_MOUSE) ==
                  common::ToolType::MOUSE);
    static_assert(static_cast<common::ToolType>(AMOTION_EVENT_TOOL_TYPE_ERASER) ==
                  common::ToolType::ERASER);
    return static_cast<common::ToolType>(toolType);
}

// MotionEvent axes asserts
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_X) == common::Axis::X);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_Y) == common::Axis::Y);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_PRESSURE) == common::Axis::PRESSURE);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_SIZE) == common::Axis::SIZE);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_TOUCH_MAJOR) ==
              common::Axis::TOUCH_MAJOR);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_TOUCH_MINOR) ==
              common::Axis::TOUCH_MINOR);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_TOOL_MAJOR) == common::Axis::TOOL_MAJOR);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_TOOL_MINOR) == common::Axis::TOOL_MINOR);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_ORIENTATION) ==
              common::Axis::ORIENTATION);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_VSCROLL) == common::Axis::VSCROLL);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_HSCROLL) == common::Axis::HSCROLL);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_Z) == common::Axis::Z);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_RX) == common::Axis::RX);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_RY) == common::Axis::RY);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_RZ) == common::Axis::RZ);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_HAT_X) == common::Axis::HAT_X);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_HAT_Y) == common::Axis::HAT_Y);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_LTRIGGER) == common::Axis::LTRIGGER);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_RTRIGGER) == common::Axis::RTRIGGER);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_THROTTLE) == common::Axis::THROTTLE);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_RUDDER) == common::Axis::RUDDER);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_WHEEL) == common::Axis::WHEEL);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GAS) == common::Axis::GAS);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_BRAKE) == common::Axis::BRAKE);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_DISTANCE) == common::Axis::DISTANCE);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_TILT) == common::Axis::TILT);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_SCROLL) == common::Axis::SCROLL);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_RELATIVE_X) == common::Axis::RELATIVE_X);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_RELATIVE_Y) == common::Axis::RELATIVE_Y);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_1) == common::Axis::GENERIC_1);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_2) == common::Axis::GENERIC_2);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_3) == common::Axis::GENERIC_3);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_4) == common::Axis::GENERIC_4);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_5) == common::Axis::GENERIC_5);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_6) == common::Axis::GENERIC_6);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_7) == common::Axis::GENERIC_7);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_8) == common::Axis::GENERIC_8);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_9) == common::Axis::GENERIC_9);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_10) == common::Axis::GENERIC_10);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_11) == common::Axis::GENERIC_11);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_12) == common::Axis::GENERIC_12);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_13) == common::Axis::GENERIC_13);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_14) == common::Axis::GENERIC_14);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_15) == common::Axis::GENERIC_15);
static_assert(static_cast<common::Axis>(AMOTION_EVENT_AXIS_GENERIC_16) == common::Axis::GENERIC_16);

static common::VideoFrame getHalVideoFrame(const TouchVideoFrame& frame) {
    common::VideoFrame out;
    out.width = frame.getWidth();
    out.height = frame.getHeight();
    std::vector<char16_t> unsignedData(frame.getData().begin(), frame.getData().end());
    out.data = unsignedData;
    struct timeval timestamp = frame.getTimestamp();
    out.timestamp = seconds_to_nanoseconds(timestamp.tv_sec) +
            microseconds_to_nanoseconds(timestamp.tv_usec);
    return out;
}

static std::vector<common::VideoFrame> convertVideoFrames(
        const std::vector<TouchVideoFrame>& frames) {
    std::vector<common::VideoFrame> out;
    for (const TouchVideoFrame& frame : frames) {
        out.push_back(getHalVideoFrame(frame));
    }
    return out;
}

static void getHalPropertiesAndCoords(const NotifyMotionArgs& args,
                                      std::vector<common::PointerProperties>& outPointerProperties,
                                      std::vector<common::PointerCoords>& outPointerCoords) {
    outPointerProperties.reserve(args.pointerCount);
    outPointerCoords.reserve(args.pointerCount);
    for (size_t i = 0; i < args.pointerCount; i++) {
        common::PointerProperties properties;
        properties.id = args.pointerProperties[i].id;
        properties.toolType = getToolType(args.pointerProperties[i].toolType);
        outPointerProperties.push_back(properties);

        common::PointerCoords coords;
        // OK to copy bits because we have static_assert for pointerCoords axes
        coords.bits = args.pointerCoords[i].bits;
        coords.values = std::vector<float>(args.pointerCoords[i].values,
                                           args.pointerCoords[i].values +
                                                   BitSet64::count(args.pointerCoords[i].bits));
        outPointerCoords.push_back(coords);
    }
}

common::MotionEvent notifyMotionArgsToHalMotionEvent(const NotifyMotionArgs& args) {
    common::MotionEvent event;
    event.deviceId = args.deviceId;
    event.source = getSource(args.source);
    event.displayId = args.displayId;
    event.downTime = args.downTime;
    event.eventTime = args.eventTime;
    event.deviceTimestamp = 0;
    event.action = getAction(args.action & AMOTION_EVENT_ACTION_MASK);
    event.actionIndex = MotionEvent::getActionIndex(args.action);
    event.actionButton = getActionButton(args.actionButton);
    event.flags = getFlags(args.flags);
    event.policyFlags = getPolicyFlags(args.policyFlags);
    event.edgeFlags = getEdgeFlags(args.edgeFlags);
    event.metaState = getMetastate(args.metaState);
    event.buttonState = getButtonState(args.buttonState);
    event.xPrecision = args.xPrecision;
    event.yPrecision = args.yPrecision;

    std::vector<common::PointerProperties> pointerProperties;
    std::vector<common::PointerCoords> pointerCoords;
    getHalPropertiesAndCoords(args, /*out*/ pointerProperties, /*out*/ pointerCoords);
    event.pointerProperties = pointerProperties;
    event.pointerCoords = pointerCoords;

    event.frames = convertVideoFrames(args.videoFrames);

    return event;
}

} // namespace android
