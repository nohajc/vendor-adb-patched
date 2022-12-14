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

#include "../Macros.h"

#include "CursorInputMapper.h"

#include "CursorButtonAccumulator.h"
#include "CursorScrollAccumulator.h"
#include "PointerControllerInterface.h"
#include "TouchCursorInputMapperCommon.h"

namespace android {

// --- CursorMotionAccumulator ---

CursorMotionAccumulator::CursorMotionAccumulator() {
    clearRelativeAxes();
}

void CursorMotionAccumulator::reset(InputDeviceContext& deviceContext) {
    clearRelativeAxes();
}

void CursorMotionAccumulator::clearRelativeAxes() {
    mRelX = 0;
    mRelY = 0;
}

void CursorMotionAccumulator::process(const RawEvent* rawEvent) {
    if (rawEvent->type == EV_REL) {
        switch (rawEvent->code) {
            case REL_X:
                mRelX = rawEvent->value;
                break;
            case REL_Y:
                mRelY = rawEvent->value;
                break;
        }
    }
}

void CursorMotionAccumulator::finishSync() {
    clearRelativeAxes();
}

// --- CursorInputMapper ---

CursorInputMapper::CursorInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext) {}

CursorInputMapper::~CursorInputMapper() {}

uint32_t CursorInputMapper::getSources() {
    return mSource;
}

void CursorInputMapper::populateDeviceInfo(InputDeviceInfo* info) {
    InputMapper::populateDeviceInfo(info);

    if (mParameters.mode == Parameters::MODE_POINTER) {
        float minX, minY, maxX, maxY;
        if (mPointerController->getBounds(&minX, &minY, &maxX, &maxY)) {
            info->addMotionRange(AMOTION_EVENT_AXIS_X, mSource, minX, maxX, 0.0f, 0.0f, 0.0f);
            info->addMotionRange(AMOTION_EVENT_AXIS_Y, mSource, minY, maxY, 0.0f, 0.0f, 0.0f);
        }
    } else {
        info->addMotionRange(AMOTION_EVENT_AXIS_X, mSource, -1.0f, 1.0f, 0.0f, mXScale, 0.0f);
        info->addMotionRange(AMOTION_EVENT_AXIS_Y, mSource, -1.0f, 1.0f, 0.0f, mYScale, 0.0f);
        info->addMotionRange(AMOTION_EVENT_AXIS_RELATIVE_X, mSource, -1.0f, 1.0f, 0.0f, mXScale,
                             0.0f);
        info->addMotionRange(AMOTION_EVENT_AXIS_RELATIVE_Y, mSource, -1.0f, 1.0f, 0.0f, mYScale,
                             0.0f);
    }
    info->addMotionRange(AMOTION_EVENT_AXIS_PRESSURE, mSource, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f);

    if (mCursorScrollAccumulator.haveRelativeVWheel()) {
        info->addMotionRange(AMOTION_EVENT_AXIS_VSCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }
    if (mCursorScrollAccumulator.haveRelativeHWheel()) {
        info->addMotionRange(AMOTION_EVENT_AXIS_HSCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }
}

void CursorInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Cursor Input Mapper:\n";
    dumpParameters(dump);
    dump += StringPrintf(INDENT3 "XScale: %0.3f\n", mXScale);
    dump += StringPrintf(INDENT3 "YScale: %0.3f\n", mYScale);
    dump += StringPrintf(INDENT3 "XPrecision: %0.3f\n", mXPrecision);
    dump += StringPrintf(INDENT3 "YPrecision: %0.3f\n", mYPrecision);
    dump += StringPrintf(INDENT3 "HaveVWheel: %s\n",
                         toString(mCursorScrollAccumulator.haveRelativeVWheel()));
    dump += StringPrintf(INDENT3 "HaveHWheel: %s\n",
                         toString(mCursorScrollAccumulator.haveRelativeHWheel()));
    dump += StringPrintf(INDENT3 "VWheelScale: %0.3f\n", mVWheelScale);
    dump += StringPrintf(INDENT3 "HWheelScale: %0.3f\n", mHWheelScale);
    dump += StringPrintf(INDENT3 "Orientation: %d\n", mOrientation);
    dump += StringPrintf(INDENT3 "ButtonState: 0x%08x\n", mButtonState);
    dump += StringPrintf(INDENT3 "Down: %s\n", toString(isPointerDown(mButtonState)));
    dump += StringPrintf(INDENT3 "DownTime: %" PRId64 "\n", mDownTime);
}

void CursorInputMapper::configure(nsecs_t when, const InputReaderConfiguration* config,
                                  uint32_t changes) {
    InputMapper::configure(when, config, changes);

    if (!changes) { // first time only
        mCursorScrollAccumulator.configure(getDeviceContext());

        // Configure basic parameters.
        configureParameters();

        // Configure device mode.
        switch (mParameters.mode) {
            case Parameters::MODE_POINTER_RELATIVE:
                // Should not happen during first time configuration.
                ALOGE("Cannot start a device in MODE_POINTER_RELATIVE, starting in MODE_POINTER");
                mParameters.mode = Parameters::MODE_POINTER;
                [[fallthrough]];
            case Parameters::MODE_POINTER:
                mSource = AINPUT_SOURCE_MOUSE;
                mXPrecision = 1.0f;
                mYPrecision = 1.0f;
                mXScale = 1.0f;
                mYScale = 1.0f;
                mPointerController = getContext()->getPointerController(getDeviceId());
                break;
            case Parameters::MODE_NAVIGATION:
                mSource = AINPUT_SOURCE_TRACKBALL;
                mXPrecision = TRACKBALL_MOVEMENT_THRESHOLD;
                mYPrecision = TRACKBALL_MOVEMENT_THRESHOLD;
                mXScale = 1.0f / TRACKBALL_MOVEMENT_THRESHOLD;
                mYScale = 1.0f / TRACKBALL_MOVEMENT_THRESHOLD;
                break;
        }

        mVWheelScale = 1.0f;
        mHWheelScale = 1.0f;
    }

    if ((!changes && config->pointerCapture) ||
        (changes & InputReaderConfiguration::CHANGE_POINTER_CAPTURE)) {
        if (config->pointerCapture) {
            if (mParameters.mode == Parameters::MODE_POINTER) {
                mParameters.mode = Parameters::MODE_POINTER_RELATIVE;
                mSource = AINPUT_SOURCE_MOUSE_RELATIVE;
                // Keep PointerController around in order to preserve the pointer position.
                mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
            } else {
                ALOGE("Cannot request pointer capture, device is not in MODE_POINTER");
            }
        } else {
            if (mParameters.mode == Parameters::MODE_POINTER_RELATIVE) {
                mParameters.mode = Parameters::MODE_POINTER;
                mSource = AINPUT_SOURCE_MOUSE;
            } else {
                ALOGE("Cannot release pointer capture, device is not in MODE_POINTER_RELATIVE");
            }
        }
        bumpGeneration();
        if (changes) {
            NotifyDeviceResetArgs args(getContext()->getNextId(), when, getDeviceId());
            getListener()->notifyDeviceReset(&args);
        }
    }

    if (!changes || (changes & InputReaderConfiguration::CHANGE_POINTER_SPEED)) {
        mPointerVelocityControl.setParameters(config->pointerVelocityControlParameters);
        mWheelXVelocityControl.setParameters(config->wheelVelocityControlParameters);
        mWheelYVelocityControl.setParameters(config->wheelVelocityControlParameters);
    }

    if (!changes || (changes & InputReaderConfiguration::CHANGE_DISPLAY_INFO)) {
        mOrientation = DISPLAY_ORIENTATION_0;
        if (mParameters.orientationAware && mParameters.hasAssociatedDisplay) {
            std::optional<DisplayViewport> internalViewport =
                    config->getDisplayViewportByType(ViewportType::VIEWPORT_INTERNAL);
            if (internalViewport) {
                mOrientation = internalViewport->orientation;
            }
        }

        bumpGeneration();
    }
}

void CursorInputMapper::configureParameters() {
    mParameters.mode = Parameters::MODE_POINTER;
    String8 cursorModeString;
    if (getDeviceContext().getConfiguration().tryGetProperty(String8("cursor.mode"),
                                                             cursorModeString)) {
        if (cursorModeString == "navigation") {
            mParameters.mode = Parameters::MODE_NAVIGATION;
        } else if (cursorModeString != "pointer" && cursorModeString != "default") {
            ALOGW("Invalid value for cursor.mode: '%s'", cursorModeString.string());
        }
    }

    mParameters.orientationAware = false;
    getDeviceContext().getConfiguration().tryGetProperty(String8("cursor.orientationAware"),
                                                         mParameters.orientationAware);

    mParameters.hasAssociatedDisplay = false;
    if (mParameters.mode == Parameters::MODE_POINTER || mParameters.orientationAware) {
        mParameters.hasAssociatedDisplay = true;
    }
}

void CursorInputMapper::dumpParameters(std::string& dump) {
    dump += INDENT3 "Parameters:\n";
    dump += StringPrintf(INDENT4 "HasAssociatedDisplay: %s\n",
                         toString(mParameters.hasAssociatedDisplay));

    switch (mParameters.mode) {
        case Parameters::MODE_POINTER:
            dump += INDENT4 "Mode: pointer\n";
            break;
        case Parameters::MODE_POINTER_RELATIVE:
            dump += INDENT4 "Mode: relative pointer\n";
            break;
        case Parameters::MODE_NAVIGATION:
            dump += INDENT4 "Mode: navigation\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    dump += StringPrintf(INDENT4 "OrientationAware: %s\n", toString(mParameters.orientationAware));
}

void CursorInputMapper::reset(nsecs_t when) {
    mButtonState = 0;
    mDownTime = 0;

    mPointerVelocityControl.reset();
    mWheelXVelocityControl.reset();
    mWheelYVelocityControl.reset();

    mCursorButtonAccumulator.reset(getDeviceContext());
    mCursorMotionAccumulator.reset(getDeviceContext());
    mCursorScrollAccumulator.reset(getDeviceContext());

    InputMapper::reset(when);
}

void CursorInputMapper::process(const RawEvent* rawEvent) {
    mCursorButtonAccumulator.process(rawEvent);
    mCursorMotionAccumulator.process(rawEvent);
    mCursorScrollAccumulator.process(rawEvent);

    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        sync(rawEvent->when);
    }
}

void CursorInputMapper::sync(nsecs_t when) {
    int32_t lastButtonState = mButtonState;
    int32_t currentButtonState = mCursorButtonAccumulator.getButtonState();
    mButtonState = currentButtonState;

    bool wasDown = isPointerDown(lastButtonState);
    bool down = isPointerDown(currentButtonState);
    bool downChanged;
    if (!wasDown && down) {
        mDownTime = when;
        downChanged = true;
    } else if (wasDown && !down) {
        downChanged = true;
    } else {
        downChanged = false;
    }
    nsecs_t downTime = mDownTime;
    bool buttonsChanged = currentButtonState != lastButtonState;
    int32_t buttonsPressed = currentButtonState & ~lastButtonState;
    int32_t buttonsReleased = lastButtonState & ~currentButtonState;

    float deltaX = mCursorMotionAccumulator.getRelativeX() * mXScale;
    float deltaY = mCursorMotionAccumulator.getRelativeY() * mYScale;
    bool moved = deltaX != 0 || deltaY != 0;

    // Rotate delta according to orientation if needed.
    if (mParameters.orientationAware && mParameters.hasAssociatedDisplay &&
        (deltaX != 0.0f || deltaY != 0.0f)) {
        rotateDelta(mOrientation, &deltaX, &deltaY);
    }

    // Move the pointer.
    PointerProperties pointerProperties;
    pointerProperties.clear();
    pointerProperties.id = 0;
    pointerProperties.toolType = AMOTION_EVENT_TOOL_TYPE_MOUSE;

    PointerCoords pointerCoords;
    pointerCoords.clear();

    float vscroll = mCursorScrollAccumulator.getRelativeVWheel();
    float hscroll = mCursorScrollAccumulator.getRelativeHWheel();
    bool scrolled = vscroll != 0 || hscroll != 0;

    mWheelYVelocityControl.move(when, nullptr, &vscroll);
    mWheelXVelocityControl.move(when, &hscroll, nullptr);

    mPointerVelocityControl.move(when, &deltaX, &deltaY);

    int32_t displayId = ADISPLAY_ID_NONE;
    float xCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    float yCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    if (mSource == AINPUT_SOURCE_MOUSE) {
        if (moved || scrolled || buttonsChanged) {
            mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);

            if (moved) {
                mPointerController->move(deltaX, deltaY);
            }

            if (buttonsChanged) {
                mPointerController->setButtonState(currentButtonState);
            }

            mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
        }

        mPointerController->getPosition(&xCursorPosition, &yCursorPosition);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_X, xCursorPosition);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, yCursorPosition);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, deltaX);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, deltaY);
        displayId = mPointerController->getDisplayId();
    } else if (mSource == AINPUT_SOURCE_MOUSE_RELATIVE) {
        // Pointer capture mode
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_X, deltaX);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, deltaY);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, deltaX);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, deltaY);
    }

    pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, down ? 1.0f : 0.0f);

    // Moving an external trackball or mouse should wake the device.
    // We don't do this for internal cursor devices to prevent them from waking up
    // the device in your pocket.
    // TODO: Use the input device configuration to control this behavior more finely.
    uint32_t policyFlags = 0;
    if ((buttonsPressed || moved || scrolled) && getDeviceContext().isExternal()) {
        policyFlags |= POLICY_FLAG_WAKE;
    }

    // Synthesize key down from buttons if needed.
    synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_DOWN, when, getDeviceId(), mSource,
                         displayId, policyFlags, lastButtonState, currentButtonState);

    // Send motion event.
    if (downChanged || moved || scrolled || buttonsChanged) {
        int32_t metaState = getContext()->getGlobalMetaState();
        int32_t buttonState = lastButtonState;
        int32_t motionEventAction;
        if (downChanged) {
            motionEventAction = down ? AMOTION_EVENT_ACTION_DOWN : AMOTION_EVENT_ACTION_UP;
        } else if (down || (mSource != AINPUT_SOURCE_MOUSE)) {
            motionEventAction = AMOTION_EVENT_ACTION_MOVE;
        } else {
            motionEventAction = AMOTION_EVENT_ACTION_HOVER_MOVE;
        }

        if (buttonsReleased) {
            BitSet32 released(buttonsReleased);
            while (!released.isEmpty()) {
                int32_t actionButton = BitSet32::valueForBit(released.clearFirstMarkedBit());
                buttonState &= ~actionButton;
                NotifyMotionArgs releaseArgs(getContext()->getNextId(), when, getDeviceId(),
                                             mSource, displayId, policyFlags,
                                             AMOTION_EVENT_ACTION_BUTTON_RELEASE, actionButton, 0,
                                             metaState, buttonState, MotionClassification::NONE,
                                             AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                             &pointerCoords, mXPrecision, mYPrecision,
                                             xCursorPosition, yCursorPosition, downTime,
                                             /* videoFrames */ {});
                getListener()->notifyMotion(&releaseArgs);
            }
        }

        NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource, displayId,
                              policyFlags, motionEventAction, 0, 0, metaState, currentButtonState,
                              MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                              &pointerProperties, &pointerCoords, mXPrecision, mYPrecision,
                              xCursorPosition, yCursorPosition, downTime,
                              /* videoFrames */ {});
        getListener()->notifyMotion(&args);

        if (buttonsPressed) {
            BitSet32 pressed(buttonsPressed);
            while (!pressed.isEmpty()) {
                int32_t actionButton = BitSet32::valueForBit(pressed.clearFirstMarkedBit());
                buttonState |= actionButton;
                NotifyMotionArgs pressArgs(getContext()->getNextId(), when, getDeviceId(), mSource,
                                           displayId, policyFlags,
                                           AMOTION_EVENT_ACTION_BUTTON_PRESS, actionButton, 0,
                                           metaState, buttonState, MotionClassification::NONE,
                                           AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                           &pointerCoords, mXPrecision, mYPrecision,
                                           xCursorPosition, yCursorPosition, downTime,
                                           /* videoFrames */ {});
                getListener()->notifyMotion(&pressArgs);
            }
        }

        ALOG_ASSERT(buttonState == currentButtonState);

        // Send hover move after UP to tell the application that the mouse is hovering now.
        if (motionEventAction == AMOTION_EVENT_ACTION_UP && (mSource == AINPUT_SOURCE_MOUSE)) {
            NotifyMotionArgs hoverArgs(getContext()->getNextId(), when, getDeviceId(), mSource,
                                       displayId, policyFlags, AMOTION_EVENT_ACTION_HOVER_MOVE, 0,
                                       0, metaState, currentButtonState, MotionClassification::NONE,
                                       AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                       &pointerCoords, mXPrecision, mYPrecision, xCursorPosition,
                                       yCursorPosition, downTime, /* videoFrames */ {});
            getListener()->notifyMotion(&hoverArgs);
        }

        // Send scroll events.
        if (scrolled) {
            pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_VSCROLL, vscroll);
            pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_HSCROLL, hscroll);

            NotifyMotionArgs scrollArgs(getContext()->getNextId(), when, getDeviceId(), mSource,
                                        displayId, policyFlags, AMOTION_EVENT_ACTION_SCROLL, 0, 0,
                                        metaState, currentButtonState, MotionClassification::NONE,
                                        AMOTION_EVENT_EDGE_FLAG_NONE, 1, &pointerProperties,
                                        &pointerCoords, mXPrecision, mYPrecision, xCursorPosition,
                                        yCursorPosition, downTime, /* videoFrames */ {});
            getListener()->notifyMotion(&scrollArgs);
        }
    }

    // Synthesize key up from buttons if needed.
    synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_UP, when, getDeviceId(), mSource,
                         displayId, policyFlags, lastButtonState, currentButtonState);

    mCursorMotionAccumulator.finishSync();
    mCursorScrollAccumulator.finishSync();
}

int32_t CursorInputMapper::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    if (scanCode >= BTN_MOUSE && scanCode < BTN_JOYSTICK) {
        return getDeviceContext().getScanCodeState(scanCode);
    } else {
        return AKEY_STATE_UNKNOWN;
    }
}

std::optional<int32_t> CursorInputMapper::getAssociatedDisplayId() {
    if (mParameters.hasAssociatedDisplay) {
        if (mParameters.mode == Parameters::MODE_POINTER) {
            return std::make_optional(mPointerController->getDisplayId());
        } else {
            // If the device is orientationAware and not a mouse,
            // it expects to dispatch events to any display
            return std::make_optional(ADISPLAY_ID_NONE);
        }
    }
    return std::nullopt;
}

} // namespace android
