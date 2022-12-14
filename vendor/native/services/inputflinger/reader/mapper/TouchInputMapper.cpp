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

// clang-format off
#include "../Macros.h"
// clang-format on

#include "TouchInputMapper.h"

#include "CursorButtonAccumulator.h"
#include "CursorScrollAccumulator.h"
#include "TouchButtonAccumulator.h"
#include "TouchCursorInputMapperCommon.h"

namespace android {

// --- Constants ---

// Maximum amount of latency to add to touch events while waiting for data from an
// external stylus.
static constexpr nsecs_t EXTERNAL_STYLUS_DATA_TIMEOUT = ms2ns(72);

// Maximum amount of time to wait on touch data before pushing out new pressure data.
static constexpr nsecs_t TOUCH_DATA_TIMEOUT = ms2ns(20);

// Artificial latency on synthetic events created from stylus data without corresponding touch
// data.
static constexpr nsecs_t STYLUS_DATA_LATENCY = ms2ns(10);

// --- Static Definitions ---

template <typename T>
inline static void swap(T& a, T& b) {
    T temp = a;
    a = b;
    b = temp;
}

static float calculateCommonVector(float a, float b) {
    if (a > 0 && b > 0) {
        return a < b ? a : b;
    } else if (a < 0 && b < 0) {
        return a > b ? a : b;
    } else {
        return 0;
    }
}

inline static float distance(float x1, float y1, float x2, float y2) {
    return hypotf(x1 - x2, y1 - y2);
}

inline static int32_t signExtendNybble(int32_t value) {
    return value >= 8 ? value - 16 : value;
}

// --- RawPointerAxes ---

RawPointerAxes::RawPointerAxes() {
    clear();
}

void RawPointerAxes::clear() {
    x.clear();
    y.clear();
    pressure.clear();
    touchMajor.clear();
    touchMinor.clear();
    toolMajor.clear();
    toolMinor.clear();
    orientation.clear();
    distance.clear();
    tiltX.clear();
    tiltY.clear();
    trackingId.clear();
    slot.clear();
}

// --- RawPointerData ---

RawPointerData::RawPointerData() {
    clear();
}

void RawPointerData::clear() {
    pointerCount = 0;
    clearIdBits();
}

void RawPointerData::copyFrom(const RawPointerData& other) {
    pointerCount = other.pointerCount;
    hoveringIdBits = other.hoveringIdBits;
    touchingIdBits = other.touchingIdBits;
    canceledIdBits = other.canceledIdBits;

    for (uint32_t i = 0; i < pointerCount; i++) {
        pointers[i] = other.pointers[i];

        int id = pointers[i].id;
        idToIndex[id] = other.idToIndex[id];
    }
}

void RawPointerData::getCentroidOfTouchingPointers(float* outX, float* outY) const {
    float x = 0, y = 0;
    uint32_t count = touchingIdBits.count();
    if (count) {
        for (BitSet32 idBits(touchingIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            const Pointer& pointer = pointerForId(id);
            x += pointer.x;
            y += pointer.y;
        }
        x /= count;
        y /= count;
    }
    *outX = x;
    *outY = y;
}

// --- CookedPointerData ---

CookedPointerData::CookedPointerData() {
    clear();
}

void CookedPointerData::clear() {
    pointerCount = 0;
    hoveringIdBits.clear();
    touchingIdBits.clear();
    canceledIdBits.clear();
    validIdBits.clear();
}

void CookedPointerData::copyFrom(const CookedPointerData& other) {
    pointerCount = other.pointerCount;
    hoveringIdBits = other.hoveringIdBits;
    touchingIdBits = other.touchingIdBits;
    validIdBits = other.validIdBits;

    for (uint32_t i = 0; i < pointerCount; i++) {
        pointerProperties[i].copyFrom(other.pointerProperties[i]);
        pointerCoords[i].copyFrom(other.pointerCoords[i]);

        int id = pointerProperties[i].id;
        idToIndex[id] = other.idToIndex[id];
    }
}

// --- TouchInputMapper ---

TouchInputMapper::TouchInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext),
        mSource(0),
        mDeviceMode(DeviceMode::DISABLED),
        mRawSurfaceWidth(-1),
        mRawSurfaceHeight(-1),
        mSurfaceLeft(0),
        mSurfaceTop(0),
        mPhysicalWidth(-1),
        mPhysicalHeight(-1),
        mPhysicalLeft(0),
        mPhysicalTop(0),
        mSurfaceOrientation(DISPLAY_ORIENTATION_0) {}

TouchInputMapper::~TouchInputMapper() {}

uint32_t TouchInputMapper::getSources() {
    return mSource;
}

void TouchInputMapper::populateDeviceInfo(InputDeviceInfo* info) {
    InputMapper::populateDeviceInfo(info);

    if (mDeviceMode != DeviceMode::DISABLED) {
        info->addMotionRange(mOrientedRanges.x);
        info->addMotionRange(mOrientedRanges.y);
        info->addMotionRange(mOrientedRanges.pressure);

        if (mDeviceMode == DeviceMode::UNSCALED && mSource == AINPUT_SOURCE_TOUCHPAD) {
            // Populate RELATIVE_X and RELATIVE_Y motion ranges for touchpad capture mode.
            //
            // RELATIVE_X and RELATIVE_Y motion ranges should be the largest possible relative
            // motion, i.e. the hardware dimensions, as the finger could move completely across the
            // touchpad in one sample cycle.
            const InputDeviceInfo::MotionRange& x = mOrientedRanges.x;
            const InputDeviceInfo::MotionRange& y = mOrientedRanges.y;
            info->addMotionRange(AMOTION_EVENT_AXIS_RELATIVE_X, mSource, -x.max, x.max, x.flat,
                                 x.fuzz, x.resolution);
            info->addMotionRange(AMOTION_EVENT_AXIS_RELATIVE_Y, mSource, -y.max, y.max, y.flat,
                                 y.fuzz, y.resolution);
        }

        if (mOrientedRanges.haveSize) {
            info->addMotionRange(mOrientedRanges.size);
        }

        if (mOrientedRanges.haveTouchSize) {
            info->addMotionRange(mOrientedRanges.touchMajor);
            info->addMotionRange(mOrientedRanges.touchMinor);
        }

        if (mOrientedRanges.haveToolSize) {
            info->addMotionRange(mOrientedRanges.toolMajor);
            info->addMotionRange(mOrientedRanges.toolMinor);
        }

        if (mOrientedRanges.haveOrientation) {
            info->addMotionRange(mOrientedRanges.orientation);
        }

        if (mOrientedRanges.haveDistance) {
            info->addMotionRange(mOrientedRanges.distance);
        }

        if (mOrientedRanges.haveTilt) {
            info->addMotionRange(mOrientedRanges.tilt);
        }

        if (mCursorScrollAccumulator.haveRelativeVWheel()) {
            info->addMotionRange(AMOTION_EVENT_AXIS_VSCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f,
                                 0.0f);
        }
        if (mCursorScrollAccumulator.haveRelativeHWheel()) {
            info->addMotionRange(AMOTION_EVENT_AXIS_HSCROLL, mSource, -1.0f, 1.0f, 0.0f, 0.0f,
                                 0.0f);
        }
        if (mCalibration.coverageCalibration == Calibration::CoverageCalibration::BOX) {
            const InputDeviceInfo::MotionRange& x = mOrientedRanges.x;
            const InputDeviceInfo::MotionRange& y = mOrientedRanges.y;
            info->addMotionRange(AMOTION_EVENT_AXIS_GENERIC_1, mSource, x.min, x.max, x.flat,
                                 x.fuzz, x.resolution);
            info->addMotionRange(AMOTION_EVENT_AXIS_GENERIC_2, mSource, y.min, y.max, y.flat,
                                 y.fuzz, y.resolution);
            info->addMotionRange(AMOTION_EVENT_AXIS_GENERIC_3, mSource, x.min, x.max, x.flat,
                                 x.fuzz, x.resolution);
            info->addMotionRange(AMOTION_EVENT_AXIS_GENERIC_4, mSource, y.min, y.max, y.flat,
                                 y.fuzz, y.resolution);
        }
        info->setButtonUnderPad(mParameters.hasButtonUnderPad);
    }
}

void TouchInputMapper::dump(std::string& dump) {
    dump += StringPrintf(INDENT2 "Touch Input Mapper (mode - %s):\n", modeToString(mDeviceMode));
    dumpParameters(dump);
    dumpVirtualKeys(dump);
    dumpRawPointerAxes(dump);
    dumpCalibration(dump);
    dumpAffineTransformation(dump);
    dumpSurface(dump);

    dump += StringPrintf(INDENT3 "Translation and Scaling Factors:\n");
    dump += StringPrintf(INDENT4 "XTranslate: %0.3f\n", mXTranslate);
    dump += StringPrintf(INDENT4 "YTranslate: %0.3f\n", mYTranslate);
    dump += StringPrintf(INDENT4 "XScale: %0.3f\n", mXScale);
    dump += StringPrintf(INDENT4 "YScale: %0.3f\n", mYScale);
    dump += StringPrintf(INDENT4 "XPrecision: %0.3f\n", mXPrecision);
    dump += StringPrintf(INDENT4 "YPrecision: %0.3f\n", mYPrecision);
    dump += StringPrintf(INDENT4 "GeometricScale: %0.3f\n", mGeometricScale);
    dump += StringPrintf(INDENT4 "PressureScale: %0.3f\n", mPressureScale);
    dump += StringPrintf(INDENT4 "SizeScale: %0.3f\n", mSizeScale);
    dump += StringPrintf(INDENT4 "OrientationScale: %0.3f\n", mOrientationScale);
    dump += StringPrintf(INDENT4 "DistanceScale: %0.3f\n", mDistanceScale);
    dump += StringPrintf(INDENT4 "HaveTilt: %s\n", toString(mHaveTilt));
    dump += StringPrintf(INDENT4 "TiltXCenter: %0.3f\n", mTiltXCenter);
    dump += StringPrintf(INDENT4 "TiltXScale: %0.3f\n", mTiltXScale);
    dump += StringPrintf(INDENT4 "TiltYCenter: %0.3f\n", mTiltYCenter);
    dump += StringPrintf(INDENT4 "TiltYScale: %0.3f\n", mTiltYScale);

    dump += StringPrintf(INDENT3 "Last Raw Button State: 0x%08x\n", mLastRawState.buttonState);
    dump += StringPrintf(INDENT3 "Last Raw Touch: pointerCount=%d\n",
                         mLastRawState.rawPointerData.pointerCount);
    for (uint32_t i = 0; i < mLastRawState.rawPointerData.pointerCount; i++) {
        const RawPointerData::Pointer& pointer = mLastRawState.rawPointerData.pointers[i];
        dump += StringPrintf(INDENT4 "[%d]: id=%d, x=%d, y=%d, pressure=%d, "
                                     "touchMajor=%d, touchMinor=%d, toolMajor=%d, toolMinor=%d, "
                                     "orientation=%d, tiltX=%d, tiltY=%d, distance=%d, "
                                     "toolType=%d, isHovering=%s\n",
                             i, pointer.id, pointer.x, pointer.y, pointer.pressure,
                             pointer.touchMajor, pointer.touchMinor, pointer.toolMajor,
                             pointer.toolMinor, pointer.orientation, pointer.tiltX, pointer.tiltY,
                             pointer.distance, pointer.toolType, toString(pointer.isHovering));
    }

    dump += StringPrintf(INDENT3 "Last Cooked Button State: 0x%08x\n",
                         mLastCookedState.buttonState);
    dump += StringPrintf(INDENT3 "Last Cooked Touch: pointerCount=%d\n",
                         mLastCookedState.cookedPointerData.pointerCount);
    for (uint32_t i = 0; i < mLastCookedState.cookedPointerData.pointerCount; i++) {
        const PointerProperties& pointerProperties =
                mLastCookedState.cookedPointerData.pointerProperties[i];
        const PointerCoords& pointerCoords = mLastCookedState.cookedPointerData.pointerCoords[i];
        dump += StringPrintf(INDENT4 "[%d]: id=%d, x=%0.3f, y=%0.3f, dx=%0.3f, dy=%0.3f, "
                                     "pressure=%0.3f, touchMajor=%0.3f, touchMinor=%0.3f, "
                                     "toolMajor=%0.3f, toolMinor=%0.3f, "
                                     "orientation=%0.3f, tilt=%0.3f, distance=%0.3f, "
                                     "toolType=%d, isHovering=%s\n",
                             i, pointerProperties.id, pointerCoords.getX(), pointerCoords.getY(),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_TILT),
                             pointerCoords.getAxisValue(AMOTION_EVENT_AXIS_DISTANCE),
                             pointerProperties.toolType,
                             toString(mLastCookedState.cookedPointerData.isHovering(i)));
    }

    dump += INDENT3 "Stylus Fusion:\n";
    dump += StringPrintf(INDENT4 "ExternalStylusConnected: %s\n",
                         toString(mExternalStylusConnected));
    dump += StringPrintf(INDENT4 "External Stylus ID: %" PRId64 "\n", mExternalStylusId);
    dump += StringPrintf(INDENT4 "External Stylus Data Timeout: %" PRId64 "\n",
                         mExternalStylusFusionTimeout);
    dump += INDENT3 "External Stylus State:\n";
    dumpStylusState(dump, mExternalStylusState);

    if (mDeviceMode == DeviceMode::POINTER) {
        dump += StringPrintf(INDENT3 "Pointer Gesture Detector:\n");
        dump += StringPrintf(INDENT4 "XMovementScale: %0.3f\n", mPointerXMovementScale);
        dump += StringPrintf(INDENT4 "YMovementScale: %0.3f\n", mPointerYMovementScale);
        dump += StringPrintf(INDENT4 "XZoomScale: %0.3f\n", mPointerXZoomScale);
        dump += StringPrintf(INDENT4 "YZoomScale: %0.3f\n", mPointerYZoomScale);
        dump += StringPrintf(INDENT4 "MaxSwipeWidth: %f\n", mPointerGestureMaxSwipeWidth);
    }
}

const char* TouchInputMapper::modeToString(DeviceMode deviceMode) {
    switch (deviceMode) {
        case DeviceMode::DISABLED:
            return "disabled";
        case DeviceMode::DIRECT:
            return "direct";
        case DeviceMode::UNSCALED:
            return "unscaled";
        case DeviceMode::NAVIGATION:
            return "navigation";
        case DeviceMode::POINTER:
            return "pointer";
    }
    return "unknown";
}

void TouchInputMapper::configure(nsecs_t when, const InputReaderConfiguration* config,
                                 uint32_t changes) {
    InputMapper::configure(when, config, changes);

    mConfig = *config;

    if (!changes) { // first time only
        // Configure basic parameters.
        configureParameters();

        // Configure common accumulators.
        mCursorScrollAccumulator.configure(getDeviceContext());
        mTouchButtonAccumulator.configure(getDeviceContext());

        // Configure absolute axis information.
        configureRawPointerAxes();

        // Prepare input device calibration.
        parseCalibration();
        resolveCalibration();
    }

    if (!changes || (changes & InputReaderConfiguration::CHANGE_TOUCH_AFFINE_TRANSFORMATION)) {
        // Update location calibration to reflect current settings
        updateAffineTransformation();
    }

    if (!changes || (changes & InputReaderConfiguration::CHANGE_POINTER_SPEED)) {
        // Update pointer speed.
        mPointerVelocityControl.setParameters(mConfig.pointerVelocityControlParameters);
        mWheelXVelocityControl.setParameters(mConfig.wheelVelocityControlParameters);
        mWheelYVelocityControl.setParameters(mConfig.wheelVelocityControlParameters);
    }

    bool resetNeeded = false;
    if (!changes ||
        (changes &
         (InputReaderConfiguration::CHANGE_DISPLAY_INFO |
          InputReaderConfiguration::CHANGE_POINTER_CAPTURE |
          InputReaderConfiguration::CHANGE_POINTER_GESTURE_ENABLEMENT |
          InputReaderConfiguration::CHANGE_SHOW_TOUCHES |
          InputReaderConfiguration::CHANGE_EXTERNAL_STYLUS_PRESENCE))) {
        // Configure device sources, surface dimensions, orientation and
        // scaling factors.
        configureSurface(when, &resetNeeded);
    }

    if (changes && resetNeeded) {
        // Send reset, unless this is the first time the device has been configured,
        // in which case the reader will call reset itself after all mappers are ready.
        NotifyDeviceResetArgs args(getContext()->getNextId(), when, getDeviceId());
        getListener()->notifyDeviceReset(&args);
    }
}

void TouchInputMapper::resolveExternalStylusPresence() {
    std::vector<InputDeviceInfo> devices;
    getContext()->getExternalStylusDevices(devices);
    mExternalStylusConnected = !devices.empty();

    if (!mExternalStylusConnected) {
        resetExternalStylus();
    }
}

void TouchInputMapper::configureParameters() {
    // Use the pointer presentation mode for devices that do not support distinct
    // multitouch.  The spot-based presentation relies on being able to accurately
    // locate two or more fingers on the touch pad.
    mParameters.gestureMode = getDeviceContext().hasInputProperty(INPUT_PROP_SEMI_MT)
            ? Parameters::GestureMode::SINGLE_TOUCH
            : Parameters::GestureMode::MULTI_TOUCH;

    String8 gestureModeString;
    if (getDeviceContext().getConfiguration().tryGetProperty(String8("touch.gestureMode"),
                                                             gestureModeString)) {
        if (gestureModeString == "single-touch") {
            mParameters.gestureMode = Parameters::GestureMode::SINGLE_TOUCH;
        } else if (gestureModeString == "multi-touch") {
            mParameters.gestureMode = Parameters::GestureMode::MULTI_TOUCH;
        } else if (gestureModeString != "default") {
            ALOGW("Invalid value for touch.gestureMode: '%s'", gestureModeString.string());
        }
    }

    if (getDeviceContext().hasInputProperty(INPUT_PROP_DIRECT)) {
        // The device is a touch screen.
        mParameters.deviceType = Parameters::DeviceType::TOUCH_SCREEN;
    } else if (getDeviceContext().hasInputProperty(INPUT_PROP_POINTER)) {
        // The device is a pointing device like a track pad.
        mParameters.deviceType = Parameters::DeviceType::POINTER;
    } else if (getDeviceContext().hasRelativeAxis(REL_X) ||
               getDeviceContext().hasRelativeAxis(REL_Y)) {
        // The device is a cursor device with a touch pad attached.
        // By default don't use the touch pad to move the pointer.
        mParameters.deviceType = Parameters::DeviceType::TOUCH_PAD;
    } else {
        // The device is a touch pad of unknown purpose.
        mParameters.deviceType = Parameters::DeviceType::POINTER;
    }

    mParameters.hasButtonUnderPad = getDeviceContext().hasInputProperty(INPUT_PROP_BUTTONPAD);

    String8 deviceTypeString;
    if (getDeviceContext().getConfiguration().tryGetProperty(String8("touch.deviceType"),
                                                             deviceTypeString)) {
        if (deviceTypeString == "touchScreen") {
            mParameters.deviceType = Parameters::DeviceType::TOUCH_SCREEN;
        } else if (deviceTypeString == "touchPad") {
            mParameters.deviceType = Parameters::DeviceType::TOUCH_PAD;
        } else if (deviceTypeString == "touchNavigation") {
            mParameters.deviceType = Parameters::DeviceType::TOUCH_NAVIGATION;
        } else if (deviceTypeString == "pointer") {
            mParameters.deviceType = Parameters::DeviceType::POINTER;
        } else if (deviceTypeString != "default") {
            ALOGW("Invalid value for touch.deviceType: '%s'", deviceTypeString.string());
        }
    }

    mParameters.orientationAware = mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN;
    getDeviceContext().getConfiguration().tryGetProperty(String8("touch.orientationAware"),
                                                         mParameters.orientationAware);

    mParameters.hasAssociatedDisplay = false;
    mParameters.associatedDisplayIsExternal = false;
    if (mParameters.orientationAware ||
        mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN ||
        mParameters.deviceType == Parameters::DeviceType::POINTER) {
        mParameters.hasAssociatedDisplay = true;
        if (mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN) {
            mParameters.associatedDisplayIsExternal = getDeviceContext().isExternal();
            String8 uniqueDisplayId;
            getDeviceContext().getConfiguration().tryGetProperty(String8("touch.displayId"),
                                                                 uniqueDisplayId);
            mParameters.uniqueDisplayId = uniqueDisplayId.c_str();
        }
    }
    if (getDeviceContext().getAssociatedDisplayPort()) {
        mParameters.hasAssociatedDisplay = true;
    }

    // Initial downs on external touch devices should wake the device.
    // Normally we don't do this for internal touch screens to prevent them from waking
    // up in your pocket but you can enable it using the input device configuration.
    mParameters.wake = getDeviceContext().isExternal();
    getDeviceContext().getConfiguration().tryGetProperty(String8("touch.wake"), mParameters.wake);
}

void TouchInputMapper::dumpParameters(std::string& dump) {
    dump += INDENT3 "Parameters:\n";

    switch (mParameters.gestureMode) {
        case Parameters::GestureMode::SINGLE_TOUCH:
            dump += INDENT4 "GestureMode: single-touch\n";
            break;
        case Parameters::GestureMode::MULTI_TOUCH:
            dump += INDENT4 "GestureMode: multi-touch\n";
            break;
        default:
            assert(false);
    }

    switch (mParameters.deviceType) {
        case Parameters::DeviceType::TOUCH_SCREEN:
            dump += INDENT4 "DeviceType: touchScreen\n";
            break;
        case Parameters::DeviceType::TOUCH_PAD:
            dump += INDENT4 "DeviceType: touchPad\n";
            break;
        case Parameters::DeviceType::TOUCH_NAVIGATION:
            dump += INDENT4 "DeviceType: touchNavigation\n";
            break;
        case Parameters::DeviceType::POINTER:
            dump += INDENT4 "DeviceType: pointer\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    dump += StringPrintf(INDENT4 "AssociatedDisplay: hasAssociatedDisplay=%s, isExternal=%s, "
                                 "displayId='%s'\n",
                         toString(mParameters.hasAssociatedDisplay),
                         toString(mParameters.associatedDisplayIsExternal),
                         mParameters.uniqueDisplayId.c_str());
    dump += StringPrintf(INDENT4 "OrientationAware: %s\n", toString(mParameters.orientationAware));
}

void TouchInputMapper::configureRawPointerAxes() {
    mRawPointerAxes.clear();
}

void TouchInputMapper::dumpRawPointerAxes(std::string& dump) {
    dump += INDENT3 "Raw Touch Axes:\n";
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.x, "X");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.y, "Y");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.pressure, "Pressure");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.touchMajor, "TouchMajor");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.touchMinor, "TouchMinor");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.toolMajor, "ToolMajor");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.toolMinor, "ToolMinor");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.orientation, "Orientation");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.distance, "Distance");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.tiltX, "TiltX");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.tiltY, "TiltY");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.trackingId, "TrackingId");
    dumpRawAbsoluteAxisInfo(dump, mRawPointerAxes.slot, "Slot");
}

bool TouchInputMapper::hasExternalStylus() const {
    return mExternalStylusConnected;
}

/**
 * Determine which DisplayViewport to use.
 * 1. If display port is specified, return the matching viewport. If matching viewport not
 * found, then return.
 * 2. Always use the suggested viewport from WindowManagerService for pointers.
 * 3. If a device has associated display, get the matching viewport by either unique id or by
 * the display type (internal or external).
 * 4. Otherwise, use a non-display viewport.
 */
std::optional<DisplayViewport> TouchInputMapper::findViewport() {
    if (mParameters.hasAssociatedDisplay && mDeviceMode != DeviceMode::UNSCALED) {
        const std::optional<uint8_t> displayPort = getDeviceContext().getAssociatedDisplayPort();
        if (displayPort) {
            // Find the viewport that contains the same port
            return getDeviceContext().getAssociatedViewport();
        }

        if (mDeviceMode == DeviceMode::POINTER) {
            std::optional<DisplayViewport> viewport =
                    mConfig.getDisplayViewportById(mConfig.defaultPointerDisplayId);
            if (viewport) {
                return viewport;
            } else {
                ALOGW("Can't find designated display viewport with ID %" PRId32 " for pointers.",
                      mConfig.defaultPointerDisplayId);
            }
        }

        // Check if uniqueDisplayId is specified in idc file.
        if (!mParameters.uniqueDisplayId.empty()) {
            return mConfig.getDisplayViewportByUniqueId(mParameters.uniqueDisplayId);
        }

        ViewportType viewportTypeToUse;
        if (mParameters.associatedDisplayIsExternal) {
            viewportTypeToUse = ViewportType::VIEWPORT_EXTERNAL;
        } else {
            viewportTypeToUse = ViewportType::VIEWPORT_INTERNAL;
        }

        std::optional<DisplayViewport> viewport =
                mConfig.getDisplayViewportByType(viewportTypeToUse);
        if (!viewport && viewportTypeToUse == ViewportType::VIEWPORT_EXTERNAL) {
            ALOGW("Input device %s should be associated with external display, "
                  "fallback to internal one for the external viewport is not found.",
                  getDeviceName().c_str());
            viewport = mConfig.getDisplayViewportByType(ViewportType::VIEWPORT_INTERNAL);
        }

        return viewport;
    }

    // No associated display, return a non-display viewport.
    DisplayViewport newViewport;
    // Raw width and height in the natural orientation.
    int32_t rawWidth = mRawPointerAxes.getRawWidth();
    int32_t rawHeight = mRawPointerAxes.getRawHeight();
    newViewport.setNonDisplayViewport(rawWidth, rawHeight);
    return std::make_optional(newViewport);
}

void TouchInputMapper::configureSurface(nsecs_t when, bool* outResetNeeded) {
    DeviceMode oldDeviceMode = mDeviceMode;

    resolveExternalStylusPresence();

    // Determine device mode.
    if (mParameters.deviceType == Parameters::DeviceType::POINTER &&
        mConfig.pointerGesturesEnabled && !mConfig.pointerCapture) {
        mSource = AINPUT_SOURCE_MOUSE;
        mDeviceMode = DeviceMode::POINTER;
        if (hasStylus()) {
            mSource |= AINPUT_SOURCE_STYLUS;
        }
    } else if (mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN &&
               mParameters.hasAssociatedDisplay) {
        mSource = AINPUT_SOURCE_TOUCHSCREEN;
        mDeviceMode = DeviceMode::DIRECT;
        if (hasStylus()) {
            mSource |= AINPUT_SOURCE_STYLUS;
        }
        if (hasExternalStylus()) {
            mSource |= AINPUT_SOURCE_BLUETOOTH_STYLUS;
        }
    } else if (mParameters.deviceType == Parameters::DeviceType::TOUCH_NAVIGATION) {
        mSource = AINPUT_SOURCE_TOUCH_NAVIGATION;
        mDeviceMode = DeviceMode::NAVIGATION;
    } else {
        mSource = AINPUT_SOURCE_TOUCHPAD;
        mDeviceMode = DeviceMode::UNSCALED;
    }

    // Ensure we have valid X and Y axes.
    if (!mRawPointerAxes.x.valid || !mRawPointerAxes.y.valid) {
        ALOGW("Touch device '%s' did not report support for X or Y axis!  "
              "The device will be inoperable.",
              getDeviceName().c_str());
        mDeviceMode = DeviceMode::DISABLED;
        return;
    }

    // Get associated display dimensions.
    std::optional<DisplayViewport> newViewport = findViewport();
    if (!newViewport) {
        ALOGI("Touch device '%s' could not query the properties of its associated "
              "display.  The device will be inoperable until the display size "
              "becomes available.",
              getDeviceName().c_str());
        mDeviceMode = DeviceMode::DISABLED;
        return;
    }

    // Raw width and height in the natural orientation.
    int32_t rawWidth = mRawPointerAxes.getRawWidth();
    int32_t rawHeight = mRawPointerAxes.getRawHeight();

    bool viewportChanged = mViewport != *newViewport;
    if (viewportChanged) {
        mViewport = *newViewport;

        if (mDeviceMode == DeviceMode::DIRECT || mDeviceMode == DeviceMode::POINTER) {
            // Convert rotated viewport to natural surface coordinates.
            int32_t naturalLogicalWidth, naturalLogicalHeight;
            int32_t naturalPhysicalWidth, naturalPhysicalHeight;
            int32_t naturalPhysicalLeft, naturalPhysicalTop;
            int32_t naturalDeviceWidth, naturalDeviceHeight;
            switch (mViewport.orientation) {
                case DISPLAY_ORIENTATION_90:
                    naturalLogicalWidth = mViewport.logicalBottom - mViewport.logicalTop;
                    naturalLogicalHeight = mViewport.logicalRight - mViewport.logicalLeft;
                    naturalPhysicalWidth = mViewport.physicalBottom - mViewport.physicalTop;
                    naturalPhysicalHeight = mViewport.physicalRight - mViewport.physicalLeft;
                    naturalPhysicalLeft = mViewport.deviceHeight - mViewport.physicalBottom;
                    naturalPhysicalTop = mViewport.physicalLeft;
                    naturalDeviceWidth = mViewport.deviceHeight;
                    naturalDeviceHeight = mViewport.deviceWidth;
                    break;
                case DISPLAY_ORIENTATION_180:
                    naturalLogicalWidth = mViewport.logicalRight - mViewport.logicalLeft;
                    naturalLogicalHeight = mViewport.logicalBottom - mViewport.logicalTop;
                    naturalPhysicalWidth = mViewport.physicalRight - mViewport.physicalLeft;
                    naturalPhysicalHeight = mViewport.physicalBottom - mViewport.physicalTop;
                    naturalPhysicalLeft = mViewport.deviceWidth - mViewport.physicalRight;
                    naturalPhysicalTop = mViewport.deviceHeight - mViewport.physicalBottom;
                    naturalDeviceWidth = mViewport.deviceWidth;
                    naturalDeviceHeight = mViewport.deviceHeight;
                    break;
                case DISPLAY_ORIENTATION_270:
                    naturalLogicalWidth = mViewport.logicalBottom - mViewport.logicalTop;
                    naturalLogicalHeight = mViewport.logicalRight - mViewport.logicalLeft;
                    naturalPhysicalWidth = mViewport.physicalBottom - mViewport.physicalTop;
                    naturalPhysicalHeight = mViewport.physicalRight - mViewport.physicalLeft;
                    naturalPhysicalLeft = mViewport.physicalTop;
                    naturalPhysicalTop = mViewport.deviceWidth - mViewport.physicalRight;
                    naturalDeviceWidth = mViewport.deviceHeight;
                    naturalDeviceHeight = mViewport.deviceWidth;
                    break;
                case DISPLAY_ORIENTATION_0:
                default:
                    naturalLogicalWidth = mViewport.logicalRight - mViewport.logicalLeft;
                    naturalLogicalHeight = mViewport.logicalBottom - mViewport.logicalTop;
                    naturalPhysicalWidth = mViewport.physicalRight - mViewport.physicalLeft;
                    naturalPhysicalHeight = mViewport.physicalBottom - mViewport.physicalTop;
                    naturalPhysicalLeft = mViewport.physicalLeft;
                    naturalPhysicalTop = mViewport.physicalTop;
                    naturalDeviceWidth = mViewport.deviceWidth;
                    naturalDeviceHeight = mViewport.deviceHeight;
                    break;
            }

            if (naturalPhysicalHeight == 0 || naturalPhysicalWidth == 0) {
                ALOGE("Viewport is not set properly: %s", mViewport.toString().c_str());
                naturalPhysicalHeight = naturalPhysicalHeight == 0 ? 1 : naturalPhysicalHeight;
                naturalPhysicalWidth = naturalPhysicalWidth == 0 ? 1 : naturalPhysicalWidth;
            }

            mPhysicalWidth = naturalPhysicalWidth;
            mPhysicalHeight = naturalPhysicalHeight;
            mPhysicalLeft = naturalPhysicalLeft;
            mPhysicalTop = naturalPhysicalTop;

            mRawSurfaceWidth = naturalLogicalWidth * naturalDeviceWidth / naturalPhysicalWidth;
            mRawSurfaceHeight = naturalLogicalHeight * naturalDeviceHeight / naturalPhysicalHeight;
            mSurfaceLeft = naturalPhysicalLeft * naturalLogicalWidth / naturalPhysicalWidth;
            mSurfaceTop = naturalPhysicalTop * naturalLogicalHeight / naturalPhysicalHeight;
            mSurfaceRight = mSurfaceLeft + naturalLogicalWidth;
            mSurfaceBottom = mSurfaceTop + naturalLogicalHeight;

            mSurfaceOrientation =
                    mParameters.orientationAware ? mViewport.orientation : DISPLAY_ORIENTATION_0;
        } else {
            mPhysicalWidth = rawWidth;
            mPhysicalHeight = rawHeight;
            mPhysicalLeft = 0;
            mPhysicalTop = 0;

            mRawSurfaceWidth = rawWidth;
            mRawSurfaceHeight = rawHeight;
            mSurfaceLeft = 0;
            mSurfaceTop = 0;
            mSurfaceOrientation = DISPLAY_ORIENTATION_0;
        }
    }

    // If moving between pointer modes, need to reset some state.
    bool deviceModeChanged = mDeviceMode != oldDeviceMode;
    if (deviceModeChanged) {
        mOrientedRanges.clear();
    }

    // Create pointer controller if needed, and keep it around if Pointer Capture is enabled to
    // preserve the cursor position.
    if (mDeviceMode == DeviceMode::POINTER ||
        (mDeviceMode == DeviceMode::DIRECT && mConfig.showTouches) ||
        (mParameters.deviceType == Parameters::DeviceType::POINTER && mConfig.pointerCapture)) {
        if (mPointerController == nullptr) {
            mPointerController = getContext()->getPointerController(getDeviceId());
        }
        if (mConfig.pointerCapture) {
            mPointerController->fade(PointerControllerInterface::Transition::IMMEDIATE);
        }
    } else {
        mPointerController.reset();
    }

    if (viewportChanged || deviceModeChanged) {
        ALOGI("Device reconfigured: id=%d, name='%s', size %dx%d, orientation %d, mode %d, "
              "display id %d",
              getDeviceId(), getDeviceName().c_str(), mRawSurfaceWidth, mRawSurfaceHeight,
              mSurfaceOrientation, mDeviceMode, mViewport.displayId);

        // Configure X and Y factors.
        mXScale = float(mRawSurfaceWidth) / rawWidth;
        mYScale = float(mRawSurfaceHeight) / rawHeight;
        mXTranslate = -mSurfaceLeft;
        mYTranslate = -mSurfaceTop;
        mXPrecision = 1.0f / mXScale;
        mYPrecision = 1.0f / mYScale;

        mOrientedRanges.x.axis = AMOTION_EVENT_AXIS_X;
        mOrientedRanges.x.source = mSource;
        mOrientedRanges.y.axis = AMOTION_EVENT_AXIS_Y;
        mOrientedRanges.y.source = mSource;

        configureVirtualKeys();

        // Scale factor for terms that are not oriented in a particular axis.
        // If the pixels are square then xScale == yScale otherwise we fake it
        // by choosing an average.
        mGeometricScale = avg(mXScale, mYScale);

        // Size of diagonal axis.
        float diagonalSize = hypotf(mRawSurfaceWidth, mRawSurfaceHeight);

        // Size factors.
        if (mCalibration.sizeCalibration != Calibration::SizeCalibration::NONE) {
            if (mRawPointerAxes.touchMajor.valid && mRawPointerAxes.touchMajor.maxValue != 0) {
                mSizeScale = 1.0f / mRawPointerAxes.touchMajor.maxValue;
            } else if (mRawPointerAxes.toolMajor.valid && mRawPointerAxes.toolMajor.maxValue != 0) {
                mSizeScale = 1.0f / mRawPointerAxes.toolMajor.maxValue;
            } else {
                mSizeScale = 0.0f;
            }

            mOrientedRanges.haveTouchSize = true;
            mOrientedRanges.haveToolSize = true;
            mOrientedRanges.haveSize = true;

            mOrientedRanges.touchMajor.axis = AMOTION_EVENT_AXIS_TOUCH_MAJOR;
            mOrientedRanges.touchMajor.source = mSource;
            mOrientedRanges.touchMajor.min = 0;
            mOrientedRanges.touchMajor.max = diagonalSize;
            mOrientedRanges.touchMajor.flat = 0;
            mOrientedRanges.touchMajor.fuzz = 0;
            mOrientedRanges.touchMajor.resolution = 0;

            mOrientedRanges.touchMinor = mOrientedRanges.touchMajor;
            mOrientedRanges.touchMinor.axis = AMOTION_EVENT_AXIS_TOUCH_MINOR;

            mOrientedRanges.toolMajor.axis = AMOTION_EVENT_AXIS_TOOL_MAJOR;
            mOrientedRanges.toolMajor.source = mSource;
            mOrientedRanges.toolMajor.min = 0;
            mOrientedRanges.toolMajor.max = diagonalSize;
            mOrientedRanges.toolMajor.flat = 0;
            mOrientedRanges.toolMajor.fuzz = 0;
            mOrientedRanges.toolMajor.resolution = 0;

            mOrientedRanges.toolMinor = mOrientedRanges.toolMajor;
            mOrientedRanges.toolMinor.axis = AMOTION_EVENT_AXIS_TOOL_MINOR;

            mOrientedRanges.size.axis = AMOTION_EVENT_AXIS_SIZE;
            mOrientedRanges.size.source = mSource;
            mOrientedRanges.size.min = 0;
            mOrientedRanges.size.max = 1.0;
            mOrientedRanges.size.flat = 0;
            mOrientedRanges.size.fuzz = 0;
            mOrientedRanges.size.resolution = 0;
        } else {
            mSizeScale = 0.0f;
        }

        // Pressure factors.
        mPressureScale = 0;
        float pressureMax = 1.0;
        if (mCalibration.pressureCalibration == Calibration::PressureCalibration::PHYSICAL ||
            mCalibration.pressureCalibration == Calibration::PressureCalibration::AMPLITUDE) {
            if (mCalibration.havePressureScale) {
                mPressureScale = mCalibration.pressureScale;
                pressureMax = mPressureScale * mRawPointerAxes.pressure.maxValue;
            } else if (mRawPointerAxes.pressure.valid && mRawPointerAxes.pressure.maxValue != 0) {
                mPressureScale = 1.0f / mRawPointerAxes.pressure.maxValue;
            }
        }

        mOrientedRanges.pressure.axis = AMOTION_EVENT_AXIS_PRESSURE;
        mOrientedRanges.pressure.source = mSource;
        mOrientedRanges.pressure.min = 0;
        mOrientedRanges.pressure.max = pressureMax;
        mOrientedRanges.pressure.flat = 0;
        mOrientedRanges.pressure.fuzz = 0;
        mOrientedRanges.pressure.resolution = 0;

        // Tilt
        mTiltXCenter = 0;
        mTiltXScale = 0;
        mTiltYCenter = 0;
        mTiltYScale = 0;
        mHaveTilt = mRawPointerAxes.tiltX.valid && mRawPointerAxes.tiltY.valid;
        if (mHaveTilt) {
            mTiltXCenter = avg(mRawPointerAxes.tiltX.minValue, mRawPointerAxes.tiltX.maxValue);
            mTiltYCenter = avg(mRawPointerAxes.tiltY.minValue, mRawPointerAxes.tiltY.maxValue);
            mTiltXScale = M_PI / 180;
            mTiltYScale = M_PI / 180;

            mOrientedRanges.haveTilt = true;

            mOrientedRanges.tilt.axis = AMOTION_EVENT_AXIS_TILT;
            mOrientedRanges.tilt.source = mSource;
            mOrientedRanges.tilt.min = 0;
            mOrientedRanges.tilt.max = M_PI_2;
            mOrientedRanges.tilt.flat = 0;
            mOrientedRanges.tilt.fuzz = 0;
            mOrientedRanges.tilt.resolution = 0;
        }

        // Orientation
        mOrientationScale = 0;
        if (mHaveTilt) {
            mOrientedRanges.haveOrientation = true;

            mOrientedRanges.orientation.axis = AMOTION_EVENT_AXIS_ORIENTATION;
            mOrientedRanges.orientation.source = mSource;
            mOrientedRanges.orientation.min = -M_PI;
            mOrientedRanges.orientation.max = M_PI;
            mOrientedRanges.orientation.flat = 0;
            mOrientedRanges.orientation.fuzz = 0;
            mOrientedRanges.orientation.resolution = 0;
        } else if (mCalibration.orientationCalibration !=
                   Calibration::OrientationCalibration::NONE) {
            if (mCalibration.orientationCalibration ==
                Calibration::OrientationCalibration::INTERPOLATED) {
                if (mRawPointerAxes.orientation.valid) {
                    if (mRawPointerAxes.orientation.maxValue > 0) {
                        mOrientationScale = M_PI_2 / mRawPointerAxes.orientation.maxValue;
                    } else if (mRawPointerAxes.orientation.minValue < 0) {
                        mOrientationScale = -M_PI_2 / mRawPointerAxes.orientation.minValue;
                    } else {
                        mOrientationScale = 0;
                    }
                }
            }

            mOrientedRanges.haveOrientation = true;

            mOrientedRanges.orientation.axis = AMOTION_EVENT_AXIS_ORIENTATION;
            mOrientedRanges.orientation.source = mSource;
            mOrientedRanges.orientation.min = -M_PI_2;
            mOrientedRanges.orientation.max = M_PI_2;
            mOrientedRanges.orientation.flat = 0;
            mOrientedRanges.orientation.fuzz = 0;
            mOrientedRanges.orientation.resolution = 0;
        }

        // Distance
        mDistanceScale = 0;
        if (mCalibration.distanceCalibration != Calibration::DistanceCalibration::NONE) {
            if (mCalibration.distanceCalibration == Calibration::DistanceCalibration::SCALED) {
                if (mCalibration.haveDistanceScale) {
                    mDistanceScale = mCalibration.distanceScale;
                } else {
                    mDistanceScale = 1.0f;
                }
            }

            mOrientedRanges.haveDistance = true;

            mOrientedRanges.distance.axis = AMOTION_EVENT_AXIS_DISTANCE;
            mOrientedRanges.distance.source = mSource;
            mOrientedRanges.distance.min = mRawPointerAxes.distance.minValue * mDistanceScale;
            mOrientedRanges.distance.max = mRawPointerAxes.distance.maxValue * mDistanceScale;
            mOrientedRanges.distance.flat = 0;
            mOrientedRanges.distance.fuzz = mRawPointerAxes.distance.fuzz * mDistanceScale;
            mOrientedRanges.distance.resolution = 0;
        }

        // Compute oriented precision, scales and ranges.
        // Note that the maximum value reported is an inclusive maximum value so it is one
        // unit less than the total width or height of surface.
        switch (mSurfaceOrientation) {
            case DISPLAY_ORIENTATION_90:
            case DISPLAY_ORIENTATION_270:
                mOrientedXPrecision = mYPrecision;
                mOrientedYPrecision = mXPrecision;

                mOrientedRanges.x.min = mYTranslate;
                mOrientedRanges.x.max = mRawSurfaceHeight + mYTranslate - 1;
                mOrientedRanges.x.flat = 0;
                mOrientedRanges.x.fuzz = 0;
                mOrientedRanges.x.resolution = mRawPointerAxes.y.resolution * mYScale;

                mOrientedRanges.y.min = mXTranslate;
                mOrientedRanges.y.max = mRawSurfaceWidth + mXTranslate - 1;
                mOrientedRanges.y.flat = 0;
                mOrientedRanges.y.fuzz = 0;
                mOrientedRanges.y.resolution = mRawPointerAxes.x.resolution * mXScale;
                break;

            default:
                mOrientedXPrecision = mXPrecision;
                mOrientedYPrecision = mYPrecision;

                mOrientedRanges.x.min = mXTranslate;
                mOrientedRanges.x.max = mRawSurfaceWidth + mXTranslate - 1;
                mOrientedRanges.x.flat = 0;
                mOrientedRanges.x.fuzz = 0;
                mOrientedRanges.x.resolution = mRawPointerAxes.x.resolution * mXScale;

                mOrientedRanges.y.min = mYTranslate;
                mOrientedRanges.y.max = mRawSurfaceHeight + mYTranslate - 1;
                mOrientedRanges.y.flat = 0;
                mOrientedRanges.y.fuzz = 0;
                mOrientedRanges.y.resolution = mRawPointerAxes.y.resolution * mYScale;
                break;
        }

        // Location
        updateAffineTransformation();

        if (mDeviceMode == DeviceMode::POINTER) {
            // Compute pointer gesture detection parameters.
            float rawDiagonal = hypotf(rawWidth, rawHeight);
            float displayDiagonal = hypotf(mRawSurfaceWidth, mRawSurfaceHeight);

            // Scale movements such that one whole swipe of the touch pad covers a
            // given area relative to the diagonal size of the display when no acceleration
            // is applied.
            // Assume that the touch pad has a square aspect ratio such that movements in
            // X and Y of the same number of raw units cover the same physical distance.
            mPointerXMovementScale =
                    mConfig.pointerGestureMovementSpeedRatio * displayDiagonal / rawDiagonal;
            mPointerYMovementScale = mPointerXMovementScale;

            // Scale zooms to cover a smaller range of the display than movements do.
            // This value determines the area around the pointer that is affected by freeform
            // pointer gestures.
            mPointerXZoomScale =
                    mConfig.pointerGestureZoomSpeedRatio * displayDiagonal / rawDiagonal;
            mPointerYZoomScale = mPointerXZoomScale;

            // Max width between pointers to detect a swipe gesture is more than some fraction
            // of the diagonal axis of the touch pad.  Touches that are wider than this are
            // translated into freeform gestures.
            mPointerGestureMaxSwipeWidth = mConfig.pointerGestureSwipeMaxWidthRatio * rawDiagonal;

            // Abort current pointer usages because the state has changed.
            abortPointerUsage(when, 0 /*policyFlags*/);
        }

        // Inform the dispatcher about the changes.
        *outResetNeeded = true;
        bumpGeneration();
    }
}

void TouchInputMapper::dumpSurface(std::string& dump) {
    dump += StringPrintf(INDENT3 "%s\n", mViewport.toString().c_str());
    dump += StringPrintf(INDENT3 "RawSurfaceWidth: %dpx\n", mRawSurfaceWidth);
    dump += StringPrintf(INDENT3 "RawSurfaceHeight: %dpx\n", mRawSurfaceHeight);
    dump += StringPrintf(INDENT3 "SurfaceLeft: %d\n", mSurfaceLeft);
    dump += StringPrintf(INDENT3 "SurfaceTop: %d\n", mSurfaceTop);
    dump += StringPrintf(INDENT3 "SurfaceRight: %d\n", mSurfaceRight);
    dump += StringPrintf(INDENT3 "SurfaceBottom: %d\n", mSurfaceBottom);
    dump += StringPrintf(INDENT3 "PhysicalWidth: %dpx\n", mPhysicalWidth);
    dump += StringPrintf(INDENT3 "PhysicalHeight: %dpx\n", mPhysicalHeight);
    dump += StringPrintf(INDENT3 "PhysicalLeft: %d\n", mPhysicalLeft);
    dump += StringPrintf(INDENT3 "PhysicalTop: %d\n", mPhysicalTop);
    dump += StringPrintf(INDENT3 "SurfaceOrientation: %d\n", mSurfaceOrientation);
}

void TouchInputMapper::configureVirtualKeys() {
    std::vector<VirtualKeyDefinition> virtualKeyDefinitions;
    getDeviceContext().getVirtualKeyDefinitions(virtualKeyDefinitions);

    mVirtualKeys.clear();

    if (virtualKeyDefinitions.size() == 0) {
        return;
    }

    int32_t touchScreenLeft = mRawPointerAxes.x.minValue;
    int32_t touchScreenTop = mRawPointerAxes.y.minValue;
    int32_t touchScreenWidth = mRawPointerAxes.getRawWidth();
    int32_t touchScreenHeight = mRawPointerAxes.getRawHeight();

    for (const VirtualKeyDefinition& virtualKeyDefinition : virtualKeyDefinitions) {
        VirtualKey virtualKey;

        virtualKey.scanCode = virtualKeyDefinition.scanCode;
        int32_t keyCode;
        int32_t dummyKeyMetaState;
        uint32_t flags;
        if (getDeviceContext().mapKey(virtualKey.scanCode, 0, 0, &keyCode, &dummyKeyMetaState,
                                      &flags)) {
            ALOGW(INDENT "VirtualKey %d: could not obtain key code, ignoring", virtualKey.scanCode);
            continue; // drop the key
        }

        virtualKey.keyCode = keyCode;
        virtualKey.flags = flags;

        // convert the key definition's display coordinates into touch coordinates for a hit box
        int32_t halfWidth = virtualKeyDefinition.width / 2;
        int32_t halfHeight = virtualKeyDefinition.height / 2;

        virtualKey.hitLeft =
                (virtualKeyDefinition.centerX - halfWidth) * touchScreenWidth / mRawSurfaceWidth +
                touchScreenLeft;
        virtualKey.hitRight =
                (virtualKeyDefinition.centerX + halfWidth) * touchScreenWidth / mRawSurfaceWidth +
                touchScreenLeft;
        virtualKey.hitTop = (virtualKeyDefinition.centerY - halfHeight) * touchScreenHeight /
                        mRawSurfaceHeight +
                touchScreenTop;
        virtualKey.hitBottom = (virtualKeyDefinition.centerY + halfHeight) * touchScreenHeight /
                        mRawSurfaceHeight +
                touchScreenTop;
        mVirtualKeys.push_back(virtualKey);
    }
}

void TouchInputMapper::dumpVirtualKeys(std::string& dump) {
    if (!mVirtualKeys.empty()) {
        dump += INDENT3 "Virtual Keys:\n";

        for (size_t i = 0; i < mVirtualKeys.size(); i++) {
            const VirtualKey& virtualKey = mVirtualKeys[i];
            dump += StringPrintf(INDENT4 "%zu: scanCode=%d, keyCode=%d, "
                                         "hitLeft=%d, hitRight=%d, hitTop=%d, hitBottom=%d\n",
                                 i, virtualKey.scanCode, virtualKey.keyCode, virtualKey.hitLeft,
                                 virtualKey.hitRight, virtualKey.hitTop, virtualKey.hitBottom);
        }
    }
}

void TouchInputMapper::parseCalibration() {
    const PropertyMap& in = getDeviceContext().getConfiguration();
    Calibration& out = mCalibration;

    // Size
    out.sizeCalibration = Calibration::SizeCalibration::DEFAULT;
    String8 sizeCalibrationString;
    if (in.tryGetProperty(String8("touch.size.calibration"), sizeCalibrationString)) {
        if (sizeCalibrationString == "none") {
            out.sizeCalibration = Calibration::SizeCalibration::NONE;
        } else if (sizeCalibrationString == "geometric") {
            out.sizeCalibration = Calibration::SizeCalibration::GEOMETRIC;
        } else if (sizeCalibrationString == "diameter") {
            out.sizeCalibration = Calibration::SizeCalibration::DIAMETER;
        } else if (sizeCalibrationString == "box") {
            out.sizeCalibration = Calibration::SizeCalibration::BOX;
        } else if (sizeCalibrationString == "area") {
            out.sizeCalibration = Calibration::SizeCalibration::AREA;
        } else if (sizeCalibrationString != "default") {
            ALOGW("Invalid value for touch.size.calibration: '%s'", sizeCalibrationString.string());
        }
    }

    out.haveSizeScale = in.tryGetProperty(String8("touch.size.scale"), out.sizeScale);
    out.haveSizeBias = in.tryGetProperty(String8("touch.size.bias"), out.sizeBias);
    out.haveSizeIsSummed = in.tryGetProperty(String8("touch.size.isSummed"), out.sizeIsSummed);

    // Pressure
    out.pressureCalibration = Calibration::PressureCalibration::DEFAULT;
    String8 pressureCalibrationString;
    if (in.tryGetProperty(String8("touch.pressure.calibration"), pressureCalibrationString)) {
        if (pressureCalibrationString == "none") {
            out.pressureCalibration = Calibration::PressureCalibration::NONE;
        } else if (pressureCalibrationString == "physical") {
            out.pressureCalibration = Calibration::PressureCalibration::PHYSICAL;
        } else if (pressureCalibrationString == "amplitude") {
            out.pressureCalibration = Calibration::PressureCalibration::AMPLITUDE;
        } else if (pressureCalibrationString != "default") {
            ALOGW("Invalid value for touch.pressure.calibration: '%s'",
                  pressureCalibrationString.string());
        }
    }

    out.havePressureScale = in.tryGetProperty(String8("touch.pressure.scale"), out.pressureScale);

    // Orientation
    out.orientationCalibration = Calibration::OrientationCalibration::DEFAULT;
    String8 orientationCalibrationString;
    if (in.tryGetProperty(String8("touch.orientation.calibration"), orientationCalibrationString)) {
        if (orientationCalibrationString == "none") {
            out.orientationCalibration = Calibration::OrientationCalibration::NONE;
        } else if (orientationCalibrationString == "interpolated") {
            out.orientationCalibration = Calibration::OrientationCalibration::INTERPOLATED;
        } else if (orientationCalibrationString == "vector") {
            out.orientationCalibration = Calibration::OrientationCalibration::VECTOR;
        } else if (orientationCalibrationString != "default") {
            ALOGW("Invalid value for touch.orientation.calibration: '%s'",
                  orientationCalibrationString.string());
        }
    }

    // Distance
    out.distanceCalibration = Calibration::DistanceCalibration::DEFAULT;
    String8 distanceCalibrationString;
    if (in.tryGetProperty(String8("touch.distance.calibration"), distanceCalibrationString)) {
        if (distanceCalibrationString == "none") {
            out.distanceCalibration = Calibration::DistanceCalibration::NONE;
        } else if (distanceCalibrationString == "scaled") {
            out.distanceCalibration = Calibration::DistanceCalibration::SCALED;
        } else if (distanceCalibrationString != "default") {
            ALOGW("Invalid value for touch.distance.calibration: '%s'",
                  distanceCalibrationString.string());
        }
    }

    out.haveDistanceScale = in.tryGetProperty(String8("touch.distance.scale"), out.distanceScale);

    out.coverageCalibration = Calibration::CoverageCalibration::DEFAULT;
    String8 coverageCalibrationString;
    if (in.tryGetProperty(String8("touch.coverage.calibration"), coverageCalibrationString)) {
        if (coverageCalibrationString == "none") {
            out.coverageCalibration = Calibration::CoverageCalibration::NONE;
        } else if (coverageCalibrationString == "box") {
            out.coverageCalibration = Calibration::CoverageCalibration::BOX;
        } else if (coverageCalibrationString != "default") {
            ALOGW("Invalid value for touch.coverage.calibration: '%s'",
                  coverageCalibrationString.string());
        }
    }
}

void TouchInputMapper::resolveCalibration() {
    // Size
    if (mRawPointerAxes.touchMajor.valid || mRawPointerAxes.toolMajor.valid) {
        if (mCalibration.sizeCalibration == Calibration::SizeCalibration::DEFAULT) {
            mCalibration.sizeCalibration = Calibration::SizeCalibration::GEOMETRIC;
        }
    } else {
        mCalibration.sizeCalibration = Calibration::SizeCalibration::NONE;
    }

    // Pressure
    if (mRawPointerAxes.pressure.valid) {
        if (mCalibration.pressureCalibration == Calibration::PressureCalibration::DEFAULT) {
            mCalibration.pressureCalibration = Calibration::PressureCalibration::PHYSICAL;
        }
    } else {
        mCalibration.pressureCalibration = Calibration::PressureCalibration::NONE;
    }

    // Orientation
    if (mRawPointerAxes.orientation.valid) {
        if (mCalibration.orientationCalibration == Calibration::OrientationCalibration::DEFAULT) {
            mCalibration.orientationCalibration = Calibration::OrientationCalibration::INTERPOLATED;
        }
    } else {
        mCalibration.orientationCalibration = Calibration::OrientationCalibration::NONE;
    }

    // Distance
    if (mRawPointerAxes.distance.valid) {
        if (mCalibration.distanceCalibration == Calibration::DistanceCalibration::DEFAULT) {
            mCalibration.distanceCalibration = Calibration::DistanceCalibration::SCALED;
        }
    } else {
        mCalibration.distanceCalibration = Calibration::DistanceCalibration::NONE;
    }

    // Coverage
    if (mCalibration.coverageCalibration == Calibration::CoverageCalibration::DEFAULT) {
        mCalibration.coverageCalibration = Calibration::CoverageCalibration::NONE;
    }
}

void TouchInputMapper::dumpCalibration(std::string& dump) {
    dump += INDENT3 "Calibration:\n";

    // Size
    switch (mCalibration.sizeCalibration) {
        case Calibration::SizeCalibration::NONE:
            dump += INDENT4 "touch.size.calibration: none\n";
            break;
        case Calibration::SizeCalibration::GEOMETRIC:
            dump += INDENT4 "touch.size.calibration: geometric\n";
            break;
        case Calibration::SizeCalibration::DIAMETER:
            dump += INDENT4 "touch.size.calibration: diameter\n";
            break;
        case Calibration::SizeCalibration::BOX:
            dump += INDENT4 "touch.size.calibration: box\n";
            break;
        case Calibration::SizeCalibration::AREA:
            dump += INDENT4 "touch.size.calibration: area\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    if (mCalibration.haveSizeScale) {
        dump += StringPrintf(INDENT4 "touch.size.scale: %0.3f\n", mCalibration.sizeScale);
    }

    if (mCalibration.haveSizeBias) {
        dump += StringPrintf(INDENT4 "touch.size.bias: %0.3f\n", mCalibration.sizeBias);
    }

    if (mCalibration.haveSizeIsSummed) {
        dump += StringPrintf(INDENT4 "touch.size.isSummed: %s\n",
                             toString(mCalibration.sizeIsSummed));
    }

    // Pressure
    switch (mCalibration.pressureCalibration) {
        case Calibration::PressureCalibration::NONE:
            dump += INDENT4 "touch.pressure.calibration: none\n";
            break;
        case Calibration::PressureCalibration::PHYSICAL:
            dump += INDENT4 "touch.pressure.calibration: physical\n";
            break;
        case Calibration::PressureCalibration::AMPLITUDE:
            dump += INDENT4 "touch.pressure.calibration: amplitude\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    if (mCalibration.havePressureScale) {
        dump += StringPrintf(INDENT4 "touch.pressure.scale: %0.3f\n", mCalibration.pressureScale);
    }

    // Orientation
    switch (mCalibration.orientationCalibration) {
        case Calibration::OrientationCalibration::NONE:
            dump += INDENT4 "touch.orientation.calibration: none\n";
            break;
        case Calibration::OrientationCalibration::INTERPOLATED:
            dump += INDENT4 "touch.orientation.calibration: interpolated\n";
            break;
        case Calibration::OrientationCalibration::VECTOR:
            dump += INDENT4 "touch.orientation.calibration: vector\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    // Distance
    switch (mCalibration.distanceCalibration) {
        case Calibration::DistanceCalibration::NONE:
            dump += INDENT4 "touch.distance.calibration: none\n";
            break;
        case Calibration::DistanceCalibration::SCALED:
            dump += INDENT4 "touch.distance.calibration: scaled\n";
            break;
        default:
            ALOG_ASSERT(false);
    }

    if (mCalibration.haveDistanceScale) {
        dump += StringPrintf(INDENT4 "touch.distance.scale: %0.3f\n", mCalibration.distanceScale);
    }

    switch (mCalibration.coverageCalibration) {
        case Calibration::CoverageCalibration::NONE:
            dump += INDENT4 "touch.coverage.calibration: none\n";
            break;
        case Calibration::CoverageCalibration::BOX:
            dump += INDENT4 "touch.coverage.calibration: box\n";
            break;
        default:
            ALOG_ASSERT(false);
    }
}

void TouchInputMapper::dumpAffineTransformation(std::string& dump) {
    dump += INDENT3 "Affine Transformation:\n";

    dump += StringPrintf(INDENT4 "X scale: %0.3f\n", mAffineTransform.x_scale);
    dump += StringPrintf(INDENT4 "X ymix: %0.3f\n", mAffineTransform.x_ymix);
    dump += StringPrintf(INDENT4 "X offset: %0.3f\n", mAffineTransform.x_offset);
    dump += StringPrintf(INDENT4 "Y xmix: %0.3f\n", mAffineTransform.y_xmix);
    dump += StringPrintf(INDENT4 "Y scale: %0.3f\n", mAffineTransform.y_scale);
    dump += StringPrintf(INDENT4 "Y offset: %0.3f\n", mAffineTransform.y_offset);
}

void TouchInputMapper::updateAffineTransformation() {
    mAffineTransform = getPolicy()->getTouchAffineTransformation(getDeviceContext().getDescriptor(),
                                                                 mSurfaceOrientation);
}

void TouchInputMapper::reset(nsecs_t when) {
    mCursorButtonAccumulator.reset(getDeviceContext());
    mCursorScrollAccumulator.reset(getDeviceContext());
    mTouchButtonAccumulator.reset(getDeviceContext());

    mPointerVelocityControl.reset();
    mWheelXVelocityControl.reset();
    mWheelYVelocityControl.reset();

    mRawStatesPending.clear();
    mCurrentRawState.clear();
    mCurrentCookedState.clear();
    mLastRawState.clear();
    mLastCookedState.clear();
    mPointerUsage = PointerUsage::NONE;
    mSentHoverEnter = false;
    mHavePointerIds = false;
    mCurrentMotionAborted = false;
    mDownTime = 0;

    mCurrentVirtualKey.down = false;

    mPointerGesture.reset();
    mPointerSimple.reset();
    resetExternalStylus();

    if (mPointerController != nullptr) {
        mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
        mPointerController->clearSpots();
    }

    InputMapper::reset(when);
}

void TouchInputMapper::resetExternalStylus() {
    mExternalStylusState.clear();
    mExternalStylusId = -1;
    mExternalStylusFusionTimeout = LLONG_MAX;
    mExternalStylusDataPending = false;
}

void TouchInputMapper::clearStylusDataPendingFlags() {
    mExternalStylusDataPending = false;
    mExternalStylusFusionTimeout = LLONG_MAX;
}

void TouchInputMapper::process(const RawEvent* rawEvent) {
    mCursorButtonAccumulator.process(rawEvent);
    mCursorScrollAccumulator.process(rawEvent);
    mTouchButtonAccumulator.process(rawEvent);

    if (rawEvent->type == EV_SYN && rawEvent->code == SYN_REPORT) {
        sync(rawEvent->when);
    }
}

void TouchInputMapper::sync(nsecs_t when) {
    const RawState* last =
            mRawStatesPending.empty() ? &mCurrentRawState : &mRawStatesPending.back();

    // Push a new state.
    mRawStatesPending.emplace_back();

    RawState* next = &mRawStatesPending.back();
    next->clear();
    next->when = when;

    // Sync button state.
    next->buttonState =
            mTouchButtonAccumulator.getButtonState() | mCursorButtonAccumulator.getButtonState();

    // Sync scroll
    next->rawVScroll = mCursorScrollAccumulator.getRelativeVWheel();
    next->rawHScroll = mCursorScrollAccumulator.getRelativeHWheel();
    mCursorScrollAccumulator.finishSync();

    // Sync touch
    syncTouch(when, next);

    // Assign pointer ids.
    if (!mHavePointerIds) {
        assignPointerIds(last, next);
    }

#if DEBUG_RAW_EVENTS
    ALOGD("syncTouch: pointerCount %d -> %d, touching ids 0x%08x -> 0x%08x, "
          "hovering ids 0x%08x -> 0x%08x, canceled ids 0x%08x",
          last->rawPointerData.pointerCount, next->rawPointerData.pointerCount,
          last->rawPointerData.touchingIdBits.value, next->rawPointerData.touchingIdBits.value,
          last->rawPointerData.hoveringIdBits.value, next->rawPointerData.hoveringIdBits.value,
          next->rawPointerData.canceledIdBits.value);
#endif

    processRawTouches(false /*timeout*/);
}

void TouchInputMapper::processRawTouches(bool timeout) {
    if (mDeviceMode == DeviceMode::DISABLED) {
        // Drop all input if the device is disabled.
        mCurrentRawState.clear();
        mRawStatesPending.clear();
        return;
    }

    // Drain any pending touch states. The invariant here is that the mCurrentRawState is always
    // valid and must go through the full cook and dispatch cycle. This ensures that anything
    // touching the current state will only observe the events that have been dispatched to the
    // rest of the pipeline.
    const size_t N = mRawStatesPending.size();
    size_t count;
    for (count = 0; count < N; count++) {
        const RawState& next = mRawStatesPending[count];

        // A failure to assign the stylus id means that we're waiting on stylus data
        // and so should defer the rest of the pipeline.
        if (assignExternalStylusId(next, timeout)) {
            break;
        }

        // All ready to go.
        clearStylusDataPendingFlags();
        mCurrentRawState.copyFrom(next);
        if (mCurrentRawState.when < mLastRawState.when) {
            mCurrentRawState.when = mLastRawState.when;
        }
        cookAndDispatch(mCurrentRawState.when);
    }
    if (count != 0) {
        mRawStatesPending.erase(mRawStatesPending.begin(), mRawStatesPending.begin() + count);
    }

    if (mExternalStylusDataPending) {
        if (timeout) {
            nsecs_t when = mExternalStylusFusionTimeout - STYLUS_DATA_LATENCY;
            clearStylusDataPendingFlags();
            mCurrentRawState.copyFrom(mLastRawState);
#if DEBUG_STYLUS_FUSION
            ALOGD("Timeout expired, synthesizing event with new stylus data");
#endif
            cookAndDispatch(when);
        } else if (mExternalStylusFusionTimeout == LLONG_MAX) {
            mExternalStylusFusionTimeout = mExternalStylusState.when + TOUCH_DATA_TIMEOUT;
            getContext()->requestTimeoutAtTime(mExternalStylusFusionTimeout);
        }
    }
}

void TouchInputMapper::cookAndDispatch(nsecs_t when) {
    // Always start with a clean state.
    mCurrentCookedState.clear();

    // Apply stylus buttons to current raw state.
    applyExternalStylusButtonState(when);

    // Handle policy on initial down or hover events.
    bool initialDown = mLastRawState.rawPointerData.pointerCount == 0 &&
            mCurrentRawState.rawPointerData.pointerCount != 0;

    uint32_t policyFlags = 0;
    bool buttonsPressed = mCurrentRawState.buttonState & ~mLastRawState.buttonState;
    if (initialDown || buttonsPressed) {
        // If this is a touch screen, hide the pointer on an initial down.
        if (mDeviceMode == DeviceMode::DIRECT) {
            getContext()->fadePointer();
        }

        if (mParameters.wake) {
            policyFlags |= POLICY_FLAG_WAKE;
        }
    }

    // Consume raw off-screen touches before cooking pointer data.
    // If touches are consumed, subsequent code will not receive any pointer data.
    if (consumeRawTouches(when, policyFlags)) {
        mCurrentRawState.rawPointerData.clear();
    }

    // Cook pointer data.  This call populates the mCurrentCookedState.cookedPointerData structure
    // with cooked pointer data that has the same ids and indices as the raw data.
    // The following code can use either the raw or cooked data, as needed.
    cookPointerData();

    // Apply stylus pressure to current cooked state.
    applyExternalStylusTouchState(when);

    // Synthesize key down from raw buttons if needed.
    synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_DOWN, when, getDeviceId(), mSource,
                         mViewport.displayId, policyFlags, mLastCookedState.buttonState,
                         mCurrentCookedState.buttonState);

    // Dispatch the touches either directly or by translation through a pointer on screen.
    if (mDeviceMode == DeviceMode::POINTER) {
        for (BitSet32 idBits(mCurrentRawState.rawPointerData.touchingIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(id);
            if (pointer.toolType == AMOTION_EVENT_TOOL_TYPE_STYLUS ||
                pointer.toolType == AMOTION_EVENT_TOOL_TYPE_ERASER) {
                mCurrentCookedState.stylusIdBits.markBit(id);
            } else if (pointer.toolType == AMOTION_EVENT_TOOL_TYPE_FINGER ||
                       pointer.toolType == AMOTION_EVENT_TOOL_TYPE_UNKNOWN) {
                mCurrentCookedState.fingerIdBits.markBit(id);
            } else if (pointer.toolType == AMOTION_EVENT_TOOL_TYPE_MOUSE) {
                mCurrentCookedState.mouseIdBits.markBit(id);
            }
        }
        for (BitSet32 idBits(mCurrentRawState.rawPointerData.hoveringIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(id);
            if (pointer.toolType == AMOTION_EVENT_TOOL_TYPE_STYLUS ||
                pointer.toolType == AMOTION_EVENT_TOOL_TYPE_ERASER) {
                mCurrentCookedState.stylusIdBits.markBit(id);
            }
        }

        // Stylus takes precedence over all tools, then mouse, then finger.
        PointerUsage pointerUsage = mPointerUsage;
        if (!mCurrentCookedState.stylusIdBits.isEmpty()) {
            mCurrentCookedState.mouseIdBits.clear();
            mCurrentCookedState.fingerIdBits.clear();
            pointerUsage = PointerUsage::STYLUS;
        } else if (!mCurrentCookedState.mouseIdBits.isEmpty()) {
            mCurrentCookedState.fingerIdBits.clear();
            pointerUsage = PointerUsage::MOUSE;
        } else if (!mCurrentCookedState.fingerIdBits.isEmpty() ||
                   isPointerDown(mCurrentRawState.buttonState)) {
            pointerUsage = PointerUsage::GESTURES;
        }

        dispatchPointerUsage(when, policyFlags, pointerUsage);
    } else {
        if (mDeviceMode == DeviceMode::DIRECT && mConfig.showTouches &&
            mPointerController != nullptr) {
            mPointerController->setPresentation(PointerControllerInterface::Presentation::SPOT);
            mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);

            mPointerController->setButtonState(mCurrentRawState.buttonState);
            mPointerController->setSpots(mCurrentCookedState.cookedPointerData.pointerCoords,
                                         mCurrentCookedState.cookedPointerData.idToIndex,
                                         mCurrentCookedState.cookedPointerData.touchingIdBits,
                                         mViewport.displayId);
        }

        if (!mCurrentMotionAborted) {
            dispatchButtonRelease(when, policyFlags);
            dispatchHoverExit(when, policyFlags);
            dispatchTouches(when, policyFlags);
            dispatchHoverEnterAndMove(when, policyFlags);
            dispatchButtonPress(when, policyFlags);
        }

        if (mCurrentCookedState.cookedPointerData.pointerCount == 0) {
            mCurrentMotionAborted = false;
        }
    }

    // Synthesize key up from raw buttons if needed.
    synthesizeButtonKeys(getContext(), AKEY_EVENT_ACTION_UP, when, getDeviceId(), mSource,
                         mViewport.displayId, policyFlags, mLastCookedState.buttonState,
                         mCurrentCookedState.buttonState);

    // Clear some transient state.
    mCurrentRawState.rawVScroll = 0;
    mCurrentRawState.rawHScroll = 0;

    // Copy current touch to last touch in preparation for the next cycle.
    mLastRawState.copyFrom(mCurrentRawState);
    mLastCookedState.copyFrom(mCurrentCookedState);
}

void TouchInputMapper::applyExternalStylusButtonState(nsecs_t when) {
    if (mDeviceMode == DeviceMode::DIRECT && hasExternalStylus() && mExternalStylusId != -1) {
        mCurrentRawState.buttonState |= mExternalStylusState.buttons;
    }
}

void TouchInputMapper::applyExternalStylusTouchState(nsecs_t when) {
    CookedPointerData& currentPointerData = mCurrentCookedState.cookedPointerData;
    const CookedPointerData& lastPointerData = mLastCookedState.cookedPointerData;

    if (mExternalStylusId != -1 && currentPointerData.isTouching(mExternalStylusId)) {
        float pressure = mExternalStylusState.pressure;
        if (pressure == 0.0f && lastPointerData.isTouching(mExternalStylusId)) {
            const PointerCoords& coords = lastPointerData.pointerCoordsForId(mExternalStylusId);
            pressure = coords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE);
        }
        PointerCoords& coords = currentPointerData.editPointerCoordsWithId(mExternalStylusId);
        coords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, pressure);

        PointerProperties& properties =
                currentPointerData.editPointerPropertiesWithId(mExternalStylusId);
        if (mExternalStylusState.toolType != AMOTION_EVENT_TOOL_TYPE_UNKNOWN) {
            properties.toolType = mExternalStylusState.toolType;
        }
    }
}

bool TouchInputMapper::assignExternalStylusId(const RawState& state, bool timeout) {
    if (mDeviceMode != DeviceMode::DIRECT || !hasExternalStylus()) {
        return false;
    }

    const bool initialDown = mLastRawState.rawPointerData.pointerCount == 0 &&
            state.rawPointerData.pointerCount != 0;
    if (initialDown) {
        if (mExternalStylusState.pressure != 0.0f) {
#if DEBUG_STYLUS_FUSION
            ALOGD("Have both stylus and touch data, beginning fusion");
#endif
            mExternalStylusId = state.rawPointerData.touchingIdBits.firstMarkedBit();
        } else if (timeout) {
#if DEBUG_STYLUS_FUSION
            ALOGD("Timeout expired, assuming touch is not a stylus.");
#endif
            resetExternalStylus();
        } else {
            if (mExternalStylusFusionTimeout == LLONG_MAX) {
                mExternalStylusFusionTimeout = state.when + EXTERNAL_STYLUS_DATA_TIMEOUT;
            }
#if DEBUG_STYLUS_FUSION
            ALOGD("No stylus data but stylus is connected, requesting timeout "
                  "(%" PRId64 "ms)",
                  mExternalStylusFusionTimeout);
#endif
            getContext()->requestTimeoutAtTime(mExternalStylusFusionTimeout);
            return true;
        }
    }

    // Check if the stylus pointer has gone up.
    if (mExternalStylusId != -1 && !state.rawPointerData.touchingIdBits.hasBit(mExternalStylusId)) {
#if DEBUG_STYLUS_FUSION
        ALOGD("Stylus pointer is going up");
#endif
        mExternalStylusId = -1;
    }

    return false;
}

void TouchInputMapper::timeoutExpired(nsecs_t when) {
    if (mDeviceMode == DeviceMode::POINTER) {
        if (mPointerUsage == PointerUsage::GESTURES) {
            dispatchPointerGestures(when, 0 /*policyFlags*/, true /*isTimeout*/);
        }
    } else if (mDeviceMode == DeviceMode::DIRECT) {
        if (mExternalStylusFusionTimeout < when) {
            processRawTouches(true /*timeout*/);
        } else if (mExternalStylusFusionTimeout != LLONG_MAX) {
            getContext()->requestTimeoutAtTime(mExternalStylusFusionTimeout);
        }
    }
}

void TouchInputMapper::updateExternalStylusState(const StylusState& state) {
    mExternalStylusState.copyFrom(state);
    if (mExternalStylusId != -1 || mExternalStylusFusionTimeout != LLONG_MAX) {
        // We're either in the middle of a fused stream of data or we're waiting on data before
        // dispatching the initial down, so go ahead and dispatch now that we have fresh stylus
        // data.
        mExternalStylusDataPending = true;
        processRawTouches(false /*timeout*/);
    }
}

bool TouchInputMapper::consumeRawTouches(nsecs_t when, uint32_t policyFlags) {
    // Check for release of a virtual key.
    if (mCurrentVirtualKey.down) {
        if (mCurrentRawState.rawPointerData.touchingIdBits.isEmpty()) {
            // Pointer went up while virtual key was down.
            mCurrentVirtualKey.down = false;
            if (!mCurrentVirtualKey.ignored) {
#if DEBUG_VIRTUAL_KEYS
                ALOGD("VirtualKeys: Generating key up: keyCode=%d, scanCode=%d",
                      mCurrentVirtualKey.keyCode, mCurrentVirtualKey.scanCode);
#endif
                dispatchVirtualKey(when, policyFlags, AKEY_EVENT_ACTION_UP,
                                   AKEY_EVENT_FLAG_FROM_SYSTEM | AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY);
            }
            return true;
        }

        if (mCurrentRawState.rawPointerData.touchingIdBits.count() == 1) {
            uint32_t id = mCurrentRawState.rawPointerData.touchingIdBits.firstMarkedBit();
            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(id);
            const VirtualKey* virtualKey = findVirtualKeyHit(pointer.x, pointer.y);
            if (virtualKey && virtualKey->keyCode == mCurrentVirtualKey.keyCode) {
                // Pointer is still within the space of the virtual key.
                return true;
            }
        }

        // Pointer left virtual key area or another pointer also went down.
        // Send key cancellation but do not consume the touch yet.
        // This is useful when the user swipes through from the virtual key area
        // into the main display surface.
        mCurrentVirtualKey.down = false;
        if (!mCurrentVirtualKey.ignored) {
#if DEBUG_VIRTUAL_KEYS
            ALOGD("VirtualKeys: Canceling key: keyCode=%d, scanCode=%d", mCurrentVirtualKey.keyCode,
                  mCurrentVirtualKey.scanCode);
#endif
            dispatchVirtualKey(when, policyFlags, AKEY_EVENT_ACTION_UP,
                               AKEY_EVENT_FLAG_FROM_SYSTEM | AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY |
                                       AKEY_EVENT_FLAG_CANCELED);
        }
    }

    if (mLastRawState.rawPointerData.touchingIdBits.isEmpty() &&
        !mCurrentRawState.rawPointerData.touchingIdBits.isEmpty()) {
        // Pointer just went down.  Check for virtual key press or off-screen touches.
        uint32_t id = mCurrentRawState.rawPointerData.touchingIdBits.firstMarkedBit();
        const RawPointerData::Pointer& pointer = mCurrentRawState.rawPointerData.pointerForId(id);
        // Exclude unscaled device for inside surface checking.
        if (!isPointInsideSurface(pointer.x, pointer.y) && mDeviceMode != DeviceMode::UNSCALED) {
            // If exactly one pointer went down, check for virtual key hit.
            // Otherwise we will drop the entire stroke.
            if (mCurrentRawState.rawPointerData.touchingIdBits.count() == 1) {
                const VirtualKey* virtualKey = findVirtualKeyHit(pointer.x, pointer.y);
                if (virtualKey) {
                    mCurrentVirtualKey.down = true;
                    mCurrentVirtualKey.downTime = when;
                    mCurrentVirtualKey.keyCode = virtualKey->keyCode;
                    mCurrentVirtualKey.scanCode = virtualKey->scanCode;
                    mCurrentVirtualKey.ignored =
                            getContext()->shouldDropVirtualKey(when, virtualKey->keyCode,
                                                               virtualKey->scanCode);

                    if (!mCurrentVirtualKey.ignored) {
#if DEBUG_VIRTUAL_KEYS
                        ALOGD("VirtualKeys: Generating key down: keyCode=%d, scanCode=%d",
                              mCurrentVirtualKey.keyCode, mCurrentVirtualKey.scanCode);
#endif
                        dispatchVirtualKey(when, policyFlags, AKEY_EVENT_ACTION_DOWN,
                                           AKEY_EVENT_FLAG_FROM_SYSTEM |
                                                   AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY);
                    }
                }
            }
            return true;
        }
    }

    // Disable all virtual key touches that happen within a short time interval of the
    // most recent touch within the screen area.  The idea is to filter out stray
    // virtual key presses when interacting with the touch screen.
    //
    // Problems we're trying to solve:
    //
    // 1. While scrolling a list or dragging the window shade, the user swipes down into a
    //    virtual key area that is implemented by a separate touch panel and accidentally
    //    triggers a virtual key.
    //
    // 2. While typing in the on screen keyboard, the user taps slightly outside the screen
    //    area and accidentally triggers a virtual key.  This often happens when virtual keys
    //    are layed out below the screen near to where the on screen keyboard's space bar
    //    is displayed.
    if (mConfig.virtualKeyQuietTime > 0 &&
        !mCurrentRawState.rawPointerData.touchingIdBits.isEmpty()) {
        getContext()->disableVirtualKeysUntil(when + mConfig.virtualKeyQuietTime);
    }
    return false;
}

void TouchInputMapper::dispatchVirtualKey(nsecs_t when, uint32_t policyFlags,
                                          int32_t keyEventAction, int32_t keyEventFlags) {
    int32_t keyCode = mCurrentVirtualKey.keyCode;
    int32_t scanCode = mCurrentVirtualKey.scanCode;
    nsecs_t downTime = mCurrentVirtualKey.downTime;
    int32_t metaState = getContext()->getGlobalMetaState();
    policyFlags |= POLICY_FLAG_VIRTUAL;

    NotifyKeyArgs args(getContext()->getNextId(), when, getDeviceId(), AINPUT_SOURCE_KEYBOARD,
                       mViewport.displayId, policyFlags, keyEventAction, keyEventFlags, keyCode,
                       scanCode, metaState, downTime);
    getListener()->notifyKey(&args);
}

void TouchInputMapper::abortTouches(nsecs_t when, uint32_t policyFlags) {
    BitSet32 currentIdBits = mCurrentCookedState.cookedPointerData.touchingIdBits;
    if (!currentIdBits.isEmpty()) {
        int32_t metaState = getContext()->getGlobalMetaState();
        int32_t buttonState = mCurrentCookedState.buttonState;
        dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_CANCEL, 0, 0, metaState,
                       buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                       mCurrentCookedState.cookedPointerData.pointerProperties,
                       mCurrentCookedState.cookedPointerData.pointerCoords,
                       mCurrentCookedState.cookedPointerData.idToIndex, currentIdBits, -1,
                       mOrientedXPrecision, mOrientedYPrecision, mDownTime);
        mCurrentMotionAborted = true;
    }
}

void TouchInputMapper::dispatchTouches(nsecs_t when, uint32_t policyFlags) {
    BitSet32 currentIdBits = mCurrentCookedState.cookedPointerData.touchingIdBits;
    BitSet32 lastIdBits = mLastCookedState.cookedPointerData.touchingIdBits;
    int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mCurrentCookedState.buttonState;

    if (currentIdBits == lastIdBits) {
        if (!currentIdBits.isEmpty()) {
            // No pointer id changes so this is a move event.
            // The listener takes care of batching moves so we don't have to deal with that here.
            dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_MOVE, 0, 0, metaState,
                           buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                           mCurrentCookedState.cookedPointerData.pointerProperties,
                           mCurrentCookedState.cookedPointerData.pointerCoords,
                           mCurrentCookedState.cookedPointerData.idToIndex, currentIdBits, -1,
                           mOrientedXPrecision, mOrientedYPrecision, mDownTime);
        }
    } else {
        // There may be pointers going up and pointers going down and pointers moving
        // all at the same time.
        BitSet32 upIdBits(lastIdBits.value & ~currentIdBits.value);
        BitSet32 downIdBits(currentIdBits.value & ~lastIdBits.value);
        BitSet32 moveIdBits(lastIdBits.value & currentIdBits.value);
        BitSet32 dispatchedIdBits(lastIdBits.value);

        // Update last coordinates of pointers that have moved so that we observe the new
        // pointer positions at the same time as other pointers that have just gone up.
        bool moveNeeded =
                updateMovedPointers(mCurrentCookedState.cookedPointerData.pointerProperties,
                                    mCurrentCookedState.cookedPointerData.pointerCoords,
                                    mCurrentCookedState.cookedPointerData.idToIndex,
                                    mLastCookedState.cookedPointerData.pointerProperties,
                                    mLastCookedState.cookedPointerData.pointerCoords,
                                    mLastCookedState.cookedPointerData.idToIndex, moveIdBits);
        if (buttonState != mLastCookedState.buttonState) {
            moveNeeded = true;
        }

        // Dispatch pointer up events.
        while (!upIdBits.isEmpty()) {
            uint32_t upId = upIdBits.clearFirstMarkedBit();
            bool isCanceled = mCurrentCookedState.cookedPointerData.canceledIdBits.hasBit(upId);
            dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_POINTER_UP, 0,
                           isCanceled ? AMOTION_EVENT_FLAG_CANCELED : 0, metaState, buttonState, 0,
                           mLastCookedState.cookedPointerData.pointerProperties,
                           mLastCookedState.cookedPointerData.pointerCoords,
                           mLastCookedState.cookedPointerData.idToIndex, dispatchedIdBits, upId,
                           mOrientedXPrecision, mOrientedYPrecision, mDownTime);
            dispatchedIdBits.clearBit(upId);
            mCurrentCookedState.cookedPointerData.canceledIdBits.clearBit(upId);
        }

        // Dispatch move events if any of the remaining pointers moved from their old locations.
        // Although applications receive new locations as part of individual pointer up
        // events, they do not generally handle them except when presented in a move event.
        if (moveNeeded && !moveIdBits.isEmpty()) {
            ALOG_ASSERT(moveIdBits.value == dispatchedIdBits.value);
            dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_MOVE, 0, 0, metaState,
                           buttonState, 0, mCurrentCookedState.cookedPointerData.pointerProperties,
                           mCurrentCookedState.cookedPointerData.pointerCoords,
                           mCurrentCookedState.cookedPointerData.idToIndex, dispatchedIdBits, -1,
                           mOrientedXPrecision, mOrientedYPrecision, mDownTime);
        }

        // Dispatch pointer down events using the new pointer locations.
        while (!downIdBits.isEmpty()) {
            uint32_t downId = downIdBits.clearFirstMarkedBit();
            dispatchedIdBits.markBit(downId);

            if (dispatchedIdBits.count() == 1) {
                // First pointer is going down.  Set down time.
                mDownTime = when;
            }

            dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_POINTER_DOWN, 0, 0,
                           metaState, buttonState, 0,
                           mCurrentCookedState.cookedPointerData.pointerProperties,
                           mCurrentCookedState.cookedPointerData.pointerCoords,
                           mCurrentCookedState.cookedPointerData.idToIndex, dispatchedIdBits,
                           downId, mOrientedXPrecision, mOrientedYPrecision, mDownTime);
        }
    }
}

void TouchInputMapper::dispatchHoverExit(nsecs_t when, uint32_t policyFlags) {
    if (mSentHoverEnter &&
        (mCurrentCookedState.cookedPointerData.hoveringIdBits.isEmpty() ||
         !mCurrentCookedState.cookedPointerData.touchingIdBits.isEmpty())) {
        int32_t metaState = getContext()->getGlobalMetaState();
        dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_HOVER_EXIT, 0, 0, metaState,
                       mLastCookedState.buttonState, 0,
                       mLastCookedState.cookedPointerData.pointerProperties,
                       mLastCookedState.cookedPointerData.pointerCoords,
                       mLastCookedState.cookedPointerData.idToIndex,
                       mLastCookedState.cookedPointerData.hoveringIdBits, -1, mOrientedXPrecision,
                       mOrientedYPrecision, mDownTime);
        mSentHoverEnter = false;
    }
}

void TouchInputMapper::dispatchHoverEnterAndMove(nsecs_t when, uint32_t policyFlags) {
    if (mCurrentCookedState.cookedPointerData.touchingIdBits.isEmpty() &&
        !mCurrentCookedState.cookedPointerData.hoveringIdBits.isEmpty()) {
        int32_t metaState = getContext()->getGlobalMetaState();
        if (!mSentHoverEnter) {
            dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_HOVER_ENTER, 0, 0,
                           metaState, mCurrentRawState.buttonState, 0,
                           mCurrentCookedState.cookedPointerData.pointerProperties,
                           mCurrentCookedState.cookedPointerData.pointerCoords,
                           mCurrentCookedState.cookedPointerData.idToIndex,
                           mCurrentCookedState.cookedPointerData.hoveringIdBits, -1,
                           mOrientedXPrecision, mOrientedYPrecision, mDownTime);
            mSentHoverEnter = true;
        }

        dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_HOVER_MOVE, 0, 0, metaState,
                       mCurrentRawState.buttonState, 0,
                       mCurrentCookedState.cookedPointerData.pointerProperties,
                       mCurrentCookedState.cookedPointerData.pointerCoords,
                       mCurrentCookedState.cookedPointerData.idToIndex,
                       mCurrentCookedState.cookedPointerData.hoveringIdBits, -1,
                       mOrientedXPrecision, mOrientedYPrecision, mDownTime);
    }
}

void TouchInputMapper::dispatchButtonRelease(nsecs_t when, uint32_t policyFlags) {
    BitSet32 releasedButtons(mLastCookedState.buttonState & ~mCurrentCookedState.buttonState);
    const BitSet32& idBits = findActiveIdBits(mLastCookedState.cookedPointerData);
    const int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mLastCookedState.buttonState;
    while (!releasedButtons.isEmpty()) {
        int32_t actionButton = BitSet32::valueForBit(releasedButtons.clearFirstMarkedBit());
        buttonState &= ~actionButton;
        dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_BUTTON_RELEASE,
                       actionButton, 0, metaState, buttonState, 0,
                       mCurrentCookedState.cookedPointerData.pointerProperties,
                       mCurrentCookedState.cookedPointerData.pointerCoords,
                       mCurrentCookedState.cookedPointerData.idToIndex, idBits, -1,
                       mOrientedXPrecision, mOrientedYPrecision, mDownTime);
    }
}

void TouchInputMapper::dispatchButtonPress(nsecs_t when, uint32_t policyFlags) {
    BitSet32 pressedButtons(mCurrentCookedState.buttonState & ~mLastCookedState.buttonState);
    const BitSet32& idBits = findActiveIdBits(mCurrentCookedState.cookedPointerData);
    const int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mLastCookedState.buttonState;
    while (!pressedButtons.isEmpty()) {
        int32_t actionButton = BitSet32::valueForBit(pressedButtons.clearFirstMarkedBit());
        buttonState |= actionButton;
        dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_BUTTON_PRESS, actionButton,
                       0, metaState, buttonState, 0,
                       mCurrentCookedState.cookedPointerData.pointerProperties,
                       mCurrentCookedState.cookedPointerData.pointerCoords,
                       mCurrentCookedState.cookedPointerData.idToIndex, idBits, -1,
                       mOrientedXPrecision, mOrientedYPrecision, mDownTime);
    }
}

const BitSet32& TouchInputMapper::findActiveIdBits(const CookedPointerData& cookedPointerData) {
    if (!cookedPointerData.touchingIdBits.isEmpty()) {
        return cookedPointerData.touchingIdBits;
    }
    return cookedPointerData.hoveringIdBits;
}

void TouchInputMapper::cookPointerData() {
    uint32_t currentPointerCount = mCurrentRawState.rawPointerData.pointerCount;

    mCurrentCookedState.cookedPointerData.clear();
    mCurrentCookedState.cookedPointerData.pointerCount = currentPointerCount;
    mCurrentCookedState.cookedPointerData.hoveringIdBits =
            mCurrentRawState.rawPointerData.hoveringIdBits;
    mCurrentCookedState.cookedPointerData.touchingIdBits =
            mCurrentRawState.rawPointerData.touchingIdBits;
    mCurrentCookedState.cookedPointerData.canceledIdBits =
            mCurrentRawState.rawPointerData.canceledIdBits;

    if (mCurrentCookedState.cookedPointerData.pointerCount == 0) {
        mCurrentCookedState.buttonState = 0;
    } else {
        mCurrentCookedState.buttonState = mCurrentRawState.buttonState;
    }

    // Walk through the the active pointers and map device coordinates onto
    // surface coordinates and adjust for display orientation.
    for (uint32_t i = 0; i < currentPointerCount; i++) {
        const RawPointerData::Pointer& in = mCurrentRawState.rawPointerData.pointers[i];

        // Size
        float touchMajor, touchMinor, toolMajor, toolMinor, size;
        switch (mCalibration.sizeCalibration) {
            case Calibration::SizeCalibration::GEOMETRIC:
            case Calibration::SizeCalibration::DIAMETER:
            case Calibration::SizeCalibration::BOX:
            case Calibration::SizeCalibration::AREA:
                if (mRawPointerAxes.touchMajor.valid && mRawPointerAxes.toolMajor.valid) {
                    touchMajor = in.touchMajor;
                    touchMinor = mRawPointerAxes.touchMinor.valid ? in.touchMinor : in.touchMajor;
                    toolMajor = in.toolMajor;
                    toolMinor = mRawPointerAxes.toolMinor.valid ? in.toolMinor : in.toolMajor;
                    size = mRawPointerAxes.touchMinor.valid ? avg(in.touchMajor, in.touchMinor)
                                                            : in.touchMajor;
                } else if (mRawPointerAxes.touchMajor.valid) {
                    toolMajor = touchMajor = in.touchMajor;
                    toolMinor = touchMinor =
                            mRawPointerAxes.touchMinor.valid ? in.touchMinor : in.touchMajor;
                    size = mRawPointerAxes.touchMinor.valid ? avg(in.touchMajor, in.touchMinor)
                                                            : in.touchMajor;
                } else if (mRawPointerAxes.toolMajor.valid) {
                    touchMajor = toolMajor = in.toolMajor;
                    touchMinor = toolMinor =
                            mRawPointerAxes.toolMinor.valid ? in.toolMinor : in.toolMajor;
                    size = mRawPointerAxes.toolMinor.valid ? avg(in.toolMajor, in.toolMinor)
                                                           : in.toolMajor;
                } else {
                    ALOG_ASSERT(false,
                                "No touch or tool axes.  "
                                "Size calibration should have been resolved to NONE.");
                    touchMajor = 0;
                    touchMinor = 0;
                    toolMajor = 0;
                    toolMinor = 0;
                    size = 0;
                }

                if (mCalibration.haveSizeIsSummed && mCalibration.sizeIsSummed) {
                    uint32_t touchingCount = mCurrentRawState.rawPointerData.touchingIdBits.count();
                    if (touchingCount > 1) {
                        touchMajor /= touchingCount;
                        touchMinor /= touchingCount;
                        toolMajor /= touchingCount;
                        toolMinor /= touchingCount;
                        size /= touchingCount;
                    }
                }

                if (mCalibration.sizeCalibration == Calibration::SizeCalibration::GEOMETRIC) {
                    touchMajor *= mGeometricScale;
                    touchMinor *= mGeometricScale;
                    toolMajor *= mGeometricScale;
                    toolMinor *= mGeometricScale;
                } else if (mCalibration.sizeCalibration == Calibration::SizeCalibration::AREA) {
                    touchMajor = touchMajor > 0 ? sqrtf(touchMajor) : 0;
                    touchMinor = touchMajor;
                    toolMajor = toolMajor > 0 ? sqrtf(toolMajor) : 0;
                    toolMinor = toolMajor;
                } else if (mCalibration.sizeCalibration == Calibration::SizeCalibration::DIAMETER) {
                    touchMinor = touchMajor;
                    toolMinor = toolMajor;
                }

                mCalibration.applySizeScaleAndBias(&touchMajor);
                mCalibration.applySizeScaleAndBias(&touchMinor);
                mCalibration.applySizeScaleAndBias(&toolMajor);
                mCalibration.applySizeScaleAndBias(&toolMinor);
                size *= mSizeScale;
                break;
            default:
                touchMajor = 0;
                touchMinor = 0;
                toolMajor = 0;
                toolMinor = 0;
                size = 0;
                break;
        }

        // Pressure
        float pressure;
        switch (mCalibration.pressureCalibration) {
            case Calibration::PressureCalibration::PHYSICAL:
            case Calibration::PressureCalibration::AMPLITUDE:
                pressure = in.pressure * mPressureScale;
                break;
            default:
                pressure = in.isHovering ? 0 : 1;
                break;
        }

        // Tilt and Orientation
        float tilt;
        float orientation;
        if (mHaveTilt) {
            float tiltXAngle = (in.tiltX - mTiltXCenter) * mTiltXScale;
            float tiltYAngle = (in.tiltY - mTiltYCenter) * mTiltYScale;
            orientation = atan2f(-sinf(tiltXAngle), sinf(tiltYAngle));
            tilt = acosf(cosf(tiltXAngle) * cosf(tiltYAngle));
        } else {
            tilt = 0;

            switch (mCalibration.orientationCalibration) {
                case Calibration::OrientationCalibration::INTERPOLATED:
                    orientation = in.orientation * mOrientationScale;
                    break;
                case Calibration::OrientationCalibration::VECTOR: {
                    int32_t c1 = signExtendNybble((in.orientation & 0xf0) >> 4);
                    int32_t c2 = signExtendNybble(in.orientation & 0x0f);
                    if (c1 != 0 || c2 != 0) {
                        orientation = atan2f(c1, c2) * 0.5f;
                        float confidence = hypotf(c1, c2);
                        float scale = 1.0f + confidence / 16.0f;
                        touchMajor *= scale;
                        touchMinor /= scale;
                        toolMajor *= scale;
                        toolMinor /= scale;
                    } else {
                        orientation = 0;
                    }
                    break;
                }
                default:
                    orientation = 0;
            }
        }

        // Distance
        float distance;
        switch (mCalibration.distanceCalibration) {
            case Calibration::DistanceCalibration::SCALED:
                distance = in.distance * mDistanceScale;
                break;
            default:
                distance = 0;
        }

        // Coverage
        int32_t rawLeft, rawTop, rawRight, rawBottom;
        switch (mCalibration.coverageCalibration) {
            case Calibration::CoverageCalibration::BOX:
                rawLeft = (in.toolMinor & 0xffff0000) >> 16;
                rawRight = in.toolMinor & 0x0000ffff;
                rawBottom = in.toolMajor & 0x0000ffff;
                rawTop = (in.toolMajor & 0xffff0000) >> 16;
                break;
            default:
                rawLeft = rawTop = rawRight = rawBottom = 0;
                break;
        }

        // Adjust X,Y coords for device calibration
        // TODO: Adjust coverage coords?
        float xTransformed = in.x, yTransformed = in.y;
        mAffineTransform.applyTo(xTransformed, yTransformed);
        rotateAndScale(xTransformed, yTransformed);

        // Adjust X, Y, and coverage coords for surface orientation.
        float left, top, right, bottom;

        switch (mSurfaceOrientation) {
            case DISPLAY_ORIENTATION_90:
                left = float(rawTop - mRawPointerAxes.y.minValue) * mYScale + mYTranslate;
                right = float(rawBottom - mRawPointerAxes.y.minValue) * mYScale + mYTranslate;
                bottom = float(mRawPointerAxes.x.maxValue - rawLeft) * mXScale + mXTranslate;
                top = float(mRawPointerAxes.x.maxValue - rawRight) * mXScale + mXTranslate;
                orientation -= M_PI_2;
                if (mOrientedRanges.haveOrientation &&
                    orientation < mOrientedRanges.orientation.min) {
                    orientation +=
                            (mOrientedRanges.orientation.max - mOrientedRanges.orientation.min);
                }
                break;
            case DISPLAY_ORIENTATION_180:
                left = float(mRawPointerAxes.x.maxValue - rawRight) * mXScale;
                right = float(mRawPointerAxes.x.maxValue - rawLeft) * mXScale;
                bottom = float(mRawPointerAxes.y.maxValue - rawTop) * mYScale + mYTranslate;
                top = float(mRawPointerAxes.y.maxValue - rawBottom) * mYScale + mYTranslate;
                orientation -= M_PI;
                if (mOrientedRanges.haveOrientation &&
                    orientation < mOrientedRanges.orientation.min) {
                    orientation +=
                            (mOrientedRanges.orientation.max - mOrientedRanges.orientation.min);
                }
                break;
            case DISPLAY_ORIENTATION_270:
                left = float(mRawPointerAxes.y.maxValue - rawBottom) * mYScale;
                right = float(mRawPointerAxes.y.maxValue - rawTop) * mYScale;
                bottom = float(rawRight - mRawPointerAxes.x.minValue) * mXScale + mXTranslate;
                top = float(rawLeft - mRawPointerAxes.x.minValue) * mXScale + mXTranslate;
                orientation += M_PI_2;
                if (mOrientedRanges.haveOrientation &&
                    orientation > mOrientedRanges.orientation.max) {
                    orientation -=
                            (mOrientedRanges.orientation.max - mOrientedRanges.orientation.min);
                }
                break;
            default:
                left = float(rawLeft - mRawPointerAxes.x.minValue) * mXScale + mXTranslate;
                right = float(rawRight - mRawPointerAxes.x.minValue) * mXScale + mXTranslate;
                bottom = float(rawBottom - mRawPointerAxes.y.minValue) * mYScale + mYTranslate;
                top = float(rawTop - mRawPointerAxes.y.minValue) * mYScale + mYTranslate;
                break;
        }

        // Write output coords.
        PointerCoords& out = mCurrentCookedState.cookedPointerData.pointerCoords[i];
        out.clear();
        out.setAxisValue(AMOTION_EVENT_AXIS_X, xTransformed);
        out.setAxisValue(AMOTION_EVENT_AXIS_Y, yTransformed);
        out.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, pressure);
        out.setAxisValue(AMOTION_EVENT_AXIS_SIZE, size);
        out.setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR, touchMajor);
        out.setAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR, touchMinor);
        out.setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION, orientation);
        out.setAxisValue(AMOTION_EVENT_AXIS_TILT, tilt);
        out.setAxisValue(AMOTION_EVENT_AXIS_DISTANCE, distance);
        if (mCalibration.coverageCalibration == Calibration::CoverageCalibration::BOX) {
            out.setAxisValue(AMOTION_EVENT_AXIS_GENERIC_1, left);
            out.setAxisValue(AMOTION_EVENT_AXIS_GENERIC_2, top);
            out.setAxisValue(AMOTION_EVENT_AXIS_GENERIC_3, right);
            out.setAxisValue(AMOTION_EVENT_AXIS_GENERIC_4, bottom);
        } else {
            out.setAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR, toolMajor);
            out.setAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR, toolMinor);
        }

        // Write output relative fields if applicable.
        uint32_t id = in.id;
        if (mSource == AINPUT_SOURCE_TOUCHPAD &&
            mLastCookedState.cookedPointerData.hasPointerCoordsForId(id)) {
            const PointerCoords& p = mLastCookedState.cookedPointerData.pointerCoordsForId(id);
            float dx = xTransformed - p.getAxisValue(AMOTION_EVENT_AXIS_X);
            float dy = yTransformed - p.getAxisValue(AMOTION_EVENT_AXIS_Y);
            out.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, dx);
            out.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, dy);
        }

        // Write output properties.
        PointerProperties& properties = mCurrentCookedState.cookedPointerData.pointerProperties[i];
        properties.clear();
        properties.id = id;
        properties.toolType = in.toolType;

        // Write id index and mark id as valid.
        mCurrentCookedState.cookedPointerData.idToIndex[id] = i;
        mCurrentCookedState.cookedPointerData.validIdBits.markBit(id);
    }
}

void TouchInputMapper::dispatchPointerUsage(nsecs_t when, uint32_t policyFlags,
                                            PointerUsage pointerUsage) {
    if (pointerUsage != mPointerUsage) {
        abortPointerUsage(when, policyFlags);
        mPointerUsage = pointerUsage;
    }

    switch (mPointerUsage) {
        case PointerUsage::GESTURES:
            dispatchPointerGestures(when, policyFlags, false /*isTimeout*/);
            break;
        case PointerUsage::STYLUS:
            dispatchPointerStylus(when, policyFlags);
            break;
        case PointerUsage::MOUSE:
            dispatchPointerMouse(when, policyFlags);
            break;
        case PointerUsage::NONE:
            break;
    }
}

void TouchInputMapper::abortPointerUsage(nsecs_t when, uint32_t policyFlags) {
    switch (mPointerUsage) {
        case PointerUsage::GESTURES:
            abortPointerGestures(when, policyFlags);
            break;
        case PointerUsage::STYLUS:
            abortPointerStylus(when, policyFlags);
            break;
        case PointerUsage::MOUSE:
            abortPointerMouse(when, policyFlags);
            break;
        case PointerUsage::NONE:
            break;
    }

    mPointerUsage = PointerUsage::NONE;
}

void TouchInputMapper::dispatchPointerGestures(nsecs_t when, uint32_t policyFlags, bool isTimeout) {
    // Update current gesture coordinates.
    bool cancelPreviousGesture, finishPreviousGesture;
    bool sendEvents =
            preparePointerGestures(when, &cancelPreviousGesture, &finishPreviousGesture, isTimeout);
    if (!sendEvents) {
        return;
    }
    if (finishPreviousGesture) {
        cancelPreviousGesture = false;
    }

    // Update the pointer presentation and spots.
    if (mParameters.gestureMode == Parameters::GestureMode::MULTI_TOUCH) {
        mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
        if (finishPreviousGesture || cancelPreviousGesture) {
            mPointerController->clearSpots();
        }

        if (mPointerGesture.currentGestureMode == PointerGesture::Mode::FREEFORM) {
            mPointerController->setSpots(mPointerGesture.currentGestureCoords,
                                         mPointerGesture.currentGestureIdToIndex,
                                         mPointerGesture.currentGestureIdBits,
                                         mPointerController->getDisplayId());
        }
    } else {
        mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
    }

    // Show or hide the pointer if needed.
    switch (mPointerGesture.currentGestureMode) {
        case PointerGesture::Mode::NEUTRAL:
        case PointerGesture::Mode::QUIET:
            if (mParameters.gestureMode == Parameters::GestureMode::MULTI_TOUCH &&
                mPointerGesture.lastGestureMode == PointerGesture::Mode::FREEFORM) {
                // Remind the user of where the pointer is after finishing a gesture with spots.
                mPointerController->unfade(PointerControllerInterface::Transition::GRADUAL);
            }
            break;
        case PointerGesture::Mode::TAP:
        case PointerGesture::Mode::TAP_DRAG:
        case PointerGesture::Mode::BUTTON_CLICK_OR_DRAG:
        case PointerGesture::Mode::HOVER:
        case PointerGesture::Mode::PRESS:
        case PointerGesture::Mode::SWIPE:
            // Unfade the pointer when the current gesture manipulates the
            // area directly under the pointer.
            mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
            break;
        case PointerGesture::Mode::FREEFORM:
            // Fade the pointer when the current gesture manipulates a different
            // area and there are spots to guide the user experience.
            if (mParameters.gestureMode == Parameters::GestureMode::MULTI_TOUCH) {
                mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
            } else {
                mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
            }
            break;
    }

    // Send events!
    int32_t metaState = getContext()->getGlobalMetaState();
    int32_t buttonState = mCurrentCookedState.buttonState;

    // Update last coordinates of pointers that have moved so that we observe the new
    // pointer positions at the same time as other pointers that have just gone up.
    bool down = mPointerGesture.currentGestureMode == PointerGesture::Mode::TAP ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::TAP_DRAG ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::BUTTON_CLICK_OR_DRAG ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::PRESS ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::SWIPE ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::FREEFORM;
    bool moveNeeded = false;
    if (down && !cancelPreviousGesture && !finishPreviousGesture &&
        !mPointerGesture.lastGestureIdBits.isEmpty() &&
        !mPointerGesture.currentGestureIdBits.isEmpty()) {
        BitSet32 movedGestureIdBits(mPointerGesture.currentGestureIdBits.value &
                                    mPointerGesture.lastGestureIdBits.value);
        moveNeeded = updateMovedPointers(mPointerGesture.currentGestureProperties,
                                         mPointerGesture.currentGestureCoords,
                                         mPointerGesture.currentGestureIdToIndex,
                                         mPointerGesture.lastGestureProperties,
                                         mPointerGesture.lastGestureCoords,
                                         mPointerGesture.lastGestureIdToIndex, movedGestureIdBits);
        if (buttonState != mLastCookedState.buttonState) {
            moveNeeded = true;
        }
    }

    // Send motion events for all pointers that went up or were canceled.
    BitSet32 dispatchedGestureIdBits(mPointerGesture.lastGestureIdBits);
    if (!dispatchedGestureIdBits.isEmpty()) {
        if (cancelPreviousGesture) {
            dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_CANCEL, 0, 0, metaState,
                           buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                           mPointerGesture.lastGestureProperties, mPointerGesture.lastGestureCoords,
                           mPointerGesture.lastGestureIdToIndex, dispatchedGestureIdBits, -1, 0, 0,
                           mPointerGesture.downTime);

            dispatchedGestureIdBits.clear();
        } else {
            BitSet32 upGestureIdBits;
            if (finishPreviousGesture) {
                upGestureIdBits = dispatchedGestureIdBits;
            } else {
                upGestureIdBits.value =
                        dispatchedGestureIdBits.value & ~mPointerGesture.currentGestureIdBits.value;
            }
            while (!upGestureIdBits.isEmpty()) {
                uint32_t id = upGestureIdBits.clearFirstMarkedBit();

                dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_POINTER_UP, 0, 0,
                               metaState, buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                               mPointerGesture.lastGestureProperties,
                               mPointerGesture.lastGestureCoords,
                               mPointerGesture.lastGestureIdToIndex, dispatchedGestureIdBits, id, 0,
                               0, mPointerGesture.downTime);

                dispatchedGestureIdBits.clearBit(id);
            }
        }
    }

    // Send motion events for all pointers that moved.
    if (moveNeeded) {
        dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_MOVE, 0, 0, metaState,
                       buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                       mPointerGesture.currentGestureProperties,
                       mPointerGesture.currentGestureCoords,
                       mPointerGesture.currentGestureIdToIndex, dispatchedGestureIdBits, -1, 0, 0,
                       mPointerGesture.downTime);
    }

    // Send motion events for all pointers that went down.
    if (down) {
        BitSet32 downGestureIdBits(mPointerGesture.currentGestureIdBits.value &
                                   ~dispatchedGestureIdBits.value);
        while (!downGestureIdBits.isEmpty()) {
            uint32_t id = downGestureIdBits.clearFirstMarkedBit();
            dispatchedGestureIdBits.markBit(id);

            if (dispatchedGestureIdBits.count() == 1) {
                mPointerGesture.downTime = when;
            }

            dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_POINTER_DOWN, 0, 0,
                           metaState, buttonState, 0, mPointerGesture.currentGestureProperties,
                           mPointerGesture.currentGestureCoords,
                           mPointerGesture.currentGestureIdToIndex, dispatchedGestureIdBits, id, 0,
                           0, mPointerGesture.downTime);
        }
    }

    // Send motion events for hover.
    if (mPointerGesture.currentGestureMode == PointerGesture::Mode::HOVER) {
        dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_HOVER_MOVE, 0, 0, metaState,
                       buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                       mPointerGesture.currentGestureProperties,
                       mPointerGesture.currentGestureCoords,
                       mPointerGesture.currentGestureIdToIndex,
                       mPointerGesture.currentGestureIdBits, -1, 0, 0, mPointerGesture.downTime);
    } else if (dispatchedGestureIdBits.isEmpty() && !mPointerGesture.lastGestureIdBits.isEmpty()) {
        // Synthesize a hover move event after all pointers go up to indicate that
        // the pointer is hovering again even if the user is not currently touching
        // the touch pad.  This ensures that a view will receive a fresh hover enter
        // event after a tap.
        float x, y;
        mPointerController->getPosition(&x, &y);

        PointerProperties pointerProperties;
        pointerProperties.clear();
        pointerProperties.id = 0;
        pointerProperties.toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

        PointerCoords pointerCoords;
        pointerCoords.clear();
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_X, x);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, y);

        const int32_t displayId = mPointerController->getDisplayId();
        NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource, displayId,
                              policyFlags, AMOTION_EVENT_ACTION_HOVER_MOVE, 0, 0, metaState,
                              buttonState, MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE,
                              1, &pointerProperties, &pointerCoords, 0, 0, x, y,
                              mPointerGesture.downTime, /* videoFrames */ {});
        getListener()->notifyMotion(&args);
    }

    // Update state.
    mPointerGesture.lastGestureMode = mPointerGesture.currentGestureMode;
    if (!down) {
        mPointerGesture.lastGestureIdBits.clear();
    } else {
        mPointerGesture.lastGestureIdBits = mPointerGesture.currentGestureIdBits;
        for (BitSet32 idBits(mPointerGesture.currentGestureIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            uint32_t index = mPointerGesture.currentGestureIdToIndex[id];
            mPointerGesture.lastGestureProperties[index].copyFrom(
                    mPointerGesture.currentGestureProperties[index]);
            mPointerGesture.lastGestureCoords[index].copyFrom(
                    mPointerGesture.currentGestureCoords[index]);
            mPointerGesture.lastGestureIdToIndex[id] = index;
        }
    }
}

void TouchInputMapper::abortPointerGestures(nsecs_t when, uint32_t policyFlags) {
    // Cancel previously dispatches pointers.
    if (!mPointerGesture.lastGestureIdBits.isEmpty()) {
        int32_t metaState = getContext()->getGlobalMetaState();
        int32_t buttonState = mCurrentRawState.buttonState;
        dispatchMotion(when, policyFlags, mSource, AMOTION_EVENT_ACTION_CANCEL, 0, 0, metaState,
                       buttonState, AMOTION_EVENT_EDGE_FLAG_NONE,
                       mPointerGesture.lastGestureProperties, mPointerGesture.lastGestureCoords,
                       mPointerGesture.lastGestureIdToIndex, mPointerGesture.lastGestureIdBits, -1,
                       0, 0, mPointerGesture.downTime);
    }

    // Reset the current pointer gesture.
    mPointerGesture.reset();
    mPointerVelocityControl.reset();

    // Remove any current spots.
    if (mPointerController != nullptr) {
        mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
        mPointerController->clearSpots();
    }
}

bool TouchInputMapper::preparePointerGestures(nsecs_t when, bool* outCancelPreviousGesture,
                                              bool* outFinishPreviousGesture, bool isTimeout) {
    *outCancelPreviousGesture = false;
    *outFinishPreviousGesture = false;

    // Handle TAP timeout.
    if (isTimeout) {
#if DEBUG_GESTURES
        ALOGD("Gestures: Processing timeout");
#endif

        if (mPointerGesture.lastGestureMode == PointerGesture::Mode::TAP) {
            if (when <= mPointerGesture.tapUpTime + mConfig.pointerGestureTapDragInterval) {
                // The tap/drag timeout has not yet expired.
                getContext()->requestTimeoutAtTime(mPointerGesture.tapUpTime +
                                                   mConfig.pointerGestureTapDragInterval);
            } else {
                // The tap is finished.
#if DEBUG_GESTURES
                ALOGD("Gestures: TAP finished");
#endif
                *outFinishPreviousGesture = true;

                mPointerGesture.activeGestureId = -1;
                mPointerGesture.currentGestureMode = PointerGesture::Mode::NEUTRAL;
                mPointerGesture.currentGestureIdBits.clear();

                mPointerVelocityControl.reset();
                return true;
            }
        }

        // We did not handle this timeout.
        return false;
    }

    const uint32_t currentFingerCount = mCurrentCookedState.fingerIdBits.count();
    const uint32_t lastFingerCount = mLastCookedState.fingerIdBits.count();

    // Update the velocity tracker.
    {
        VelocityTracker::Position positions[MAX_POINTERS];
        uint32_t count = 0;
        for (BitSet32 idBits(mCurrentCookedState.fingerIdBits); !idBits.isEmpty(); count++) {
            uint32_t id = idBits.clearFirstMarkedBit();
            const RawPointerData::Pointer& pointer =
                    mCurrentRawState.rawPointerData.pointerForId(id);
            positions[count].x = pointer.x * mPointerXMovementScale;
            positions[count].y = pointer.y * mPointerYMovementScale;
        }
        mPointerGesture.velocityTracker.addMovement(when, mCurrentCookedState.fingerIdBits,
                                                    positions);
    }

    // If the gesture ever enters a mode other than TAP, HOVER or TAP_DRAG, without first returning
    // to NEUTRAL, then we should not generate tap event.
    if (mPointerGesture.lastGestureMode != PointerGesture::Mode::HOVER &&
        mPointerGesture.lastGestureMode != PointerGesture::Mode::TAP &&
        mPointerGesture.lastGestureMode != PointerGesture::Mode::TAP_DRAG) {
        mPointerGesture.resetTap();
    }

    // Pick a new active touch id if needed.
    // Choose an arbitrary pointer that just went down, if there is one.
    // Otherwise choose an arbitrary remaining pointer.
    // This guarantees we always have an active touch id when there is at least one pointer.
    // We keep the same active touch id for as long as possible.
    int32_t lastActiveTouchId = mPointerGesture.activeTouchId;
    int32_t activeTouchId = lastActiveTouchId;
    if (activeTouchId < 0) {
        if (!mCurrentCookedState.fingerIdBits.isEmpty()) {
            activeTouchId = mPointerGesture.activeTouchId =
                    mCurrentCookedState.fingerIdBits.firstMarkedBit();
            mPointerGesture.firstTouchTime = when;
        }
    } else if (!mCurrentCookedState.fingerIdBits.hasBit(activeTouchId)) {
        if (!mCurrentCookedState.fingerIdBits.isEmpty()) {
            activeTouchId = mPointerGesture.activeTouchId =
                    mCurrentCookedState.fingerIdBits.firstMarkedBit();
        } else {
            activeTouchId = mPointerGesture.activeTouchId = -1;
        }
    }

    // Determine whether we are in quiet time.
    bool isQuietTime = false;
    if (activeTouchId < 0) {
        mPointerGesture.resetQuietTime();
    } else {
        isQuietTime = when < mPointerGesture.quietTime + mConfig.pointerGestureQuietInterval;
        if (!isQuietTime) {
            if ((mPointerGesture.lastGestureMode == PointerGesture::Mode::PRESS ||
                 mPointerGesture.lastGestureMode == PointerGesture::Mode::SWIPE ||
                 mPointerGesture.lastGestureMode == PointerGesture::Mode::FREEFORM) &&
                currentFingerCount < 2) {
                // Enter quiet time when exiting swipe or freeform state.
                // This is to prevent accidentally entering the hover state and flinging the
                // pointer when finishing a swipe and there is still one pointer left onscreen.
                isQuietTime = true;
            } else if (mPointerGesture.lastGestureMode ==
                               PointerGesture::Mode::BUTTON_CLICK_OR_DRAG &&
                       currentFingerCount >= 2 && !isPointerDown(mCurrentRawState.buttonState)) {
                // Enter quiet time when releasing the button and there are still two or more
                // fingers down.  This may indicate that one finger was used to press the button
                // but it has not gone up yet.
                isQuietTime = true;
            }
            if (isQuietTime) {
                mPointerGesture.quietTime = when;
            }
        }
    }

    // Switch states based on button and pointer state.
    if (isQuietTime) {
        // Case 1: Quiet time. (QUIET)
#if DEBUG_GESTURES
        ALOGD("Gestures: QUIET for next %0.3fms",
              (mPointerGesture.quietTime + mConfig.pointerGestureQuietInterval - when) * 0.000001f);
#endif
        if (mPointerGesture.lastGestureMode != PointerGesture::Mode::QUIET) {
            *outFinishPreviousGesture = true;
        }

        mPointerGesture.activeGestureId = -1;
        mPointerGesture.currentGestureMode = PointerGesture::Mode::QUIET;
        mPointerGesture.currentGestureIdBits.clear();

        mPointerVelocityControl.reset();
    } else if (isPointerDown(mCurrentRawState.buttonState)) {
        // Case 2: Button is pressed. (BUTTON_CLICK_OR_DRAG)
        // The pointer follows the active touch point.
        // Emit DOWN, MOVE, UP events at the pointer location.
        //
        // Only the active touch matters; other fingers are ignored.  This policy helps
        // to handle the case where the user places a second finger on the touch pad
        // to apply the necessary force to depress an integrated button below the surface.
        // We don't want the second finger to be delivered to applications.
        //
        // For this to work well, we need to make sure to track the pointer that is really
        // active.  If the user first puts one finger down to click then adds another
        // finger to drag then the active pointer should switch to the finger that is
        // being dragged.
#if DEBUG_GESTURES
        ALOGD("Gestures: BUTTON_CLICK_OR_DRAG activeTouchId=%d, "
              "currentFingerCount=%d",
              activeTouchId, currentFingerCount);
#endif
        // Reset state when just starting.
        if (mPointerGesture.lastGestureMode != PointerGesture::Mode::BUTTON_CLICK_OR_DRAG) {
            *outFinishPreviousGesture = true;
            mPointerGesture.activeGestureId = 0;
        }

        // Switch pointers if needed.
        // Find the fastest pointer and follow it.
        if (activeTouchId >= 0 && currentFingerCount > 1) {
            int32_t bestId = -1;
            float bestSpeed = mConfig.pointerGestureDragMinSwitchSpeed;
            for (BitSet32 idBits(mCurrentCookedState.fingerIdBits); !idBits.isEmpty();) {
                uint32_t id = idBits.clearFirstMarkedBit();
                float vx, vy;
                if (mPointerGesture.velocityTracker.getVelocity(id, &vx, &vy)) {
                    float speed = hypotf(vx, vy);
                    if (speed > bestSpeed) {
                        bestId = id;
                        bestSpeed = speed;
                    }
                }
            }
            if (bestId >= 0 && bestId != activeTouchId) {
                mPointerGesture.activeTouchId = activeTouchId = bestId;
#if DEBUG_GESTURES
                ALOGD("Gestures: BUTTON_CLICK_OR_DRAG switched pointers, "
                      "bestId=%d, bestSpeed=%0.3f",
                      bestId, bestSpeed);
#endif
            }
        }

        float deltaX = 0, deltaY = 0;
        if (activeTouchId >= 0 && mLastCookedState.fingerIdBits.hasBit(activeTouchId)) {
            const RawPointerData::Pointer& currentPointer =
                    mCurrentRawState.rawPointerData.pointerForId(activeTouchId);
            const RawPointerData::Pointer& lastPointer =
                    mLastRawState.rawPointerData.pointerForId(activeTouchId);
            deltaX = (currentPointer.x - lastPointer.x) * mPointerXMovementScale;
            deltaY = (currentPointer.y - lastPointer.y) * mPointerYMovementScale;

            rotateDelta(mSurfaceOrientation, &deltaX, &deltaY);
            mPointerVelocityControl.move(when, &deltaX, &deltaY);

            // Move the pointer using a relative motion.
            // When using spots, the click will occur at the position of the anchor
            // spot and all other spots will move there.
            mPointerController->move(deltaX, deltaY);
        } else {
            mPointerVelocityControl.reset();
        }

        float x, y;
        mPointerController->getPosition(&x, &y);

        mPointerGesture.currentGestureMode = PointerGesture::Mode::BUTTON_CLICK_OR_DRAG;
        mPointerGesture.currentGestureIdBits.clear();
        mPointerGesture.currentGestureIdBits.markBit(mPointerGesture.activeGestureId);
        mPointerGesture.currentGestureIdToIndex[mPointerGesture.activeGestureId] = 0;
        mPointerGesture.currentGestureProperties[0].clear();
        mPointerGesture.currentGestureProperties[0].id = mPointerGesture.activeGestureId;
        mPointerGesture.currentGestureProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
        mPointerGesture.currentGestureCoords[0].clear();
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, x);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
    } else if (currentFingerCount == 0) {
        // Case 3. No fingers down and button is not pressed. (NEUTRAL)
        if (mPointerGesture.lastGestureMode != PointerGesture::Mode::NEUTRAL) {
            *outFinishPreviousGesture = true;
        }

        // Watch for taps coming out of HOVER or TAP_DRAG mode.
        // Checking for taps after TAP_DRAG allows us to detect double-taps.
        bool tapped = false;
        if ((mPointerGesture.lastGestureMode == PointerGesture::Mode::HOVER ||
             mPointerGesture.lastGestureMode == PointerGesture::Mode::TAP_DRAG) &&
            lastFingerCount == 1) {
            if (when <= mPointerGesture.tapDownTime + mConfig.pointerGestureTapInterval) {
                float x, y;
                mPointerController->getPosition(&x, &y);
                if (fabs(x - mPointerGesture.tapX) <= mConfig.pointerGestureTapSlop &&
                    fabs(y - mPointerGesture.tapY) <= mConfig.pointerGestureTapSlop) {
#if DEBUG_GESTURES
                    ALOGD("Gestures: TAP");
#endif

                    mPointerGesture.tapUpTime = when;
                    getContext()->requestTimeoutAtTime(when +
                                                       mConfig.pointerGestureTapDragInterval);

                    mPointerGesture.activeGestureId = 0;
                    mPointerGesture.currentGestureMode = PointerGesture::Mode::TAP;
                    mPointerGesture.currentGestureIdBits.clear();
                    mPointerGesture.currentGestureIdBits.markBit(mPointerGesture.activeGestureId);
                    mPointerGesture.currentGestureIdToIndex[mPointerGesture.activeGestureId] = 0;
                    mPointerGesture.currentGestureProperties[0].clear();
                    mPointerGesture.currentGestureProperties[0].id =
                            mPointerGesture.activeGestureId;
                    mPointerGesture.currentGestureProperties[0].toolType =
                            AMOTION_EVENT_TOOL_TYPE_FINGER;
                    mPointerGesture.currentGestureCoords[0].clear();
                    mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X,
                                                                         mPointerGesture.tapX);
                    mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y,
                                                                         mPointerGesture.tapY);
                    mPointerGesture.currentGestureCoords[0]
                            .setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);

                    tapped = true;
                } else {
#if DEBUG_GESTURES
                    ALOGD("Gestures: Not a TAP, deltaX=%f, deltaY=%f", x - mPointerGesture.tapX,
                          y - mPointerGesture.tapY);
#endif
                }
            } else {
#if DEBUG_GESTURES
                if (mPointerGesture.tapDownTime != LLONG_MIN) {
                    ALOGD("Gestures: Not a TAP, %0.3fms since down",
                          (when - mPointerGesture.tapDownTime) * 0.000001f);
                } else {
                    ALOGD("Gestures: Not a TAP, incompatible mode transitions");
                }
#endif
            }
        }

        mPointerVelocityControl.reset();

        if (!tapped) {
#if DEBUG_GESTURES
            ALOGD("Gestures: NEUTRAL");
#endif
            mPointerGesture.activeGestureId = -1;
            mPointerGesture.currentGestureMode = PointerGesture::Mode::NEUTRAL;
            mPointerGesture.currentGestureIdBits.clear();
        }
    } else if (currentFingerCount == 1) {
        // Case 4. Exactly one finger down, button is not pressed. (HOVER or TAP_DRAG)
        // The pointer follows the active touch point.
        // When in HOVER, emit HOVER_MOVE events at the pointer location.
        // When in TAP_DRAG, emit MOVE events at the pointer location.
        ALOG_ASSERT(activeTouchId >= 0);

        mPointerGesture.currentGestureMode = PointerGesture::Mode::HOVER;
        if (mPointerGesture.lastGestureMode == PointerGesture::Mode::TAP) {
            if (when <= mPointerGesture.tapUpTime + mConfig.pointerGestureTapDragInterval) {
                float x, y;
                mPointerController->getPosition(&x, &y);
                if (fabs(x - mPointerGesture.tapX) <= mConfig.pointerGestureTapSlop &&
                    fabs(y - mPointerGesture.tapY) <= mConfig.pointerGestureTapSlop) {
                    mPointerGesture.currentGestureMode = PointerGesture::Mode::TAP_DRAG;
                } else {
#if DEBUG_GESTURES
                    ALOGD("Gestures: Not a TAP_DRAG, deltaX=%f, deltaY=%f",
                          x - mPointerGesture.tapX, y - mPointerGesture.tapY);
#endif
                }
            } else {
#if DEBUG_GESTURES
                ALOGD("Gestures: Not a TAP_DRAG, %0.3fms time since up",
                      (when - mPointerGesture.tapUpTime) * 0.000001f);
#endif
            }
        } else if (mPointerGesture.lastGestureMode == PointerGesture::Mode::TAP_DRAG) {
            mPointerGesture.currentGestureMode = PointerGesture::Mode::TAP_DRAG;
        }

        float deltaX = 0, deltaY = 0;
        if (mLastCookedState.fingerIdBits.hasBit(activeTouchId)) {
            const RawPointerData::Pointer& currentPointer =
                    mCurrentRawState.rawPointerData.pointerForId(activeTouchId);
            const RawPointerData::Pointer& lastPointer =
                    mLastRawState.rawPointerData.pointerForId(activeTouchId);
            deltaX = (currentPointer.x - lastPointer.x) * mPointerXMovementScale;
            deltaY = (currentPointer.y - lastPointer.y) * mPointerYMovementScale;

            rotateDelta(mSurfaceOrientation, &deltaX, &deltaY);
            mPointerVelocityControl.move(when, &deltaX, &deltaY);

            // Move the pointer using a relative motion.
            // When using spots, the hover or drag will occur at the position of the anchor spot.
            mPointerController->move(deltaX, deltaY);
        } else {
            mPointerVelocityControl.reset();
        }

        bool down;
        if (mPointerGesture.currentGestureMode == PointerGesture::Mode::TAP_DRAG) {
#if DEBUG_GESTURES
            ALOGD("Gestures: TAP_DRAG");
#endif
            down = true;
        } else {
#if DEBUG_GESTURES
            ALOGD("Gestures: HOVER");
#endif
            if (mPointerGesture.lastGestureMode != PointerGesture::Mode::HOVER) {
                *outFinishPreviousGesture = true;
            }
            mPointerGesture.activeGestureId = 0;
            down = false;
        }

        float x, y;
        mPointerController->getPosition(&x, &y);

        mPointerGesture.currentGestureIdBits.clear();
        mPointerGesture.currentGestureIdBits.markBit(mPointerGesture.activeGestureId);
        mPointerGesture.currentGestureIdToIndex[mPointerGesture.activeGestureId] = 0;
        mPointerGesture.currentGestureProperties[0].clear();
        mPointerGesture.currentGestureProperties[0].id = mPointerGesture.activeGestureId;
        mPointerGesture.currentGestureProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
        mPointerGesture.currentGestureCoords[0].clear();
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, x);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE,
                                                             down ? 1.0f : 0.0f);

        if (lastFingerCount == 0 && currentFingerCount != 0) {
            mPointerGesture.resetTap();
            mPointerGesture.tapDownTime = when;
            mPointerGesture.tapX = x;
            mPointerGesture.tapY = y;
        }
    } else {
        // Case 5. At least two fingers down, button is not pressed. (PRESS, SWIPE or FREEFORM)
        // We need to provide feedback for each finger that goes down so we cannot wait
        // for the fingers to move before deciding what to do.
        //
        // The ambiguous case is deciding what to do when there are two fingers down but they
        // have not moved enough to determine whether they are part of a drag or part of a
        // freeform gesture, or just a press or long-press at the pointer location.
        //
        // When there are two fingers we start with the PRESS hypothesis and we generate a
        // down at the pointer location.
        //
        // When the two fingers move enough or when additional fingers are added, we make
        // a decision to transition into SWIPE or FREEFORM mode accordingly.
        ALOG_ASSERT(activeTouchId >= 0);

        bool settled = when >=
                mPointerGesture.firstTouchTime + mConfig.pointerGestureMultitouchSettleInterval;
        if (mPointerGesture.lastGestureMode != PointerGesture::Mode::PRESS &&
            mPointerGesture.lastGestureMode != PointerGesture::Mode::SWIPE &&
            mPointerGesture.lastGestureMode != PointerGesture::Mode::FREEFORM) {
            *outFinishPreviousGesture = true;
        } else if (!settled && currentFingerCount > lastFingerCount) {
            // Additional pointers have gone down but not yet settled.
            // Reset the gesture.
#if DEBUG_GESTURES
            ALOGD("Gestures: Resetting gesture since additional pointers went down for MULTITOUCH, "
                  "settle time remaining %0.3fms",
                  (mPointerGesture.firstTouchTime + mConfig.pointerGestureMultitouchSettleInterval -
                   when) * 0.000001f);
#endif
            *outCancelPreviousGesture = true;
        } else {
            // Continue previous gesture.
            mPointerGesture.currentGestureMode = mPointerGesture.lastGestureMode;
        }

        if (*outFinishPreviousGesture || *outCancelPreviousGesture) {
            mPointerGesture.currentGestureMode = PointerGesture::Mode::PRESS;
            mPointerGesture.activeGestureId = 0;
            mPointerGesture.referenceIdBits.clear();
            mPointerVelocityControl.reset();

            // Use the centroid and pointer location as the reference points for the gesture.
#if DEBUG_GESTURES
            ALOGD("Gestures: Using centroid as reference for MULTITOUCH, "
                  "settle time remaining %0.3fms",
                  (mPointerGesture.firstTouchTime + mConfig.pointerGestureMultitouchSettleInterval -
                   when) * 0.000001f);
#endif
            mCurrentRawState.rawPointerData
                    .getCentroidOfTouchingPointers(&mPointerGesture.referenceTouchX,
                                                   &mPointerGesture.referenceTouchY);
            mPointerController->getPosition(&mPointerGesture.referenceGestureX,
                                            &mPointerGesture.referenceGestureY);
        }

        // Clear the reference deltas for fingers not yet included in the reference calculation.
        for (BitSet32 idBits(mCurrentCookedState.fingerIdBits.value &
                             ~mPointerGesture.referenceIdBits.value);
             !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            mPointerGesture.referenceDeltas[id].dx = 0;
            mPointerGesture.referenceDeltas[id].dy = 0;
        }
        mPointerGesture.referenceIdBits = mCurrentCookedState.fingerIdBits;

        // Add delta for all fingers and calculate a common movement delta.
        float commonDeltaX = 0, commonDeltaY = 0;
        BitSet32 commonIdBits(mLastCookedState.fingerIdBits.value &
                              mCurrentCookedState.fingerIdBits.value);
        for (BitSet32 idBits(commonIdBits); !idBits.isEmpty();) {
            bool first = (idBits == commonIdBits);
            uint32_t id = idBits.clearFirstMarkedBit();
            const RawPointerData::Pointer& cpd = mCurrentRawState.rawPointerData.pointerForId(id);
            const RawPointerData::Pointer& lpd = mLastRawState.rawPointerData.pointerForId(id);
            PointerGesture::Delta& delta = mPointerGesture.referenceDeltas[id];
            delta.dx += cpd.x - lpd.x;
            delta.dy += cpd.y - lpd.y;

            if (first) {
                commonDeltaX = delta.dx;
                commonDeltaY = delta.dy;
            } else {
                commonDeltaX = calculateCommonVector(commonDeltaX, delta.dx);
                commonDeltaY = calculateCommonVector(commonDeltaY, delta.dy);
            }
        }

        // Consider transitions from PRESS to SWIPE or MULTITOUCH.
        if (mPointerGesture.currentGestureMode == PointerGesture::Mode::PRESS) {
            float dist[MAX_POINTER_ID + 1];
            int32_t distOverThreshold = 0;
            for (BitSet32 idBits(mPointerGesture.referenceIdBits); !idBits.isEmpty();) {
                uint32_t id = idBits.clearFirstMarkedBit();
                PointerGesture::Delta& delta = mPointerGesture.referenceDeltas[id];
                dist[id] = hypotf(delta.dx * mPointerXZoomScale, delta.dy * mPointerYZoomScale);
                if (dist[id] > mConfig.pointerGestureMultitouchMinDistance) {
                    distOverThreshold += 1;
                }
            }

            // Only transition when at least two pointers have moved further than
            // the minimum distance threshold.
            if (distOverThreshold >= 2) {
                if (currentFingerCount > 2) {
                    // There are more than two pointers, switch to FREEFORM.
#if DEBUG_GESTURES
                    ALOGD("Gestures: PRESS transitioned to FREEFORM, number of pointers %d > 2",
                          currentFingerCount);
#endif
                    *outCancelPreviousGesture = true;
                    mPointerGesture.currentGestureMode = PointerGesture::Mode::FREEFORM;
                } else {
                    // There are exactly two pointers.
                    BitSet32 idBits(mCurrentCookedState.fingerIdBits);
                    uint32_t id1 = idBits.clearFirstMarkedBit();
                    uint32_t id2 = idBits.firstMarkedBit();
                    const RawPointerData::Pointer& p1 =
                            mCurrentRawState.rawPointerData.pointerForId(id1);
                    const RawPointerData::Pointer& p2 =
                            mCurrentRawState.rawPointerData.pointerForId(id2);
                    float mutualDistance = distance(p1.x, p1.y, p2.x, p2.y);
                    if (mutualDistance > mPointerGestureMaxSwipeWidth) {
                        // There are two pointers but they are too far apart for a SWIPE,
                        // switch to FREEFORM.
#if DEBUG_GESTURES
                        ALOGD("Gestures: PRESS transitioned to FREEFORM, distance %0.3f > %0.3f",
                              mutualDistance, mPointerGestureMaxSwipeWidth);
#endif
                        *outCancelPreviousGesture = true;
                        mPointerGesture.currentGestureMode = PointerGesture::Mode::FREEFORM;
                    } else {
                        // There are two pointers.  Wait for both pointers to start moving
                        // before deciding whether this is a SWIPE or FREEFORM gesture.
                        float dist1 = dist[id1];
                        float dist2 = dist[id2];
                        if (dist1 >= mConfig.pointerGestureMultitouchMinDistance &&
                            dist2 >= mConfig.pointerGestureMultitouchMinDistance) {
                            // Calculate the dot product of the displacement vectors.
                            // When the vectors are oriented in approximately the same direction,
                            // the angle betweeen them is near zero and the cosine of the angle
                            // approches 1.0.  Recall that dot(v1, v2) = cos(angle) * mag(v1) *
                            // mag(v2).
                            PointerGesture::Delta& delta1 = mPointerGesture.referenceDeltas[id1];
                            PointerGesture::Delta& delta2 = mPointerGesture.referenceDeltas[id2];
                            float dx1 = delta1.dx * mPointerXZoomScale;
                            float dy1 = delta1.dy * mPointerYZoomScale;
                            float dx2 = delta2.dx * mPointerXZoomScale;
                            float dy2 = delta2.dy * mPointerYZoomScale;
                            float dot = dx1 * dx2 + dy1 * dy2;
                            float cosine = dot / (dist1 * dist2); // denominator always > 0
                            if (cosine >= mConfig.pointerGestureSwipeTransitionAngleCosine) {
                                // Pointers are moving in the same direction.  Switch to SWIPE.
#if DEBUG_GESTURES
                                ALOGD("Gestures: PRESS transitioned to SWIPE, "
                                      "dist1 %0.3f >= %0.3f, dist2 %0.3f >= %0.3f, "
                                      "cosine %0.3f >= %0.3f",
                                      dist1, mConfig.pointerGestureMultitouchMinDistance, dist2,
                                      mConfig.pointerGestureMultitouchMinDistance, cosine,
                                      mConfig.pointerGestureSwipeTransitionAngleCosine);
#endif
                                mPointerGesture.currentGestureMode = PointerGesture::Mode::SWIPE;
                            } else {
                                // Pointers are moving in different directions.  Switch to FREEFORM.
#if DEBUG_GESTURES
                                ALOGD("Gestures: PRESS transitioned to FREEFORM, "
                                      "dist1 %0.3f >= %0.3f, dist2 %0.3f >= %0.3f, "
                                      "cosine %0.3f < %0.3f",
                                      dist1, mConfig.pointerGestureMultitouchMinDistance, dist2,
                                      mConfig.pointerGestureMultitouchMinDistance, cosine,
                                      mConfig.pointerGestureSwipeTransitionAngleCosine);
#endif
                                *outCancelPreviousGesture = true;
                                mPointerGesture.currentGestureMode = PointerGesture::Mode::FREEFORM;
                            }
                        }
                    }
                }
            }
        } else if (mPointerGesture.currentGestureMode == PointerGesture::Mode::SWIPE) {
            // Switch from SWIPE to FREEFORM if additional pointers go down.
            // Cancel previous gesture.
            if (currentFingerCount > 2) {
#if DEBUG_GESTURES
                ALOGD("Gestures: SWIPE transitioned to FREEFORM, number of pointers %d > 2",
                      currentFingerCount);
#endif
                *outCancelPreviousGesture = true;
                mPointerGesture.currentGestureMode = PointerGesture::Mode::FREEFORM;
            }
        }

        // Move the reference points based on the overall group motion of the fingers
        // except in PRESS mode while waiting for a transition to occur.
        if (mPointerGesture.currentGestureMode != PointerGesture::Mode::PRESS &&
            (commonDeltaX || commonDeltaY)) {
            for (BitSet32 idBits(mPointerGesture.referenceIdBits); !idBits.isEmpty();) {
                uint32_t id = idBits.clearFirstMarkedBit();
                PointerGesture::Delta& delta = mPointerGesture.referenceDeltas[id];
                delta.dx = 0;
                delta.dy = 0;
            }

            mPointerGesture.referenceTouchX += commonDeltaX;
            mPointerGesture.referenceTouchY += commonDeltaY;

            commonDeltaX *= mPointerXMovementScale;
            commonDeltaY *= mPointerYMovementScale;

            rotateDelta(mSurfaceOrientation, &commonDeltaX, &commonDeltaY);
            mPointerVelocityControl.move(when, &commonDeltaX, &commonDeltaY);

            mPointerGesture.referenceGestureX += commonDeltaX;
            mPointerGesture.referenceGestureY += commonDeltaY;
        }

        // Report gestures.
        if (mPointerGesture.currentGestureMode == PointerGesture::Mode::PRESS ||
            mPointerGesture.currentGestureMode == PointerGesture::Mode::SWIPE) {
            // PRESS or SWIPE mode.
#if DEBUG_GESTURES
            ALOGD("Gestures: PRESS or SWIPE activeTouchId=%d,"
                  "activeGestureId=%d, currentTouchPointerCount=%d",
                  activeTouchId, mPointerGesture.activeGestureId, currentFingerCount);
#endif
            ALOG_ASSERT(mPointerGesture.activeGestureId >= 0);

            mPointerGesture.currentGestureIdBits.clear();
            mPointerGesture.currentGestureIdBits.markBit(mPointerGesture.activeGestureId);
            mPointerGesture.currentGestureIdToIndex[mPointerGesture.activeGestureId] = 0;
            mPointerGesture.currentGestureProperties[0].clear();
            mPointerGesture.currentGestureProperties[0].id = mPointerGesture.activeGestureId;
            mPointerGesture.currentGestureProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
            mPointerGesture.currentGestureCoords[0].clear();
            mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X,
                                                                 mPointerGesture.referenceGestureX);
            mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y,
                                                                 mPointerGesture.referenceGestureY);
            mPointerGesture.currentGestureCoords[0].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE, 1.0f);
        } else if (mPointerGesture.currentGestureMode == PointerGesture::Mode::FREEFORM) {
            // FREEFORM mode.
#if DEBUG_GESTURES
            ALOGD("Gestures: FREEFORM activeTouchId=%d,"
                  "activeGestureId=%d, currentTouchPointerCount=%d",
                  activeTouchId, mPointerGesture.activeGestureId, currentFingerCount);
#endif
            ALOG_ASSERT(mPointerGesture.activeGestureId >= 0);

            mPointerGesture.currentGestureIdBits.clear();

            BitSet32 mappedTouchIdBits;
            BitSet32 usedGestureIdBits;
            if (mPointerGesture.lastGestureMode != PointerGesture::Mode::FREEFORM) {
                // Initially, assign the active gesture id to the active touch point
                // if there is one.  No other touch id bits are mapped yet.
                if (!*outCancelPreviousGesture) {
                    mappedTouchIdBits.markBit(activeTouchId);
                    usedGestureIdBits.markBit(mPointerGesture.activeGestureId);
                    mPointerGesture.freeformTouchToGestureIdMap[activeTouchId] =
                            mPointerGesture.activeGestureId;
                } else {
                    mPointerGesture.activeGestureId = -1;
                }
            } else {
                // Otherwise, assume we mapped all touches from the previous frame.
                // Reuse all mappings that are still applicable.
                mappedTouchIdBits.value = mLastCookedState.fingerIdBits.value &
                        mCurrentCookedState.fingerIdBits.value;
                usedGestureIdBits = mPointerGesture.lastGestureIdBits;

                // Check whether we need to choose a new active gesture id because the
                // current went went up.
                for (BitSet32 upTouchIdBits(mLastCookedState.fingerIdBits.value &
                                            ~mCurrentCookedState.fingerIdBits.value);
                     !upTouchIdBits.isEmpty();) {
                    uint32_t upTouchId = upTouchIdBits.clearFirstMarkedBit();
                    uint32_t upGestureId = mPointerGesture.freeformTouchToGestureIdMap[upTouchId];
                    if (upGestureId == uint32_t(mPointerGesture.activeGestureId)) {
                        mPointerGesture.activeGestureId = -1;
                        break;
                    }
                }
            }

#if DEBUG_GESTURES
            ALOGD("Gestures: FREEFORM follow up "
                  "mappedTouchIdBits=0x%08x, usedGestureIdBits=0x%08x, "
                  "activeGestureId=%d",
                  mappedTouchIdBits.value, usedGestureIdBits.value,
                  mPointerGesture.activeGestureId);
#endif

            BitSet32 idBits(mCurrentCookedState.fingerIdBits);
            for (uint32_t i = 0; i < currentFingerCount; i++) {
                uint32_t touchId = idBits.clearFirstMarkedBit();
                uint32_t gestureId;
                if (!mappedTouchIdBits.hasBit(touchId)) {
                    gestureId = usedGestureIdBits.markFirstUnmarkedBit();
                    mPointerGesture.freeformTouchToGestureIdMap[touchId] = gestureId;
#if DEBUG_GESTURES
                    ALOGD("Gestures: FREEFORM "
                          "new mapping for touch id %d -> gesture id %d",
                          touchId, gestureId);
#endif
                } else {
                    gestureId = mPointerGesture.freeformTouchToGestureIdMap[touchId];
#if DEBUG_GESTURES
                    ALOGD("Gestures: FREEFORM "
                          "existing mapping for touch id %d -> gesture id %d",
                          touchId, gestureId);
#endif
                }
                mPointerGesture.currentGestureIdBits.markBit(gestureId);
                mPointerGesture.currentGestureIdToIndex[gestureId] = i;

                const RawPointerData::Pointer& pointer =
                        mCurrentRawState.rawPointerData.pointerForId(touchId);
                float deltaX = (pointer.x - mPointerGesture.referenceTouchX) * mPointerXZoomScale;
                float deltaY = (pointer.y - mPointerGesture.referenceTouchY) * mPointerYZoomScale;
                rotateDelta(mSurfaceOrientation, &deltaX, &deltaY);

                mPointerGesture.currentGestureProperties[i].clear();
                mPointerGesture.currentGestureProperties[i].id = gestureId;
                mPointerGesture.currentGestureProperties[i].toolType =
                        AMOTION_EVENT_TOOL_TYPE_FINGER;
                mPointerGesture.currentGestureCoords[i].clear();
                mPointerGesture.currentGestureCoords[i]
                        .setAxisValue(AMOTION_EVENT_AXIS_X,
                                      mPointerGesture.referenceGestureX + deltaX);
                mPointerGesture.currentGestureCoords[i]
                        .setAxisValue(AMOTION_EVENT_AXIS_Y,
                                      mPointerGesture.referenceGestureY + deltaY);
                mPointerGesture.currentGestureCoords[i].setAxisValue(AMOTION_EVENT_AXIS_PRESSURE,
                                                                     1.0f);
            }

            if (mPointerGesture.activeGestureId < 0) {
                mPointerGesture.activeGestureId =
                        mPointerGesture.currentGestureIdBits.firstMarkedBit();
#if DEBUG_GESTURES
                ALOGD("Gestures: FREEFORM new "
                      "activeGestureId=%d",
                      mPointerGesture.activeGestureId);
#endif
            }
        }
    }

    mPointerController->setButtonState(mCurrentRawState.buttonState);

#if DEBUG_GESTURES
    ALOGD("Gestures: finishPreviousGesture=%s, cancelPreviousGesture=%s, "
          "currentGestureMode=%d, currentGestureIdBits=0x%08x, "
          "lastGestureMode=%d, lastGestureIdBits=0x%08x",
          toString(*outFinishPreviousGesture), toString(*outCancelPreviousGesture),
          mPointerGesture.currentGestureMode, mPointerGesture.currentGestureIdBits.value,
          mPointerGesture.lastGestureMode, mPointerGesture.lastGestureIdBits.value);
    for (BitSet32 idBits = mPointerGesture.currentGestureIdBits; !idBits.isEmpty();) {
        uint32_t id = idBits.clearFirstMarkedBit();
        uint32_t index = mPointerGesture.currentGestureIdToIndex[id];
        const PointerProperties& properties = mPointerGesture.currentGestureProperties[index];
        const PointerCoords& coords = mPointerGesture.currentGestureCoords[index];
        ALOGD("  currentGesture[%d]: index=%d, toolType=%d, "
              "x=%0.3f, y=%0.3f, pressure=%0.3f",
              id, index, properties.toolType, coords.getAxisValue(AMOTION_EVENT_AXIS_X),
              coords.getAxisValue(AMOTION_EVENT_AXIS_Y),
              coords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE));
    }
    for (BitSet32 idBits = mPointerGesture.lastGestureIdBits; !idBits.isEmpty();) {
        uint32_t id = idBits.clearFirstMarkedBit();
        uint32_t index = mPointerGesture.lastGestureIdToIndex[id];
        const PointerProperties& properties = mPointerGesture.lastGestureProperties[index];
        const PointerCoords& coords = mPointerGesture.lastGestureCoords[index];
        ALOGD("  lastGesture[%d]: index=%d, toolType=%d, "
              "x=%0.3f, y=%0.3f, pressure=%0.3f",
              id, index, properties.toolType, coords.getAxisValue(AMOTION_EVENT_AXIS_X),
              coords.getAxisValue(AMOTION_EVENT_AXIS_Y),
              coords.getAxisValue(AMOTION_EVENT_AXIS_PRESSURE));
    }
#endif
    return true;
}

void TouchInputMapper::dispatchPointerStylus(nsecs_t when, uint32_t policyFlags) {
    mPointerSimple.currentCoords.clear();
    mPointerSimple.currentProperties.clear();

    bool down, hovering;
    if (!mCurrentCookedState.stylusIdBits.isEmpty()) {
        uint32_t id = mCurrentCookedState.stylusIdBits.firstMarkedBit();
        uint32_t index = mCurrentCookedState.cookedPointerData.idToIndex[id];
        float x = mCurrentCookedState.cookedPointerData.pointerCoords[index].getX();
        float y = mCurrentCookedState.cookedPointerData.pointerCoords[index].getY();
        mPointerController->setPosition(x, y);

        hovering = mCurrentCookedState.cookedPointerData.hoveringIdBits.hasBit(id);
        down = !hovering;

        mPointerController->getPosition(&x, &y);
        mPointerSimple.currentCoords.copyFrom(
                mCurrentCookedState.cookedPointerData.pointerCoords[index]);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_X, x);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        mPointerSimple.currentProperties.id = 0;
        mPointerSimple.currentProperties.toolType =
                mCurrentCookedState.cookedPointerData.pointerProperties[index].toolType;
    } else {
        down = false;
        hovering = false;
    }

    dispatchPointerSimple(when, policyFlags, down, hovering);
}

void TouchInputMapper::abortPointerStylus(nsecs_t when, uint32_t policyFlags) {
    abortPointerSimple(when, policyFlags);
}

void TouchInputMapper::dispatchPointerMouse(nsecs_t when, uint32_t policyFlags) {
    mPointerSimple.currentCoords.clear();
    mPointerSimple.currentProperties.clear();

    bool down, hovering;
    if (!mCurrentCookedState.mouseIdBits.isEmpty()) {
        uint32_t id = mCurrentCookedState.mouseIdBits.firstMarkedBit();
        uint32_t currentIndex = mCurrentRawState.rawPointerData.idToIndex[id];
        float deltaX = 0, deltaY = 0;
        if (mLastCookedState.mouseIdBits.hasBit(id)) {
            uint32_t lastIndex = mCurrentRawState.rawPointerData.idToIndex[id];
            deltaX = (mCurrentRawState.rawPointerData.pointers[currentIndex].x -
                      mLastRawState.rawPointerData.pointers[lastIndex].x) *
                    mPointerXMovementScale;
            deltaY = (mCurrentRawState.rawPointerData.pointers[currentIndex].y -
                      mLastRawState.rawPointerData.pointers[lastIndex].y) *
                    mPointerYMovementScale;

            rotateDelta(mSurfaceOrientation, &deltaX, &deltaY);
            mPointerVelocityControl.move(when, &deltaX, &deltaY);

            mPointerController->move(deltaX, deltaY);
        } else {
            mPointerVelocityControl.reset();
        }

        down = isPointerDown(mCurrentRawState.buttonState);
        hovering = !down;

        float x, y;
        mPointerController->getPosition(&x, &y);
        mPointerSimple.currentCoords.copyFrom(
                mCurrentCookedState.cookedPointerData.pointerCoords[currentIndex]);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_X, x);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_Y, y);
        mPointerSimple.currentCoords.setAxisValue(AMOTION_EVENT_AXIS_PRESSURE,
                                                  hovering ? 0.0f : 1.0f);
        mPointerSimple.currentProperties.id = 0;
        mPointerSimple.currentProperties.toolType =
                mCurrentCookedState.cookedPointerData.pointerProperties[currentIndex].toolType;
    } else {
        mPointerVelocityControl.reset();

        down = false;
        hovering = false;
    }

    dispatchPointerSimple(when, policyFlags, down, hovering);
}

void TouchInputMapper::abortPointerMouse(nsecs_t when, uint32_t policyFlags) {
    abortPointerSimple(when, policyFlags);

    mPointerVelocityControl.reset();
}

void TouchInputMapper::dispatchPointerSimple(nsecs_t when, uint32_t policyFlags, bool down,
                                             bool hovering) {
    int32_t metaState = getContext()->getGlobalMetaState();

    if (down || hovering) {
        mPointerController->setPresentation(PointerControllerInterface::Presentation::POINTER);
        mPointerController->clearSpots();
        mPointerController->setButtonState(mCurrentRawState.buttonState);
        mPointerController->unfade(PointerControllerInterface::Transition::IMMEDIATE);
    } else if (!down && !hovering && (mPointerSimple.down || mPointerSimple.hovering)) {
        mPointerController->fade(PointerControllerInterface::Transition::GRADUAL);
    }
    int32_t displayId = mPointerController->getDisplayId();

    float xCursorPosition;
    float yCursorPosition;
    mPointerController->getPosition(&xCursorPosition, &yCursorPosition);

    if (mPointerSimple.down && !down) {
        mPointerSimple.down = false;

        // Send up.
        NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource, displayId,
                              policyFlags, AMOTION_EVENT_ACTION_UP, 0, 0, metaState,
                              mLastRawState.buttonState, MotionClassification::NONE,
                              AMOTION_EVENT_EDGE_FLAG_NONE, 1, &mPointerSimple.lastProperties,
                              &mPointerSimple.lastCoords, mOrientedXPrecision, mOrientedYPrecision,
                              xCursorPosition, yCursorPosition, mPointerSimple.downTime,
                              /* videoFrames */ {});
        getListener()->notifyMotion(&args);
    }

    if (mPointerSimple.hovering && !hovering) {
        mPointerSimple.hovering = false;

        // Send hover exit.
        NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource, displayId,
                              policyFlags, AMOTION_EVENT_ACTION_HOVER_EXIT, 0, 0, metaState,
                              mLastRawState.buttonState, MotionClassification::NONE,
                              AMOTION_EVENT_EDGE_FLAG_NONE, 1, &mPointerSimple.lastProperties,
                              &mPointerSimple.lastCoords, mOrientedXPrecision, mOrientedYPrecision,
                              xCursorPosition, yCursorPosition, mPointerSimple.downTime,
                              /* videoFrames */ {});
        getListener()->notifyMotion(&args);
    }

    if (down) {
        if (!mPointerSimple.down) {
            mPointerSimple.down = true;
            mPointerSimple.downTime = when;

            // Send down.
            NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource,
                                  displayId, policyFlags, AMOTION_EVENT_ACTION_DOWN, 0, 0,
                                  metaState, mCurrentRawState.buttonState,
                                  MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                  &mPointerSimple.currentProperties, &mPointerSimple.currentCoords,
                                  mOrientedXPrecision, mOrientedYPrecision, xCursorPosition,
                                  yCursorPosition, mPointerSimple.downTime, /* videoFrames */ {});
            getListener()->notifyMotion(&args);
        }

        // Send move.
        NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource, displayId,
                              policyFlags, AMOTION_EVENT_ACTION_MOVE, 0, 0, metaState,
                              mCurrentRawState.buttonState, MotionClassification::NONE,
                              AMOTION_EVENT_EDGE_FLAG_NONE, 1, &mPointerSimple.currentProperties,
                              &mPointerSimple.currentCoords, mOrientedXPrecision,
                              mOrientedYPrecision, xCursorPosition, yCursorPosition,
                              mPointerSimple.downTime, /* videoFrames */ {});
        getListener()->notifyMotion(&args);
    }

    if (hovering) {
        if (!mPointerSimple.hovering) {
            mPointerSimple.hovering = true;

            // Send hover enter.
            NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource,
                                  displayId, policyFlags, AMOTION_EVENT_ACTION_HOVER_ENTER, 0, 0,
                                  metaState, mCurrentRawState.buttonState,
                                  MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                                  &mPointerSimple.currentProperties, &mPointerSimple.currentCoords,
                                  mOrientedXPrecision, mOrientedYPrecision, xCursorPosition,
                                  yCursorPosition, mPointerSimple.downTime, /* videoFrames */ {});
            getListener()->notifyMotion(&args);
        }

        // Send hover move.
        NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource, displayId,
                              policyFlags, AMOTION_EVENT_ACTION_HOVER_MOVE, 0, 0, metaState,
                              mCurrentRawState.buttonState, MotionClassification::NONE,
                              AMOTION_EVENT_EDGE_FLAG_NONE, 1, &mPointerSimple.currentProperties,
                              &mPointerSimple.currentCoords, mOrientedXPrecision,
                              mOrientedYPrecision, xCursorPosition, yCursorPosition,
                              mPointerSimple.downTime, /* videoFrames */ {});
        getListener()->notifyMotion(&args);
    }

    if (mCurrentRawState.rawVScroll || mCurrentRawState.rawHScroll) {
        float vscroll = mCurrentRawState.rawVScroll;
        float hscroll = mCurrentRawState.rawHScroll;
        mWheelYVelocityControl.move(when, nullptr, &vscroll);
        mWheelXVelocityControl.move(when, &hscroll, nullptr);

        // Send scroll.
        PointerCoords pointerCoords;
        pointerCoords.copyFrom(mPointerSimple.currentCoords);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_VSCROLL, vscroll);
        pointerCoords.setAxisValue(AMOTION_EVENT_AXIS_HSCROLL, hscroll);

        NotifyMotionArgs args(getContext()->getNextId(), when, getDeviceId(), mSource, displayId,
                              policyFlags, AMOTION_EVENT_ACTION_SCROLL, 0, 0, metaState,
                              mCurrentRawState.buttonState, MotionClassification::NONE,
                              AMOTION_EVENT_EDGE_FLAG_NONE, 1, &mPointerSimple.currentProperties,
                              &pointerCoords, mOrientedXPrecision, mOrientedYPrecision,
                              xCursorPosition, yCursorPosition, mPointerSimple.downTime,
                              /* videoFrames */ {});
        getListener()->notifyMotion(&args);
    }

    // Save state.
    if (down || hovering) {
        mPointerSimple.lastCoords.copyFrom(mPointerSimple.currentCoords);
        mPointerSimple.lastProperties.copyFrom(mPointerSimple.currentProperties);
    } else {
        mPointerSimple.reset();
    }
}

void TouchInputMapper::abortPointerSimple(nsecs_t when, uint32_t policyFlags) {
    mPointerSimple.currentCoords.clear();
    mPointerSimple.currentProperties.clear();

    dispatchPointerSimple(when, policyFlags, false, false);
}

void TouchInputMapper::dispatchMotion(nsecs_t when, uint32_t policyFlags, uint32_t source,
                                      int32_t action, int32_t actionButton, int32_t flags,
                                      int32_t metaState, int32_t buttonState, int32_t edgeFlags,
                                      const PointerProperties* properties,
                                      const PointerCoords* coords, const uint32_t* idToIndex,
                                      BitSet32 idBits, int32_t changedId, float xPrecision,
                                      float yPrecision, nsecs_t downTime) {
    PointerCoords pointerCoords[MAX_POINTERS];
    PointerProperties pointerProperties[MAX_POINTERS];
    uint32_t pointerCount = 0;
    while (!idBits.isEmpty()) {
        uint32_t id = idBits.clearFirstMarkedBit();
        uint32_t index = idToIndex[id];
        pointerProperties[pointerCount].copyFrom(properties[index]);
        pointerCoords[pointerCount].copyFrom(coords[index]);

        if (changedId >= 0 && id == uint32_t(changedId)) {
            action |= pointerCount << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
        }

        pointerCount += 1;
    }

    ALOG_ASSERT(pointerCount != 0);

    if (changedId >= 0 && pointerCount == 1) {
        // Replace initial down and final up action.
        // We can compare the action without masking off the changed pointer index
        // because we know the index is 0.
        if (action == AMOTION_EVENT_ACTION_POINTER_DOWN) {
            action = AMOTION_EVENT_ACTION_DOWN;
        } else if (action == AMOTION_EVENT_ACTION_POINTER_UP) {
            if ((flags & AMOTION_EVENT_FLAG_CANCELED) != 0) {
                action = AMOTION_EVENT_ACTION_CANCEL;
            } else {
                action = AMOTION_EVENT_ACTION_UP;
            }
        } else {
            // Can't happen.
            ALOG_ASSERT(false);
        }
    }
    float xCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    float yCursorPosition = AMOTION_EVENT_INVALID_CURSOR_POSITION;
    if (mDeviceMode == DeviceMode::POINTER) {
        mPointerController->getPosition(&xCursorPosition, &yCursorPosition);
    }
    const int32_t displayId = getAssociatedDisplayId().value_or(ADISPLAY_ID_NONE);
    const int32_t deviceId = getDeviceId();
    std::vector<TouchVideoFrame> frames = getDeviceContext().getVideoFrames();
    std::for_each(frames.begin(), frames.end(),
                  [this](TouchVideoFrame& frame) { frame.rotate(this->mSurfaceOrientation); });
    NotifyMotionArgs args(getContext()->getNextId(), when, deviceId, source, displayId, policyFlags,
                          action, actionButton, flags, metaState, buttonState,
                          MotionClassification::NONE, edgeFlags, pointerCount, pointerProperties,
                          pointerCoords, xPrecision, yPrecision, xCursorPosition, yCursorPosition,
                          downTime, std::move(frames));
    getListener()->notifyMotion(&args);
}

bool TouchInputMapper::updateMovedPointers(const PointerProperties* inProperties,
                                           const PointerCoords* inCoords,
                                           const uint32_t* inIdToIndex,
                                           PointerProperties* outProperties,
                                           PointerCoords* outCoords, const uint32_t* outIdToIndex,
                                           BitSet32 idBits) const {
    bool changed = false;
    while (!idBits.isEmpty()) {
        uint32_t id = idBits.clearFirstMarkedBit();
        uint32_t inIndex = inIdToIndex[id];
        uint32_t outIndex = outIdToIndex[id];

        const PointerProperties& curInProperties = inProperties[inIndex];
        const PointerCoords& curInCoords = inCoords[inIndex];
        PointerProperties& curOutProperties = outProperties[outIndex];
        PointerCoords& curOutCoords = outCoords[outIndex];

        if (curInProperties != curOutProperties) {
            curOutProperties.copyFrom(curInProperties);
            changed = true;
        }

        if (curInCoords != curOutCoords) {
            curOutCoords.copyFrom(curInCoords);
            changed = true;
        }
    }
    return changed;
}

void TouchInputMapper::cancelTouch(nsecs_t when) {
    abortPointerUsage(when, 0 /*policyFlags*/);
    abortTouches(when, 0 /* policyFlags*/);
}

// Transform raw coordinate to surface coordinate
void TouchInputMapper::rotateAndScale(float& x, float& y) {
    // Scale to surface coordinate.
    const float xScaled = float(x - mRawPointerAxes.x.minValue) * mXScale;
    const float yScaled = float(y - mRawPointerAxes.y.minValue) * mYScale;

    const float xScaledMax = float(mRawPointerAxes.x.maxValue - x) * mXScale;
    const float yScaledMax = float(mRawPointerAxes.y.maxValue - y) * mYScale;

    // Rotate to surface coordinate.
    // 0 - no swap and reverse.
    // 90 - swap x/y and reverse y.
    // 180 - reverse x, y.
    // 270 - swap x/y and reverse x.
    switch (mSurfaceOrientation) {
        case DISPLAY_ORIENTATION_0:
            x = xScaled + mXTranslate;
            y = yScaled + mYTranslate;
            break;
        case DISPLAY_ORIENTATION_90:
            y = xScaledMax - (mRawSurfaceWidth - mSurfaceRight);
            x = yScaled + mYTranslate;
            break;
        case DISPLAY_ORIENTATION_180:
            x = xScaledMax - (mRawSurfaceWidth - mSurfaceRight);
            y = yScaledMax - (mRawSurfaceHeight - mSurfaceBottom);
            break;
        case DISPLAY_ORIENTATION_270:
            y = xScaled + mXTranslate;
            x = yScaledMax - (mRawSurfaceHeight - mSurfaceBottom);
            break;
        default:
            assert(false);
    }
}

bool TouchInputMapper::isPointInsideSurface(int32_t x, int32_t y) {
    const float xScaled = (x - mRawPointerAxes.x.minValue) * mXScale;
    const float yScaled = (y - mRawPointerAxes.y.minValue) * mYScale;

    return x >= mRawPointerAxes.x.minValue && x <= mRawPointerAxes.x.maxValue &&
            xScaled >= mSurfaceLeft && xScaled <= mSurfaceRight &&
            y >= mRawPointerAxes.y.minValue && y <= mRawPointerAxes.y.maxValue &&
            yScaled >= mSurfaceTop && yScaled <= mSurfaceBottom;
}

const TouchInputMapper::VirtualKey* TouchInputMapper::findVirtualKeyHit(int32_t x, int32_t y) {
    for (const VirtualKey& virtualKey : mVirtualKeys) {
#if DEBUG_VIRTUAL_KEYS
        ALOGD("VirtualKeys: Hit test (%d, %d): keyCode=%d, scanCode=%d, "
              "left=%d, top=%d, right=%d, bottom=%d",
              x, y, virtualKey.keyCode, virtualKey.scanCode, virtualKey.hitLeft, virtualKey.hitTop,
              virtualKey.hitRight, virtualKey.hitBottom);
#endif

        if (virtualKey.isHit(x, y)) {
            return &virtualKey;
        }
    }

    return nullptr;
}

void TouchInputMapper::assignPointerIds(const RawState* last, RawState* current) {
    uint32_t currentPointerCount = current->rawPointerData.pointerCount;
    uint32_t lastPointerCount = last->rawPointerData.pointerCount;

    current->rawPointerData.clearIdBits();

    if (currentPointerCount == 0) {
        // No pointers to assign.
        return;
    }

    if (lastPointerCount == 0) {
        // All pointers are new.
        for (uint32_t i = 0; i < currentPointerCount; i++) {
            uint32_t id = i;
            current->rawPointerData.pointers[i].id = id;
            current->rawPointerData.idToIndex[id] = i;
            current->rawPointerData.markIdBit(id, current->rawPointerData.isHovering(i));
        }
        return;
    }

    if (currentPointerCount == 1 && lastPointerCount == 1 &&
        current->rawPointerData.pointers[0].toolType == last->rawPointerData.pointers[0].toolType) {
        // Only one pointer and no change in count so it must have the same id as before.
        uint32_t id = last->rawPointerData.pointers[0].id;
        current->rawPointerData.pointers[0].id = id;
        current->rawPointerData.idToIndex[id] = 0;
        current->rawPointerData.markIdBit(id, current->rawPointerData.isHovering(0));
        return;
    }

    // General case.
    // We build a heap of squared euclidean distances between current and last pointers
    // associated with the current and last pointer indices.  Then, we find the best
    // match (by distance) for each current pointer.
    // The pointers must have the same tool type but it is possible for them to
    // transition from hovering to touching or vice-versa while retaining the same id.
    PointerDistanceHeapElement heap[MAX_POINTERS * MAX_POINTERS];

    uint32_t heapSize = 0;
    for (uint32_t currentPointerIndex = 0; currentPointerIndex < currentPointerCount;
         currentPointerIndex++) {
        for (uint32_t lastPointerIndex = 0; lastPointerIndex < lastPointerCount;
             lastPointerIndex++) {
            const RawPointerData::Pointer& currentPointer =
                    current->rawPointerData.pointers[currentPointerIndex];
            const RawPointerData::Pointer& lastPointer =
                    last->rawPointerData.pointers[lastPointerIndex];
            if (currentPointer.toolType == lastPointer.toolType) {
                int64_t deltaX = currentPointer.x - lastPointer.x;
                int64_t deltaY = currentPointer.y - lastPointer.y;

                uint64_t distance = uint64_t(deltaX * deltaX + deltaY * deltaY);

                // Insert new element into the heap (sift up).
                heap[heapSize].currentPointerIndex = currentPointerIndex;
                heap[heapSize].lastPointerIndex = lastPointerIndex;
                heap[heapSize].distance = distance;
                heapSize += 1;
            }
        }
    }

    // Heapify
    for (uint32_t startIndex = heapSize / 2; startIndex != 0;) {
        startIndex -= 1;
        for (uint32_t parentIndex = startIndex;;) {
            uint32_t childIndex = parentIndex * 2 + 1;
            if (childIndex >= heapSize) {
                break;
            }

            if (childIndex + 1 < heapSize &&
                heap[childIndex + 1].distance < heap[childIndex].distance) {
                childIndex += 1;
            }

            if (heap[parentIndex].distance <= heap[childIndex].distance) {
                break;
            }

            swap(heap[parentIndex], heap[childIndex]);
            parentIndex = childIndex;
        }
    }

#if DEBUG_POINTER_ASSIGNMENT
    ALOGD("assignPointerIds - initial distance min-heap: size=%d", heapSize);
    for (size_t i = 0; i < heapSize; i++) {
        ALOGD("  heap[%zu]: cur=%" PRIu32 ", last=%" PRIu32 ", distance=%" PRIu64, i,
              heap[i].currentPointerIndex, heap[i].lastPointerIndex, heap[i].distance);
    }
#endif

    // Pull matches out by increasing order of distance.
    // To avoid reassigning pointers that have already been matched, the loop keeps track
    // of which last and current pointers have been matched using the matchedXXXBits variables.
    // It also tracks the used pointer id bits.
    BitSet32 matchedLastBits(0);
    BitSet32 matchedCurrentBits(0);
    BitSet32 usedIdBits(0);
    bool first = true;
    for (uint32_t i = min(currentPointerCount, lastPointerCount); heapSize > 0 && i > 0; i--) {
        while (heapSize > 0) {
            if (first) {
                // The first time through the loop, we just consume the root element of
                // the heap (the one with smallest distance).
                first = false;
            } else {
                // Previous iterations consumed the root element of the heap.
                // Pop root element off of the heap (sift down).
                heap[0] = heap[heapSize];
                for (uint32_t parentIndex = 0;;) {
                    uint32_t childIndex = parentIndex * 2 + 1;
                    if (childIndex >= heapSize) {
                        break;
                    }

                    if (childIndex + 1 < heapSize &&
                        heap[childIndex + 1].distance < heap[childIndex].distance) {
                        childIndex += 1;
                    }

                    if (heap[parentIndex].distance <= heap[childIndex].distance) {
                        break;
                    }

                    swap(heap[parentIndex], heap[childIndex]);
                    parentIndex = childIndex;
                }

#if DEBUG_POINTER_ASSIGNMENT
                ALOGD("assignPointerIds - reduced distance min-heap: size=%d", heapSize);
                for (size_t i = 0; i < heapSize; i++) {
                    ALOGD("  heap[%zu]: cur=%" PRIu32 ", last=%" PRIu32 ", distance=%" PRIu64, i,
                          heap[i].currentPointerIndex, heap[i].lastPointerIndex, heap[i].distance);
                }
#endif
            }

            heapSize -= 1;

            uint32_t currentPointerIndex = heap[0].currentPointerIndex;
            if (matchedCurrentBits.hasBit(currentPointerIndex)) continue; // already matched

            uint32_t lastPointerIndex = heap[0].lastPointerIndex;
            if (matchedLastBits.hasBit(lastPointerIndex)) continue; // already matched

            matchedCurrentBits.markBit(currentPointerIndex);
            matchedLastBits.markBit(lastPointerIndex);

            uint32_t id = last->rawPointerData.pointers[lastPointerIndex].id;
            current->rawPointerData.pointers[currentPointerIndex].id = id;
            current->rawPointerData.idToIndex[id] = currentPointerIndex;
            current->rawPointerData.markIdBit(id,
                                              current->rawPointerData.isHovering(
                                                      currentPointerIndex));
            usedIdBits.markBit(id);

#if DEBUG_POINTER_ASSIGNMENT
            ALOGD("assignPointerIds - matched: cur=%" PRIu32 ", last=%" PRIu32 ", id=%" PRIu32
                  ", distance=%" PRIu64,
                  lastPointerIndex, currentPointerIndex, id, heap[0].distance);
#endif
            break;
        }
    }

    // Assign fresh ids to pointers that were not matched in the process.
    for (uint32_t i = currentPointerCount - matchedCurrentBits.count(); i != 0; i--) {
        uint32_t currentPointerIndex = matchedCurrentBits.markFirstUnmarkedBit();
        uint32_t id = usedIdBits.markFirstUnmarkedBit();

        current->rawPointerData.pointers[currentPointerIndex].id = id;
        current->rawPointerData.idToIndex[id] = currentPointerIndex;
        current->rawPointerData.markIdBit(id,
                                          current->rawPointerData.isHovering(currentPointerIndex));

#if DEBUG_POINTER_ASSIGNMENT
        ALOGD("assignPointerIds - assigned: cur=%" PRIu32 ", id=%" PRIu32, currentPointerIndex, id);
#endif
    }
}

int32_t TouchInputMapper::getKeyCodeState(uint32_t sourceMask, int32_t keyCode) {
    if (mCurrentVirtualKey.down && mCurrentVirtualKey.keyCode == keyCode) {
        return AKEY_STATE_VIRTUAL;
    }

    for (const VirtualKey& virtualKey : mVirtualKeys) {
        if (virtualKey.keyCode == keyCode) {
            return AKEY_STATE_UP;
        }
    }

    return AKEY_STATE_UNKNOWN;
}

int32_t TouchInputMapper::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    if (mCurrentVirtualKey.down && mCurrentVirtualKey.scanCode == scanCode) {
        return AKEY_STATE_VIRTUAL;
    }

    for (const VirtualKey& virtualKey : mVirtualKeys) {
        if (virtualKey.scanCode == scanCode) {
            return AKEY_STATE_UP;
        }
    }

    return AKEY_STATE_UNKNOWN;
}

bool TouchInputMapper::markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes,
                                             const int32_t* keyCodes, uint8_t* outFlags) {
    for (const VirtualKey& virtualKey : mVirtualKeys) {
        for (size_t i = 0; i < numCodes; i++) {
            if (virtualKey.keyCode == keyCodes[i]) {
                outFlags[i] = 1;
            }
        }
    }

    return true;
}

std::optional<int32_t> TouchInputMapper::getAssociatedDisplayId() {
    if (mParameters.hasAssociatedDisplay) {
        if (mDeviceMode == DeviceMode::POINTER) {
            return std::make_optional(mPointerController->getDisplayId());
        } else {
            return std::make_optional(mViewport.displayId);
        }
    }
    return std::nullopt;
}

} // namespace android
