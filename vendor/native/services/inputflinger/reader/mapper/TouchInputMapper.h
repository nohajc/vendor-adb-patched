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

#ifndef _UI_INPUTREADER_TOUCH_INPUT_MAPPER_H
#define _UI_INPUTREADER_TOUCH_INPUT_MAPPER_H

#include <stdint.h>

#include "CursorButtonAccumulator.h"
#include "CursorScrollAccumulator.h"
#include "EventHub.h"
#include "InputMapper.h"
#include "InputReaderBase.h"
#include "TouchButtonAccumulator.h"

namespace android {

/* Raw axis information from the driver. */
struct RawPointerAxes {
    RawAbsoluteAxisInfo x;
    RawAbsoluteAxisInfo y;
    RawAbsoluteAxisInfo pressure;
    RawAbsoluteAxisInfo touchMajor;
    RawAbsoluteAxisInfo touchMinor;
    RawAbsoluteAxisInfo toolMajor;
    RawAbsoluteAxisInfo toolMinor;
    RawAbsoluteAxisInfo orientation;
    RawAbsoluteAxisInfo distance;
    RawAbsoluteAxisInfo tiltX;
    RawAbsoluteAxisInfo tiltY;
    RawAbsoluteAxisInfo trackingId;
    RawAbsoluteAxisInfo slot;

    RawPointerAxes();
    inline int32_t getRawWidth() const { return x.maxValue - x.minValue + 1; }
    inline int32_t getRawHeight() const { return y.maxValue - y.minValue + 1; }
    void clear();
};

/* Raw data for a collection of pointers including a pointer id mapping table. */
struct RawPointerData {
    struct Pointer {
        uint32_t id;
        int32_t x;
        int32_t y;
        int32_t pressure;
        int32_t touchMajor;
        int32_t touchMinor;
        int32_t toolMajor;
        int32_t toolMinor;
        int32_t orientation;
        int32_t distance;
        int32_t tiltX;
        int32_t tiltY;
        int32_t toolType; // a fully decoded AMOTION_EVENT_TOOL_TYPE constant
        bool isHovering;
    };

    uint32_t pointerCount;
    Pointer pointers[MAX_POINTERS];
    BitSet32 hoveringIdBits, touchingIdBits, canceledIdBits;
    uint32_t idToIndex[MAX_POINTER_ID + 1];

    RawPointerData();
    void clear();
    void copyFrom(const RawPointerData& other);
    void getCentroidOfTouchingPointers(float* outX, float* outY) const;

    inline void markIdBit(uint32_t id, bool isHovering) {
        if (isHovering) {
            hoveringIdBits.markBit(id);
        } else {
            touchingIdBits.markBit(id);
        }
    }

    inline void clearIdBits() {
        hoveringIdBits.clear();
        touchingIdBits.clear();
        canceledIdBits.clear();
    }

    inline const Pointer& pointerForId(uint32_t id) const { return pointers[idToIndex[id]]; }

    inline bool isHovering(uint32_t pointerIndex) { return pointers[pointerIndex].isHovering; }
};

/* Cooked data for a collection of pointers including a pointer id mapping table. */
struct CookedPointerData {
    uint32_t pointerCount;
    PointerProperties pointerProperties[MAX_POINTERS];
    PointerCoords pointerCoords[MAX_POINTERS];
    BitSet32 hoveringIdBits, touchingIdBits, canceledIdBits, validIdBits;
    uint32_t idToIndex[MAX_POINTER_ID + 1];

    CookedPointerData();
    void clear();
    void copyFrom(const CookedPointerData& other);

    inline const PointerCoords& pointerCoordsForId(uint32_t id) const {
        return pointerCoords[idToIndex[id]];
    }

    inline PointerCoords& editPointerCoordsWithId(uint32_t id) {
        return pointerCoords[idToIndex[id]];
    }

    inline PointerProperties& editPointerPropertiesWithId(uint32_t id) {
        return pointerProperties[idToIndex[id]];
    }

    inline bool isHovering(uint32_t pointerIndex) const {
        return hoveringIdBits.hasBit(pointerProperties[pointerIndex].id);
    }

    inline bool isTouching(uint32_t pointerIndex) const {
        return touchingIdBits.hasBit(pointerProperties[pointerIndex].id);
    }

    inline bool hasPointerCoordsForId(uint32_t id) const { return validIdBits.hasBit(id); }
};

class TouchInputMapper : public InputMapper {
public:
    explicit TouchInputMapper(InputDeviceContext& deviceContext);
    ~TouchInputMapper() override;

    uint32_t getSources() const override;
    void populateDeviceInfo(InputDeviceInfo* deviceInfo) override;
    void dump(std::string& dump) override;
    void configure(nsecs_t when, const InputReaderConfiguration* config, uint32_t changes) override;
    void reset(nsecs_t when) override;
    void process(const RawEvent* rawEvent) override;

    int32_t getKeyCodeState(uint32_t sourceMask, int32_t keyCode) override;
    int32_t getScanCodeState(uint32_t sourceMask, int32_t scanCode) override;
    bool markSupportedKeyCodes(uint32_t sourceMask, size_t numCodes, const int32_t* keyCodes,
                               uint8_t* outFlags) override;

    void cancelTouch(nsecs_t when, nsecs_t readTime) override;
    void timeoutExpired(nsecs_t when) override;
    void updateExternalStylusState(const StylusState& state) override;
    std::optional<int32_t> getAssociatedDisplayId() override;

protected:
    CursorButtonAccumulator mCursorButtonAccumulator;
    CursorScrollAccumulator mCursorScrollAccumulator;
    TouchButtonAccumulator mTouchButtonAccumulator;

    struct VirtualKey {
        int32_t keyCode;
        int32_t scanCode;
        uint32_t flags;

        // computed hit box, specified in touch screen coords based on known display size
        int32_t hitLeft;
        int32_t hitTop;
        int32_t hitRight;
        int32_t hitBottom;

        inline bool isHit(int32_t x, int32_t y) const {
            return x >= hitLeft && x <= hitRight && y >= hitTop && y <= hitBottom;
        }
    };

    // Input sources and device mode.
    uint32_t mSource;

    enum class DeviceMode {
        DISABLED,   // input is disabled
        DIRECT,     // direct mapping (touchscreen)
        UNSCALED,   // unscaled mapping (touchpad)
        NAVIGATION, // unscaled mapping with assist gesture (touch navigation)
        POINTER,    // pointer mapping (pointer)

        ftl_last = POINTER
    };
    DeviceMode mDeviceMode;

    // The reader's configuration.
    InputReaderConfiguration mConfig;

    // Immutable configuration parameters.
    struct Parameters {
        enum class DeviceType {
            TOUCH_SCREEN,
            TOUCH_PAD,
            TOUCH_NAVIGATION,
            POINTER,

            ftl_last = POINTER
        };

        DeviceType deviceType;
        bool hasAssociatedDisplay;
        bool associatedDisplayIsExternal;
        bool orientationAware;

        enum class Orientation : int32_t {
            ORIENTATION_0 = DISPLAY_ORIENTATION_0,
            ORIENTATION_90 = DISPLAY_ORIENTATION_90,
            ORIENTATION_180 = DISPLAY_ORIENTATION_180,
            ORIENTATION_270 = DISPLAY_ORIENTATION_270,

            ftl_last = ORIENTATION_270
        };
        Orientation orientation;

        bool hasButtonUnderPad;
        std::string uniqueDisplayId;

        enum class GestureMode {
            SINGLE_TOUCH,
            MULTI_TOUCH,

            ftl_last = MULTI_TOUCH
        };
        GestureMode gestureMode;

        bool wake;
    } mParameters;

    // Immutable calibration parameters in parsed form.
    struct Calibration {
        // Size
        enum class SizeCalibration {
            DEFAULT,
            NONE,
            GEOMETRIC,
            DIAMETER,
            BOX,
            AREA,
            ftl_last = AREA
        };

        SizeCalibration sizeCalibration;

        bool haveSizeScale;
        float sizeScale;
        bool haveSizeBias;
        float sizeBias;
        bool haveSizeIsSummed;
        bool sizeIsSummed;

        // Pressure
        enum class PressureCalibration {
            DEFAULT,
            NONE,
            PHYSICAL,
            AMPLITUDE,
        };

        PressureCalibration pressureCalibration;
        bool havePressureScale;
        float pressureScale;

        // Orientation
        enum class OrientationCalibration {
            DEFAULT,
            NONE,
            INTERPOLATED,
            VECTOR,
        };

        OrientationCalibration orientationCalibration;

        // Distance
        enum class DistanceCalibration {
            DEFAULT,
            NONE,
            SCALED,
        };

        DistanceCalibration distanceCalibration;
        bool haveDistanceScale;
        float distanceScale;

        enum class CoverageCalibration {
            DEFAULT,
            NONE,
            BOX,
        };

        CoverageCalibration coverageCalibration;

        inline void applySizeScaleAndBias(float* outSize) const {
            if (haveSizeScale) {
                *outSize *= sizeScale;
            }
            if (haveSizeBias) {
                *outSize += sizeBias;
            }
            if (*outSize < 0) {
                *outSize = 0;
            }
        }
    } mCalibration;

    // Affine location transformation/calibration
    struct TouchAffineTransformation mAffineTransform;

    RawPointerAxes mRawPointerAxes;

    struct RawState {
        nsecs_t when;
        nsecs_t readTime;

        // Raw pointer sample data.
        RawPointerData rawPointerData;

        int32_t buttonState;

        // Scroll state.
        int32_t rawVScroll;
        int32_t rawHScroll;

        explicit inline RawState() { clear(); }

        void copyFrom(const RawState& other) {
            when = other.when;
            readTime = other.readTime;
            rawPointerData.copyFrom(other.rawPointerData);
            buttonState = other.buttonState;
            rawVScroll = other.rawVScroll;
            rawHScroll = other.rawHScroll;
        }

        void clear() {
            when = 0;
            readTime = 0;
            rawPointerData.clear();
            buttonState = 0;
            rawVScroll = 0;
            rawHScroll = 0;
        }
    };

    struct CookedState {
        // Cooked pointer sample data.
        CookedPointerData cookedPointerData;

        // Id bits used to differentiate fingers, stylus and mouse tools.
        BitSet32 fingerIdBits;
        BitSet32 stylusIdBits;
        BitSet32 mouseIdBits;

        int32_t buttonState;

        void copyFrom(const CookedState& other) {
            cookedPointerData.copyFrom(other.cookedPointerData);
            fingerIdBits = other.fingerIdBits;
            stylusIdBits = other.stylusIdBits;
            mouseIdBits = other.mouseIdBits;
            buttonState = other.buttonState;
        }

        void clear() {
            cookedPointerData.clear();
            fingerIdBits.clear();
            stylusIdBits.clear();
            mouseIdBits.clear();
            buttonState = 0;
        }
    };

    std::vector<RawState> mRawStatesPending;
    RawState mCurrentRawState;
    CookedState mCurrentCookedState;
    RawState mLastRawState;
    CookedState mLastCookedState;

    // State provided by an external stylus
    StylusState mExternalStylusState;
    int64_t mExternalStylusId;
    nsecs_t mExternalStylusFusionTimeout;
    bool mExternalStylusDataPending;

    // True if we sent a HOVER_ENTER event.
    bool mSentHoverEnter;

    // Have we assigned pointer IDs for this stream
    bool mHavePointerIds;

    // Is the current stream of direct touch events aborted
    bool mCurrentMotionAborted;

    // The time the primary pointer last went down.
    nsecs_t mDownTime;

    // The pointer controller, or null if the device is not a pointer.
    std::shared_ptr<PointerControllerInterface> mPointerController;

    std::vector<VirtualKey> mVirtualKeys;

    virtual void configureParameters();
    virtual void dumpParameters(std::string& dump);
    virtual void configureRawPointerAxes();
    virtual void dumpRawPointerAxes(std::string& dump);
    virtual void configureInputDevice(nsecs_t when, bool* outResetNeeded);
    virtual void dumpDisplay(std::string& dump);
    virtual void configureVirtualKeys();
    virtual void dumpVirtualKeys(std::string& dump);
    virtual void parseCalibration();
    virtual void resolveCalibration();
    virtual void dumpCalibration(std::string& dump);
    virtual void updateAffineTransformation();
    virtual void dumpAffineTransformation(std::string& dump);
    virtual void resolveExternalStylusPresence();
    virtual bool hasStylus() const = 0;
    virtual bool hasExternalStylus() const;

    virtual void syncTouch(nsecs_t when, RawState* outState) = 0;

private:
    // The current viewport.
    // The components of the viewport are specified in the display's rotated orientation.
    DisplayViewport mViewport;

    // The width and height are obtained from the viewport and are specified
    // in the natural orientation.
    int32_t mDisplayWidth;
    int32_t mDisplayHeight;

    // The physical frame is the rectangle in the display's coordinate space that maps to the
    // the logical display frame.
    int32_t mPhysicalWidth;
    int32_t mPhysicalHeight;
    int32_t mPhysicalLeft;
    int32_t mPhysicalTop;

    // The orientation of the input device relative to that of the display panel. It specifies
    // the rotation of the input device coordinates required to produce the display panel
    // orientation, so it will depend on whether the device is orientation aware.
    int32_t mInputDeviceOrientation;

    // Translation and scaling factors, orientation-independent.
    float mXScale;
    float mXPrecision;

    float mYScale;
    float mYPrecision;

    float mGeometricScale;

    float mPressureScale;

    float mSizeScale;

    float mOrientationScale;

    float mDistanceScale;

    bool mHaveTilt;
    float mTiltXCenter;
    float mTiltXScale;
    float mTiltYCenter;
    float mTiltYScale;

    bool mExternalStylusConnected;

    // Oriented motion ranges for input device info.
    struct OrientedRanges {
        InputDeviceInfo::MotionRange x;
        InputDeviceInfo::MotionRange y;
        InputDeviceInfo::MotionRange pressure;

        bool haveSize;
        InputDeviceInfo::MotionRange size;

        bool haveTouchSize;
        InputDeviceInfo::MotionRange touchMajor;
        InputDeviceInfo::MotionRange touchMinor;

        bool haveToolSize;
        InputDeviceInfo::MotionRange toolMajor;
        InputDeviceInfo::MotionRange toolMinor;

        bool haveOrientation;
        InputDeviceInfo::MotionRange orientation;

        bool haveDistance;
        InputDeviceInfo::MotionRange distance;

        bool haveTilt;
        InputDeviceInfo::MotionRange tilt;

        OrientedRanges() { clear(); }

        void clear() {
            haveSize = false;
            haveTouchSize = false;
            haveToolSize = false;
            haveOrientation = false;
            haveDistance = false;
            haveTilt = false;
        }
    } mOrientedRanges;

    // Oriented dimensions and precision.
    float mOrientedXPrecision;
    float mOrientedYPrecision;

    struct CurrentVirtualKeyState {
        bool down;
        bool ignored;
        nsecs_t downTime;
        int32_t keyCode;
        int32_t scanCode;
    } mCurrentVirtualKey;

    // Scale factor for gesture or mouse based pointer movements.
    float mPointerXMovementScale;
    float mPointerYMovementScale;

    // Scale factor for gesture based zooming and other freeform motions.
    float mPointerXZoomScale;
    float mPointerYZoomScale;

    // The maximum swipe width.
    float mPointerGestureMaxSwipeWidth;

    struct PointerDistanceHeapElement {
        uint32_t currentPointerIndex : 8;
        uint32_t lastPointerIndex : 8;
        uint64_t distance : 48; // squared distance
    };

    enum class PointerUsage {
        NONE,
        GESTURES,
        STYLUS,
        MOUSE,
    };
    PointerUsage mPointerUsage;

    struct PointerGesture {
        enum class Mode {
            // No fingers, button is not pressed.
            // Nothing happening.
            NEUTRAL,

            // No fingers, button is not pressed.
            // Tap detected.
            // Emits DOWN and UP events at the pointer location.
            TAP,

            // Exactly one finger dragging following a tap.
            // Pointer follows the active finger.
            // Emits DOWN, MOVE and UP events at the pointer location.
            //
            // Detect double-taps when the finger goes up while in TAP_DRAG mode.
            TAP_DRAG,

            // Button is pressed.
            // Pointer follows the active finger if there is one.  Other fingers are ignored.
            // Emits DOWN, MOVE and UP events at the pointer location.
            BUTTON_CLICK_OR_DRAG,

            // Exactly one finger, button is not pressed.
            // Pointer follows the active finger.
            // Emits HOVER_MOVE events at the pointer location.
            //
            // Detect taps when the finger goes up while in HOVER mode.
            HOVER,

            // Exactly two fingers but neither have moved enough to clearly indicate
            // whether a swipe or freeform gesture was intended.  We consider the
            // pointer to be pressed so this enables clicking or long-pressing on buttons.
            // Pointer does not move.
            // Emits DOWN, MOVE and UP events with a single stationary pointer coordinate.
            PRESS,

            // Exactly two fingers moving in the same direction, button is not pressed.
            // Pointer does not move.
            // Emits DOWN, MOVE and UP events with a single pointer coordinate that
            // follows the midpoint between both fingers.
            SWIPE,

            // Two or more fingers moving in arbitrary directions, button is not pressed.
            // Pointer does not move.
            // Emits DOWN, POINTER_DOWN, MOVE, POINTER_UP and UP events that follow
            // each finger individually relative to the initial centroid of the finger.
            FREEFORM,

            // Waiting for quiet time to end before starting the next gesture.
            QUIET,
        };

        // When a gesture is sent to an unfocused window, return true if it can bring that window
        // into focus, false otherwise.
        static bool canGestureAffectWindowFocus(Mode mode) {
            switch (mode) {
                case Mode::TAP:
                case Mode::TAP_DRAG:
                case Mode::BUTTON_CLICK_OR_DRAG:
                    // Taps can affect window focus.
                    return true;
                case Mode::FREEFORM:
                case Mode::HOVER:
                case Mode::NEUTRAL:
                case Mode::PRESS:
                case Mode::QUIET:
                case Mode::SWIPE:
                    // Most gestures can be performed on an unfocused window, so they should not
                    // not affect window focus.
                    return false;
            }
        }

        // Time the first finger went down.
        nsecs_t firstTouchTime;

        // The active pointer id from the raw touch data.
        int32_t activeTouchId; // -1 if none

        // The active pointer id from the gesture last delivered to the application.
        int32_t activeGestureId; // -1 if none

        // Pointer coords and ids for the current and previous pointer gesture.
        Mode currentGestureMode;
        BitSet32 currentGestureIdBits;
        uint32_t currentGestureIdToIndex[MAX_POINTER_ID + 1];
        PointerProperties currentGestureProperties[MAX_POINTERS];
        PointerCoords currentGestureCoords[MAX_POINTERS];

        Mode lastGestureMode;
        BitSet32 lastGestureIdBits;
        uint32_t lastGestureIdToIndex[MAX_POINTER_ID + 1];
        PointerProperties lastGestureProperties[MAX_POINTERS];
        PointerCoords lastGestureCoords[MAX_POINTERS];

        // Time the pointer gesture last went down.
        nsecs_t downTime;

        // Time when the pointer went down for a TAP.
        nsecs_t tapDownTime;

        // Time when the pointer went up for a TAP.
        nsecs_t tapUpTime;

        // Location of initial tap.
        float tapX, tapY;

        // Time we started waiting for quiescence.
        nsecs_t quietTime;

        // Reference points for multitouch gestures.
        float referenceTouchX; // reference touch X/Y coordinates in surface units
        float referenceTouchY;
        float referenceGestureX; // reference gesture X/Y coordinates in pixels
        float referenceGestureY;

        // Distance that each pointer has traveled which has not yet been
        // subsumed into the reference gesture position.
        BitSet32 referenceIdBits;
        struct Delta {
            float dx, dy;
        };
        Delta referenceDeltas[MAX_POINTER_ID + 1];

        // Describes how touch ids are mapped to gesture ids for freeform gestures.
        uint32_t freeformTouchToGestureIdMap[MAX_POINTER_ID + 1];

        // A velocity tracker for determining whether to switch active pointers during drags.
        VelocityTracker velocityTracker;

        void reset() {
            firstTouchTime = LLONG_MIN;
            activeTouchId = -1;
            activeGestureId = -1;
            currentGestureMode = Mode::NEUTRAL;
            currentGestureIdBits.clear();
            lastGestureMode = Mode::NEUTRAL;
            lastGestureIdBits.clear();
            downTime = 0;
            velocityTracker.clear();
            resetTap();
            resetQuietTime();
        }

        void resetTap() {
            tapDownTime = LLONG_MIN;
            tapUpTime = LLONG_MIN;
        }

        void resetQuietTime() { quietTime = LLONG_MIN; }
    } mPointerGesture;

    struct PointerSimple {
        PointerCoords currentCoords;
        PointerProperties currentProperties;
        PointerCoords lastCoords;
        PointerProperties lastProperties;

        // True if the pointer is down.
        bool down;

        // True if the pointer is hovering.
        bool hovering;

        // Time the pointer last went down.
        nsecs_t downTime;

        // Values reported for the last pointer event.
        uint32_t source;
        int32_t displayId;
        float lastCursorX;
        float lastCursorY;

        void reset() {
            currentCoords.clear();
            currentProperties.clear();
            lastCoords.clear();
            lastProperties.clear();
            down = false;
            hovering = false;
            downTime = 0;
            source = 0;
            displayId = ADISPLAY_ID_NONE;
            lastCursorX = 0.f;
            lastCursorY = 0.f;
        }
    } mPointerSimple;

    // The pointer and scroll velocity controls.
    VelocityControl mPointerVelocityControl;
    VelocityControl mWheelXVelocityControl;
    VelocityControl mWheelYVelocityControl;

    std::optional<DisplayViewport> findViewport();

    void resetExternalStylus();
    void clearStylusDataPendingFlags();

    int32_t clampResolution(const char* axisName, int32_t resolution) const;
    void initializeOrientedRanges();
    void initializeSizeRanges();

    void sync(nsecs_t when, nsecs_t readTime);

    bool consumeRawTouches(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    void processRawTouches(bool timeout);
    void cookAndDispatch(nsecs_t when, nsecs_t readTime);
    void dispatchVirtualKey(nsecs_t when, nsecs_t readTime, uint32_t policyFlags,
                            int32_t keyEventAction, int32_t keyEventFlags);

    void dispatchTouches(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    void dispatchHoverExit(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    void dispatchHoverEnterAndMove(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    void dispatchButtonRelease(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    void dispatchButtonPress(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    const BitSet32& findActiveIdBits(const CookedPointerData& cookedPointerData);
    void cookPointerData();
    void abortTouches(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);

    void dispatchPointerUsage(nsecs_t when, nsecs_t readTime, uint32_t policyFlags,
                              PointerUsage pointerUsage);
    void abortPointerUsage(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);

    void dispatchPointerGestures(nsecs_t when, nsecs_t readTime, uint32_t policyFlags,
                                 bool isTimeout);
    void abortPointerGestures(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    bool preparePointerGestures(nsecs_t when, bool* outCancelPreviousGesture,
                                bool* outFinishPreviousGesture, bool isTimeout);

    void dispatchPointerStylus(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    void abortPointerStylus(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);

    void dispatchPointerMouse(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);
    void abortPointerMouse(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);

    void dispatchPointerSimple(nsecs_t when, nsecs_t readTime, uint32_t policyFlags, bool down,
                               bool hovering);
    void abortPointerSimple(nsecs_t when, nsecs_t readTime, uint32_t policyFlags);

    bool assignExternalStylusId(const RawState& state, bool timeout);
    void applyExternalStylusButtonState(nsecs_t when);
    void applyExternalStylusTouchState(nsecs_t when);

    // Dispatches a motion event.
    // If the changedId is >= 0 and the action is POINTER_DOWN or POINTER_UP, the
    // method will take care of setting the index and transmuting the action to DOWN or UP
    // it is the first / last pointer to go down / up.
    void dispatchMotion(nsecs_t when, nsecs_t readTime, uint32_t policyFlags, uint32_t source,
                        int32_t action, int32_t actionButton, int32_t flags, int32_t metaState,
                        int32_t buttonState, int32_t edgeFlags, const PointerProperties* properties,
                        const PointerCoords* coords, const uint32_t* idToIndex, BitSet32 idBits,
                        int32_t changedId, float xPrecision, float yPrecision, nsecs_t downTime);

    // Updates pointer coords and properties for pointers with specified ids that have moved.
    // Returns true if any of them changed.
    bool updateMovedPointers(const PointerProperties* inProperties, const PointerCoords* inCoords,
                             const uint32_t* inIdToIndex, PointerProperties* outProperties,
                             PointerCoords* outCoords, const uint32_t* outIdToIndex,
                             BitSet32 idBits) const;

    // Returns if this touch device is a touch screen with an associated display.
    bool isTouchScreen();
    // Updates touch spots if they are enabled. Should only be used when this device is a
    // touchscreen.
    void updateTouchSpots();

    bool isPointInsidePhysicalFrame(int32_t x, int32_t y) const;
    const VirtualKey* findVirtualKeyHit(int32_t x, int32_t y);

    static void assignPointerIds(const RawState& last, RawState& current);

    const char* modeToString(DeviceMode deviceMode);
    void rotateAndScale(float& x, float& y) const;
};

} // namespace android

#endif // _UI_INPUTREADER_TOUCH_INPUT_MAPPER_H
