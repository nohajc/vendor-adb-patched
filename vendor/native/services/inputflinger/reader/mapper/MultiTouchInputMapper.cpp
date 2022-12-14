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

#include "MultiTouchInputMapper.h"

#include <android/sysprop/InputProperties.sysprop.h>

namespace android {

// --- Constants ---

// Maximum number of slots supported when using the slot-based Multitouch Protocol B.
static constexpr size_t MAX_SLOTS = 32;

// --- MultiTouchMotionAccumulator ---

MultiTouchMotionAccumulator::MultiTouchMotionAccumulator()
      : mCurrentSlot(-1),
        mSlots(nullptr),
        mSlotCount(0),
        mUsingSlotsProtocol(false),
        mHaveStylus(false) {}

MultiTouchMotionAccumulator::~MultiTouchMotionAccumulator() {
    delete[] mSlots;
}

void MultiTouchMotionAccumulator::configure(InputDeviceContext& deviceContext, size_t slotCount,
                                            bool usingSlotsProtocol) {
    mSlotCount = slotCount;
    mUsingSlotsProtocol = usingSlotsProtocol;
    mHaveStylus = deviceContext.hasAbsoluteAxis(ABS_MT_TOOL_TYPE);

    delete[] mSlots;
    mSlots = new Slot[slotCount];

    mCurrentSlot = -1;
    if (mUsingSlotsProtocol) {
        // Query the driver for the current slot index and use it as the initial slot
        // before we start reading events from the device.  It is possible that the
        // current slot index will not be the same as it was when the first event was
        // written into the evdev buffer, which means the input mapper could start
        // out of sync with the initial state of the events in the evdev buffer.
        // In the extremely unlikely case that this happens, the data from
        // two slots will be confused until the next ABS_MT_SLOT event is received.
        // This can cause the touch point to "jump", but at least there will be
        // no stuck touches.
        int32_t initialSlot;
        if (const auto status = deviceContext.getAbsoluteAxisValue(ABS_MT_SLOT, &initialSlot);
            status == OK) {
            mCurrentSlot = initialSlot;
        } else {
            ALOGD("Could not retrieve current multi-touch slot index. status=%d", status);
        }
    }
}

void MultiTouchMotionAccumulator::resetSlots() {
    if (mSlots) {
        for (size_t i = 0; i < mSlotCount; i++) {
            mSlots[i].clear();
        }
    }
    mCurrentSlot = -1;
}

void MultiTouchMotionAccumulator::process(const RawEvent* rawEvent) {
    if (rawEvent->type == EV_ABS) {
        bool newSlot = false;
        if (mUsingSlotsProtocol) {
            if (rawEvent->code == ABS_MT_SLOT) {
                mCurrentSlot = rawEvent->value;
                newSlot = true;
            }
        } else if (mCurrentSlot < 0) {
            mCurrentSlot = 0;
        }

        if (mCurrentSlot < 0 || size_t(mCurrentSlot) >= mSlotCount) {
            if (DEBUG_POINTERS) {
                if (newSlot) {
                    ALOGW("MultiTouch device emitted invalid slot index %d but it "
                          "should be between 0 and %zd; ignoring this slot.",
                          mCurrentSlot, mSlotCount - 1);
                }
            }
        } else {
            Slot* slot = &mSlots[mCurrentSlot];
            // If mUsingSlotsProtocol is true, it means the raw pointer has axis info of
            // ABS_MT_TRACKING_ID and ABS_MT_SLOT, so driver should send a valid trackingId while
            // updating the slot.
            if (!mUsingSlotsProtocol) {
                slot->mInUse = true;
            }

            switch (rawEvent->code) {
                case ABS_MT_POSITION_X:
                    slot->mAbsMTPositionX = rawEvent->value;
                    warnIfNotInUse(*rawEvent, *slot);
                    break;
                case ABS_MT_POSITION_Y:
                    slot->mAbsMTPositionY = rawEvent->value;
                    warnIfNotInUse(*rawEvent, *slot);
                    break;
                case ABS_MT_TOUCH_MAJOR:
                    slot->mAbsMTTouchMajor = rawEvent->value;
                    break;
                case ABS_MT_TOUCH_MINOR:
                    slot->mAbsMTTouchMinor = rawEvent->value;
                    slot->mHaveAbsMTTouchMinor = true;
                    break;
                case ABS_MT_WIDTH_MAJOR:
                    slot->mAbsMTWidthMajor = rawEvent->value;
                    break;
                case ABS_MT_WIDTH_MINOR:
                    slot->mAbsMTWidthMinor = rawEvent->value;
                    slot->mHaveAbsMTWidthMinor = true;
                    break;
                case ABS_MT_ORIENTATION:
                    slot->mAbsMTOrientation = rawEvent->value;
                    break;
                case ABS_MT_TRACKING_ID:
                    if (mUsingSlotsProtocol && rawEvent->value < 0) {
                        // The slot is no longer in use but it retains its previous contents,
                        // which may be reused for subsequent touches.
                        slot->mInUse = false;
                    } else {
                        slot->mInUse = true;
                        slot->mAbsMTTrackingId = rawEvent->value;
                    }
                    break;
                case ABS_MT_PRESSURE:
                    slot->mAbsMTPressure = rawEvent->value;
                    break;
                case ABS_MT_DISTANCE:
                    slot->mAbsMTDistance = rawEvent->value;
                    break;
                case ABS_MT_TOOL_TYPE:
                    slot->mAbsMTToolType = rawEvent->value;
                    slot->mHaveAbsMTToolType = true;
                    break;
            }
        }
    } else if (rawEvent->type == EV_SYN && rawEvent->code == SYN_MT_REPORT) {
        // MultiTouch Sync: The driver has returned all data for *one* of the pointers.
        mCurrentSlot += 1;
    }
}

void MultiTouchMotionAccumulator::finishSync() {
    if (!mUsingSlotsProtocol) {
        resetSlots();
    }
}

bool MultiTouchMotionAccumulator::hasStylus() const {
    return mHaveStylus;
}

void MultiTouchMotionAccumulator::warnIfNotInUse(const RawEvent& event, const Slot& slot) {
    if (!slot.mInUse) {
        ALOGW("Received unexpected event (0x%0x, 0x%0x) for slot %i with tracking id %i",
              event.code, event.value, mCurrentSlot, slot.mAbsMTTrackingId);
    }
}

// --- MultiTouchMotionAccumulator::Slot ---

MultiTouchMotionAccumulator::Slot::Slot() {
    clear();
}

void MultiTouchMotionAccumulator::Slot::clear() {
    mInUse = false;
    mHaveAbsMTTouchMinor = false;
    mHaveAbsMTWidthMinor = false;
    mHaveAbsMTToolType = false;
    mAbsMTPositionX = 0;
    mAbsMTPositionY = 0;
    mAbsMTTouchMajor = 0;
    mAbsMTTouchMinor = 0;
    mAbsMTWidthMajor = 0;
    mAbsMTWidthMinor = 0;
    mAbsMTOrientation = 0;
    mAbsMTTrackingId = -1;
    mAbsMTPressure = 0;
    mAbsMTDistance = 0;
    mAbsMTToolType = 0;
}

int32_t MultiTouchMotionAccumulator::Slot::getToolType() const {
    if (mHaveAbsMTToolType) {
        switch (mAbsMTToolType) {
            case MT_TOOL_FINGER:
                return AMOTION_EVENT_TOOL_TYPE_FINGER;
            case MT_TOOL_PEN:
                return AMOTION_EVENT_TOOL_TYPE_STYLUS;
            case MT_TOOL_PALM:
                return AMOTION_EVENT_TOOL_TYPE_PALM;
        }
    }
    return AMOTION_EVENT_TOOL_TYPE_UNKNOWN;
}

// --- MultiTouchInputMapper ---

MultiTouchInputMapper::MultiTouchInputMapper(InputDeviceContext& deviceContext)
      : TouchInputMapper(deviceContext) {}

MultiTouchInputMapper::~MultiTouchInputMapper() {}

void MultiTouchInputMapper::reset(nsecs_t when) {
    // The evdev multi-touch protocol does not allow userspace applications to query the initial or
    // current state of the pointers at any time. This means if we clear our accumulated state when
    // resetting the input mapper, there's no way to rebuild the full initial state of the pointers.
    // We can only wait for updates to all the pointers and axes. Rather than clearing the state and
    // rebuilding the state from scratch, we work around this kernel API limitation by never
    // fully clearing any state specific to the multi-touch protocol.
    TouchInputMapper::reset(when);
}

void MultiTouchInputMapper::process(const RawEvent* rawEvent) {
    TouchInputMapper::process(rawEvent);

    mMultiTouchMotionAccumulator.process(rawEvent);
}

std::optional<int32_t> MultiTouchInputMapper::getActiveBitId(
        const MultiTouchMotionAccumulator::Slot& inSlot) {
    if (mHavePointerIds) {
        int32_t trackingId = inSlot.getTrackingId();
        for (BitSet32 idBits(mPointerIdBits); !idBits.isEmpty();) {
            int32_t n = idBits.clearFirstMarkedBit();
            if (mPointerTrackingIdMap[n] == trackingId) {
                return std::make_optional(n);
            }
        }
    }
    return std::nullopt;
}

void MultiTouchInputMapper::syncTouch(nsecs_t when, RawState* outState) {
    size_t inCount = mMultiTouchMotionAccumulator.getSlotCount();
    size_t outCount = 0;
    BitSet32 newPointerIdBits;
    mHavePointerIds = true;

    for (size_t inIndex = 0; inIndex < inCount; inIndex++) {
        const MultiTouchMotionAccumulator::Slot* inSlot =
                mMultiTouchMotionAccumulator.getSlot(inIndex);
        if (!inSlot->isInUse()) {
            continue;
        }

        if (inSlot->getToolType() == AMOTION_EVENT_TOOL_TYPE_PALM) {
            std::optional<int32_t> id = getActiveBitId(*inSlot);
            if (id) {
                outState->rawPointerData.canceledIdBits.markBit(id.value());
            }
            if (DEBUG_POINTERS) {
                ALOGI("Stop processing slot %zu for it received a palm event from device %s",
                      inIndex, getDeviceName().c_str());
            }
            continue;
        }

        if (outCount >= MAX_POINTERS) {
            if (DEBUG_POINTERS) {
                ALOGD("MultiTouch device %s emitted more than maximum of %zu pointers; "
                      "ignoring the rest.",
                      getDeviceName().c_str(), MAX_POINTERS);
            }
            break; // too many fingers!
        }

        RawPointerData::Pointer& outPointer = outState->rawPointerData.pointers[outCount];
        outPointer.x = inSlot->getX();
        outPointer.y = inSlot->getY();
        outPointer.pressure = inSlot->getPressure();
        outPointer.touchMajor = inSlot->getTouchMajor();
        outPointer.touchMinor = inSlot->getTouchMinor();
        outPointer.toolMajor = inSlot->getToolMajor();
        outPointer.toolMinor = inSlot->getToolMinor();
        outPointer.orientation = inSlot->getOrientation();
        outPointer.distance = inSlot->getDistance();
        outPointer.tiltX = 0;
        outPointer.tiltY = 0;

        outPointer.toolType = inSlot->getToolType();
        if (outPointer.toolType == AMOTION_EVENT_TOOL_TYPE_UNKNOWN) {
            outPointer.toolType = mTouchButtonAccumulator.getToolType();
            if (outPointer.toolType == AMOTION_EVENT_TOOL_TYPE_UNKNOWN) {
                outPointer.toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;
            }
        }
        if (shouldSimulateStylusWithTouch() &&
            outPointer.toolType == AMOTION_EVENT_TOOL_TYPE_FINGER) {
            outPointer.toolType = AMOTION_EVENT_TOOL_TYPE_STYLUS;
        }

        bool isHovering = mTouchButtonAccumulator.getToolType() != AMOTION_EVENT_TOOL_TYPE_MOUSE &&
                (mTouchButtonAccumulator.isHovering() ||
                 (mRawPointerAxes.pressure.valid && inSlot->getPressure() <= 0));
        outPointer.isHovering = isHovering;

        // Assign pointer id using tracking id if available.
        if (mHavePointerIds) {
            int32_t trackingId = inSlot->getTrackingId();
            int32_t id = -1;
            if (trackingId >= 0) {
                for (BitSet32 idBits(mPointerIdBits); !idBits.isEmpty();) {
                    uint32_t n = idBits.clearFirstMarkedBit();
                    if (mPointerTrackingIdMap[n] == trackingId) {
                        id = n;
                    }
                }

                if (id < 0 && !mPointerIdBits.isFull()) {
                    id = mPointerIdBits.markFirstUnmarkedBit();
                    mPointerTrackingIdMap[id] = trackingId;
                }
            }
            if (id < 0) {
                mHavePointerIds = false;
                outState->rawPointerData.clearIdBits();
                newPointerIdBits.clear();
            } else {
                outPointer.id = id;
                outState->rawPointerData.idToIndex[id] = outCount;
                outState->rawPointerData.markIdBit(id, isHovering);
                newPointerIdBits.markBit(id);
            }
        }
        outCount += 1;
    }

    outState->rawPointerData.pointerCount = outCount;
    mPointerIdBits = newPointerIdBits;

    mMultiTouchMotionAccumulator.finishSync();
}

void MultiTouchInputMapper::configureRawPointerAxes() {
    TouchInputMapper::configureRawPointerAxes();

    getAbsoluteAxisInfo(ABS_MT_POSITION_X, &mRawPointerAxes.x);
    getAbsoluteAxisInfo(ABS_MT_POSITION_Y, &mRawPointerAxes.y);
    getAbsoluteAxisInfo(ABS_MT_TOUCH_MAJOR, &mRawPointerAxes.touchMajor);
    getAbsoluteAxisInfo(ABS_MT_TOUCH_MINOR, &mRawPointerAxes.touchMinor);
    getAbsoluteAxisInfo(ABS_MT_WIDTH_MAJOR, &mRawPointerAxes.toolMajor);
    getAbsoluteAxisInfo(ABS_MT_WIDTH_MINOR, &mRawPointerAxes.toolMinor);
    getAbsoluteAxisInfo(ABS_MT_ORIENTATION, &mRawPointerAxes.orientation);
    getAbsoluteAxisInfo(ABS_MT_PRESSURE, &mRawPointerAxes.pressure);
    getAbsoluteAxisInfo(ABS_MT_DISTANCE, &mRawPointerAxes.distance);
    getAbsoluteAxisInfo(ABS_MT_TRACKING_ID, &mRawPointerAxes.trackingId);
    getAbsoluteAxisInfo(ABS_MT_SLOT, &mRawPointerAxes.slot);

    if (mRawPointerAxes.trackingId.valid && mRawPointerAxes.slot.valid &&
        mRawPointerAxes.slot.minValue == 0 && mRawPointerAxes.slot.maxValue > 0) {
        size_t slotCount = mRawPointerAxes.slot.maxValue + 1;
        if (slotCount > MAX_SLOTS) {
            ALOGW("MultiTouch Device %s reported %zu slots but the framework "
                  "only supports a maximum of %zu slots at this time.",
                  getDeviceName().c_str(), slotCount, MAX_SLOTS);
            slotCount = MAX_SLOTS;
        }
        mMultiTouchMotionAccumulator.configure(getDeviceContext(), slotCount,
                                               true /*usingSlotsProtocol*/);
    } else {
        mMultiTouchMotionAccumulator.configure(getDeviceContext(), MAX_POINTERS,
                                               false /*usingSlotsProtocol*/);
    }
}

bool MultiTouchInputMapper::hasStylus() const {
    return mMultiTouchMotionAccumulator.hasStylus() || mTouchButtonAccumulator.hasStylus() ||
            shouldSimulateStylusWithTouch();
}

bool MultiTouchInputMapper::shouldSimulateStylusWithTouch() const {
    static const bool SIMULATE_STYLUS_WITH_TOUCH =
            sysprop::InputProperties::simulate_stylus_with_touch().value_or(false);
    return SIMULATE_STYLUS_WITH_TOUCH &&
            mParameters.deviceType == Parameters::DeviceType::TOUCH_SCREEN;
}

} // namespace android
