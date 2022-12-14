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

#ifndef _UI_INPUT_INPUTDISPATCHER_INPUTTARGET_H
#define _UI_INPUT_INPUTDISPATCHER_INPUTTARGET_H

#include <input/InputTransport.h>
#include <utils/BitSet.h>
#include <utils/RefBase.h>

namespace android::inputdispatcher {

/*
 * Information about each pointer for an InputTarget. This includes offset and scale so
 * all pointers can be normalized to a single offset and scale.
 *
 * These values are ignored for KeyEvents
 */
struct PointerInfo {
    // The x and y offset to add to a MotionEvent as it is delivered.
    float xOffset = 0.0f;
    float yOffset = 0.0f;

    // Scaling factor to apply to MotionEvent as it is delivered.
    float windowXScale = 1.0f;
    float windowYScale = 1.0f;
};

/*
 * An input target specifies how an input event is to be dispatched to a particular window
 * including the window's input channel, control flags, a timeout, and an X / Y offset to
 * be added to input event coordinates to compensate for the absolute position of the
 * window area.
 */
struct InputTarget {
    enum {
        /* This flag indicates that the event is being delivered to a foreground application. */
        FLAG_FOREGROUND = 1 << 0,

        /* This flag indicates that the MotionEvent falls within the area of the target
         * obscured by another visible window above it.  The motion event should be
         * delivered with flag AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED. */
        FLAG_WINDOW_IS_OBSCURED = 1 << 1,

        /* This flag indicates that a motion event is being split across multiple windows. */
        FLAG_SPLIT = 1 << 2,

        /* This flag indicates that the pointer coordinates dispatched to the application
         * will be zeroed out to avoid revealing information to an application. This is
         * used in conjunction with FLAG_DISPATCH_AS_OUTSIDE to prevent apps not sharing
         * the same UID from watching all touches. */
        FLAG_ZERO_COORDS = 1 << 3,

        /* This flag indicates that the event should be sent as is.
         * Should always be set unless the event is to be transmuted. */
        FLAG_DISPATCH_AS_IS = 1 << 8,

        /* This flag indicates that a MotionEvent with AMOTION_EVENT_ACTION_DOWN falls outside
         * of the area of this target and so should instead be delivered as an
         * AMOTION_EVENT_ACTION_OUTSIDE to this target. */
        FLAG_DISPATCH_AS_OUTSIDE = 1 << 9,

        /* This flag indicates that a hover sequence is starting in the given window.
         * The event is transmuted into ACTION_HOVER_ENTER. */
        FLAG_DISPATCH_AS_HOVER_ENTER = 1 << 10,

        /* This flag indicates that a hover event happened outside of a window which handled
         * previous hover events, signifying the end of the current hover sequence for that
         * window.
         * The event is transmuted into ACTION_HOVER_ENTER. */
        FLAG_DISPATCH_AS_HOVER_EXIT = 1 << 11,

        /* This flag indicates that the event should be canceled.
         * It is used to transmute ACTION_MOVE into ACTION_CANCEL when a touch slips
         * outside of a window. */
        FLAG_DISPATCH_AS_SLIPPERY_EXIT = 1 << 12,

        /* This flag indicates that the event should be dispatched as an initial down.
         * It is used to transmute ACTION_MOVE into ACTION_DOWN when a touch slips
         * into a new window. */
        FLAG_DISPATCH_AS_SLIPPERY_ENTER = 1 << 13,

        /* Mask for all dispatch modes. */
        FLAG_DISPATCH_MASK = FLAG_DISPATCH_AS_IS | FLAG_DISPATCH_AS_OUTSIDE |
                FLAG_DISPATCH_AS_HOVER_ENTER | FLAG_DISPATCH_AS_HOVER_EXIT |
                FLAG_DISPATCH_AS_SLIPPERY_EXIT | FLAG_DISPATCH_AS_SLIPPERY_ENTER,

        /* This flag indicates that the target of a MotionEvent is partly or wholly
         * obscured by another visible window above it.  The motion event should be
         * delivered with flag AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED. */
        FLAG_WINDOW_IS_PARTIALLY_OBSCURED = 1 << 14,

    };

    // The input channel to be targeted.
    sp<InputChannel> inputChannel;

    // Flags for the input target.
    int32_t flags = 0;

    // Scaling factor to apply to MotionEvent as it is delivered.
    // (ignored for KeyEvents)
    float globalScaleFactor = 1.0f;

    // The subset of pointer ids to include in motion events dispatched to this input target
    // if FLAG_SPLIT is set.
    BitSet32 pointerIds;
    // The data is stored by the pointerId. Use the bit position of pointerIds to look up
    // PointerInfo per pointerId.
    PointerInfo pointerInfos[MAX_POINTERS];

    void addPointers(BitSet32 pointerIds, float xOffset, float yOffset, float windowXScale,
                     float windowYScale);
    void setDefaultPointerInfo(float xOffset, float yOffset, float windowXScale,
                               float windowYScale);

    /**
     * Returns whether the default pointer information should be used. This will be true when the
     * InputTarget doesn't have any bits set in the pointerIds bitset. This can happen for monitors
     * and non splittable windows since we want all pointers for the EventEntry to go to this
     * target.
     */
    bool useDefaultPointerInfo() const;

    /**
     * Returns the default PointerInfo object. This should be used when useDefaultPointerInfo is
     * true.
     */
    const PointerInfo& getDefaultPointerInfo() const;

    std::string getPointerInfoString() const;
};

std::string dispatchModeToString(int32_t dispatchMode);

} // namespace android::inputdispatcher

#endif // _UI_INPUT_INPUTDISPATCHER_INPUTTARGET_H
