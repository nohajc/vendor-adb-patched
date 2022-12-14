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

#ifndef _UI_INPUT_INPUTDISPATCHER_INPUTSTATE_H
#define _UI_INPUT_INPUTDISPATCHER_INPUTSTATE_H

#include "CancelationOptions.h"
#include "Entry.h"

#include <utils/Timers.h>

namespace android::inputdispatcher {

static constexpr int32_t INVALID_POINTER_INDEX = -1;

/* Tracks dispatched key and motion event state so that cancellation events can be
 * synthesized when events are dropped. */
class InputState {
public:
    explicit InputState(const IdGenerator& idGenerator);
    ~InputState();

    // Returns true if there is no state to be canceled.
    bool isNeutral() const;

    // Returns true if the specified source is known to have received a hover enter
    // motion event.
    bool isHovering(int32_t deviceId, uint32_t source, int32_t displayId) const;

    // Records tracking information for a key event that has just been published.
    // Returns true if the event should be delivered, false if it is inconsistent
    // and should be skipped.
    bool trackKey(const KeyEntry& entry, int32_t action, int32_t flags);

    // Records tracking information for a motion event that has just been published.
    // Returns true if the event should be delivered, false if it is inconsistent
    // and should be skipped.
    bool trackMotion(const MotionEntry& entry, int32_t action, int32_t flags);

    // Synthesizes cancelation events for the current state and resets the tracked state.
    std::vector<EventEntry*> synthesizeCancelationEvents(nsecs_t currentTime,
                                                         const CancelationOptions& options);

    // Synthesizes down events for the current state.
    std::vector<EventEntry*> synthesizePointerDownEvents(nsecs_t currentTime);

    // Clears the current state.
    void clear();

    // Merges pointer-related parts of the input state into another instance.
    void mergePointerStateTo(InputState& other);

    // Gets the fallback key associated with a keycode.
    // Returns -1 if none.
    // Returns AKEYCODE_UNKNOWN if we are only dispatching the unhandled key to the policy.
    int32_t getFallbackKey(int32_t originalKeyCode);

    // Sets the fallback key for a particular keycode.
    void setFallbackKey(int32_t originalKeyCode, int32_t fallbackKeyCode);

    // Removes the fallback key for a particular keycode.
    void removeFallbackKey(int32_t originalKeyCode);

    inline const KeyedVector<int32_t, int32_t>& getFallbackKeys() const { return mFallbackKeys; }

private:
    struct KeyMemento {
        int32_t deviceId;
        uint32_t source;
        int32_t displayId;
        int32_t keyCode;
        int32_t scanCode;
        int32_t metaState;
        int32_t flags;
        nsecs_t downTime;
        uint32_t policyFlags;
    };

    struct MotionMemento {
        int32_t deviceId;
        uint32_t source;
        int32_t displayId;
        int32_t flags;
        float xPrecision;
        float yPrecision;
        float xCursorPosition;
        float yCursorPosition;
        nsecs_t downTime;
        uint32_t pointerCount;
        PointerProperties pointerProperties[MAX_POINTERS];
        PointerCoords pointerCoords[MAX_POINTERS];
        // Track for which pointers the target doesn't know about.
        int32_t firstNewPointerIdx = INVALID_POINTER_INDEX;
        bool hovering;
        uint32_t policyFlags;

        void setPointers(const MotionEntry& entry);
        void mergePointerStateTo(MotionMemento& other) const;
    };

    const IdGenerator& mIdGenerator; // InputDispatcher owns it so we won't have dangling reference.

    std::vector<KeyMemento> mKeyMementos;
    std::vector<MotionMemento> mMotionMementos;
    KeyedVector<int32_t, int32_t> mFallbackKeys;

    ssize_t findKeyMemento(const KeyEntry& entry) const;
    ssize_t findMotionMemento(const MotionEntry& entry, bool hovering) const;

    void addKeyMemento(const KeyEntry& entry, int32_t flags);
    void addMotionMemento(const MotionEntry& entry, int32_t flags, bool hovering);

    static bool shouldCancelKey(const KeyMemento& memento, const CancelationOptions& options);
    static bool shouldCancelMotion(const MotionMemento& memento, const CancelationOptions& options);
};

} // namespace android::inputdispatcher

#endif // _UI_INPUT_INPUTDISPATCHER_INPUTSTATE_H
