/*
 * Copyright (C) 2021 The Android Open Source Project
 * Android BPF library - public API
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

#pragma once

#include <inttypes.h>
#include <log/log.h>
#include <time.h>
#include <sstream>
#include <string>

/**
 * An object that can track changes of some value over time, taking into account an additional
 * dimension: the object's state.  As the tracked value changes, the deltas are distributed
 * among the object states in accordance with the time spent in those states.
 */
namespace android {
namespace battery {

typedef uint16_t state_t;

template <class T>
class MultiStateCounter {
    uint16_t stateCount;
    state_t currentState;
    time_t lastStateChangeTimestamp;
    T emptyValue;
    T lastValue;
    time_t lastUpdateTimestamp;
    T deltaValue;
    bool isEnabled;

    struct State {
        time_t timeInStateSinceUpdate;
        T counter;
    };

    State* states;

public:
    MultiStateCounter(uint16_t stateCount, const T& emptyValue);

    virtual ~MultiStateCounter();

    void setEnabled(bool enabled, time_t timestamp);

    void setState(state_t state, time_t timestamp);

    void setValue(state_t state, const T& value);

    /**
     * Updates the value by distributing the delta from the previously set value
     * among states according to their respective time-in-state.
     * Returns the delta from the previously set value.
     */
    const T& updateValue(const T& value, time_t timestamp);

    /**
     * Updates the value by distributing the specified increment among states according
     * to their respective time-in-state.
     */
    void incrementValue(const T& increment, time_t timestamp);

    /**
     * Adds the specified increment to the value for the current state, without affecting
     * the last updated value or timestamp.  Ignores partial time-in-state: the entirety of
     * the increment is given to the current state.
     */
    void addValue(const T& increment);

    void reset();

    uint16_t getStateCount();

    const T& getCount(state_t state);

    std::string toString();

private:
    /**
     * Subtracts previousValue from newValue and returns the result in outValue.
     * Returns true iff the combination of previousValue and newValue is valid
     * (newValue >= prevValue)
     */
    bool delta(const T& previousValue, const T& newValue, T* outValue) const;

    /**
     * Adds value2 to value1 and stores the result in value1.  Denominator is
     * guaranteed to be non-zero.
     */
    void add(T* value1, const T& value2, const uint64_t numerator,
             const uint64_t denominator) const;

    std::string valueToString(const T& value) const;
};

// ---------------------- MultiStateCounter Implementation -------------------------
// Since MultiStateCounter is a template, the implementation must be inlined.

template <class T>
MultiStateCounter<T>::MultiStateCounter(uint16_t stateCount, const T& emptyValue)
      : stateCount(stateCount),
        currentState(0),
        lastStateChangeTimestamp(-1),
        emptyValue(emptyValue),
        lastValue(emptyValue),
        lastUpdateTimestamp(-1),
        deltaValue(emptyValue),
        isEnabled(true) {
    states = new State[stateCount];
    for (int i = 0; i < stateCount; i++) {
        states[i].timeInStateSinceUpdate = 0;
        states[i].counter = emptyValue;
    }
}

template <class T>
MultiStateCounter<T>::~MultiStateCounter() {
    delete[] states;
};

template <class T>
void MultiStateCounter<T>::setEnabled(bool enabled, time_t timestamp) {
    if (enabled == isEnabled) {
        return;
    }

    if (isEnabled) {
        // Confirm the current state for the side-effect of updating the time-in-state
        // counter for the current state.
        setState(currentState, timestamp);
        isEnabled = false;
    } else {
        // If the counter is being enabled with an out-of-order timestamp, just push back
        // the timestamp to avoid having the situation where
        // timeInStateSinceUpdate > timeSinceUpdate
        if (timestamp < lastUpdateTimestamp) {
            timestamp = lastUpdateTimestamp;
        }

        if (lastStateChangeTimestamp >= 0) {
            lastStateChangeTimestamp = timestamp;
        }
        isEnabled = true;
    }
}

template <class T>
void MultiStateCounter<T>::setState(state_t state, time_t timestamp) {
    if (isEnabled && lastStateChangeTimestamp >= 0 && lastUpdateTimestamp >= 0) {
        // If the update arrived out-of-order, just push back the timestamp to
        // avoid having the situation where timeInStateSinceUpdate > timeSinceUpdate
        if (timestamp < lastUpdateTimestamp) {
            timestamp = lastUpdateTimestamp;
        }

        if (timestamp >= lastStateChangeTimestamp) {
            states[currentState].timeInStateSinceUpdate += timestamp - lastStateChangeTimestamp;
        } else {
            ALOGE("setState is called with an earlier timestamp: %lu, previous timestamp: %lu\n",
                  (unsigned long)timestamp, (unsigned long)lastStateChangeTimestamp);
            // The accumulated durations have become unreliable. For example, if the timestamp
            // sequence was 1000, 2000, 1000, 3000, if we accumulated the positive deltas,
            // we would get 4000, which is greater than (last - first). This could lead to
            // counts exceeding 100%.
            for (int i = 0; i < stateCount; i++) {
                states[i].timeInStateSinceUpdate = 0;
            }
        }
    }
    currentState = state;
    lastStateChangeTimestamp = timestamp;
}

template <class T>
void MultiStateCounter<T>::setValue(state_t state, const T& value) {
    states[state].counter = value;
}

template <class T>
const T& MultiStateCounter<T>::updateValue(const T& value, time_t timestamp) {
    T* returnValue = &emptyValue;

    // If the counter is disabled, we ignore the update, except when the counter got disabled after
    // the previous update, in which case we still need to pick up the residual delta.
    if (isEnabled || lastUpdateTimestamp < lastStateChangeTimestamp) {
        // If the update arrived out of order, just push back the timestamp to
        // avoid having the situation where timeInStateSinceUpdate > timeSinceUpdate
        if (timestamp < lastStateChangeTimestamp) {
            timestamp = lastStateChangeTimestamp;
        }

        // Confirm the current state for the side-effect of updating the time-in-state
        // counter for the current state.
        setState(currentState, timestamp);

        if (lastUpdateTimestamp >= 0) {
            if (timestamp > lastUpdateTimestamp) {
                if (delta(lastValue, value, &deltaValue)) {
                    returnValue = &deltaValue;
                    time_t timeSinceUpdate = timestamp - lastUpdateTimestamp;
                    for (int i = 0; i < stateCount; i++) {
                        time_t timeInState = states[i].timeInStateSinceUpdate;
                        if (timeInState) {
                            add(&states[i].counter, deltaValue, timeInState, timeSinceUpdate);
                            states[i].timeInStateSinceUpdate = 0;
                        }
                    }
                } else {
                    std::stringstream str;
                    str << "updateValue is called with a value " << valueToString(value)
                        << ", which is lower than the previous value " << valueToString(lastValue)
                        << "\n";
                    ALOGE("%s", str.str().c_str());

                    for (int i = 0; i < stateCount; i++) {
                        states[i].timeInStateSinceUpdate = 0;
                    }
                }
            } else if (timestamp < lastUpdateTimestamp) {
                ALOGE("updateValue is called with an earlier timestamp: %lu, previous: %lu\n",
                      (unsigned long)timestamp, (unsigned long)lastUpdateTimestamp);

                for (int i = 0; i < stateCount; i++) {
                    states[i].timeInStateSinceUpdate = 0;
                }
            }
        }
    }
    lastValue = value;
    lastUpdateTimestamp = timestamp;
    return *returnValue;
}

template <class T>
void MultiStateCounter<T>::incrementValue(const T& increment, time_t timestamp) {
    T newValue = lastValue;
    add(&newValue, increment, 1 /* numerator */, 1 /* denominator */);
    updateValue(newValue, timestamp);
}

template <class T>
void MultiStateCounter<T>::addValue(const T& value) {
    if (!isEnabled) {
        return;
    }
    add(&states[currentState].counter, value, 1 /* numerator */, 1 /* denominator */);
}

template <class T>
void MultiStateCounter<T>::reset() {
    lastStateChangeTimestamp = -1;
    lastUpdateTimestamp = -1;
    for (int i = 0; i < stateCount; i++) {
        states[i].timeInStateSinceUpdate = 0;
        states[i].counter = emptyValue;
    }
}

template <class T>
uint16_t MultiStateCounter<T>::getStateCount() {
    return stateCount;
}

template <class T>
const T& MultiStateCounter<T>::getCount(state_t state) {
    return states[state].counter;
}

template <class T>
std::string MultiStateCounter<T>::toString() {
    std::stringstream str;
    str << "[";
    for (int i = 0; i < stateCount; i++) {
        if (i != 0) {
            str << ", ";
        }
        str << i << ": " << valueToString(states[i].counter);
        if (states[i].timeInStateSinceUpdate > 0) {
            str << " timeInStateSinceUpdate: " << states[i].timeInStateSinceUpdate;
        }
    }
    str << "]";
    if (lastUpdateTimestamp >= 0) {
        str << " updated: " << lastUpdateTimestamp;
    }
    if (lastStateChangeTimestamp >= 0) {
        str << " currentState: " << currentState;
        if (lastStateChangeTimestamp > lastUpdateTimestamp) {
            str << " stateChanged: " << lastStateChangeTimestamp;
        }
    } else {
        str << " currentState: none";
    }
    if (!isEnabled) {
        str << " disabled";
    }
    return str.str();
}

} // namespace battery
} // namespace android
