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

#ifndef _UI_INPUTREADER_MACROS_H
#define _UI_INPUTREADER_MACROS_H

#define LOG_TAG "InputReader"

//#define LOG_NDEBUG 0

// Log debug messages for each raw event received from the EventHub.
#define DEBUG_RAW_EVENTS 0

// Log debug messages about touch screen filtering hacks.
#define DEBUG_HACKS 0

// Log debug messages about virtual key processing.
#define DEBUG_VIRTUAL_KEYS 0

// Log debug messages about pointers.
#define DEBUG_POINTERS 0

// Log debug messages about pointer assignment calculations.
#define DEBUG_POINTER_ASSIGNMENT 0

// Log debug messages about gesture detection.
#define DEBUG_GESTURES 0

// Log debug messages about the vibrator.
#define DEBUG_VIBRATOR 0

// Log debug messages about fusing stylus data.
#define DEBUG_STYLUS_FUSION 0

#define INDENT "  "
#define INDENT2 "    "
#define INDENT3 "      "
#define INDENT4 "        "
#define INDENT5 "          "

#include <input/Input.h>

namespace android {

// --- Static Functions ---

template <typename T>
inline static T abs(const T& value) {
    return value < 0 ? -value : value;
}

template <typename T>
inline static T min(const T& a, const T& b) {
    return a < b ? a : b;
}

inline static float avg(float x, float y) {
    return (x + y) / 2;
}

static inline const char* toString(bool value) {
    return value ? "true" : "false";
}

static inline bool sourcesMatchMask(uint32_t sources, uint32_t sourceMask) {
    return (sources & sourceMask & ~AINPUT_SOURCE_CLASS_MASK) != 0;
}

} // namespace android

#endif // _UI_INPUTREADER_MACROS_H