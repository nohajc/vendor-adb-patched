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
static constexpr bool DEBUG_RAW_EVENTS = false;

// Log debug messages about virtual key processing.
static constexpr bool DEBUG_VIRTUAL_KEYS = false;

// Log debug messages about pointers.
static constexpr bool DEBUG_POINTERS = false;

// Log debug messages about pointer assignment calculations.
static constexpr bool DEBUG_POINTER_ASSIGNMENT = false;

// Log debug messages about gesture detection.
static constexpr bool DEBUG_GESTURES = false;

// Log debug messages about the vibrator.
static constexpr bool DEBUG_VIBRATOR = false;

// Log debug messages about fusing stylus data.
static constexpr bool DEBUG_STYLUS_FUSION = false;

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