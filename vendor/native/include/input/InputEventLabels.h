/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _LIBINPUT_INPUT_EVENT_LABELS_H
#define _LIBINPUT_INPUT_EVENT_LABELS_H

#include <input/Input.h>
#include <android/keycodes.h>
#include <unordered_map>

namespace android {

template<typename T, size_t N>
size_t size(T (&)[N]) { return N; }

struct InputEventLabel {
    const char *literal;
    int value;
};

//   NOTE: If you want a new key code, axis code, led code or flag code in keylayout file,
//   then you must add it to InputEventLabels.cpp.

class InputEventLookup {
public:
    static int lookupValueByLabel(const std::unordered_map<std::string, int>& map,
                                  const char* literal);

    static const char* lookupLabelByValue(const std::vector<InputEventLabel>& vec, int value);

    static int32_t getKeyCodeByLabel(const char* label);

    static const char* getLabelByKeyCode(int32_t keyCode);

    static uint32_t getKeyFlagByLabel(const char* label);

    static int32_t getAxisByLabel(const char* label);

    static const char* getAxisLabel(int32_t axisId);

    static int32_t getLedByLabel(const char* label);

private:
    static const std::unordered_map<std::string, int> KEYCODES;

    static const std::vector<InputEventLabel> KEY_NAMES;

    static const std::unordered_map<std::string, int> AXES;

    static const std::vector<InputEventLabel> AXES_NAMES;

    static const std::unordered_map<std::string, int> LEDS;

    static const std::unordered_map<std::string, int> FLAGS;
};

} // namespace android
#endif // _LIBINPUT_INPUT_EVENT_LABELS_H
