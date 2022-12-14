/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "PrintTools"

#include <input/PrintTools.h>
#include <sstream>

namespace android {

const char* toString(bool value) {
    return value ? "true" : "false";
}

std::string addLinePrefix(std::string str, const std::string& prefix) {
    std::stringstream ss;
    bool newLineStarted = true;
    for (const auto& ch : str) {
        if (newLineStarted) {
            ss << prefix;
            newLineStarted = false;
        }
        if (ch == '\n') {
            newLineStarted = true;
        }
        ss << ch;
    }
    return ss.str();
}

} // namespace android
