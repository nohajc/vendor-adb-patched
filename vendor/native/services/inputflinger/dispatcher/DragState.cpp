/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "DragState.h"
#include <android-base/stringprintf.h>

using android::base::StringPrintf;

namespace android::inputdispatcher {

void DragState::dump(std::string& dump, const char* prefix) {
    dump += prefix + StringPrintf("Drag Window: %s\n", dragWindow->getName().c_str());
    if (dragHoverWindowHandle) {
        dump += prefix +
                StringPrintf("Drag Hover Window: %s\n", dragHoverWindowHandle->getName().c_str());
    }
    dump += prefix + StringPrintf("isStartDrag: %s\n", isStartDrag ? "true" : "false");
    dump += prefix +
            StringPrintf("isStylusButtonDownAtStart: %s\n",
                         isStylusButtonDownAtStart ? "true" : "false");
}

} // namespace android::inputdispatcher