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

#include "InputTarget.h"

#include <android-base/stringprintf.h>
#include <inttypes.h>
#include <string>

using android::base::StringPrintf;

namespace android::inputdispatcher {

std::string dispatchModeToString(int32_t dispatchMode) {
    switch (dispatchMode) {
        case InputTarget::FLAG_DISPATCH_AS_IS:
            return "DISPATCH_AS_IS";
        case InputTarget::FLAG_DISPATCH_AS_OUTSIDE:
            return "DISPATCH_AS_OUTSIDE";
        case InputTarget::FLAG_DISPATCH_AS_HOVER_ENTER:
            return "DISPATCH_AS_HOVER_ENTER";
        case InputTarget::FLAG_DISPATCH_AS_HOVER_EXIT:
            return "DISPATCH_AS_HOVER_EXIT";
        case InputTarget::FLAG_DISPATCH_AS_SLIPPERY_EXIT:
            return "DISPATCH_AS_SLIPPERY_EXIT";
        case InputTarget::FLAG_DISPATCH_AS_SLIPPERY_ENTER:
            return "DISPATCH_AS_SLIPPERY_ENTER";
    }
    return StringPrintf("%" PRId32, dispatchMode);
}

void InputTarget::addPointers(BitSet32 newPointerIds, float xOffset, float yOffset,
                              float windowXScale, float windowYScale) {
    // The pointerIds can be empty, but still a valid InputTarget. This can happen for Monitors
    // and non splittable windows since we will just use all the pointers from the input event.
    if (newPointerIds.isEmpty()) {
        setDefaultPointerInfo(xOffset, yOffset, windowXScale, windowYScale);
        return;
    }

    // Ensure that the new set of pointers doesn't overlap with the current set of pointers.
    ALOG_ASSERT((pointerIds & newPointerIds) == 0);

    pointerIds |= newPointerIds;
    while (!newPointerIds.isEmpty()) {
        int32_t pointerId = newPointerIds.clearFirstMarkedBit();
        pointerInfos[pointerId].xOffset = xOffset;
        pointerInfos[pointerId].yOffset = yOffset;
        pointerInfos[pointerId].windowXScale = windowXScale;
        pointerInfos[pointerId].windowYScale = windowYScale;
    }
}

void InputTarget::setDefaultPointerInfo(float xOffset, float yOffset, float windowXScale,
                                        float windowYScale) {
    pointerIds.clear();
    pointerInfos[0].xOffset = xOffset;
    pointerInfos[0].yOffset = yOffset;
    pointerInfos[0].windowXScale = windowXScale;
    pointerInfos[0].windowYScale = windowYScale;
}

bool InputTarget::useDefaultPointerInfo() const {
    return pointerIds.isEmpty();
}

const PointerInfo& InputTarget::getDefaultPointerInfo() const {
    return pointerInfos[0];
}

std::string InputTarget::getPointerInfoString() const {
    if (useDefaultPointerInfo()) {
        const PointerInfo& pointerInfo = getDefaultPointerInfo();
        return StringPrintf("xOffset=%.1f, yOffset=%.1f windowScaleFactor=(%.1f, %.1f)",
                            pointerInfo.xOffset, pointerInfo.yOffset, pointerInfo.windowXScale,
                            pointerInfo.windowYScale);
    }

    std::string out;
    for (uint32_t i = pointerIds.firstMarkedBit(); i <= pointerIds.lastMarkedBit(); i++) {
        if (!pointerIds.hasBit(i)) {
            continue;
        }
        out += StringPrintf("\n  pointerId %d: xOffset=%.1f, yOffset=%.1f "
                            "windowScaleFactor=(%.1f, %.1f)",
                            i, pointerInfos[i].xOffset, pointerInfos[i].yOffset,
                            pointerInfos[i].windowXScale, pointerInfos[i].windowYScale);
    }
    return out;
}
} // namespace android::inputdispatcher
