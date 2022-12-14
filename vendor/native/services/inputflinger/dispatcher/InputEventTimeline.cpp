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

#include "InputEventTimeline.h"

namespace android::inputdispatcher {

ConnectionTimeline::ConnectionTimeline(nsecs_t deliveryTime, nsecs_t consumeTime,
                                       nsecs_t finishTime)
      : deliveryTime(deliveryTime),
        consumeTime(consumeTime),
        finishTime(finishTime),
        mHasDispatchTimeline(true) {}

ConnectionTimeline::ConnectionTimeline(std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline)
      : graphicsTimeline(std::move(graphicsTimeline)), mHasGraphicsTimeline(true) {}

bool ConnectionTimeline::isComplete() const {
    return mHasDispatchTimeline && mHasGraphicsTimeline;
}

bool ConnectionTimeline::setDispatchTimeline(nsecs_t inDeliveryTime, nsecs_t inConsumeTime,
                                             nsecs_t inFinishTime) {
    if (mHasDispatchTimeline) {
        return false;
    }
    deliveryTime = inDeliveryTime;
    consumeTime = inConsumeTime;
    finishTime = inFinishTime;
    mHasDispatchTimeline = true;
    return true;
}

bool ConnectionTimeline::setGraphicsTimeline(std::array<nsecs_t, GraphicsTimeline::SIZE> timeline) {
    if (mHasGraphicsTimeline) {
        return false;
    }
    graphicsTimeline = std::move(timeline);
    mHasGraphicsTimeline = true;
    return true;
}

bool ConnectionTimeline::operator==(const ConnectionTimeline& rhs) const {
    return deliveryTime == rhs.deliveryTime && consumeTime == rhs.consumeTime &&
            finishTime == rhs.finishTime && graphicsTimeline == rhs.graphicsTimeline &&
            mHasDispatchTimeline == rhs.mHasDispatchTimeline &&
            mHasGraphicsTimeline == rhs.mHasGraphicsTimeline;
}

bool ConnectionTimeline::operator!=(const ConnectionTimeline& rhs) const {
    return !operator==(rhs);
}

InputEventTimeline::InputEventTimeline(bool isDown, nsecs_t eventTime, nsecs_t readTime)
      : isDown(isDown), eventTime(eventTime), readTime(readTime) {}

bool InputEventTimeline::operator==(const InputEventTimeline& rhs) const {
    if (connectionTimelines.size() != rhs.connectionTimelines.size()) {
        return false;
    }
    for (const auto& [connectionToken, connectionTimeline] : connectionTimelines) {
        auto it = rhs.connectionTimelines.find(connectionToken);
        if (it == rhs.connectionTimelines.end()) {
            return false;
        }
        if (connectionTimeline != it->second) {
            return false;
        }
    }
    return isDown == rhs.isDown && eventTime == rhs.eventTime && readTime == rhs.readTime;
}

} // namespace android::inputdispatcher
