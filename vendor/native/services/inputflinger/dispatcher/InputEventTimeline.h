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

#ifndef _UI_INPUT_INPUTDISPATCHER_INPUTEVENTTIMELINE_H
#define _UI_INPUT_INPUTDISPATCHER_INPUTEVENTTIMELINE_H

#include <binder/IBinder.h>
#include <input/Input.h>
#include <unordered_map>

namespace android {

namespace inputdispatcher {

/**
 * Describes the input event timeline for each connection.
 * An event with the same inputEventId can go to more than 1 connection simultaneously.
 * For each connection that the input event goes to, there will be a separate ConnectionTimeline
 * created.
 * To create a complete ConnectionTimeline, we must receive two calls:
 * 1) setDispatchTimeline
 * 2) setGraphicsTimeline
 *
 * In a typical scenario, the dispatch timeline is known first. Later, if a frame is produced, the
 * graphics timeline is available.
 */
struct ConnectionTimeline {
    // DispatchTimeline
    nsecs_t deliveryTime; // time at which the event was sent to the receiver
    nsecs_t consumeTime;  // time at which the receiver read the event
    nsecs_t finishTime;   // time at which the finish event was received
    // GraphicsTimeline
    std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;

    ConnectionTimeline(nsecs_t deliveryTime, nsecs_t consumeTime, nsecs_t finishTime);
    ConnectionTimeline(std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline);

    /**
     * True if all contained timestamps are valid, false otherwise.
     */
    bool isComplete() const;
    /**
     * Set the dispatching-related times. Return true if the operation succeeded, false if the
     * dispatching times have already been set. If this function returns false, it likely indicates
     * an error from the app side.
     */
    bool setDispatchTimeline(nsecs_t deliveryTime, nsecs_t consumeTime, nsecs_t finishTime);
    /**
     * Set the graphics-related times. Return true if the operation succeeded, false if the
     * graphics times have already been set. If this function returns false, it likely indicates
     * an error from the app side.
     */
    bool setGraphicsTimeline(std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline);

    inline bool operator==(const ConnectionTimeline& rhs) const;
    inline bool operator!=(const ConnectionTimeline& rhs) const;

private:
    bool mHasDispatchTimeline = false;
    bool mHasGraphicsTimeline = false;
};

struct InputEventTimeline {
    InputEventTimeline(bool isDown, nsecs_t eventTime, nsecs_t readTime);
    const bool isDown; // True if this is an ACTION_DOWN event
    const nsecs_t eventTime;
    const nsecs_t readTime;

    struct IBinderHash {
        std::size_t operator()(const sp<IBinder>& b) const {
            return std::hash<IBinder*>{}(b.get());
        }
    };

    std::unordered_map<sp<IBinder>, ConnectionTimeline, IBinderHash> connectionTimelines;

    bool operator==(const InputEventTimeline& rhs) const;
};

class InputEventTimelineProcessor {
protected:
    InputEventTimelineProcessor() {}
    virtual ~InputEventTimelineProcessor() {}

public:
    /**
     * Process the provided timeline
     */
    virtual void processTimeline(const InputEventTimeline& timeline) = 0;
};

} // namespace inputdispatcher
} // namespace android

#endif // _UI_INPUT_INPUTDISPATCHER_INPUTEVENTTIMELINE_H
