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

#ifndef _UI_INPUT_INPUTDISPATCHER_CONNECTION_H
#define _UI_INPUT_INPUTDISPATCHER_CONNECTION_H

#include "InputState.h"

#include <input/InputTransport.h>
#include <deque>

namespace android::inputdispatcher {

struct DispatchEntry;

/* Manages the dispatch state associated with a single input channel. */
class Connection : public RefBase {
protected:
    virtual ~Connection();

public:
    enum Status {
        // Everything is peachy.
        STATUS_NORMAL,
        // An unrecoverable communication error has occurred.
        STATUS_BROKEN,
        // The input channel has been unregistered.
        STATUS_ZOMBIE
    };

    Status status;
    sp<InputChannel> inputChannel; // never null
    bool monitor;
    InputPublisher inputPublisher;
    InputState inputState;

    // True if this connection is responsive.
    // If this connection is not responsive, avoid publishing more events to it until the
    // application consumes some of the input.
    bool responsive = true;

    // Queue of events that need to be published to the connection.
    std::deque<DispatchEntry*> outboundQueue;

    // Queue of events that have been published to the connection but that have not
    // yet received a "finished" response from the application.
    std::deque<DispatchEntry*> waitQueue;

    Connection(const sp<InputChannel>& inputChannel, bool monitor, const IdGenerator& idGenerator);

    inline const std::string getInputChannelName() const { return inputChannel->getName(); }

    const std::string getWindowName() const;
    const char* getStatusLabel() const;

    std::deque<DispatchEntry*>::iterator findWaitQueueEntry(uint32_t seq);
};

} // namespace android::inputdispatcher

#endif // _UI_INPUT_INPUTDISPATCHER_CONNECTION_H
