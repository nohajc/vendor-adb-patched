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

#include "Connection.h"

#include "Entry.h"

namespace android::inputdispatcher {

Connection::Connection(const sp<InputChannel>& inputChannel, bool monitor,
                       const IdGenerator& idGenerator)
      : status(STATUS_NORMAL),
        inputChannel(inputChannel),
        monitor(monitor),
        inputPublisher(inputChannel),
        inputState(idGenerator) {}

Connection::~Connection() {}

const std::string Connection::getWindowName() const {
    if (inputChannel != nullptr) {
        return inputChannel->getName();
    }
    if (monitor) {
        return "monitor";
    }
    return "?";
}

const char* Connection::getStatusLabel() const {
    switch (status) {
        case STATUS_NORMAL:
            return "NORMAL";
        case STATUS_BROKEN:
            return "BROKEN";
        case STATUS_ZOMBIE:
            return "ZOMBIE";
        default:
            return "UNKNOWN";
    }
}

std::deque<DispatchEntry*>::iterator Connection::findWaitQueueEntry(uint32_t seq) {
    for (std::deque<DispatchEntry*>::iterator it = waitQueue.begin(); it != waitQueue.end(); it++) {
        if ((*it)->seq == seq) {
            return it;
        }
    }
    return waitQueue.end();
}

} // namespace android::inputdispatcher
