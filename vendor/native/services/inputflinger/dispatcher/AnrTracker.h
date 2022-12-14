/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef _UI_INPUT_INPUTDISPATCHER_ANRTRACKER_H
#define _UI_INPUT_INPUTDISPATCHER_ANRTRACKER_H

#include <binder/IBinder.h>
#include <utils/Timers.h>
#include <set>

namespace android::inputdispatcher {

/**
 * Keeps track of the times when each connection is going to ANR.
 * Provides the ability to quickly find the connection that is going to cause ANR next.
 */
class AnrTracker {
public:
    void insert(nsecs_t timeoutTime, sp<IBinder> token);
    void erase(nsecs_t timeoutTime, const sp<IBinder>& token);
    void eraseToken(const sp<IBinder>& token);
    void clear();

    bool empty() const;
    // If empty() is false, return the time at which the next connection should cause an ANR
    // If empty() is true, return LONG_LONG_MAX
    nsecs_t firstTimeout() const;
    // Return the token of the next connection that should cause an ANR.
    // Do not call this unless empty() is false, you will encounter undefined behaviour.
    const sp<IBinder>& firstToken() const;

private:
    // Optimization: use a multiset to keep track of the event timeouts. When an event is sent
    // to the InputConsumer, we add an entry to this structure. We look at the smallest value to
    // determine if any of the connections is unresponsive, and to determine when we should wake
    // next for the future ANR check.
    // Using a multiset helps quickly look up the next timeout due.
    //
    // We must use a multi-set, because it is plausible (although highly unlikely) to have entries
    // from the same connection and same timestamp, but different sequence numbers.
    // We are not tracking sequence numbers, and just allow duplicates to exist.
    std::multiset<std::pair<nsecs_t /*timeoutTime*/, sp<IBinder> /*connectionToken*/>> mAnrTimeouts;
};

} // namespace android::inputdispatcher

#endif // _UI_INPUT_INPUTDISPATCHER_ANRTRACKER_H
