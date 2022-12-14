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

#ifndef _UI_INPUT_INPUTDISPATCHER_INJECTIONSTATE_H
#define _UI_INPUT_INPUTDISPATCHER_INJECTIONSTATE_H

#include "InputDispatcherInterface.h"

#include <stdint.h>

namespace android::inputdispatcher {

/*
 * Constants used to determine the input event injection synchronization mode.
 */
enum {
    /* Injection is asynchronous and is assumed always to be successful. */
    INPUT_EVENT_INJECTION_SYNC_NONE = 0,

    /* Waits for previous events to be dispatched so that the input dispatcher can determine
     * whether input event injection willbe permitted based on the current input focus.
     * Does not wait for the input event to finish processing. */
    INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_RESULT = 1,

    /* Waits for the input event to be completely processed. */
    INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_FINISHED = 2,
};

struct InjectionState {
    mutable int32_t refCount;

    int32_t injectorPid;
    int32_t injectorUid;
    int32_t injectionResult;             // initially INPUT_EVENT_INJECTION_PENDING
    bool injectionIsAsync;               // set to true if injection is not waiting for the result
    int32_t pendingForegroundDispatches; // the number of foreground dispatches in progress

    InjectionState(int32_t injectorPid, int32_t injectorUid);
    void release();

private:
    ~InjectionState();
};

} // namespace android::inputdispatcher

#endif // _UI_INPUT_INPUTDISPATCHER_INJECTIONSTATE_H
