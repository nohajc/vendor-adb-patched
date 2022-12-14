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

#include "InjectionState.h"

#include <log/log.h>

namespace android::inputdispatcher {

InjectionState::InjectionState(int32_t injectorPid, int32_t injectorUid)
      : refCount(1),
        injectorPid(injectorPid),
        injectorUid(injectorUid),
        injectionResult(INPUT_EVENT_INJECTION_PENDING),
        injectionIsAsync(false),
        pendingForegroundDispatches(0) {}

InjectionState::~InjectionState() {}

void InjectionState::release() {
    refCount -= 1;
    if (refCount == 0) {
        delete this;
    } else {
        ALOG_ASSERT(refCount > 0);
    }
}

} // namespace android::inputdispatcher
