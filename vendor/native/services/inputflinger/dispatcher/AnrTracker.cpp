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

#include "AnrTracker.h"

namespace android::inputdispatcher {

template <typename T>
static T max(const T& a, const T& b) {
    return a < b ? b : a;
}

void AnrTracker::insert(nsecs_t timeoutTime, sp<IBinder> token) {
    mAnrTimeouts.insert(std::make_pair(timeoutTime, std::move(token)));
}

/**
 * Erase a single entry only. If there are multiple duplicate entries
 * (same time, same connection), then only remove one of them.
 */
void AnrTracker::erase(nsecs_t timeoutTime, const sp<IBinder>& token) {
    auto pair = std::make_pair(timeoutTime, token);
    auto it = mAnrTimeouts.find(pair);
    if (it != mAnrTimeouts.end()) {
        mAnrTimeouts.erase(it);
    }
}

void AnrTracker::eraseToken(const sp<IBinder>& token) {
    for (auto it = mAnrTimeouts.begin(); it != mAnrTimeouts.end();) {
        if (it->second == token) {
            it = mAnrTimeouts.erase(it);
        } else {
            ++it;
        }
    }
}

bool AnrTracker::empty() const {
    return mAnrTimeouts.empty();
}

// If empty() is false, return the time at which the next connection should cause an ANR
// If empty() is true, return LONG_LONG_MAX
nsecs_t AnrTracker::firstTimeout() const {
    if (mAnrTimeouts.empty()) {
        return std::numeric_limits<nsecs_t>::max();
    }
    return mAnrTimeouts.begin()->first;
}

const sp<IBinder>& AnrTracker::firstToken() const {
    return mAnrTimeouts.begin()->second;
}

void AnrTracker::clear() {
    mAnrTimeouts.clear();
}

} // namespace android::inputdispatcher
