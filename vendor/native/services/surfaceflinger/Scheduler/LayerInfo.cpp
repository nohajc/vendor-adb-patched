/*
 * Copyright 2019 The Android Open Source Project
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

#include "LayerInfo.h"

#include <algorithm>
#include <utility>

namespace android::scheduler {

LayerInfo::LayerInfo(float lowRefreshRate, float highRefreshRate)
      : mLowRefreshRate(lowRefreshRate), mHighRefreshRate(highRefreshRate) {}

void LayerInfo::setLastPresentTime(nsecs_t lastPresentTime, nsecs_t now) {
    lastPresentTime = std::max(lastPresentTime, static_cast<nsecs_t>(0));

    // Buffers can come with a present time far in the future. That keeps them relevant.
    mLastUpdatedTime = std::max(lastPresentTime, now);
    mPresentTimeHistory.insertPresentTime(mLastUpdatedTime);

    if (mLastPresentTime == 0) {
        // First frame
        mLastPresentTime = lastPresentTime;
        return;
    }

    const nsecs_t period = lastPresentTime - mLastPresentTime;
    mLastPresentTime = lastPresentTime;
    // Ignore time diff that are too high - those are stale values
    if (period > MAX_ACTIVE_LAYER_PERIOD_NS.count()) return;

    const float fps = std::min(1e9f / period, mHighRefreshRate);
    mRefreshRateHistory.insertRefreshRate(fps);
}

} // namespace android::scheduler
