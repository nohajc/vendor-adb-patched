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

#ifndef ANDROID_OS_PARCELDURATION_H
#define ANDROID_OS_PARCELDURATION_H

#include <binder/Parcelable.h>
#include <math.h>
#include <utils/RefBase.h>

namespace android::os {

/**
 * Parcelable version of {@link java.time.Duration} that can be used in binder calls.
 * This file needs to be kept in sync with
 * frameworks/base/core/java/android/os/ParcelDuration.java
 */
struct ParcelDuration : public android::Parcelable {
    ParcelDuration(int64_t seconds = 0, int32_t nanos = 0) : mSeconds(seconds), mNanos(nanos) {}

    status_t readFromParcel(const android::Parcel* parcel) override;
    status_t writeToParcel(android::Parcel* parcel) const override;
    bool operator==(const ParcelDuration& pd) const {
        return mSeconds == pd.mSeconds && mNanos == pd.mNanos;
    }

private:
    int64_t mSeconds;
    int32_t mNanos;
};

} // namespace android::os

#endif /* ANDROID_OS_PARCELDURATION_H */
