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

#ifndef ANDROID_OS_TEMPERATURE_H
#define ANDROID_OS_TEMPERATURE_H

#include <binder/Parcelable.h>
#include <utils/RefBase.h>

namespace android {
namespace os {

/**
 * Temperature is a structure to encapsulate temperature status.
 */
struct Temperature : public android::Parcelable {
    /** Temperature value */
    float mValue;
    /** A Temperature type from ThermalHAL */
    int32_t mType;
    /** Name of this Temperature */
    String16 mName;
    /** The level of the sensor is currently in throttling */
    int32_t mStatus;

    Temperature()
        : mValue(0.0f),
          mType(0),
          mName(""),
          mStatus(0) {
    }

    virtual status_t readFromParcel(const android::Parcel* parcel) override;
    virtual status_t writeToParcel(android::Parcel* parcel) const override;
};

} // namespace os
} // namespace android

#endif /* ANDROID_OS_TEMPERATURE_H */
