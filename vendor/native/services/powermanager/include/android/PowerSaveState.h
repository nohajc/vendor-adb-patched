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

#ifndef ANDROID_OS_POWER_SAVE_STATE_H
#define ANDROID_OS_POWER_SAVE_STATE_H

#include <math.h>
#include <binder/Parcelable.h>
#include <utils/RefBase.h>

namespace android::os {

enum class LocationMode : int32_t;
enum class SoundTriggerMode : int32_t;
/**
 * PowerSaveState is a structure to encapsulate PowerSaveState status.
 * This file needs to be kept in sync with frameworks/base/core/java/android/os/PowerSaveState.java
 */
struct PowerSaveState : public android::Parcelable {

    PowerSaveState(bool batterySaverEnabled = false,
                   bool globalBatterySaverEnabled = false,
                   LocationMode locationMode = static_cast<LocationMode>(0),
                   SoundTriggerMode soundTriggerMode = static_cast<SoundTriggerMode>(0),
                   float brightnessFactor = 0.5f)
            : mBatterySaverEnabled(batterySaverEnabled),
              mGlobalBatterySaverEnabled(globalBatterySaverEnabled),
              mLocationMode(locationMode),
              mSoundTriggerMode(soundTriggerMode),
              mBrightnessFactor(brightnessFactor) {
    }

    bool getBatterySaverEnabled() const { return mBatterySaverEnabled; }
    bool getGlobalBatterySaverEnabled() const { return mGlobalBatterySaverEnabled; }
    LocationMode getLocationMode() const { return mLocationMode; }
    SoundTriggerMode getSoundTriggerMode() const { return mSoundTriggerMode; }
    float getBrightnessFactor() const { return mBrightnessFactor; }
    bool operator == (const PowerSaveState &ps) const {
        return mBatterySaverEnabled == ps.mBatterySaverEnabled &&
               mGlobalBatterySaverEnabled == ps.mGlobalBatterySaverEnabled &&
               mLocationMode == ps.mLocationMode &&
               fabs(mBrightnessFactor - ps.mBrightnessFactor) == 0.0f;
    }

    status_t readFromParcel(const android::Parcel* parcel) override;
    status_t writeToParcel(android::Parcel* parcel) const override;

private:
    /** Whether we should enable battery saver for this service. */
    bool mBatterySaverEnabled;
    /** Whether battery saver mode is enabled. */
    bool mGlobalBatterySaverEnabled;
    /** Location mode */
    LocationMode mLocationMode;
    /** SoundTrigger mode */
    SoundTriggerMode mSoundTriggerMode;
    /** Screen brightness factor. */
    float mBrightnessFactor;
};

} // namespace android::os

#endif /* ANDROID_OS_POWER_SAVE_STATE_H */
