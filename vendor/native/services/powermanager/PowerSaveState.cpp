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

#define LOG_TAG "PowerSaveState"

#include <android/PowerSaveState.h>
#include <binder/Parcel.h>
#include <utils/Log.h>

namespace android::os {

status_t PowerSaveState::readFromParcel(const android::Parcel *parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    return parcel->readBool(&mBatterySaverEnabled)
        ?: parcel->readBool(&mGlobalBatterySaverEnabled)
        ?: parcel->readInt32(reinterpret_cast<int32_t *>(&mLocationMode))
        ?: parcel->readInt32(reinterpret_cast<int32_t *>(&mSoundTriggerMode))
        ?: parcel->readFloat(&mBrightnessFactor);
}

status_t PowerSaveState::writeToParcel(android::Parcel *parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    return parcel->writeBool(mBatterySaverEnabled)
        ?: parcel->writeBool(mGlobalBatterySaverEnabled)
        ?: parcel->writeInt32(static_cast<int32_t>(mLocationMode))
        ?: parcel->writeInt32(static_cast<int32_t>(mSoundTriggerMode))
        ?: parcel->writeFloat(mBrightnessFactor);
}

} // namespace android::os
