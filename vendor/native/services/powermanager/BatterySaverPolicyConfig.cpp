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

#define LOG_TAG "BatterySaverPolicyConfig"

#include <android/BatterySaverPolicyConfig.h>
#include <binder/Parcel.h>
#include <utils/Log.h>

namespace android::os {

status_t BatterySaverPolicyConfig::readDeviceSpecificSettings(const android::Parcel *parcel) {
    int32_t num = 0;
    status_t ret = parcel->readInt32(&num);
    if (ret != OK) {
        return ret;
    }
    for (int i = 0; i < num; i++) {
        String16 key, val;
        ret = parcel->readString16(&key) ?:
              parcel->readString16(&val);
        if (ret != OK) {
           return ret;
        }
        mDeviceSpecificSettings.emplace_back(key, val);
    }
    return ret;
}

status_t BatterySaverPolicyConfig::readFromParcel(const android::Parcel *parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    return parcel->readFloat(&mAdjustBrightnessFactor)
        ?: parcel->readBool(&mAdvertiseIsEnabled)
        ?: parcel->readBool(&mDeferFullBackup)
        ?: parcel->readBool(&mDeferKeyValueBackup)
        ?: readDeviceSpecificSettings(parcel)
        ?: parcel->readBool(&mDisableAnimation)
        ?: parcel->readBool(&mDisableAod)
        ?: parcel->readBool(&mDisableLaunchBoost)
        ?: parcel->readBool(&mDisableOptionalSensors)
        ?: parcel->readBool(&mDisableVibration)
        ?: parcel->readBool(&mEnableAdjustBrightness)
        ?: parcel->readBool(&mEnableDataSaver)
        ?: parcel->readBool(&mEnableFirewall)
        ?: parcel->readBool(&mEnableNightMode)
        ?: parcel->readBool(&mEnableQuickDoze)
        ?: parcel->readBool(&mForceAllAppsStandby)
        ?: parcel->readBool(&mForceBackgroundCheck)
        ?: parcel->readInt32(reinterpret_cast<int32_t *>(&mLocationMode))
        ?: parcel->readInt32(reinterpret_cast<int32_t *>(&mSoundTriggerMode));
}

status_t BatterySaverPolicyConfig::writeDeviceSpecificSettings(android::Parcel *parcel) const {
    status_t ret = parcel->writeInt32(mDeviceSpecificSettings.size());
    if (ret != OK) {
        return ret;
    }
    for (auto& settings : mDeviceSpecificSettings) {
        ret = parcel->writeString16(settings.first) ?:
              parcel->writeString16(settings.second);
        if (ret != OK) {
           return ret;
        }
    }
    return ret;
}

status_t BatterySaverPolicyConfig::writeToParcel(android::Parcel *parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __func__);
        return BAD_VALUE;
    }

    return parcel->writeFloat(mAdjustBrightnessFactor)
        ?: parcel->writeBool(mAdvertiseIsEnabled)
        ?: parcel->writeBool(mDeferFullBackup)
        ?: parcel->writeBool(mDeferKeyValueBackup)
        ?: writeDeviceSpecificSettings(parcel)
        ?: parcel->writeBool(mDisableAnimation)
        ?: parcel->writeBool(mDisableAod)
        ?: parcel->writeBool(mDisableLaunchBoost)
        ?: parcel->writeBool(mDisableOptionalSensors)
        ?: parcel->writeBool(mDisableVibration)
        ?: parcel->writeBool(mEnableAdjustBrightness)
        ?: parcel->writeBool(mEnableDataSaver)
        ?: parcel->writeBool(mEnableFirewall)
        ?: parcel->writeBool(mEnableNightMode)
        ?: parcel->writeBool(mEnableQuickDoze)
        ?: parcel->writeBool(mForceAllAppsStandby)
        ?: parcel->writeBool(mForceBackgroundCheck)
        ?: parcel->writeInt32(static_cast<int32_t>(mLocationMode))
        ?: parcel->writeInt32(static_cast<int32_t>(mSoundTriggerMode));
}

} // namespace android::os
