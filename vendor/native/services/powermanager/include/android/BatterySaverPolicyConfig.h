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

#ifndef ANDROID_OS_BATTERY_SAVER_POLICY_CONFIG_H
#define ANDROID_OS_BATTERY_SAVER_POLICY_CONFIG_H

#include <math.h>
#include <binder/Parcelable.h>
#include <utils/RefBase.h>

namespace android::os {

enum class LocationMode : int32_t;
enum class SoundTriggerMode : int32_t;
/**
 * BatterySaverPolicyConfig is a structure of configs to set Battery Saver policy flags.
 * This file needs to be kept in sync with
 * frameworks/base/core/java/android/os/BatterySaverPolicyConfig.java
 */
struct BatterySaverPolicyConfig : public android::Parcelable {

    BatterySaverPolicyConfig(float adjustBrightnessFactor = 1.0f,
                             bool advertiseIsEnabled = false,
                             bool deferFullBackup = false,
                             bool deferKeyValueBackup = false,
                             std::vector<std::pair<String16, String16>> deviceSpecificSettings = {},
                             bool disableAnimation = false,
                             bool disableAod = false,
                             bool disableLaunchBoost = false,
                             bool disableOptionalSensors = false,
                             bool disableVibration = false,
                             bool enableAdjustBrightness = false,
                             bool enableDataSaver = false,
                             bool enableFirewall = false,
                             bool enableNightMode = false,
                             bool enableQuickDoze = false,
                             bool forceAllAppsStandby = false,
                             bool forceBackgroundCheck = false,
                             LocationMode locationMode = static_cast<LocationMode>(0),
                             SoundTriggerMode soundTriggerMode = static_cast<SoundTriggerMode>(0))
        : mAdjustBrightnessFactor(adjustBrightnessFactor),
          mAdvertiseIsEnabled(advertiseIsEnabled),
          mDeferFullBackup(deferFullBackup),
          mDeferKeyValueBackup(deferKeyValueBackup),
          mDeviceSpecificSettings(deviceSpecificSettings),
          mDisableAnimation(disableAnimation),
          mDisableAod(disableAod),
          mDisableLaunchBoost(disableLaunchBoost),
          mDisableOptionalSensors(disableOptionalSensors),
          mDisableVibration(disableVibration),
          mEnableAdjustBrightness(enableAdjustBrightness),
          mEnableDataSaver(enableDataSaver),
          mEnableFirewall(enableFirewall),
          mEnableNightMode(enableNightMode),
          mEnableQuickDoze(enableQuickDoze),
          mForceAllAppsStandby(forceAllAppsStandby),
          mForceBackgroundCheck(forceBackgroundCheck),
          mLocationMode(locationMode),
          mSoundTriggerMode(soundTriggerMode) {
    }

    status_t readFromParcel(const android::Parcel* parcel) override;
    status_t writeToParcel(android::Parcel* parcel) const override;
    bool operator == (const BatterySaverPolicyConfig &bsp) const {
        return fabs(mAdjustBrightnessFactor - bsp.mAdjustBrightnessFactor) == 0.0f &&
               mAdvertiseIsEnabled == bsp.mAdvertiseIsEnabled &&
               mDeferFullBackup == bsp.mDeferFullBackup &&
               mDeferKeyValueBackup == bsp.mDeferKeyValueBackup &&
               mDeviceSpecificSettings == bsp.mDeviceSpecificSettings &&
               mDisableAnimation == bsp.mDisableAnimation &&
               mDisableAod == bsp.mDisableAod &&
               mDisableLaunchBoost == bsp.mDisableLaunchBoost &&
               mDisableOptionalSensors == bsp.mDisableOptionalSensors &&
               mDisableVibration == bsp.mDisableVibration &&
               mEnableAdjustBrightness == bsp.mEnableAdjustBrightness &&
               mEnableDataSaver == bsp.mEnableDataSaver &&
               mEnableFirewall == bsp.mEnableFirewall &&
               mEnableNightMode == bsp.mEnableNightMode &&
               mEnableQuickDoze == bsp.mEnableQuickDoze &&
               mForceAllAppsStandby == bsp.mForceAllAppsStandby &&
               mForceBackgroundCheck == bsp.mForceBackgroundCheck &&
               mLocationMode == bsp.mLocationMode &&
               mSoundTriggerMode == bsp.mSoundTriggerMode;
    }

private:
    status_t readDeviceSpecificSettings(const android::Parcel *parcel);
    status_t writeDeviceSpecificSettings(android::Parcel *parcel) const;
    /** Adjust screen brightness factor */
    float mAdjustBrightnessFactor;
    /** Is advertise enabled */
    bool mAdvertiseIsEnabled;
    /** Defer full backup */
    bool mDeferFullBackup;
    /** Defer key value backup */
    bool mDeferKeyValueBackup;
    /** Device specific settings */
    std::vector<std::pair<String16, String16>> mDeviceSpecificSettings;
    /** Disable animation */
    bool mDisableAnimation;
    /** Disable Aod */
    bool mDisableAod;
    /** Disable launch boost */
    bool mDisableLaunchBoost;
    /** Disable optional sensors */
    bool mDisableOptionalSensors;
    /** Disable vibration */
    bool mDisableVibration;
    /** Enable adjust brightness */
    bool mEnableAdjustBrightness;
    /** Enable data saver */
    bool mEnableDataSaver;
    /** Enable firewall */
    bool mEnableFirewall;
    /** Enable night mode */
    bool mEnableNightMode;
    /** Enable quick doze */
    bool mEnableQuickDoze;
    /** Force all Apps standby */
    bool mForceAllAppsStandby;
    /** Force Background check */
    bool mForceBackgroundCheck;
    /** Location mode */
    LocationMode mLocationMode;
    /** SoundTrigger mode */
    SoundTriggerMode mSoundTriggerMode;
};

} // namespace android::os

#endif /* ANDROID_OS_BATTERY_SAVER_POLICY_CONFIG_H */
