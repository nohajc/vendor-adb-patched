/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <vibrator/ExternalVibration.h>
#include <vibrator/ExternalVibrationUtils.h>

#include <android/os/IExternalVibratorService.h>
#include <binder/Parcel.h>
#include <log/log.h>
#include <utils/Errors.h>


// To guarantee if HapticScale enum has the same value as IExternalVibratorService
static_assert(static_cast<int>(android::os::HapticScale::MUTE) == static_cast<int>(android::os::IExternalVibratorService::SCALE_MUTE));
static_assert(static_cast<int>(android::os::HapticScale::VERY_LOW) == static_cast<int>(android::os::IExternalVibratorService::SCALE_VERY_LOW));
static_assert(static_cast<int>(android::os::HapticScale::LOW) == static_cast<int>(android::os::IExternalVibratorService::SCALE_LOW));
static_assert(static_cast<int>(android::os::HapticScale::NONE) == static_cast<int>(android::os::IExternalVibratorService::SCALE_NONE));
static_assert(static_cast<int>(android::os::HapticScale::HIGH) == static_cast<int>(android::os::IExternalVibratorService::SCALE_HIGH));
static_assert(static_cast<int>(android::os::HapticScale::VERY_HIGH) == static_cast<int>(android::os::IExternalVibratorService::SCALE_VERY_HIGH));

void writeAudioAttributes(const audio_attributes_t& attrs, android::Parcel* out) {
    out->writeInt32(attrs.usage);
    out->writeInt32(attrs.content_type);
    out->writeInt32(attrs.source);
    out->writeInt32(attrs.flags);
}

void readAudioAttributes(audio_attributes_t* attrs, const android::Parcel* in) {
    attrs->usage = static_cast<audio_usage_t>(in->readInt32());
    attrs->content_type = static_cast<audio_content_type_t>(in->readInt32());
    attrs->source = static_cast<audio_source_t>(in->readInt32());
    attrs->flags = static_cast<audio_flags_mask_t>(in->readInt32());
}

namespace android {
namespace os {

ExternalVibration::ExternalVibration(int32_t uid, std::string pkg, const audio_attributes_t& attrs,
            sp<IExternalVibrationController> controller) :
    mUid(uid), mPkg(pkg), mAttrs(attrs), mController(controller) { }

status_t ExternalVibration::writeToParcel(Parcel* parcel) const {
    parcel->writeInt32(mUid);
    parcel->writeString16(String16(mPkg.c_str()));
    writeAudioAttributes(mAttrs, parcel);
    parcel->writeStrongBinder(IInterface::asBinder(mController));
    parcel->writeStrongBinder(mToken);
    return OK;
}
status_t ExternalVibration::readFromParcel(const Parcel* parcel) {
    mUid = parcel->readInt32();
    String8 pkgStr8 = String8(parcel->readString16());
    mPkg = pkgStr8.c_str();
    readAudioAttributes(&mAttrs, parcel);
    mController = IExternalVibrationController::asInterface(parcel->readStrongBinder());
    mToken = parcel->readStrongBinder();
    return OK;
}

inline bool ExternalVibration::operator==(const ExternalVibration& rhs) const {
    return mToken == rhs.mToken;
}

} // namespace os
} // namespace android
