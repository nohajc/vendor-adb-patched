/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 */

#include <binder/Parcel.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <vibrator/ExternalVibration.h>

using namespace android;

constexpr size_t MAX_STRING_LENGTH = 100;
constexpr audio_content_type_t AUDIO_CONTENT_TYPE[] = {AUDIO_CONTENT_TYPE_UNKNOWN,
                                                       AUDIO_CONTENT_TYPE_SPEECH,
                                                       AUDIO_CONTENT_TYPE_MUSIC,
                                                       AUDIO_CONTENT_TYPE_MOVIE,
                                                       AUDIO_CONTENT_TYPE_SONIFICATION};
constexpr audio_usage_t AUDIO_USAGE[] = {
        AUDIO_USAGE_UNKNOWN,
        AUDIO_USAGE_MEDIA,
        AUDIO_USAGE_VOICE_COMMUNICATION,
        AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
        AUDIO_USAGE_ALARM,
        AUDIO_USAGE_NOTIFICATION,
        AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
        AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST,
        AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT,
        AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED,
        AUDIO_USAGE_NOTIFICATION_EVENT,
        AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
        AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
        AUDIO_USAGE_ASSISTANCE_SONIFICATION,
        AUDIO_USAGE_GAME,
        AUDIO_USAGE_VIRTUAL_SOURCE,
        AUDIO_USAGE_ASSISTANT,
        AUDIO_USAGE_CALL_ASSISTANT,
        AUDIO_USAGE_EMERGENCY,
        AUDIO_USAGE_SAFETY,
        AUDIO_USAGE_VEHICLE_STATUS,
        AUDIO_USAGE_ANNOUNCEMENT,
};
constexpr audio_source_t AUDIO_SOURCE[] = {
        AUDIO_SOURCE_DEFAULT,           AUDIO_SOURCE_MIC,
        AUDIO_SOURCE_VOICE_UPLINK,      AUDIO_SOURCE_VOICE_DOWNLINK,
        AUDIO_SOURCE_VOICE_CALL,        AUDIO_SOURCE_CAMCORDER,
        AUDIO_SOURCE_VOICE_RECOGNITION, AUDIO_SOURCE_VOICE_COMMUNICATION,
        AUDIO_SOURCE_REMOTE_SUBMIX,     AUDIO_SOURCE_UNPROCESSED,
        AUDIO_SOURCE_VOICE_PERFORMANCE, AUDIO_SOURCE_ECHO_REFERENCE,
        AUDIO_SOURCE_FM_TUNER,
};
constexpr size_t NUM_AUDIO_CONTENT_TYPE = std::size(AUDIO_CONTENT_TYPE);
constexpr size_t NUM_AUDIO_USAGE = std::size(AUDIO_USAGE);
constexpr size_t NUM_AUDIO_SOURCE = std::size(AUDIO_SOURCE);

class TestVibrationController : public os::IExternalVibrationController {
public:
    explicit TestVibrationController() {}
    IBinder *onAsBinder() override { return nullptr; }
    binder::Status mute(/*out*/ bool *ret) override {
        *ret = false;
        return binder::Status::ok();
    };
    binder::Status unmute(/*out*/ bool *ret) override {
        *ret = false;
        return binder::Status::ok();
    };
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    // Initialize the parameters using FuzzedDataProvider
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    std::string pkg = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    audio_attributes_t attributes;
    attributes.content_type =
            AUDIO_CONTENT_TYPE[fdp.ConsumeIntegralInRange<uint32_t>(0, NUM_AUDIO_CONTENT_TYPE - 1)];
    attributes.usage = AUDIO_USAGE[fdp.ConsumeIntegralInRange<uint32_t>(0, NUM_AUDIO_USAGE - 1)];
    attributes.source = AUDIO_SOURCE[fdp.ConsumeIntegralInRange<uint32_t>(0, NUM_AUDIO_SOURCE - 1)];
    attributes.flags = static_cast<audio_flags_mask_t>(fdp.ConsumeIntegral<uint32_t>());

    // Create an instance of TestVibrationController
    sp<TestVibrationController> vibrationController = new TestVibrationController();
    if (!vibrationController) {
        return 0;
    }

    // Set all the parameters in the constructor call
    sp<os::ExternalVibration> extVibration =
            new os::ExternalVibration(uid, pkg, attributes, vibrationController);
    if (!extVibration) {
        return 0;
    }

    // Get all the parameters that were previously set
    extVibration->getUid();
    extVibration->getPackage();
    extVibration->getAudioAttributes();
    extVibration->getController();

    // Set the parameters in a Parcel object and send it to libvibrator
    // This parcel shall be read by libvibrator
    Parcel parcel;
    parcel.writeInt32(uid);
    parcel.writeString16(String16(pkg.c_str()));
    parcel.writeStrongBinder(IInterface::asBinder(vibrationController));
    parcel.setDataPosition(0);
    extVibration->readFromParcel(&parcel);

    // Send a Parcel to libvibrator
    // Parameters shall be written to this parcel by libvibrator
    extVibration->writeToParcel(&parcel);
    return 0;
}
