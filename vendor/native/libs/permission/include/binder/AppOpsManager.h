/*
 * Copyright (C) 2013 The Android Open Source Project
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

#pragma once

#include <binder/IAppOpsService.h>

#include <utils/threads.h>

#include <optional>

#ifdef __ANDROID_VNDK__
#error "This header is not visible to vendors"
#endif

// ---------------------------------------------------------------------------
namespace android {

class AppOpsManager
{
public:
    enum {
        MODE_ALLOWED = IAppOpsService::MODE_ALLOWED,
        MODE_IGNORED = IAppOpsService::MODE_IGNORED,
        MODE_ERRORED = IAppOpsService::MODE_ERRORED
    };

    enum {
        OP_NONE = -1,
        OP_COARSE_LOCATION = 0,
        OP_FINE_LOCATION = 1,
        OP_GPS = 2,
        OP_VIBRATE = 3,
        OP_READ_CONTACTS = 4,
        OP_WRITE_CONTACTS = 5,
        OP_READ_CALL_LOG = 6,
        OP_WRITE_CALL_LOG = 7,
        OP_READ_CALENDAR = 8,
        OP_WRITE_CALENDAR = 9,
        OP_WIFI_SCAN = 10,
        OP_POST_NOTIFICATION = 11,
        OP_NEIGHBORING_CELLS = 12,
        OP_CALL_PHONE = 13,
        OP_READ_SMS = 14,
        OP_WRITE_SMS = 15,
        OP_RECEIVE_SMS = 16,
        OP_RECEIVE_EMERGECY_SMS = 17,
        OP_RECEIVE_MMS = 18,
        OP_RECEIVE_WAP_PUSH = 19,
        OP_SEND_SMS = 20,
        OP_READ_ICC_SMS = 21,
        OP_WRITE_ICC_SMS = 22,
        OP_WRITE_SETTINGS = 23,
        OP_SYSTEM_ALERT_WINDOW = 24,
        OP_ACCESS_NOTIFICATIONS = 25,
        OP_CAMERA = 26,
        OP_RECORD_AUDIO = 27,
        OP_PLAY_AUDIO = 28,
        OP_READ_CLIPBOARD = 29,
        OP_WRITE_CLIPBOARD = 30,
        OP_TAKE_MEDIA_BUTTONS = 31,
        OP_TAKE_AUDIO_FOCUS = 32,
        OP_AUDIO_MASTER_VOLUME = 33,
        OP_AUDIO_VOICE_VOLUME = 34,
        OP_AUDIO_RING_VOLUME = 35,
        OP_AUDIO_MEDIA_VOLUME = 36,
        OP_AUDIO_ALARM_VOLUME = 37,
        OP_AUDIO_NOTIFICATION_VOLUME = 38,
        OP_AUDIO_BLUETOOTH_VOLUME = 39,
        OP_WAKE_LOCK = 40,
        OP_MONITOR_LOCATION = 41,
        OP_MONITOR_HIGH_POWER_LOCATION = 42,
        OP_GET_USAGE_STATS = 43,
        OP_MUTE_MICROPHONE = 44,
        OP_TOAST_WINDOW = 45,
        OP_PROJECT_MEDIA = 46,
        OP_ACTIVATE_VPN = 47,
        OP_WRITE_WALLPAPER = 48,
        OP_ASSIST_STRUCTURE = 49,
        OP_ASSIST_SCREENSHOT = 50,
        OP_READ_PHONE_STATE = 51,
        OP_ADD_VOICEMAIL = 52,
        OP_USE_SIP = 53,
        OP_PROCESS_OUTGOING_CALLS = 54,
        OP_USE_FINGERPRINT = 55,
        OP_BODY_SENSORS = 56,
        OP_AUDIO_ACCESSIBILITY_VOLUME = 64,
        OP_READ_PHONE_NUMBERS = 65,
        OP_REQUEST_INSTALL_PACKAGES = 66,
        OP_PICTURE_IN_PICTURE = 67,
        OP_INSTANT_APP_START_FOREGROUND = 68,
        OP_ANSWER_PHONE_CALLS = 69,
        OP_RUN_ANY_IN_BACKGROUND = 70,
        OP_CHANGE_WIFI_STATE = 71,
        OP_REQUEST_DELETE_PACKAGES = 72,
        OP_BIND_ACCESSIBILITY_SERVICE = 73,
        OP_ACCEPT_HANDOVER = 74,
        OP_MANAGE_IPSEC_TUNNELS = 75,
        OP_START_FOREGROUND = 76,
        OP_BLUETOOTH_SCAN = 77,
        OP_USE_BIOMETRIC = 78,
        OP_ACTIVITY_RECOGNITION = 79,
        OP_SMS_FINANCIAL_TRANSACTIONS = 80,
        OP_READ_MEDIA_AUDIO = 81,
        OP_WRITE_MEDIA_AUDIO = 82,
        OP_READ_MEDIA_VIDEO = 83,
        OP_WRITE_MEDIA_VIDEO = 84,
        OP_READ_MEDIA_IMAGES = 85,
        OP_WRITE_MEDIA_IMAGES = 86,
        OP_LEGACY_STORAGE = 87,
        OP_ACCESS_ACCESSIBILITY = 88,
        OP_READ_DEVICE_IDENTIFIERS = 89,
        OP_ACCESS_MEDIA_LOCATION = 90,
        OP_QUERY_ALL_PACKAGES = 91,
        OP_MANAGE_EXTERNAL_STORAGE = 92,
        OP_INTERACT_ACROSS_PROFILES = 93,
        OP_ACTIVATE_PLATFORM_VPN = 94,
        OP_LOADER_USAGE_STATS = 95,
        OP_DEPRECATED_1 = 96,
        OP_AUTO_REVOKE_PERMISSIONS_IF_UNUSED = 97,
        OP_AUTO_REVOKE_MANAGED_BY_INSTALLER = 98,
        OP_NO_ISOLATED_STORAGE = 99,
        OP_PHONE_CALL_MICROPHONE = 100,
        OP_PHONE_CALL_CAMERA = 101,
        OP_RECORD_AUDIO_HOTWORD = 102,
        _NUM_OP = 103
    };

    AppOpsManager();

    int32_t checkOp(int32_t op, int32_t uid, const String16& callingPackage);
    int32_t checkAudioOpNoThrow(int32_t op, int32_t usage, int32_t uid,
            const String16& callingPackage);
    // @Deprecated, use noteOp(int32_t, int32_t uid, const String16&, const String16&,
    //              const String16&) instead
    int32_t noteOp(int32_t op, int32_t uid, const String16& callingPackage);
    int32_t noteOp(int32_t op, int32_t uid, const String16& callingPackage,
            const std::optional<String16>& attributionTag, const String16& message);
    // @Deprecated, use startOpNoThrow(int32_t, int32_t, const String16&, bool, const String16&,
    //              const String16&) instead
    int32_t startOpNoThrow(int32_t op, int32_t uid, const String16& callingPackage,
            bool startIfModeDefault);
    int32_t startOpNoThrow(int32_t op, int32_t uid, const String16& callingPackage,
            bool startIfModeDefault, const std::optional<String16>& attributionTag,
            const String16& message);
    // @Deprecated, use finishOp(int32_t, int32_t, const String16&, bool, const String16&) instead
    void finishOp(int32_t op, int32_t uid, const String16& callingPackage);
    void finishOp(int32_t op, int32_t uid, const String16& callingPackage,
            const std::optional<String16>& attributionTag);
    void startWatchingMode(int32_t op, const String16& packageName,
            const sp<IAppOpsCallback>& callback);
    void stopWatchingMode(const sp<IAppOpsCallback>& callback);
    int32_t permissionToOpCode(const String16& permission);
    void setCameraAudioRestriction(int32_t mode);

private:
    Mutex mLock;
    sp<IAppOpsService> mService;

    sp<IAppOpsService> getService();
    bool shouldCollectNotes(int32_t opCode);
};


} // namespace android

// ---------------------------------------------------------------------------
