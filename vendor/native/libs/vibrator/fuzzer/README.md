# Fuzzer for libvibrator

## Plugin Design Considerations
This fuzzer fuzzes native code present in libvibrator and does not cover the Java implementation ExternalVibration
The fuzzer plugin is designed based on the understanding of the
library and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

libvibrator supports the following parameters:
1. Uid (parameter name: `uid`)
2. Package Name (parameter name: `pkg`)
3. Audio Content Type (parameter name: `content_type`)
4. Audio Usage (parameter name: `usage`)
5. Audio Source (parameter name: `source`)
6. Audio flags (parameter name: `flags`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `uid` | `INT32_MIN` to `INT32_MAX` | Value obtained from FuzzedDataProvider |
| `pkg`   | Any std::string value | Value obtained from FuzzedDataProvider |
| `content_type`   | 0.`AUDIO_CONTENT_TYPE_UNKNOWN` 1.`AUDIO_CONTENT_TYPE_SPEECH` 2.`AUDIO_CONTENT_TYPE_MUSIC` 3.`AUDIO_CONTENT_TYPE_MOVIE` 4.`AUDIO_CONTENT_TYPE_SONIFICATION`| Value obtained from FuzzedDataProvider in the range 0 to 4|
| `usage`   | 0.`AUDIO_USAGE_UNKNOWN` 1.`AUDIO_USAGE_MEDIA` 2.`AUDIO_USAGE_VOICE_COMMUNICATION` 3.`AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING` 4.`AUDIO_USAGE_ALARM` 5.`AUDIO_USAGE_NOTIFICATION` 6.`AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE`  7.`AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST` 8.`AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT` 9.`AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED` 10.`AUDIO_USAGE_NOTIFICATION_EVENT` 11.`AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY` 12.`AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE` 13.`AUDIO_USAGE_ASSISTANCE_SONIFICATION` 14.`AUDIO_USAGE_GAME` 15.`AUDIO_USAGE_VIRTUAL_SOURCE` 16.`AUDIO_USAGE_ASSISTANT` 17.`AUDIO_USAGE_CALL_ASSISTANT` 18.`AUDIO_USAGE_EMERGENCY` 19.`AUDIO_USAGE_SAFETY` 20.`AUDIO_USAGE_VEHICLE_STATUS` 21.`AUDIO_USAGE_ANNOUNCEMENT`| Value obtained from FuzzedDataProvider in the range 0 to 21|
| `source`   |  0.`AUDIO_SOURCE_DEFAULT` 1.`AUDIO_SOURCE_MIC` 2.`AUDIO_SOURCE_VOICE_UPLINK` 3.`AUDIO_SOURCE_VOICE_DOWNLINK` 4.`AUDIO_SOURCE_VOICE_CALL` 5.`AUDIO_SOURCE_CAMCORDER` 6.`AUDIO_SOURCE_VOICE_RECOGNITION` 7.`AUDIO_SOURCE_VOICE_COMMUNICATION` 8.`AUDIO_SOURCE_REMOTE_SUBMIX` 9.`AUDIO_SOURCE_UNPROCESSED` 10.`AUDIO_SOURCE_VOICE_PERFORMANCE` 11.`AUDIO_SOURCE_ECHO_REFERENCE` 12.`AUDIO_SOURCE_FM_TUNER` | Value obtained from FuzzedDataProvider in the range 0 to 12 |
| `flags`   | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider |

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesn't `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build vibrator_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) vibrator_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/vibrator_fuzzer/vibrator_fuzzer CORPUS_DIR
```

To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/vibrator_fuzzer/vibrator_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
