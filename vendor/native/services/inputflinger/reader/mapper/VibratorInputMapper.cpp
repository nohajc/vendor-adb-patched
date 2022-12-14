/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "../Macros.h"

#include "VibratorInputMapper.h"

namespace android {

VibratorInputMapper::VibratorInputMapper(InputDeviceContext& deviceContext)
      : InputMapper(deviceContext), mVibrating(false) {}

VibratorInputMapper::~VibratorInputMapper() {}

uint32_t VibratorInputMapper::getSources() {
    return 0;
}

void VibratorInputMapper::populateDeviceInfo(InputDeviceInfo* info) {
    InputMapper::populateDeviceInfo(info);

    info->setVibrator(true);
}

void VibratorInputMapper::process(const RawEvent* rawEvent) {
    // TODO: Handle FF_STATUS, although it does not seem to be widely supported.
}

void VibratorInputMapper::vibrate(const nsecs_t* pattern, size_t patternSize, ssize_t repeat,
                                  int32_t token) {
#if DEBUG_VIBRATOR
    std::string patternStr;
    for (size_t i = 0; i < patternSize; i++) {
        if (i != 0) {
            patternStr += ", ";
        }
        patternStr += StringPrintf("%" PRId64, pattern[i]);
    }
    ALOGD("vibrate: deviceId=%d, pattern=[%s], repeat=%zd, token=%d", getDeviceId(),
          patternStr.c_str(), repeat, token);
#endif

    mVibrating = true;
    memcpy(mPattern, pattern, patternSize * sizeof(nsecs_t));
    mPatternSize = patternSize;
    mRepeat = repeat;
    mToken = token;
    mIndex = -1;

    nextStep();
}

void VibratorInputMapper::cancelVibrate(int32_t token) {
#if DEBUG_VIBRATOR
    ALOGD("cancelVibrate: deviceId=%d, token=%d", getDeviceId(), token);
#endif

    if (mVibrating && mToken == token) {
        stopVibrating();
    }
}

void VibratorInputMapper::timeoutExpired(nsecs_t when) {
    if (mVibrating) {
        if (when >= mNextStepTime) {
            nextStep();
        } else {
            getContext()->requestTimeoutAtTime(mNextStepTime);
        }
    }
}

void VibratorInputMapper::nextStep() {
    mIndex += 1;
    if (size_t(mIndex) >= mPatternSize) {
        if (mRepeat < 0) {
            // We are done.
            stopVibrating();
            return;
        }
        mIndex = mRepeat;
    }

    bool vibratorOn = mIndex & 1;
    nsecs_t duration = mPattern[mIndex];
    if (vibratorOn) {
#if DEBUG_VIBRATOR
        ALOGD("nextStep: sending vibrate deviceId=%d, duration=%" PRId64, getDeviceId(), duration);
#endif
        getDeviceContext().vibrate(duration);
    } else {
#if DEBUG_VIBRATOR
        ALOGD("nextStep: sending cancel vibrate deviceId=%d", getDeviceId());
#endif
        getDeviceContext().cancelVibrate();
    }
    nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
    mNextStepTime = now + duration;
    getContext()->requestTimeoutAtTime(mNextStepTime);
#if DEBUG_VIBRATOR
    ALOGD("nextStep: scheduled timeout in %0.3fms", duration * 0.000001f);
#endif
}

void VibratorInputMapper::stopVibrating() {
    mVibrating = false;
#if DEBUG_VIBRATOR
    ALOGD("stopVibrating: sending cancel vibrate deviceId=%d", getDeviceId());
#endif
    getDeviceContext().cancelVibrate();
}

void VibratorInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Vibrator Input Mapper:\n";
    dump += StringPrintf(INDENT3 "Vibrating: %s\n", toString(mVibrating));
}

} // namespace android
