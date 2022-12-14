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

#ifndef _UI_INPUTREADER_VIBRATOR_INPUT_MAPPER_H
#define _UI_INPUTREADER_VIBRATOR_INPUT_MAPPER_H

#include "InputMapper.h"

namespace android {

class VibratorInputMapper : public InputMapper {
public:
    explicit VibratorInputMapper(InputDeviceContext& deviceContext);
    virtual ~VibratorInputMapper();

    virtual uint32_t getSources() override;
    virtual void populateDeviceInfo(InputDeviceInfo* deviceInfo) override;
    virtual void process(const RawEvent* rawEvent) override;

    virtual void vibrate(const nsecs_t* pattern, size_t patternSize, ssize_t repeat,
                         int32_t token) override;
    virtual void cancelVibrate(int32_t token) override;
    virtual void timeoutExpired(nsecs_t when) override;
    virtual void dump(std::string& dump) override;

private:
    bool mVibrating;
    nsecs_t mPattern[MAX_VIBRATE_PATTERN_SIZE];
    size_t mPatternSize;
    ssize_t mRepeat;
    int32_t mToken;
    ssize_t mIndex;
    nsecs_t mNextStepTime;

    void nextStep();
    void stopVibrating();
};

} // namespace android

#endif // _UI_INPUTREADER_VIBRATOR_INPUT_MAPPER_H