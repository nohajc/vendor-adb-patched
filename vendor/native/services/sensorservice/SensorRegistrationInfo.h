/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_SENSOR_REGISTRATION_INFO_H
#define ANDROID_SENSOR_REGISTRATION_INFO_H

#include <ctime>
#include <iomanip>
#include <sstream>
#include <utils/Thread.h>

#include <android/util/ProtoOutputStream.h>
#include <frameworks/base/core/proto/android/service/sensor_service.proto.h>
#include "SensorServiceUtils.h"

namespace android {

class SensorService;

class SensorService::SensorRegistrationInfo : public SensorServiceUtil::Dumpable {
public:
    SensorRegistrationInfo() : mPackageName() {
        mSensorHandle = mSamplingRateUs = mMaxReportLatencyUs = INT32_MIN;
        mRealtimeSec = 0;
        mActivated = false;
    }

    SensorRegistrationInfo(int32_t handle, const String8 &packageName,
                           int64_t samplingRateNs, int64_t maxReportLatencyNs, bool activate) {
        mSensorHandle = handle;
        mPackageName = packageName;

        mSamplingRateUs = static_cast<int64_t>(samplingRateNs/1000);
        mMaxReportLatencyUs = static_cast<int64_t>(maxReportLatencyNs/1000);
        mActivated = activate;

        IPCThreadState *thread = IPCThreadState::self();
        mPid = (thread != nullptr) ? thread->getCallingPid() : -1;
        mUid = (thread != nullptr) ? thread->getCallingUid() : -1;

        timespec curTime;
        clock_gettime(CLOCK_REALTIME_COARSE, &curTime);
        mRealtimeSec = curTime.tv_sec;
    }

    static bool isSentinel(const SensorRegistrationInfo& info) {
       return (info.mSensorHandle == INT32_MIN && info.mRealtimeSec == 0);
    }

    // Dumpable interface
    virtual std::string dump() const override {
        struct tm* timeinfo = localtime(&mRealtimeSec);
        const int8_t hour = static_cast<int8_t>(timeinfo->tm_hour);
        const int8_t min = static_cast<int8_t>(timeinfo->tm_min);
        const int8_t sec = static_cast<int8_t>(timeinfo->tm_sec);

        std::ostringstream ss;
        ss << std::setfill('0') << std::setw(2) << static_cast<int>(hour) << ":"
           << std::setw(2) << static_cast<int>(min) << ":"
           << std::setw(2) << static_cast<int>(sec)
           << (mActivated ? " +" : " -")
           << " 0x" << std::hex << std::setw(8) << mSensorHandle << std::dec
           << std::setfill(' ') << " pid=" << std::setw(5) << mPid
           << " uid=" << std::setw(5) << mUid << " package=" << mPackageName;
        if (mActivated) {
           ss  << " samplingPeriod=" << mSamplingRateUs << "us"
               << " batchingPeriod=" << mMaxReportLatencyUs << "us";
        };
        return ss.str();
    }

    /**
     * Dump debugging information as android.service.SensorRegistrationInfoProto protobuf message
     * using ProtoOutputStream.
     *
     * See proto definition and some notes about ProtoOutputStream in
     * frameworks/base/core/proto/android/service/sensor_service.proto
     */
    virtual void dump(util::ProtoOutputStream* proto) const override {
        using namespace service::SensorRegistrationInfoProto;
        proto->write(TIMESTAMP_SEC, int64_t(mRealtimeSec));
        proto->write(SENSOR_HANDLE, mSensorHandle);
        proto->write(PACKAGE_NAME, std::string(mPackageName.string()));
        proto->write(PID, int32_t(mPid));
        proto->write(UID, int32_t(mUid));
        proto->write(SAMPLING_RATE_US, mSamplingRateUs);
        proto->write(MAX_REPORT_LATENCY_US, mMaxReportLatencyUs);
        proto->write(ACTIVATED, mActivated);
    }

private:
    int32_t mSensorHandle;
    String8 mPackageName;
    pid_t   mPid;
    uid_t   mUid;
    int64_t mSamplingRateUs;
    int64_t mMaxReportLatencyUs;
    bool mActivated;
    time_t mRealtimeSec;
};

} // namespace android;

#endif // ANDROID_SENSOR_REGISTRATION_INFO_H


