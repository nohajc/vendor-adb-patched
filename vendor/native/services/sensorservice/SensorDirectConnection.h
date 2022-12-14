/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_SENSOR_DIRECT_CONNECTION_H
#define ANDROID_SENSOR_DIRECT_CONNECTION_H

#include <stdint.h>
#include <sys/types.h>

#include <binder/BinderService.h>

#include <sensor/Sensor.h>
#include <sensor/BitTube.h>
#include <sensor/ISensorServer.h>
#include <sensor/ISensorEventConnection.h>

#include "SensorService.h"

namespace android {

class SensorService;
class BitTube;

class SensorService::SensorDirectConnection: public BnSensorEventConnection {
public:
    SensorDirectConnection(const sp<SensorService>& service, uid_t uid,
            const sensors_direct_mem_t *mem, int32_t halChannelHandle,
            const String16& opPackageName);
    void dump(String8& result) const;
    void dump(util::ProtoOutputStream* proto) const;
    uid_t getUid() const { return mUid; }
    const String16& getOpPackageName() const { return mOpPackageName; }
    int32_t getHalChannelHandle() const;
    bool isEquivalent(const sensors_direct_mem_t *mem) const;

    // Invoked when access to sensors for this connection has changed, e.g. lost or
    // regained due to changes in the sensor restricted/privacy mode or the
    // app changed to idle/active status.
    void onSensorAccessChanged(bool hasAccess);

protected:
    virtual ~SensorDirectConnection();
    // ISensorEventConnection functions
    virtual void onFirstRef();
    virtual sp<BitTube> getSensorChannel() const;
    virtual status_t enableDisable(int handle, bool enabled, nsecs_t samplingPeriodNs,
                                   nsecs_t maxBatchReportLatencyNs, int reservedFlags);
    virtual status_t setEventRate(int handle, nsecs_t samplingPeriodNs);
    virtual status_t flush();
    virtual int32_t configureChannel(int handle, int rateLevel);
    virtual void destroy();
private:
    bool hasSensorAccess() const;

    // Stops all active sensor direct report requests.
    //
    // If backupRecord is true, stopped requests can be recovered
    // by a subsequent recoverAll() call (e.g. when temporarily stopping
    // sensors for sensor privacy/restrict mode or when an app becomes
    // idle).
    void stopAll(bool backupRecord = false);
    // Same as stopAll() but with mConnectionLock held.
    void stopAllLocked(bool backupRecord);

    // Recover sensor requests previously stopped by stopAll(true).
    // This method can be called when a sensor access resumes (e.g.
    // sensor privacy/restrict mode lifted or app becomes active).
    //
    // If no requests are backed up by stopAll(), this method is no-op.
    void recoverAll();

    const sp<SensorService> mService;
    const uid_t mUid;
    const sensors_direct_mem_t mMem;
    const int32_t mHalChannelHandle;
    const String16 mOpPackageName;

    mutable Mutex mConnectionLock;
    std::unordered_map<int, int> mActivated;
    std::unordered_map<int, int> mActivatedBackup;

    mutable Mutex mDestroyLock;
    bool mDestroyed;
};

} // namepsace android

#endif // ANDROID_SENSOR_DIRECT_CONNECTION_H

