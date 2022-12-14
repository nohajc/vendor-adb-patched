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

#ifndef ANDROID_SENSOR_DEVICE_H
#define ANDROID_SENSOR_DEVICE_H

#include "HidlSensorHalWrapper.h"
#include "ISensorHalWrapper.h"

#include "ISensorsWrapper.h"
#include "SensorDeviceUtils.h"
#include "SensorService.h"
#include "SensorServiceUtils.h"

#include <sensor/Sensor.h>
#include <sensor/SensorEventQueue.h>
#include <stdint.h>
#include <sys/types.h>
#include <utils/KeyedVector.h>
#include <utils/Singleton.h>
#include <utils/String8.h>
#include <utils/Timers.h>

#include <algorithm> //std::max std::min
#include <string>
#include <unordered_map>
#include <vector>

#include "RingBuffer.h"

// ---------------------------------------------------------------------------

namespace android {

// ---------------------------------------------------------------------------

class SensorDevice : public Singleton<SensorDevice>,
                     public SensorServiceUtil::Dumpable,
                     public ISensorHalWrapper::SensorDeviceCallback {
public:
    ~SensorDevice();
    void prepareForReconnect();
    void reconnect();

    ssize_t getSensorList(sensor_t const** list);

    void handleDynamicSensorConnection(int handle, bool connected);
    status_t initCheck() const;
    int getHalDeviceVersion() const;

    ssize_t poll(sensors_event_t* buffer, size_t count);
    void writeWakeLockHandled(uint32_t count);

    status_t activate(void* ident, int handle, int enabled);
    status_t batch(void* ident, int handle, int flags, int64_t samplingPeriodNs,
                   int64_t maxBatchReportLatencyNs);
    // Call batch with timeout zero instead of calling setDelay() for newer devices.
    status_t setDelay(void* ident, int handle, int64_t ns);
    status_t flush(void* ident, int handle);
    status_t setMode(uint32_t mode);

    bool isDirectReportSupported() const;
    int32_t registerDirectChannel(const sensors_direct_mem_t* memory);
    void unregisterDirectChannel(int32_t channelHandle);
    int32_t configureDirectChannel(int32_t sensorHandle, int32_t channelHandle,
                                   const struct sensors_direct_cfg_t* config);

    void disableAllSensors();
    void enableAllSensors();
    void autoDisable(void* ident, int handle);

    status_t injectSensorData(const sensors_event_t* event);
    void notifyConnectionDestroyed(void* ident);

    // SensorDeviceCallback
    virtual void onDynamicSensorsConnected(
            const std::vector<sensor_t>& dynamicSensorsAdded) override;
    virtual void onDynamicSensorsDisconnected(
            const std::vector<int32_t>& dynamicSensorHandlesRemoved) override;

    void setUidStateForConnection(void* ident, SensorService::UidState state);

    bool isReconnecting() const { return mHalWrapper->mReconnecting; }

    bool isSensorActive(int handle) const;

    // To update the BatchParams of a SensorEventConnection when the mic toggle changes its state
    // while the Sensors Off toggle is on.
    void onMicSensorAccessChanged(void* ident, int handle, nsecs_t samplingPeriodNs);

    // Dumpable
    virtual std::string dump() const override;
    virtual void dump(util::ProtoOutputStream* proto) const override;

private:
    friend class Singleton<SensorDevice>;

    std::unique_ptr<ISensorHalWrapper> mHalWrapper;

    std::vector<sensor_t> mSensorList;
    std::unordered_map<int32_t, sensor_t> mConnectedDynamicSensors;

    // A bug in the Sensors HIDL spec which marks onDynamicSensorsConnected as oneway causes dynamic
    // meta events and onDynamicSensorsConnected to be received out of order. This mutex + CV are
    // used to block meta event processing until onDynamicSensorsConnected is received to simplify
    // HAL implementations.
    std::mutex mDynamicSensorsMutex;
    std::condition_variable mDynamicSensorsCv;
    static constexpr std::chrono::seconds MAX_DYN_SENSOR_WAIT{5};

    static const nsecs_t MINIMUM_EVENTS_PERIOD = 1000000; // 1000 Hz
    mutable Mutex mLock;                                  // protect mActivationCount[].batchParams
    // fixed-size array after construction

    // Struct to store all the parameters(samplingPeriod, maxBatchReportLatency and flags) from
    // batch call. For continous mode clients, maxBatchReportLatency is set to zero.
    struct BatchParams {
        nsecs_t mTSample, mTBatch;
        BatchParams() : mTSample(INT64_MAX), mTBatch(INT64_MAX) {}
        BatchParams(nsecs_t tSample, nsecs_t tBatch) : mTSample(tSample), mTBatch(tBatch) {}
        bool operator!=(const BatchParams& other) {
            return !(mTSample == other.mTSample && mTBatch == other.mTBatch);
        }
        // Merge another parameter with this one. The updated mTSample will be the min of the two.
        // The update mTBatch will be the min of original mTBatch and the apparent batch period
        // of the other. the apparent batch is the maximum of mTBatch and mTSample,
        void merge(const BatchParams& other) {
            mTSample = std::min(mTSample, other.mTSample);
            mTBatch = std::min(mTBatch, std::max(other.mTBatch, other.mTSample));
        }
    };

    // Store batch parameters in the KeyedVector and the optimal batch_rate and timeout in
    // bestBatchParams. For every batch() call corresponding params are stored in batchParams
    // vector. A continuous mode request is batch(... timeout=0 ..) followed by activate(). A batch
    // mode request is batch(... timeout > 0 ...) followed by activate().
    // Info is a per-sensor data structure which contains the batch parameters for each client that
    // has registered for this sensor.
    struct Info {
        BatchParams bestBatchParams;
        // Key is the unique identifier(ident) for each client, value is the batch parameters
        // requested by the client.
        KeyedVector<void*, BatchParams> batchParams;

        // Flag to track if the sensor is active
        bool isActive = false;

        // Sets batch parameters for this ident. Returns error if this ident is not already present
        // in the KeyedVector above.
        status_t setBatchParamsForIdent(void* ident, int flags, int64_t samplingPeriodNs,
                                        int64_t maxBatchReportLatencyNs);
        // Finds the optimal parameters for batching and stores them in bestBatchParams variable.
        void selectBatchParams();
        // Removes batchParams for an ident and re-computes bestBatchParams. Returns the index of
        // the removed ident. If index >=0, ident is present and successfully removed.
        ssize_t removeBatchParamsForIdent(void* ident);

        bool hasBatchParamsForIdent(void* ident) const {
            return batchParams.indexOfKey(ident) >= 0;
        }

        /**
         * @return The number of active clients of this sensor.
         */
        int numActiveClients() const;
    };
    DefaultKeyedVector<int, Info> mActivationCount;

    int mTotalHidlTransportErrors;

    /**
     * Enums describing the reason why a client was disabled.
     */
    enum DisabledReason : uint8_t {
        // UID becomes idle (e.g. app goes to background).
        DISABLED_REASON_UID_IDLE = 0,

        // Sensors are restricted for all clients.
        DISABLED_REASON_SERVICE_RESTRICTED,
        DISABLED_REASON_MAX,
    };

    static_assert(DisabledReason::DISABLED_REASON_MAX < sizeof(uint8_t) * CHAR_BIT);

    // Use this map to determine which client is activated or deactivated.
    std::unordered_map<void*, uint8_t> mDisabledClients;

    void addDisabledReasonForIdentLocked(void* ident, DisabledReason reason);
    void removeDisabledReasonForIdentLocked(void* ident, DisabledReason reason);

    SensorDevice();
    bool connectHalService();
    void initializeSensorList();
    void reactivateSensors(const DefaultKeyedVector<int, Info>& previousActivations);
    static bool sensorHandlesChanged(const std::vector<sensor_t>& oldSensorList,
                                     const std::vector<sensor_t>& newSensorList);
    static bool sensorIsEquivalent(const sensor_t& prevSensor, const sensor_t& newSensor);

    status_t activateLocked(void* ident, int handle, int enabled);
    status_t batchLocked(void* ident, int handle, int flags, int64_t samplingPeriodNs,
                         int64_t maxBatchReportLatencyNs);

    status_t updateBatchParamsLocked(int handle, Info& info);
    status_t doActivateHardwareLocked(int handle, bool enable);

    bool isClientDisabled(void* ident) const;
    bool isClientDisabledLocked(void* ident) const;
    std::vector<void*> getDisabledClientsLocked() const;

    bool clientHasNoAccessLocked(void* ident) const;

    float getResolutionForSensor(int sensorHandle);

    bool mIsDirectReportSupported;
};

// ---------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_SENSOR_DEVICE_H
