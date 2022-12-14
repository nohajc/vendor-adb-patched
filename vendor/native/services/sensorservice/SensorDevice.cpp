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

#include "SensorDevice.h"

#include "android/hardware/sensors/2.0/types.h"
#include "android/hardware/sensors/2.1/types.h"
#include "convertV2_1.h"

#include "AidlSensorHalWrapper.h"
#include "HidlSensorHalWrapper.h"

#include <android-base/logging.h>
#include <android/util/ProtoOutputStream.h>
#include <cutils/atomic.h>
#include <frameworks/base/core/proto/android/service/sensor_service.proto.h>
#include <hardware/sensors-base.h>
#include <hardware/sensors.h>
#include <sensors/convert.h>
#include <utils/Errors.h>
#include <utils/Singleton.h>

#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <thread>

using namespace android::hardware::sensors;
using android::hardware::Return;
using android::util::ProtoOutputStream;

namespace android {
// ---------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE(SensorDevice)

namespace {

template <typename EnumType>
constexpr typename std::underlying_type<EnumType>::type asBaseType(EnumType value) {
    return static_cast<typename std::underlying_type<EnumType>::type>(value);
}

// Used internally by the framework to wake the Event FMQ. These values must start after
// the last value of EventQueueFlagBits
enum EventQueueFlagBitsInternal : uint32_t {
    INTERNAL_WAKE = 1 << 16,
};

enum DevicePrivateBase : int32_t {
    DEVICE_PRIVATE_BASE = 65536,
};

} // anonymous namespace

SensorDevice::SensorDevice() {
    if (!connectHalService()) {
        return;
    }

    initializeSensorList();

    mIsDirectReportSupported = (mHalWrapper->unregisterDirectChannel(-1) != INVALID_OPERATION);
}

void SensorDevice::initializeSensorList() {
    if (mHalWrapper == nullptr) {
        return;
    }

    auto list = mHalWrapper->getSensorsList();
    const size_t count = list.size();

    mActivationCount.setCapacity(count);
    Info model;
    for (size_t i = 0; i < count; i++) {
        sensor_t sensor = list[i];

        if (sensor.type < DEVICE_PRIVATE_BASE) {
            sensor.resolution = SensorDeviceUtils::resolutionForSensor(sensor);

            // Some sensors don't have a default resolution and will be left at 0.
            // Don't crash in this case since CTS will verify that devices don't go to
            // production with a resolution of 0.
            if (sensor.resolution != 0) {
                float quantizedRange = sensor.maxRange;
                SensorDeviceUtils::quantizeValue(&quantizedRange, sensor.resolution,
                                                 /*factor=*/1);
                // Only rewrite maxRange if the requantization produced a "significant"
                // change, which is fairly arbitrarily defined as resolution / 8.
                // Smaller deltas are permitted, as they may simply be due to floating
                // point representation error, etc.
                if (fabsf(sensor.maxRange - quantizedRange) > sensor.resolution / 8) {
                    ALOGW("%s's max range %.12f is not a multiple of the resolution "
                          "%.12f - updated to %.12f",
                          sensor.name, sensor.maxRange, sensor.resolution, quantizedRange);
                    sensor.maxRange = quantizedRange;
                }
            } else {
                // Don't crash here or the device will go into a crashloop.
                ALOGW("%s should have a non-zero resolution", sensor.name);
            }
        }

        // Check and clamp power if it is 0 (or close)
        constexpr float MIN_POWER_MA = 0.001; // 1 microAmp
        if (sensor.power < MIN_POWER_MA) {
            ALOGI("%s's reported power %f invalid, clamped to %f", sensor.name, sensor.power,
                  MIN_POWER_MA);
            sensor.power = MIN_POWER_MA;
        }
        mSensorList.push_back(sensor);

        mActivationCount.add(list[i].handle, model);

        // Only disable all sensors on HAL 1.0 since HAL 2.0
        // handles this in its initialize method
        if (!mHalWrapper->supportsMessageQueues()) {
            mHalWrapper->activate(list[i].handle, 0 /* enabled */);
        }
    }
}

SensorDevice::~SensorDevice() {}

bool SensorDevice::connectHalService() {
    std::unique_ptr<ISensorHalWrapper> aidl_wrapper = std::make_unique<AidlSensorHalWrapper>();
    if (aidl_wrapper->connect(this)) {
        mHalWrapper = std::move(aidl_wrapper);
        return true;
    }

    std::unique_ptr<ISensorHalWrapper> hidl_wrapper = std::make_unique<HidlSensorHalWrapper>();
    if (hidl_wrapper->connect(this)) {
        mHalWrapper = std::move(hidl_wrapper);
        return true;
    }

    // TODO: check aidl connection;
    return false;
}

void SensorDevice::prepareForReconnect() {
    mHalWrapper->prepareForReconnect();
}

void SensorDevice::reconnect() {
    Mutex::Autolock _l(mLock);

    auto previousActivations = mActivationCount;
    auto previousSensorList = mSensorList;

    mActivationCount.clear();
    mSensorList.clear();

    if (mHalWrapper->connect(this)) {
        initializeSensorList();

        if (sensorHandlesChanged(previousSensorList, mSensorList)) {
            LOG_ALWAYS_FATAL("Sensor handles changed, cannot re-enable sensors.");
        } else {
            reactivateSensors(previousActivations);
        }
    }
    mHalWrapper->mReconnecting = false;
}

bool SensorDevice::sensorHandlesChanged(const std::vector<sensor_t>& oldSensorList,
                                        const std::vector<sensor_t>& newSensorList) {
    bool didChange = false;

    if (oldSensorList.size() != newSensorList.size()) {
        ALOGI("Sensor list size changed from %zu to %zu", oldSensorList.size(),
              newSensorList.size());
        didChange = true;
    }

    for (size_t i = 0; i < newSensorList.size() && !didChange; i++) {
        bool found = false;
        const sensor_t& newSensor = newSensorList[i];
        for (size_t j = 0; j < oldSensorList.size() && !found; j++) {
            const sensor_t& prevSensor = oldSensorList[j];
            if (prevSensor.handle == newSensor.handle) {
                found = true;
                if (!sensorIsEquivalent(prevSensor, newSensor)) {
                    ALOGI("Sensor %s not equivalent to previous version", newSensor.name);
                    didChange = true;
                }
            }
        }

        if (!found) {
            // Could not find the new sensor in the old list of sensors, the lists must
            // have changed.
            ALOGI("Sensor %s (handle %d) did not exist before", newSensor.name, newSensor.handle);
            didChange = true;
        }
    }
    return didChange;
}

bool SensorDevice::sensorIsEquivalent(const sensor_t& prevSensor, const sensor_t& newSensor) {
    bool equivalent = true;
    if (prevSensor.handle != newSensor.handle ||
        (strcmp(prevSensor.vendor, newSensor.vendor) != 0) ||
        (strcmp(prevSensor.stringType, newSensor.stringType) != 0) ||
        (strcmp(prevSensor.requiredPermission, newSensor.requiredPermission) != 0) ||
        (prevSensor.version != newSensor.version) || (prevSensor.type != newSensor.type) ||
        (std::abs(prevSensor.maxRange - newSensor.maxRange) > 0.001f) ||
        (std::abs(prevSensor.resolution - newSensor.resolution) > 0.001f) ||
        (std::abs(prevSensor.power - newSensor.power) > 0.001f) ||
        (prevSensor.minDelay != newSensor.minDelay) ||
        (prevSensor.fifoReservedEventCount != newSensor.fifoReservedEventCount) ||
        (prevSensor.fifoMaxEventCount != newSensor.fifoMaxEventCount) ||
        (prevSensor.maxDelay != newSensor.maxDelay) || (prevSensor.flags != newSensor.flags)) {
        equivalent = false;
    }
    return equivalent;
}

void SensorDevice::reactivateSensors(const DefaultKeyedVector<int, Info>& previousActivations) {
    for (size_t i = 0; i < mSensorList.size(); i++) {
        int handle = mSensorList[i].handle;
        ssize_t activationIndex = previousActivations.indexOfKey(handle);
        if (activationIndex < 0 || previousActivations[activationIndex].numActiveClients() <= 0) {
            continue;
        }

        const Info& info = previousActivations[activationIndex];
        for (size_t j = 0; j < info.batchParams.size(); j++) {
            const BatchParams& batchParams = info.batchParams[j];
            status_t res = batchLocked(info.batchParams.keyAt(j), handle, 0 /* flags */,
                                       batchParams.mTSample, batchParams.mTBatch);

            if (res == NO_ERROR) {
                activateLocked(info.batchParams.keyAt(j), handle, true /* enabled */);
            }
        }
    }
}

void SensorDevice::handleDynamicSensorConnection(int handle, bool connected) {
    // not need to check mSensors because this is is only called after successful poll()
    if (connected) {
        Info model;
        mActivationCount.add(handle, model);
        mHalWrapper->activate(handle, 0 /* enabled */);
    } else {
        mActivationCount.removeItem(handle);
    }
}

std::string SensorDevice::dump() const {
    if (mHalWrapper == nullptr) return "HAL not initialized\n";

    String8 result;
    result.appendFormat("Total %zu h/w sensors, %zu running %zu disabled clients:\n",
                        mSensorList.size(), mActivationCount.size(), mDisabledClients.size());

    Mutex::Autolock _l(mLock);
    for (const auto& s : mSensorList) {
        int32_t handle = s.handle;
        const Info& info = mActivationCount.valueFor(handle);
        if (info.numActiveClients() == 0) continue;

        result.appendFormat("0x%08x) active-count = %zu; ", handle, info.batchParams.size());

        result.append("sampling_period(ms) = {");
        for (size_t j = 0; j < info.batchParams.size(); j++) {
            const BatchParams& params = info.batchParams[j];
            result.appendFormat("%.1f%s%s", params.mTSample / 1e6f,
                                isClientDisabledLocked(info.batchParams.keyAt(j)) ? "(disabled)"
                                                                                  : "",
                                (j < info.batchParams.size() - 1) ? ", " : "");
        }
        result.appendFormat("}, selected = %.2f ms; ", info.bestBatchParams.mTSample / 1e6f);

        result.append("batching_period(ms) = {");
        for (size_t j = 0; j < info.batchParams.size(); j++) {
            const BatchParams& params = info.batchParams[j];
            result.appendFormat("%.1f%s%s", params.mTBatch / 1e6f,
                                isClientDisabledLocked(info.batchParams.keyAt(j)) ? "(disabled)"
                                                                                  : "",
                                (j < info.batchParams.size() - 1) ? ", " : "");
        }
        result.appendFormat("}, selected = %.2f ms\n", info.bestBatchParams.mTBatch / 1e6f);
    }

    return result.string();
}

/**
 * Dump debugging information as android.service.SensorDeviceProto protobuf message using
 * ProtoOutputStream.
 *
 * See proto definition and some notes about ProtoOutputStream in
 * frameworks/base/core/proto/android/service/sensor_service.proto
 */
void SensorDevice::dump(ProtoOutputStream* proto) const {
    using namespace service::SensorDeviceProto;
    if (mHalWrapper == nullptr) {
        proto->write(INITIALIZED, false);
        return;
    }
    proto->write(INITIALIZED, true);
    proto->write(TOTAL_SENSORS, int(mSensorList.size()));
    proto->write(ACTIVE_SENSORS, int(mActivationCount.size()));

    Mutex::Autolock _l(mLock);
    for (const auto& s : mSensorList) {
        int32_t handle = s.handle;
        const Info& info = mActivationCount.valueFor(handle);
        if (info.numActiveClients() == 0) continue;

        uint64_t token = proto->start(SENSORS);
        proto->write(SensorProto::HANDLE, handle);
        proto->write(SensorProto::ACTIVE_COUNT, int(info.batchParams.size()));
        for (size_t j = 0; j < info.batchParams.size(); j++) {
            const BatchParams& params = info.batchParams[j];
            proto->write(SensorProto::SAMPLING_PERIOD_MS, params.mTSample / 1e6f);
            proto->write(SensorProto::BATCHING_PERIOD_MS, params.mTBatch / 1e6f);
        }
        proto->write(SensorProto::SAMPLING_PERIOD_SELECTED, info.bestBatchParams.mTSample / 1e6f);
        proto->write(SensorProto::BATCHING_PERIOD_SELECTED, info.bestBatchParams.mTBatch / 1e6f);
        proto->end(token);
    }
}

ssize_t SensorDevice::getSensorList(sensor_t const** list) {
    *list = &mSensorList[0];

    return mSensorList.size();
}

status_t SensorDevice::initCheck() const {
    return mHalWrapper != nullptr ? NO_ERROR : NO_INIT;
}

ssize_t SensorDevice::poll(sensors_event_t* buffer, size_t count) {
    if (mHalWrapper == nullptr) return NO_INIT;

    ssize_t eventsRead = 0;
    if (mHalWrapper->supportsMessageQueues()) {
        eventsRead = mHalWrapper->pollFmq(buffer, count);
    } else if (mHalWrapper->supportsPolling()) {
        eventsRead = mHalWrapper->poll(buffer, count);
    } else {
        ALOGE("Must support polling or FMQ");
        eventsRead = -1;
    }

    if (eventsRead > 0) {
        for (ssize_t i = 0; i < eventsRead; i++) {
            float resolution = getResolutionForSensor(buffer[i].sensor);
            android::SensorDeviceUtils::quantizeSensorEventValues(&buffer[i], resolution);

            if (buffer[i].type == SENSOR_TYPE_DYNAMIC_SENSOR_META) {
                struct dynamic_sensor_meta_event& dyn = buffer[i].dynamic_sensor_meta;
                if (dyn.connected) {
                    std::unique_lock<std::mutex> lock(mDynamicSensorsMutex);
                    // Give MAX_DYN_SENSOR_WAIT_SEC for onDynamicSensorsConnected to be invoked
                    // since it can be received out of order from this event due to a bug in the
                    // HIDL spec that marks it as oneway.
                    auto it = mConnectedDynamicSensors.find(dyn.handle);
                    if (it == mConnectedDynamicSensors.end()) {
                        mDynamicSensorsCv.wait_for(lock, MAX_DYN_SENSOR_WAIT, [&, dyn] {
                            return mConnectedDynamicSensors.find(dyn.handle) !=
                                    mConnectedDynamicSensors.end();
                        });
                        it = mConnectedDynamicSensors.find(dyn.handle);
                        CHECK(it != mConnectedDynamicSensors.end());
                    }

                    dyn.sensor = &it->second;
                }
            }
        }
    }

    return eventsRead;
}

void SensorDevice::onDynamicSensorsConnected(const std::vector<sensor_t>& dynamicSensorsAdded) {
    std::unique_lock<std::mutex> lock(mDynamicSensorsMutex);

    // Allocate a sensor_t structure for each dynamic sensor added and insert
    // it into the dictionary of connected dynamic sensors keyed by handle.
    for (size_t i = 0; i < dynamicSensorsAdded.size(); ++i) {
        const sensor_t& sensor = dynamicSensorsAdded[i];

        auto it = mConnectedDynamicSensors.find(sensor.handle);
        CHECK(it == mConnectedDynamicSensors.end());

        mConnectedDynamicSensors.insert(std::make_pair(sensor.handle, sensor));
    }

    mDynamicSensorsCv.notify_all();
}

void SensorDevice::onDynamicSensorsDisconnected(
        const std::vector<int32_t>& /* dynamicSensorHandlesRemoved */) {
    // TODO: Currently dynamic sensors do not seem to be removed
}

void SensorDevice::writeWakeLockHandled(uint32_t count) {
    if (mHalWrapper != nullptr && mHalWrapper->supportsMessageQueues()) {
        mHalWrapper->writeWakeLockHandled(count);
    }
}

void SensorDevice::autoDisable(void* ident, int handle) {
    Mutex::Autolock _l(mLock);
    ssize_t activationIndex = mActivationCount.indexOfKey(handle);
    if (activationIndex < 0) {
        ALOGW("Handle %d cannot be found in activation record", handle);
        return;
    }
    Info& info(mActivationCount.editValueAt(activationIndex));
    info.removeBatchParamsForIdent(ident);
    if (info.numActiveClients() == 0) {
        info.isActive = false;
    }
}

status_t SensorDevice::activate(void* ident, int handle, int enabled) {
    if (mHalWrapper == nullptr) return NO_INIT;

    Mutex::Autolock _l(mLock);
    return activateLocked(ident, handle, enabled);
}

status_t SensorDevice::activateLocked(void* ident, int handle, int enabled) {
    bool activateHardware = false;

    status_t err(NO_ERROR);

    ssize_t activationIndex = mActivationCount.indexOfKey(handle);
    if (activationIndex < 0) {
        ALOGW("Handle %d cannot be found in activation record", handle);
        return BAD_VALUE;
    }
    Info& info(mActivationCount.editValueAt(activationIndex));

    ALOGD_IF(DEBUG_CONNECTIONS,
             "SensorDevice::activate: ident=%p, handle=0x%08x, enabled=%d, count=%zu", ident,
             handle, enabled, info.batchParams.size());

    if (enabled) {
        ALOGD_IF(DEBUG_CONNECTIONS, "enable index=%zd", info.batchParams.indexOfKey(ident));

        if (isClientDisabledLocked(ident)) {
            ALOGW("SensorDevice::activate, isClientDisabledLocked(%p):true, handle:%d", ident,
                  handle);
            return NO_ERROR;
        }

        if (info.batchParams.indexOfKey(ident) >= 0) {
            if (info.numActiveClients() > 0 && !info.isActive) {
                activateHardware = true;
            }
        } else {
            // Log error. Every activate call should be preceded by a batch() call.
            ALOGE("\t >>>ERROR: activate called without batch");
        }
    } else {
        ALOGD_IF(DEBUG_CONNECTIONS, "disable index=%zd", info.batchParams.indexOfKey(ident));

        // If a connected dynamic sensor is deactivated, remove it from the
        // dictionary.
        auto it = mConnectedDynamicSensors.find(handle);
        if (it != mConnectedDynamicSensors.end()) {
            mConnectedDynamicSensors.erase(it);
        }

        if (info.removeBatchParamsForIdent(ident) >= 0) {
            if (info.numActiveClients() == 0) {
                // This is the last connection, we need to de-activate the underlying h/w sensor.
                activateHardware = true;
            } else {
                // Call batch for this sensor with the previously calculated best effort
                // batch_rate and timeout. One of the apps has unregistered for sensor
                // events, and the best effort batch parameters might have changed.
                ALOGD_IF(DEBUG_CONNECTIONS, "\t>>> actuating h/w batch 0x%08x %" PRId64 " %" PRId64,
                         handle, info.bestBatchParams.mTSample, info.bestBatchParams.mTBatch);
                mHalWrapper->batch(handle, info.bestBatchParams.mTSample,
                                   info.bestBatchParams.mTBatch);
            }
        } else {
            // sensor wasn't enabled for this ident
        }

        if (isClientDisabledLocked(ident)) {
            return NO_ERROR;
        }
    }

    if (activateHardware) {
        err = doActivateHardwareLocked(handle, enabled);

        if (err != NO_ERROR && enabled) {
            // Failure when enabling the sensor. Clean up on failure.
            info.removeBatchParamsForIdent(ident);
        } else {
            // Update the isActive flag if there is no error. If there is an error when disabling a
            // sensor, still set the flag to false since the batch parameters have already been
            // removed. This ensures that everything remains in-sync.
            info.isActive = enabled;
        }
    }

    return err;
}

status_t SensorDevice::doActivateHardwareLocked(int handle, bool enabled) {
    ALOGD_IF(DEBUG_CONNECTIONS, "\t>>> actuating h/w activate handle=%d enabled=%d", handle,
             enabled);
    status_t err = mHalWrapper->activate(handle, enabled);
    ALOGE_IF(err, "Error %s sensor %d (%s)", enabled ? "activating" : "disabling", handle,
             strerror(-err));
    return err;
}

status_t SensorDevice::batch(void* ident, int handle, int flags, int64_t samplingPeriodNs,
                             int64_t maxBatchReportLatencyNs) {
    if (mHalWrapper == nullptr) return NO_INIT;

    if (samplingPeriodNs < MINIMUM_EVENTS_PERIOD) {
        samplingPeriodNs = MINIMUM_EVENTS_PERIOD;
    }
    if (maxBatchReportLatencyNs < 0) {
        maxBatchReportLatencyNs = 0;
    }

    ALOGD_IF(DEBUG_CONNECTIONS,
             "SensorDevice::batch: ident=%p, handle=0x%08x, flags=%d, period_ns=%" PRId64
             " timeout=%" PRId64,
             ident, handle, flags, samplingPeriodNs, maxBatchReportLatencyNs);

    Mutex::Autolock _l(mLock);
    return batchLocked(ident, handle, flags, samplingPeriodNs, maxBatchReportLatencyNs);
}

status_t SensorDevice::batchLocked(void* ident, int handle, int flags, int64_t samplingPeriodNs,
                                   int64_t maxBatchReportLatencyNs) {
    ssize_t activationIndex = mActivationCount.indexOfKey(handle);
    if (activationIndex < 0) {
        ALOGW("Handle %d cannot be found in activation record", handle);
        return BAD_VALUE;
    }
    Info& info(mActivationCount.editValueAt(activationIndex));

    if (info.batchParams.indexOfKey(ident) < 0) {
        BatchParams params(samplingPeriodNs, maxBatchReportLatencyNs);
        info.batchParams.add(ident, params);
    } else {
        // A batch has already been called with this ident. Update the batch parameters.
        info.setBatchParamsForIdent(ident, flags, samplingPeriodNs, maxBatchReportLatencyNs);
    }

    status_t err = updateBatchParamsLocked(handle, info);
    if (err != NO_ERROR) {
        ALOGE("sensor batch failed 0x%08x %" PRId64 " %" PRId64 " err=%s", handle,
              info.bestBatchParams.mTSample, info.bestBatchParams.mTBatch, strerror(-err));
        info.removeBatchParamsForIdent(ident);
    }

    return err;
}

status_t SensorDevice::updateBatchParamsLocked(int handle, Info& info) {
    BatchParams prevBestBatchParams = info.bestBatchParams;
    // Find the minimum of all timeouts and batch_rates for this sensor.
    info.selectBatchParams();

    ALOGD_IF(DEBUG_CONNECTIONS,
             "\t>>> curr_period=%" PRId64 " min_period=%" PRId64 " curr_timeout=%" PRId64
             " min_timeout=%" PRId64,
             prevBestBatchParams.mTSample, info.bestBatchParams.mTSample,
             prevBestBatchParams.mTBatch, info.bestBatchParams.mTBatch);

    status_t err(NO_ERROR);
    // If the min period or min timeout has changed since the last batch call, call batch.
    if (prevBestBatchParams != info.bestBatchParams && info.numActiveClients() > 0) {
        ALOGD_IF(DEBUG_CONNECTIONS, "\t>>> actuating h/w BATCH 0x%08x %" PRId64 " %" PRId64, handle,
                 info.bestBatchParams.mTSample, info.bestBatchParams.mTBatch);
        err = mHalWrapper->batch(handle, info.bestBatchParams.mTSample,
                                 info.bestBatchParams.mTBatch);
    }

    return err;
}

status_t SensorDevice::setDelay(void* ident, int handle, int64_t samplingPeriodNs) {
    return batch(ident, handle, 0, samplingPeriodNs, 0);
}

int SensorDevice::getHalDeviceVersion() const {
    if (mHalWrapper == nullptr) return -1;
    return SENSORS_DEVICE_API_VERSION_1_4;
}

status_t SensorDevice::flush(void* ident, int handle) {
    if (mHalWrapper == nullptr) return NO_INIT;
    if (isClientDisabled(ident)) return INVALID_OPERATION;
    ALOGD_IF(DEBUG_CONNECTIONS, "\t>>> actuating h/w flush %d", handle);
    return mHalWrapper->flush(handle);
}

bool SensorDevice::isClientDisabled(void* ident) const {
    Mutex::Autolock _l(mLock);
    return isClientDisabledLocked(ident);
}

bool SensorDevice::isClientDisabledLocked(void* ident) const {
    return mDisabledClients.count(ident) > 0;
}

std::vector<void*> SensorDevice::getDisabledClientsLocked() const {
    std::vector<void*> vec;
    for (const auto& it : mDisabledClients) {
        vec.push_back(it.first);
    }

    return vec;
}

void SensorDevice::addDisabledReasonForIdentLocked(void* ident, DisabledReason reason) {
    mDisabledClients[ident] |= 1 << reason;
}

void SensorDevice::removeDisabledReasonForIdentLocked(void* ident, DisabledReason reason) {
    if (isClientDisabledLocked(ident)) {
        mDisabledClients[ident] &= ~(1 << reason);
        if (mDisabledClients[ident] == 0) {
            mDisabledClients.erase(ident);
        }
    }
}

void SensorDevice::setUidStateForConnection(void* ident, SensorService::UidState state) {
    Mutex::Autolock _l(mLock);
    if (state == SensorService::UID_STATE_ACTIVE) {
        removeDisabledReasonForIdentLocked(ident, DisabledReason::DISABLED_REASON_UID_IDLE);
    } else {
        addDisabledReasonForIdentLocked(ident, DisabledReason::DISABLED_REASON_UID_IDLE);
    }

    for (size_t i = 0; i < mActivationCount.size(); ++i) {
        int handle = mActivationCount.keyAt(i);
        Info& info = mActivationCount.editValueAt(i);

        if (info.hasBatchParamsForIdent(ident)) {
            updateBatchParamsLocked(handle, info);
            bool disable = info.numActiveClients() == 0 && info.isActive;
            bool enable = info.numActiveClients() > 0 && !info.isActive;

            if ((enable || disable) && doActivateHardwareLocked(handle, enable) == NO_ERROR) {
                info.isActive = enable;
            }
        }
    }
}

bool SensorDevice::isSensorActive(int handle) const {
    Mutex::Autolock _l(mLock);
    ssize_t activationIndex = mActivationCount.indexOfKey(handle);
    if (activationIndex < 0) {
        return false;
    }
    return mActivationCount.valueAt(activationIndex).isActive;
}

void SensorDevice::onMicSensorAccessChanged(void* ident, int handle, nsecs_t samplingPeriodNs) {
    Mutex::Autolock _l(mLock);
    ssize_t activationIndex = mActivationCount.indexOfKey(handle);
    if (activationIndex < 0) {
        ALOGW("Handle %d cannot be found in activation record", handle);
        return;
    }
    Info& info(mActivationCount.editValueAt(activationIndex));
    if (info.hasBatchParamsForIdent(ident)) {
        ssize_t index = info.batchParams.indexOfKey(ident);
        BatchParams& params = info.batchParams.editValueAt(index);
        params.mTSample = samplingPeriodNs;
    }
}

void SensorDevice::enableAllSensors() {
    if (mHalWrapper == nullptr) return;
    Mutex::Autolock _l(mLock);

    for (void* client : getDisabledClientsLocked()) {
        removeDisabledReasonForIdentLocked(client,
                                           DisabledReason::DISABLED_REASON_SERVICE_RESTRICTED);
    }

    for (size_t i = 0; i < mActivationCount.size(); ++i) {
        Info& info = mActivationCount.editValueAt(i);
        if (info.batchParams.isEmpty()) continue;
        info.selectBatchParams();
        const int sensor_handle = mActivationCount.keyAt(i);
        ALOGD_IF(DEBUG_CONNECTIONS, "\t>> reenable actuating h/w sensor enable handle=%d ",
                 sensor_handle);
        status_t err = mHalWrapper->batch(sensor_handle, info.bestBatchParams.mTSample,
                                          info.bestBatchParams.mTBatch);
        ALOGE_IF(err, "Error calling batch on sensor %d (%s)", sensor_handle, strerror(-err));

        if (err == NO_ERROR) {
            err = mHalWrapper->activate(sensor_handle, 1 /* enabled */);
            ALOGE_IF(err, "Error activating sensor %d (%s)", sensor_handle, strerror(-err));
        }

        if (err == NO_ERROR) {
            info.isActive = true;
        }
    }
}

void SensorDevice::disableAllSensors() {
    if (mHalWrapper == nullptr) return;
    Mutex::Autolock _l(mLock);
    for (size_t i = 0; i < mActivationCount.size(); ++i) {
        Info& info = mActivationCount.editValueAt(i);
        // Check if this sensor has been activated previously and disable it.
        if (info.batchParams.size() > 0) {
            const int sensor_handle = mActivationCount.keyAt(i);
            ALOGD_IF(DEBUG_CONNECTIONS, "\t>> actuating h/w sensor disable handle=%d ",
                     sensor_handle);
            mHalWrapper->activate(sensor_handle, 0 /* enabled */);

            // Add all the connections that were registered for this sensor to the disabled
            // clients list.
            for (size_t j = 0; j < info.batchParams.size(); ++j) {
                addDisabledReasonForIdentLocked(info.batchParams.keyAt(j),
                                                DisabledReason::DISABLED_REASON_SERVICE_RESTRICTED);
                ALOGI("added %p to mDisabledClients", info.batchParams.keyAt(j));
            }

            info.isActive = false;
        }
    }
}

status_t SensorDevice::injectSensorData(const sensors_event_t* injected_sensor_event) {
    if (mHalWrapper == nullptr) return NO_INIT;
    ALOGD_IF(DEBUG_CONNECTIONS,
             "sensor_event handle=%d ts=%" PRId64 " data=%.2f, %.2f, %.2f %.2f %.2f %.2f",
             injected_sensor_event->sensor, injected_sensor_event->timestamp,
             injected_sensor_event->data[0], injected_sensor_event->data[1],
             injected_sensor_event->data[2], injected_sensor_event->data[3],
             injected_sensor_event->data[4], injected_sensor_event->data[5]);

    return mHalWrapper->injectSensorData(injected_sensor_event);
}

status_t SensorDevice::setMode(uint32_t mode) {
    if (mHalWrapper == nullptr) return NO_INIT;
    return mHalWrapper->setOperationMode(static_cast<SensorService::Mode>(mode));
}

int32_t SensorDevice::registerDirectChannel(const sensors_direct_mem_t* memory) {
    if (mHalWrapper == nullptr) return NO_INIT;
    Mutex::Autolock _l(mLock);

    int32_t channelHandle;
    status_t status = mHalWrapper->registerDirectChannel(memory, &channelHandle);
    if (status != OK) {
        channelHandle = -1;
    }

    return channelHandle;
}

void SensorDevice::unregisterDirectChannel(int32_t channelHandle) {
    mHalWrapper->unregisterDirectChannel(channelHandle);
}

int32_t SensorDevice::configureDirectChannel(int32_t sensorHandle, int32_t channelHandle,
                                             const struct sensors_direct_cfg_t* config) {
    if (mHalWrapper == nullptr) return NO_INIT;
    Mutex::Autolock _l(mLock);

    return mHalWrapper->configureDirectChannel(sensorHandle, channelHandle, config);
}

// ---------------------------------------------------------------------------

int SensorDevice::Info::numActiveClients() const {
    SensorDevice& device(SensorDevice::getInstance());
    int num = 0;
    for (size_t i = 0; i < batchParams.size(); ++i) {
        if (!device.isClientDisabledLocked(batchParams.keyAt(i))) {
            ++num;
        }
    }
    return num;
}

status_t SensorDevice::Info::setBatchParamsForIdent(void* ident, int, int64_t samplingPeriodNs,
                                                    int64_t maxBatchReportLatencyNs) {
    ssize_t index = batchParams.indexOfKey(ident);
    if (index < 0) {
        ALOGE("Info::setBatchParamsForIdent(ident=%p, period_ns=%" PRId64 " timeout=%" PRId64
              ") failed (%s)",
              ident, samplingPeriodNs, maxBatchReportLatencyNs, strerror(-index));
        return BAD_INDEX;
    }
    BatchParams& params = batchParams.editValueAt(index);
    params.mTSample = samplingPeriodNs;
    params.mTBatch = maxBatchReportLatencyNs;
    return NO_ERROR;
}

void SensorDevice::Info::selectBatchParams() {
    BatchParams bestParams; // default to max Tsample and max Tbatch
    SensorDevice& device(SensorDevice::getInstance());

    for (size_t i = 0; i < batchParams.size(); ++i) {
        if (device.isClientDisabledLocked(batchParams.keyAt(i))) {
            continue;
        }
        bestParams.merge(batchParams[i]);
    }
    // if mTBatch <= mTSample, it is in streaming mode. set mTbatch to 0 to demand this explicitly.
    if (bestParams.mTBatch <= bestParams.mTSample) {
        bestParams.mTBatch = 0;
    }
    bestBatchParams = bestParams;
}

ssize_t SensorDevice::Info::removeBatchParamsForIdent(void* ident) {
    ssize_t idx = batchParams.removeItem(ident);
    if (idx >= 0) {
        selectBatchParams();
    }
    return idx;
}

void SensorDevice::notifyConnectionDestroyed(void* ident) {
    Mutex::Autolock _l(mLock);
    mDisabledClients.erase(ident);
}

bool SensorDevice::isDirectReportSupported() const {
    return mIsDirectReportSupported;
}

float SensorDevice::getResolutionForSensor(int sensorHandle) {
    for (size_t i = 0; i < mSensorList.size(); i++) {
        if (sensorHandle == mSensorList[i].handle) {
            return mSensorList[i].resolution;
        }
    }

    auto it = mConnectedDynamicSensors.find(sensorHandle);
    if (it != mConnectedDynamicSensors.end()) {
        return it->second.resolution;
    }

    return 0;
}

// ---------------------------------------------------------------------------
}; // namespace android
