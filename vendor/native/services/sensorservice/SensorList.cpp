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

#include "SensorList.h"

#include <android/util/ProtoOutputStream.h>
#include <frameworks/base/core/proto/android/service/sensor_service.proto.h>
#include <hardware/sensors.h>
#include <utils/String8.h>

#include <cinttypes>

namespace android {
namespace SensorServiceUtil {

const Sensor SensorList::mNonSensor = Sensor("unknown");

bool SensorList::add(
        int handle, SensorInterface* si, bool isForDebug, bool isVirtual) {
    std::lock_guard<std::mutex> lk(mLock);
    if (handle == si->getSensor().getHandle() &&
        mUsedHandle.insert(handle).second) {
        // will succeed as the mUsedHandle does not have this handle
        mHandleMap.emplace(handle, Entry(si, isForDebug, isVirtual));
        return true;
    }
    // handle exist already or handle mismatch
    return false;
}

bool SensorList::remove(int handle) {
    std::lock_guard<std::mutex> lk(mLock);
    auto entry = mHandleMap.find(handle);
    if (entry != mHandleMap.end()) {
        mHandleMap.erase(entry);
        return true;
    }
    return false;
}

String8 SensorList::getName(int handle) const {
    return getOne<String8>(
            handle, [] (const Entry& e) -> String8 {return e.si->getSensor().getName();},
            mNonSensor.getName());
}

sp<SensorInterface> SensorList::getInterface(int handle) const {
    return getOne<sp<SensorInterface>>(
            handle, [] (const Entry& e) -> sp<SensorInterface> {return e.si;}, nullptr);
}


bool SensorList::isNewHandle(int handle) const {
    std::lock_guard<std::mutex> lk(mLock);
    return mUsedHandle.find(handle) == mUsedHandle.end();
}

const Vector<Sensor> SensorList::getUserSensors() const {
    // lock in forEachEntry
    Vector<Sensor> sensors;
    forEachEntry(
            [&sensors] (const Entry& e) -> bool {
                if (!e.isForDebug && !e.si->getSensor().isDynamicSensor()) {
                    sensors.add(e.si->getSensor());
                }
                return true;
            });
    return sensors;
}

const Vector<Sensor> SensorList::getUserDebugSensors() const {
    // lock in forEachEntry
    Vector<Sensor> sensors;
    forEachEntry(
            [&sensors] (const Entry& e) -> bool {
                if (!e.si->getSensor().isDynamicSensor()) {
                    sensors.add(e.si->getSensor());
                }
                return true;
            });
    return sensors;
}

const Vector<Sensor> SensorList::getDynamicSensors() const {
    // lock in forEachEntry
    Vector<Sensor> sensors;
    forEachEntry(
            [&sensors] (const Entry& e) -> bool {
                if (!e.isForDebug && e.si->getSensor().isDynamicSensor()) {
                    sensors.add(e.si->getSensor());
                }
                return true;
            });
    return sensors;
}

const Vector<Sensor> SensorList::getVirtualSensors() const {
    // lock in forEachEntry
    Vector<Sensor> sensors;
    forEachEntry(
            [&sensors] (const Entry& e) -> bool {
                if (e.isVirtual) {
                    sensors.add(e.si->getSensor());
                }
                return true;
            });
    return sensors;
}

std::string SensorList::dump() const {
    String8 result;

    forEachSensor([&result] (const Sensor& s) -> bool {
            result.appendFormat(
                    "%#010x) %-25s | %-15s | ver: %" PRId32 " | type: %20s(%" PRId32
                        ") | perm: %s | flags: 0x%08x\n",
                    s.getHandle(),
                    s.getName().string(),
                    s.getVendor().string(),
                    s.getVersion(),
                    s.getStringType().string(),
                    s.getType(),
                    s.getRequiredPermission().size() ? s.getRequiredPermission().string() : "n/a",
                    static_cast<int>(s.getFlags()));

            result.append("\t");
            const int reportingMode = s.getReportingMode();
            if (reportingMode == AREPORTING_MODE_CONTINUOUS) {
                result.append("continuous | ");
            } else if (reportingMode == AREPORTING_MODE_ON_CHANGE) {
                result.append("on-change | ");
            } else if (reportingMode == AREPORTING_MODE_ONE_SHOT) {
                result.append("one-shot | ");
            } else if (reportingMode == AREPORTING_MODE_SPECIAL_TRIGGER) {
                result.append("special-trigger | ");
            } else {
                result.append("unknown-mode | ");
            }

            if (s.getMaxDelay() > 0) {
                result.appendFormat("minRate=%.2fHz | ", 1e6f / s.getMaxDelay());
            } else {
                result.appendFormat("maxDelay=%" PRId32 "us | ", s.getMaxDelay());
            }

            if (s.getMinDelay() > 0) {
                result.appendFormat("maxRate=%.2fHz | ", 1e6f / s.getMinDelay());
            } else {
                result.appendFormat("minDelay=%" PRId32 "us | ", s.getMinDelay());
            }

            if (s.getFifoMaxEventCount() > 0) {
                result.appendFormat("FIFO (max,reserved) = (%" PRIu32 ", %" PRIu32 ") events | ",
                        s.getFifoMaxEventCount(),
                        s.getFifoReservedEventCount());
            } else {
                result.append("no batching | ");
            }

            if (s.isWakeUpSensor()) {
                result.appendFormat("wakeUp | ");
            } else {
                result.appendFormat("non-wakeUp | ");
            }

            if (s.isDataInjectionSupported()) {
                result.appendFormat("data-injection, ");
            }

            if (s.isDynamicSensor()) {
                result.appendFormat("dynamic, ");
            }

            if (s.hasAdditionalInfo()) {
                result.appendFormat("has-additional-info, ");
            }
            result.append("\n");

            if (s.getHighestDirectReportRateLevel() > SENSOR_DIRECT_RATE_STOP) {
                result.appendFormat("\thighest rate level = %d, support shared mem: ",
                        s.getHighestDirectReportRateLevel());
                if (s.isDirectChannelTypeSupported(SENSOR_DIRECT_MEM_TYPE_ASHMEM)) {
                    result.append("ashmem, ");
                }
                if (s.isDirectChannelTypeSupported(SENSOR_DIRECT_MEM_TYPE_GRALLOC)) {
                    result.append("gralloc, ");
                }
                result.append("\n");
            }
            return true;
        });
    return std::string(result.string());
}

/**
 * Dump debugging information as android.service.SensorListProto protobuf message using
 * ProtoOutputStream.
 *
 * See proto definition and some notes about ProtoOutputStream in
 * frameworks/base/core/proto/android/service/sensor_service.proto
 */
void SensorList::dump(util::ProtoOutputStream* proto) const {
    using namespace service::SensorListProto;
    using namespace service::SensorListProto::SensorProto;

    forEachSensor([&proto] (const Sensor& s) -> bool {
        const uint64_t token = proto->start(SENSORS);
        proto->write(HANDLE, s.getHandle());
        proto->write(NAME, std::string(s.getName().string()));
        proto->write(VENDOR, std::string(s.getVendor().string()));
        proto->write(VERSION, s.getVersion());
        proto->write(STRING_TYPE, std::string(s.getStringType().string()));
        proto->write(TYPE, s.getType());
        proto->write(REQUIRED_PERMISSION, std::string(s.getRequiredPermission().size() ?
                s.getRequiredPermission().string() : ""));
        proto->write(FLAGS, int(s.getFlags()));
        switch (s.getReportingMode()) {
            case AREPORTING_MODE_CONTINUOUS:
                proto->write(REPORTING_MODE, RM_CONTINUOUS);
                break;
            case AREPORTING_MODE_ON_CHANGE:
                proto->write(REPORTING_MODE, RM_ON_CHANGE);
                break;
            case AREPORTING_MODE_ONE_SHOT:
                proto->write(REPORTING_MODE, RM_ONE_SHOT);
                break;
            case AREPORTING_MODE_SPECIAL_TRIGGER:
                proto->write(REPORTING_MODE, RM_SPECIAL_TRIGGER);
                break;
            default:
                proto->write(REPORTING_MODE, RM_UNKNOWN);
        }
        proto->write(MAX_DELAY_US, s.getMaxDelay());
        proto->write(MIN_DELAY_US, s.getMinDelay());
        proto->write(FIFO_MAX_EVENT_COUNT, int(s.getFifoMaxEventCount()));
        proto->write(FIFO_RESERVED_EVENT_COUNT, int(s.getFifoReservedEventCount()));
        proto->write(IS_WAKEUP, s.isWakeUpSensor());
        proto->write(DATA_INJECTION_SUPPORTED, s.isDataInjectionSupported());
        proto->write(IS_DYNAMIC, s.isDynamicSensor());
        proto->write(HAS_ADDITIONAL_INFO, s.hasAdditionalInfo());
        proto->write(HIGHEST_RATE_LEVEL, s.getHighestDirectReportRateLevel());
        proto->write(ASHMEM, s.isDirectChannelTypeSupported(SENSOR_DIRECT_MEM_TYPE_ASHMEM));
        proto->write(GRALLOC, s.isDirectChannelTypeSupported(SENSOR_DIRECT_MEM_TYPE_GRALLOC));
        proto->write(MIN_VALUE, s.getMinValue());
        proto->write(MAX_VALUE, s.getMaxValue());
        proto->write(RESOLUTION, s.getResolution());
        proto->write(POWER_USAGE, s.getPowerUsage());
        proto->end(token);
        return true;
    });
}

SensorList::~SensorList() {
}

} // namespace SensorServiceUtil
} // namespace android

