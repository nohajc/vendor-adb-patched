/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define DEBUG false // STOPSHIP if true
#define LOG_TAG "StatsHal"

#include <log/log.h>
#include <statslog.h>

#include "StatsHal.h"

namespace android {
namespace frameworks {
namespace stats {
namespace V1_0 {
namespace implementation {

StatsHal::StatsHal() {}

hardware::Return<void> StatsHal::reportSpeakerImpedance(
        const SpeakerImpedance& speakerImpedance) {
    android::util::stats_write(android::util::SPEAKER_IMPEDANCE_REPORTED,
            speakerImpedance.speakerLocation, speakerImpedance.milliOhms);

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportHardwareFailed(const HardwareFailed& hardwareFailed) {
    android::util::stats_write(android::util::HARDWARE_FAILED, int32_t(hardwareFailed.hardwareType),
            hardwareFailed.hardwareLocation, int32_t(hardwareFailed.errorCode));

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportPhysicalDropDetected(
        const PhysicalDropDetected& physicalDropDetected) {
    android::util::stats_write(android::util::PHYSICAL_DROP_DETECTED,
            int32_t(physicalDropDetected.confidencePctg), physicalDropDetected.accelPeak,
            physicalDropDetected.freefallDuration);

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportChargeCycles(const ChargeCycles& chargeCycles) {
    std::vector<int32_t> buckets = chargeCycles.cycleBucket;
    int initialSize = buckets.size();
    for (int i = 0; i < 10 - initialSize; i++) {
        buckets.push_back(0); // Push 0 for buckets that do not exist.
    }
    android::util::stats_write(android::util::CHARGE_CYCLES_REPORTED, buckets[0], buckets[1],
            buckets[2], buckets[3], buckets[4], buckets[5], buckets[6], buckets[7], buckets[8],
            buckets[9]);

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportBatteryHealthSnapshot(
        const BatteryHealthSnapshotArgs& batteryHealthSnapshotArgs) {
    android::util::stats_write(android::util::BATTERY_HEALTH_SNAPSHOT,
            int32_t(batteryHealthSnapshotArgs.type), batteryHealthSnapshotArgs.temperatureDeciC,
            batteryHealthSnapshotArgs.voltageMicroV, batteryHealthSnapshotArgs.currentMicroA,
            batteryHealthSnapshotArgs.openCircuitVoltageMicroV,
            batteryHealthSnapshotArgs.resistanceMicroOhm, batteryHealthSnapshotArgs.levelPercent);

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportSlowIo(const SlowIo& slowIo) {
    android::util::stats_write(android::util::SLOW_IO, int32_t(slowIo.operation), slowIo.count);

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportBatteryCausedShutdown(
        const BatteryCausedShutdown& batteryCausedShutdown) {
    android::util::stats_write(android::util::BATTERY_CAUSED_SHUTDOWN,
            batteryCausedShutdown.voltageMicroV);

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportUsbPortOverheatEvent(
        const UsbPortOverheatEvent& usbPortOverheatEvent) {
    android::util::stats_write(android::util::USB_PORT_OVERHEAT_EVENT_REPORTED,
            usbPortOverheatEvent.plugTemperatureDeciC, usbPortOverheatEvent.maxTemperatureDeciC,
            usbPortOverheatEvent.timeToOverheat, usbPortOverheatEvent.timeToHysteresis,
            usbPortOverheatEvent.timeToInactive);

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportSpeechDspStat(
        const SpeechDspStat& speechDspStat) {
    android::util::stats_write(android::util::SPEECH_DSP_STAT_REPORTED,
            speechDspStat.totalUptimeMillis, speechDspStat.totalDowntimeMillis,
            speechDspStat.totalCrashCount, speechDspStat.totalRecoverCount);

    return hardware::Void();
}

hardware::Return<void> StatsHal::reportVendorAtom(const VendorAtom& vendorAtom) {
    std::string reverseDomainName = (std::string) vendorAtom.reverseDomainName;
    if (vendorAtom.atomId < 100000 || vendorAtom.atomId >= 200000) {
        ALOGE("Atom ID %ld is not a valid vendor atom ID", (long) vendorAtom.atomId);
        return hardware::Void();
    }
    if (reverseDomainName.length() > 50) {
        ALOGE("Vendor atom reverse domain name %s is too long.", reverseDomainName.c_str());
        return hardware::Void();
    }
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, vendorAtom.atomId);
    AStatsEvent_writeString(event, vendorAtom.reverseDomainName.c_str());
    for (int i = 0; i < (int)vendorAtom.values.size(); i++) {
        switch (vendorAtom.values[i].getDiscriminator()) {
            case VendorAtom::Value::hidl_discriminator::intValue:
                AStatsEvent_writeInt32(event, vendorAtom.values[i].intValue());
                break;
            case VendorAtom::Value::hidl_discriminator::longValue:
                AStatsEvent_writeInt64(event, vendorAtom.values[i].longValue());
                break;
            case VendorAtom::Value::hidl_discriminator::floatValue:
                AStatsEvent_writeFloat(event, vendorAtom.values[i].floatValue());
                break;
            case VendorAtom::Value::hidl_discriminator::stringValue:
                AStatsEvent_writeString(event, vendorAtom.values[i].stringValue().c_str());
                break;
        }
    }
    AStatsEvent_build(event);
    AStatsEvent_write(event);
    AStatsEvent_release(event);

    return hardware::Void();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace stats
}  // namespace frameworks
}  // namespace android
