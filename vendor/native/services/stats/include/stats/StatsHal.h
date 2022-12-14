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

#include <android/frameworks/stats/1.0/IStats.h>
#include <android/frameworks/stats/1.0/types.h>
#include <stats_event.h>

using namespace android::frameworks::stats::V1_0;

namespace android {
namespace frameworks {
namespace stats {
namespace V1_0 {
namespace implementation {

using android::hardware::Return;

/**
 * Implements the Stats HAL
 */
class StatsHal : public IStats {
public:
    StatsHal();

    /**
     * Binder call to get SpeakerImpedance atom.
     */
    virtual Return<void> reportSpeakerImpedance(const SpeakerImpedance& speakerImpedance) override;

    /**
     * Binder call to get HardwareFailed atom.
     */
    virtual Return<void> reportHardwareFailed(const HardwareFailed& hardwareFailed) override;

    /**
     * Binder call to get PhysicalDropDetected atom.
     */
    virtual Return<void> reportPhysicalDropDetected(
            const PhysicalDropDetected& physicalDropDetected) override;

    /**
     * Binder call to get ChargeCyclesReported atom.
     */
    virtual Return<void> reportChargeCycles(const ChargeCycles& chargeCycles) override;

    /**
     * Binder call to get BatteryHealthSnapshot atom.
     */
    virtual Return<void> reportBatteryHealthSnapshot(
            const BatteryHealthSnapshotArgs& batteryHealthSnapshotArgs) override;

    /**
     * Binder call to get SlowIo atom.
     */
    virtual Return<void> reportSlowIo(const SlowIo& slowIo) override;

    /**
     * Binder call to get BatteryCausedShutdown atom.
     */
    virtual Return<void> reportBatteryCausedShutdown(
            const BatteryCausedShutdown& batteryCausedShutdown) override;

    /**
     * Binder call to get UsbPortOverheatEvent atom.
     */
    virtual Return<void> reportUsbPortOverheatEvent(
            const UsbPortOverheatEvent& usbPortOverheatEvent) override;

    /**
     * Binder call to get Speech DSP state atom.
     */
    virtual Return<void> reportSpeechDspStat(const SpeechDspStat& speechDspStat) override;

    /**
     * Binder call to get vendor atom.
     */
    virtual Return<void> reportVendorAtom(const VendorAtom& vendorAtom) override;
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace stats
}  // namespace frameworks
}  // namespace android
