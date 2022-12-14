/*
 * Copyright 2020 The Android Open Source Project
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

#pragma once

#include <cstddef>
#include <memory>
#include <mutex>

#include <DisplayHardware/HWComposer.h>
#include <DisplayHardware/Hal.h>
#include <ui/FenceTime.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

namespace android::scheduler {

class VsyncController {
public:
    virtual ~VsyncController();

    /*
     * Adds a present fence to the model. The controller will use the fence time as
     * a vsync signal.
     *
     * \param [in] fence    The present fence given from the display
     * \return              True if the model needs more vsync signals to make
     *                      an accurate prediction,
     *                      False otherwise
     */
    virtual bool addPresentFence(std::shared_ptr<FenceTime>) = 0;

    /*
     * Adds a hw sync timestamp to the model. The controller will use the timestamp
     * time as a vsync signal.
     *
     * \param [in] timestamp       The HW Vsync timestamp
     * \param [in] hwcVsyncPeriod  The Vsync period reported by composer, if available
     * \param [out] periodFlushed  True if the vsync period changed is completed
     * \return                     True if the model needs more vsync signals to make
     *                             an accurate prediction,
     *                             False otherwise
     */
    virtual bool addHwVsyncTimestamp(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                                     bool* periodFlushed) = 0;

    /*
     * Inform the controller that the period is changing and the controller needs to recalibrate
     * itself. The controller will end the period transition internally.
     *
     * \param [in] period   The period that the system is changing into.
     */
    virtual void startPeriodTransition(nsecs_t period) = 0;

    /*
     * Tells the tracker to stop using present fences to get a vsync signal.
     *
     * \param [in] ignore  Whether to ignore the present fences or not
     */
    virtual void setIgnorePresentFences(bool ignore) = 0;

    /*
     * Sets the primary display power mode to the controller.
     *
     * \param [in] powerMode
     */
    virtual void setDisplayPowerMode(hal::PowerMode powerMode) = 0;

    virtual void dump(std::string& result) const = 0;

protected:
    VsyncController() = default;
    VsyncController(VsyncController const&) = delete;
    VsyncController& operator=(VsyncController const&) = delete;
};

} // namespace android::scheduler
