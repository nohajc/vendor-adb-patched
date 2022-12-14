/*
 * Copyright 2021 The Android Open Source Project
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

#include <memory>
#include <string>

#include <scheduler/Features.h>

namespace android::scheduler {

// TODO(b/185535769): Rename classes, and remove aliases.
class VSyncDispatch;
class VSyncTracker;

class VsyncController;
using VsyncDispatch = VSyncDispatch;
using VsyncTracker = VSyncTracker;

// Schedule that synchronizes to hardware VSYNC of a physical display.
class VsyncSchedule {
public:
    explicit VsyncSchedule(FeatureFlags);
    VsyncSchedule(VsyncSchedule&&);
    ~VsyncSchedule();

    // TODO(b/185535769): Hide behind API.
    const VsyncTracker& getTracker() const { return *mTracker; }
    VsyncTracker& getTracker() { return *mTracker; }
    VsyncController& getController() { return *mController; }

    // TODO(b/185535769): Remove once VsyncSchedule owns all registrations.
    VsyncDispatch& getDispatch() { return *mDispatch; }

    void dump(std::string&) const;

private:
    friend class TestableScheduler;

    using TrackerPtr = std::unique_ptr<VsyncTracker>;
    using DispatchPtr = std::unique_ptr<VsyncDispatch>;
    using ControllerPtr = std::unique_ptr<VsyncController>;

    // For tests.
    VsyncSchedule(TrackerPtr, DispatchPtr, ControllerPtr);

    static TrackerPtr createTracker();
    static DispatchPtr createDispatch(VsyncTracker&);
    static ControllerPtr createController(VsyncTracker&, FeatureFlags);

    class PredictedVsyncTracer;
    using TracerPtr = std::unique_ptr<PredictedVsyncTracer>;

    // Effectively const except in move constructor.
    TrackerPtr mTracker;
    DispatchPtr mDispatch;
    ControllerPtr mController;
    TracerPtr mTracer;
};

} // namespace android::scheduler
