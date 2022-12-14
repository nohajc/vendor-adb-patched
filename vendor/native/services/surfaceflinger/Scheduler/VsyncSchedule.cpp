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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <scheduler/Fps.h>
#include <scheduler/Timer.h>

#include "VsyncSchedule.h"

#include "VSyncDispatchTimerQueue.h"
#include "VSyncPredictor.h"
#include "VSyncReactor.h"

#include "../TracedOrdinal.h"

namespace android::scheduler {

class VsyncSchedule::PredictedVsyncTracer {
    // Invoked from the thread of the VsyncDispatch owned by this VsyncSchedule.
    constexpr auto makeVsyncCallback() {
        return [this](nsecs_t, nsecs_t, nsecs_t) {
            mParity = !mParity;
            schedule();
        };
    }

public:
    explicit PredictedVsyncTracer(VsyncDispatch& dispatch)
          : mRegistration(dispatch, makeVsyncCallback(), __func__) {
        schedule();
    }

private:
    void schedule() { mRegistration.schedule({0, 0, 0}); }

    TracedOrdinal<bool> mParity = {"VSYNC-predicted", 0};
    VSyncCallbackRegistration mRegistration;
};

VsyncSchedule::VsyncSchedule(FeatureFlags features)
      : mTracker(createTracker()),
        mDispatch(createDispatch(*mTracker)),
        mController(createController(*mTracker, features)) {
    if (features.test(Feature::kTracePredictedVsync)) {
        mTracer = std::make_unique<PredictedVsyncTracer>(*mDispatch);
    }
}

VsyncSchedule::VsyncSchedule(TrackerPtr tracker, DispatchPtr dispatch, ControllerPtr controller)
      : mTracker(std::move(tracker)),
        mDispatch(std::move(dispatch)),
        mController(std::move(controller)) {}

VsyncSchedule::VsyncSchedule(VsyncSchedule&&) = default;
VsyncSchedule::~VsyncSchedule() = default;

void VsyncSchedule::dump(std::string& out) const {
    out.append("VsyncController:\n");
    mController->dump(out);

    out.append("VsyncDispatch:\n");
    mDispatch->dump(out);
}

VsyncSchedule::TrackerPtr VsyncSchedule::createTracker() {
    // TODO(b/144707443): Tune constants.
    constexpr nsecs_t kInitialPeriod = (60_Hz).getPeriodNsecs();
    constexpr size_t kHistorySize = 20;
    constexpr size_t kMinSamplesForPrediction = 6;
    constexpr uint32_t kDiscardOutlierPercent = 20;

    return std::make_unique<VSyncPredictor>(kInitialPeriod, kHistorySize, kMinSamplesForPrediction,
                                            kDiscardOutlierPercent);
}

VsyncSchedule::DispatchPtr VsyncSchedule::createDispatch(VsyncTracker& tracker) {
    using namespace std::chrono_literals;

    // TODO(b/144707443): Tune constants.
    constexpr std::chrono::nanoseconds kGroupDispatchWithin = 500us;
    constexpr std::chrono::nanoseconds kSnapToSameVsyncWithin = 3ms;

    return std::make_unique<VSyncDispatchTimerQueue>(std::make_unique<Timer>(), tracker,
                                                     kGroupDispatchWithin.count(),
                                                     kSnapToSameVsyncWithin.count());
}

VsyncSchedule::ControllerPtr VsyncSchedule::createController(VsyncTracker& tracker,
                                                             FeatureFlags features) {
    // TODO(b/144707443): Tune constants.
    constexpr size_t kMaxPendingFences = 20;
    const bool hasKernelIdleTimer = features.test(Feature::kKernelIdleTimer);

    auto reactor = std::make_unique<VSyncReactor>(std::make_unique<SystemClock>(), tracker,
                                                  kMaxPendingFences, hasKernelIdleTimer);

    reactor->setIgnorePresentFences(!features.test(Feature::kPresentFences));
    return reactor;
}

} // namespace android::scheduler
