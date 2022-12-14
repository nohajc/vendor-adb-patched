/*
 * Copyright 2019 The Android Open Source Project
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

#include <android-base/thread_annotations.h>
#include <mutex>
#include <unordered_map>
#include <vector>
#include "SchedulerUtils.h"
#include "VSyncTracker.h"

namespace android::scheduler {

class VSyncPredictor : public VSyncTracker {
public:
    /*
     * \param [in] idealPeriod  The initial ideal period to use.
     * \param [in] historySize  The internal amount of entries to store in the model.
     * \param [in] minimumSamplesForPrediction The minimum number of samples to collect before
     * predicting. \param [in] outlierTolerancePercent a number 0 to 100 that will be used to filter
     * samples that fall outlierTolerancePercent from an anticipated vsync event.
     */
    VSyncPredictor(nsecs_t idealPeriod, size_t historySize, size_t minimumSamplesForPrediction,
                   uint32_t outlierTolerancePercent);
    ~VSyncPredictor();

    bool addVsyncTimestamp(nsecs_t timestamp) final;
    nsecs_t nextAnticipatedVSyncTimeFrom(nsecs_t timePoint) const final;
    nsecs_t currentPeriod() const final;
    void resetModel() final;

    /*
     * Inform the model that the period is anticipated to change to a new value.
     * model will use the period parameter to predict vsync events until enough
     * timestamps with the new period have been collected.
     *
     * \param [in] period   The new period that should be used.
     */
    void setPeriod(nsecs_t period) final;

    /* Query if the model is in need of more samples to make a prediction.
     * \return  True, if model would benefit from more samples, False if not.
     */
    bool needsMoreSamples() const final;

    std::tuple<nsecs_t /* slope */, nsecs_t /* intercept */> getVSyncPredictionModel() const;

    void dump(std::string& result) const final;

private:
    VSyncPredictor(VSyncPredictor const&) = delete;
    VSyncPredictor& operator=(VSyncPredictor const&) = delete;
    void clearTimestamps() REQUIRES(mMutex);

    inline void traceInt64If(const char* name, int64_t value) const;
    bool const mTraceOn;

    size_t const kHistorySize;
    size_t const kMinimumSamplesForPrediction;
    size_t const kOutlierTolerancePercent;

    std::mutex mutable mMutex;
    size_t next(int i) const REQUIRES(mMutex);
    bool validate(nsecs_t timestamp) const REQUIRES(mMutex);
    std::tuple<nsecs_t, nsecs_t> getVSyncPredictionModel(std::lock_guard<std::mutex> const&) const
            REQUIRES(mMutex);

    nsecs_t mIdealPeriod GUARDED_BY(mMutex);
    std::optional<nsecs_t> mKnownTimestamp GUARDED_BY(mMutex);

    std::unordered_map<nsecs_t, std::tuple<nsecs_t, nsecs_t>> mutable mRateMap GUARDED_BY(mMutex);

    int mLastTimestampIndex GUARDED_BY(mMutex) = 0;
    std::vector<nsecs_t> mTimestamps GUARDED_BY(mMutex);
};

} // namespace android::scheduler
