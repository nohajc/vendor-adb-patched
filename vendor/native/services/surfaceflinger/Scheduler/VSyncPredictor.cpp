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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#define ATRACE_TAG ATRACE_TAG_GRAPHICS
//#define LOG_NDEBUG 0
#include "VSyncPredictor.h"
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cutils/compiler.h>
#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/Trace.h>
#include <algorithm>
#include <chrono>
#include <sstream>

namespace android::scheduler {
using base::StringAppendF;

static auto constexpr kMaxPercent = 100u;

VSyncPredictor::~VSyncPredictor() = default;

VSyncPredictor::VSyncPredictor(nsecs_t idealPeriod, size_t historySize,
                               size_t minimumSamplesForPrediction, uint32_t outlierTolerancePercent)
      : mTraceOn(property_get_bool("debug.sf.vsp_trace", true)),
        kHistorySize(historySize),
        kMinimumSamplesForPrediction(minimumSamplesForPrediction),
        kOutlierTolerancePercent(std::min(outlierTolerancePercent, kMaxPercent)),
        mIdealPeriod(idealPeriod) {
    resetModel();
}

inline void VSyncPredictor::traceInt64If(const char* name, int64_t value) const {
    if (CC_UNLIKELY(mTraceOn)) {
        ATRACE_INT64(name, value);
    }
}

inline size_t VSyncPredictor::next(int i) const {
    return (i + 1) % mTimestamps.size();
}

bool VSyncPredictor::validate(nsecs_t timestamp) const {
    if (mLastTimestampIndex < 0 || mTimestamps.empty()) {
        return true;
    }

    auto const aValidTimestamp = mTimestamps[mLastTimestampIndex];
    auto const percent = (timestamp - aValidTimestamp) % mIdealPeriod * kMaxPercent / mIdealPeriod;
    return percent < kOutlierTolerancePercent || percent > (kMaxPercent - kOutlierTolerancePercent);
}

nsecs_t VSyncPredictor::currentPeriod() const {
    std::lock_guard<std::mutex> lk(mMutex);
    return std::get<0>(mRateMap.find(mIdealPeriod)->second);
}

bool VSyncPredictor::addVsyncTimestamp(nsecs_t timestamp) {
    std::lock_guard<std::mutex> lk(mMutex);

    if (!validate(timestamp)) {
        // VSR could elect to ignore the incongruent timestamp or resetModel(). If ts is ignored,
        // don't insert this ts into mTimestamps ringbuffer. If we are still
        // in the learning phase we should just clear all timestamps and start
        // over.
        if (mTimestamps.size() < kMinimumSamplesForPrediction) {
            clearTimestamps();
        } else if (!mTimestamps.empty()) {
            mKnownTimestamp =
                    std::max(timestamp, *std::max_element(mTimestamps.begin(), mTimestamps.end()));
        } else {
            mKnownTimestamp = timestamp;
        }
        return false;
    }

    if (mTimestamps.size() != kHistorySize) {
        mTimestamps.push_back(timestamp);
        mLastTimestampIndex = next(mLastTimestampIndex);
    } else {
        mLastTimestampIndex = next(mLastTimestampIndex);
        mTimestamps[mLastTimestampIndex] = timestamp;
    }

    if (mTimestamps.size() < kMinimumSamplesForPrediction) {
        mRateMap[mIdealPeriod] = {mIdealPeriod, 0};
        return true;
    }

    // This is a 'simple linear regression' calculation of Y over X, with Y being the
    // vsync timestamps, and X being the ordinal of vsync count.
    // The calculated slope is the vsync period.
    // Formula for reference:
    // Sigma_i: means sum over all timestamps.
    // mean(variable): statistical mean of variable.
    // X: snapped ordinal of the timestamp
    // Y: vsync timestamp
    //
    //         Sigma_i( (X_i - mean(X)) * (Y_i - mean(Y) )
    // slope = -------------------------------------------
    //         Sigma_i ( X_i - mean(X) ) ^ 2
    //
    // intercept = mean(Y) - slope * mean(X)
    //
    std::vector<nsecs_t> vsyncTS(mTimestamps.size());
    std::vector<nsecs_t> ordinals(mTimestamps.size());

    // normalizing to the oldest timestamp cuts down on error in calculating the intercept.
    auto const oldest_ts = *std::min_element(mTimestamps.begin(), mTimestamps.end());
    auto it = mRateMap.find(mIdealPeriod);
    auto const currentPeriod = std::get<0>(it->second);
    // TODO (b/144707443): its important that there's some precision in the mean of the ordinals
    //                     for the intercept calculation, so scale the ordinals by 1000 to continue
    //                     fixed point calculation. Explore expanding
    //                     scheduler::utils::calculate_mean to have a fixed point fractional part.
    static constexpr int64_t kScalingFactor = 1000;

    for (auto i = 0u; i < mTimestamps.size(); i++) {
        traceInt64If("VSP-ts", mTimestamps[i]);

        vsyncTS[i] = mTimestamps[i] - oldest_ts;
        ordinals[i] = ((vsyncTS[i] + (currentPeriod / 2)) / currentPeriod) * kScalingFactor;
    }

    auto meanTS = scheduler::calculate_mean(vsyncTS);
    auto meanOrdinal = scheduler::calculate_mean(ordinals);
    for (auto i = 0; i < vsyncTS.size(); i++) {
        vsyncTS[i] -= meanTS;
        ordinals[i] -= meanOrdinal;
    }

    auto top = 0ll;
    auto bottom = 0ll;
    for (auto i = 0; i < vsyncTS.size(); i++) {
        top += vsyncTS[i] * ordinals[i];
        bottom += ordinals[i] * ordinals[i];
    }

    if (CC_UNLIKELY(bottom == 0)) {
        it->second = {mIdealPeriod, 0};
        clearTimestamps();
        return false;
    }

    nsecs_t const anticipatedPeriod = top * kScalingFactor / bottom;
    nsecs_t const intercept = meanTS - (anticipatedPeriod * meanOrdinal / kScalingFactor);

    auto const percent = std::abs(anticipatedPeriod - mIdealPeriod) * kMaxPercent / mIdealPeriod;
    if (percent >= kOutlierTolerancePercent) {
        it->second = {mIdealPeriod, 0};
        clearTimestamps();
        return false;
    }

    traceInt64If("VSP-period", anticipatedPeriod);
    traceInt64If("VSP-intercept", intercept);

    it->second = {anticipatedPeriod, intercept};

    ALOGV("model update ts: %" PRId64 " slope: %" PRId64 " intercept: %" PRId64, timestamp,
          anticipatedPeriod, intercept);
    return true;
}

nsecs_t VSyncPredictor::nextAnticipatedVSyncTimeFrom(nsecs_t timePoint) const {
    std::lock_guard<std::mutex> lk(mMutex);

    auto const [slope, intercept] = getVSyncPredictionModel(lk);

    if (mTimestamps.empty()) {
        traceInt64If("VSP-mode", 1);
        auto const knownTimestamp = mKnownTimestamp ? *mKnownTimestamp : timePoint;
        auto const numPeriodsOut = ((timePoint - knownTimestamp) / mIdealPeriod) + 1;
        return knownTimestamp + numPeriodsOut * mIdealPeriod;
    }

    auto const oldest = *std::min_element(mTimestamps.begin(), mTimestamps.end());

    // See b/145667109, the ordinal calculation must take into account the intercept.
    auto const zeroPoint = oldest + intercept;
    auto const ordinalRequest = (timePoint - zeroPoint + slope) / slope;
    auto const prediction = (ordinalRequest * slope) + intercept + oldest;

    traceInt64If("VSP-mode", 0);
    traceInt64If("VSP-timePoint", timePoint);
    traceInt64If("VSP-prediction", prediction);

    auto const printer = [&, slope = slope, intercept = intercept] {
        std::stringstream str;
        str << "prediction made from: " << timePoint << "prediction: " << prediction << " (+"
            << prediction - timePoint << ") slope: " << slope << " intercept: " << intercept
            << "oldestTS: " << oldest << " ordinal: " << ordinalRequest;
        return str.str();
    };

    ALOGV("%s", printer().c_str());
    LOG_ALWAYS_FATAL_IF(prediction < timePoint, "VSyncPredictor: model miscalculation: %s",
                        printer().c_str());

    return prediction;
}

std::tuple<nsecs_t, nsecs_t> VSyncPredictor::getVSyncPredictionModel() const {
    std::lock_guard<std::mutex> lk(mMutex);
    return VSyncPredictor::getVSyncPredictionModel(lk);
}

std::tuple<nsecs_t, nsecs_t> VSyncPredictor::getVSyncPredictionModel(
        std::lock_guard<std::mutex> const&) const {
    return mRateMap.find(mIdealPeriod)->second;
}

void VSyncPredictor::setPeriod(nsecs_t period) {
    ATRACE_CALL();

    std::lock_guard<std::mutex> lk(mMutex);
    static constexpr size_t kSizeLimit = 30;
    if (CC_UNLIKELY(mRateMap.size() == kSizeLimit)) {
        mRateMap.erase(mRateMap.begin());
    }

    mIdealPeriod = period;
    if (mRateMap.find(period) == mRateMap.end()) {
        mRateMap[mIdealPeriod] = {period, 0};
    }

    clearTimestamps();
}

void VSyncPredictor::clearTimestamps() {
    if (!mTimestamps.empty()) {
        auto const maxRb = *std::max_element(mTimestamps.begin(), mTimestamps.end());
        if (mKnownTimestamp) {
            mKnownTimestamp = std::max(*mKnownTimestamp, maxRb);
        } else {
            mKnownTimestamp = maxRb;
        }

        mTimestamps.clear();
        mLastTimestampIndex = 0;
    }
}

bool VSyncPredictor::needsMoreSamples() const {
    std::lock_guard<std::mutex> lk(mMutex);
    return mTimestamps.size() < kMinimumSamplesForPrediction;
}

void VSyncPredictor::resetModel() {
    std::lock_guard<std::mutex> lk(mMutex);
    mRateMap[mIdealPeriod] = {mIdealPeriod, 0};
    clearTimestamps();
}

void VSyncPredictor::dump(std::string& result) const {
    std::lock_guard<std::mutex> lk(mMutex);
    StringAppendF(&result, "\tmIdealPeriod=%.2f\n", mIdealPeriod / 1e6f);
    StringAppendF(&result, "\tRefresh Rate Map:\n");
    for (const auto& [idealPeriod, periodInterceptTuple] : mRateMap) {
        StringAppendF(&result,
                      "\t\tFor ideal period %.2fms: period = %.2fms, intercept = %" PRId64 "\n",
                      idealPeriod / 1e6f, std::get<0>(periodInterceptTuple) / 1e6f,
                      std::get<1>(periodInterceptTuple));
    }
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
