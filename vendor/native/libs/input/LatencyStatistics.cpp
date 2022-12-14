/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <input/LatencyStatistics.h>

#include <android-base/chrono_utils.h>

#include <cmath>
#include <limits>

namespace android {

LatencyStatistics::LatencyStatistics(std::chrono::seconds period) : mReportPeriod(period) {
    reset();
}

/**
 * Add a raw value to the statistics
 */
void LatencyStatistics::addValue(float value) {
    if (value < mMin) {
        mMin = value;
    }
    if (value > mMax) {
        mMax = value;
    }
    mSum += value;
    mSum2 += value * value;
    mCount++;
}

/**
 * Get the mean. Should not be called if no samples have been added.
 */
float LatencyStatistics::getMean() {
    return mSum / mCount;
}

/**
 * Get the standard deviation. Should not be called if no samples have been added.
 */
float LatencyStatistics::getStDev() {
    float mean = getMean();
    return sqrt(mSum2 / mCount - mean * mean);
}

float LatencyStatistics::getMin() {
    return mMin;
}

float LatencyStatistics::getMax() {
    return mMax;
}

size_t LatencyStatistics::getCount() {
    return mCount;
}

/**
 * Reset internal state. The variable 'when' is the time when the data collection started.
 * Call this to start a new data collection window.
 */
void LatencyStatistics::reset() {
    mMax = std::numeric_limits<float>::lowest();
    mMin = std::numeric_limits<float>::max();
    mSum = 0;
    mSum2 = 0;
    mCount = 0;
    mLastReportTime = std::chrono::steady_clock::now();
}

bool LatencyStatistics::shouldReport() {
    std::chrono::duration timeSinceReport = std::chrono::steady_clock::now() - mLastReportTime;
    return mCount != 0 && timeSinceReport >= mReportPeriod;
}

} // namespace android
