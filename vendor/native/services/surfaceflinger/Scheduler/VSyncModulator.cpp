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

#include "VSyncModulator.h"

#include <cutils/properties.h>
#include <utils/Trace.h>

#include <chrono>
#include <cinttypes>
#include <mutex>

namespace android::scheduler {

VSyncModulator::VSyncModulator(IPhaseOffsetControl& phaseOffsetControl,
                               Scheduler::ConnectionHandle appConnectionHandle,
                               Scheduler::ConnectionHandle sfConnectionHandle,
                               const OffsetsConfig& config)
      : mPhaseOffsetControl(phaseOffsetControl),
        mAppConnectionHandle(appConnectionHandle),
        mSfConnectionHandle(sfConnectionHandle),
        mOffsetsConfig(config) {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.vsync_trace_detailed_info", value, "0");
    mTraceDetailedInfo = atoi(value);
}

void VSyncModulator::setPhaseOffsets(const OffsetsConfig& config) {
    std::lock_guard<std::mutex> lock(mMutex);
    mOffsetsConfig = config;
    updateOffsetsLocked();
}

void VSyncModulator::setTransactionStart(Scheduler::TransactionStart transactionStart) {
    switch (transactionStart) {
        case Scheduler::TransactionStart::EarlyStart:
            ALOGW_IF(mExplicitEarlyWakeup, "Already in TransactionStart::EarlyStart");
            mExplicitEarlyWakeup = true;
            break;
        case Scheduler::TransactionStart::EarlyEnd:
            ALOGW_IF(!mExplicitEarlyWakeup, "Not in TransactionStart::EarlyStart");
            mExplicitEarlyWakeup = false;
            break;
        case Scheduler::TransactionStart::Normal:
        case Scheduler::TransactionStart::Early:
            // Non explicit don't change the explicit early wakeup state
            break;
    }

    if (mTraceDetailedInfo) {
        ATRACE_INT("mExplicitEarlyWakeup", mExplicitEarlyWakeup);
    }

    if (!mExplicitEarlyWakeup &&
        (transactionStart == Scheduler::TransactionStart::Early ||
         transactionStart == Scheduler::TransactionStart::EarlyEnd)) {
        mRemainingEarlyFrameCount = MIN_EARLY_FRAME_COUNT_TRANSACTION;
        mEarlyTxnStartTime = std::chrono::steady_clock::now();
    }

    // An early transaction stays an early transaction.
    if (transactionStart == mTransactionStart ||
        mTransactionStart == Scheduler::TransactionStart::EarlyEnd) {
        return;
    }
    mTransactionStart = transactionStart;
    updateOffsets();
}

void VSyncModulator::onTransactionHandled() {
    mTxnAppliedTime = std::chrono::steady_clock::now();
    if (mTransactionStart == Scheduler::TransactionStart::Normal) return;
    mTransactionStart = Scheduler::TransactionStart::Normal;
    updateOffsets();
}

void VSyncModulator::onRefreshRateChangeInitiated() {
    if (mRefreshRateChangePending) {
        return;
    }
    mRefreshRateChangePending = true;
    updateOffsets();
}

void VSyncModulator::onRefreshRateChangeCompleted() {
    if (!mRefreshRateChangePending) {
        return;
    }
    mRefreshRateChangePending = false;
    updateOffsets();
}

void VSyncModulator::onRefreshed(bool usedRenderEngine) {
    bool updateOffsetsNeeded = false;

    // Apply a margin to account for potential data races
    // This might make us stay in early offsets for one
    // additional frame but it's better to be conservative here.
    if ((mEarlyTxnStartTime.load() + MARGIN_FOR_TX_APPLY) < mTxnAppliedTime.load()) {
        if (mRemainingEarlyFrameCount > 0) {
            mRemainingEarlyFrameCount--;
            updateOffsetsNeeded = true;
        }
    }
    if (usedRenderEngine) {
        mRemainingRenderEngineUsageCount = MIN_EARLY_GL_FRAME_COUNT_TRANSACTION;
        updateOffsetsNeeded = true;
    } else if (mRemainingRenderEngineUsageCount > 0) {
        mRemainingRenderEngineUsageCount--;
        updateOffsetsNeeded = true;
    }
    if (updateOffsetsNeeded) {
        updateOffsets();
    }
}

VSyncModulator::Offsets VSyncModulator::getOffsets() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mOffsets;
}

const VSyncModulator::Offsets& VSyncModulator::getNextOffsets() const {
    // Early offsets are used if we're in the middle of a refresh rate
    // change, or if we recently begin a transaction.
    if (mExplicitEarlyWakeup || mTransactionStart == Scheduler::TransactionStart::EarlyEnd ||
        mRemainingEarlyFrameCount > 0 || mRefreshRateChangePending) {
        return mOffsetsConfig.early;
    } else if (mRemainingRenderEngineUsageCount > 0) {
        return mOffsetsConfig.earlyGl;
    } else {
        return mOffsetsConfig.late;
    }
}

void VSyncModulator::updateOffsets() {
    std::lock_guard<std::mutex> lock(mMutex);
    updateOffsetsLocked();
}

void VSyncModulator::updateOffsetsLocked() {
    const Offsets& offsets = getNextOffsets();

    mPhaseOffsetControl.setPhaseOffset(mSfConnectionHandle, offsets.sf);
    mPhaseOffsetControl.setPhaseOffset(mAppConnectionHandle, offsets.app);

    mOffsets = offsets;

    if (!mTraceDetailedInfo) {
        return;
    }

    const bool isEarly = &offsets == &mOffsetsConfig.early;
    const bool isEarlyGl = &offsets == &mOffsetsConfig.earlyGl;
    const bool isLate = &offsets == &mOffsetsConfig.late;

    ATRACE_INT("Vsync-EarlyOffsetsOn", isEarly);
    ATRACE_INT("Vsync-EarlyGLOffsetsOn", isEarlyGl);
    ATRACE_INT("Vsync-LateOffsetsOn", isLate);
}

} // namespace android::scheduler

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
