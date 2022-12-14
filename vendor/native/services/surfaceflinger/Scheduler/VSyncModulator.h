/*
 * Copyright 2018 The Android Open Source Project
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

#include <chrono>
#include <mutex>

#include "Scheduler.h"

namespace android::scheduler {

/*
 * Modulates the vsync-offsets depending on current SurfaceFlinger state.
 */
class VSyncModulator {
private:
    // Number of frames we'll keep the early phase offsets once they are activated for a
    // transaction. This acts as a low-pass filter in case the client isn't quick enough in
    // sending new transactions.
    static constexpr int MIN_EARLY_FRAME_COUNT_TRANSACTION = 2;

    // Number of frames we'll keep the early gl phase offsets once they are activated.
    // This acts as a low-pass filter to avoid scenarios where we rapidly
    // switch in and out of gl composition.
    static constexpr int MIN_EARLY_GL_FRAME_COUNT_TRANSACTION = 2;

    // Margin used to account for potential data races
    static const constexpr std::chrono::nanoseconds MARGIN_FOR_TX_APPLY = 1ms;

public:
    // Wrapper for a collection of surfaceflinger/app offsets for a particular
    // configuration.
    struct Offsets {
        nsecs_t sf;
        nsecs_t app;

        bool operator==(const Offsets& other) const { return sf == other.sf && app == other.app; }

        bool operator!=(const Offsets& other) const { return !(*this == other); }
    };

    struct OffsetsConfig {
        Offsets early;   // For transactions with the eEarlyWakeup flag.
        Offsets earlyGl; // As above but while compositing with GL.
        Offsets late;    // Default.

        bool operator==(const OffsetsConfig& other) const {
            return early == other.early && earlyGl == other.earlyGl && late == other.late;
        }

        bool operator!=(const OffsetsConfig& other) const { return !(*this == other); }
    };

    VSyncModulator(IPhaseOffsetControl&, ConnectionHandle appConnectionHandle,
                   ConnectionHandle sfConnectionHandle, const OffsetsConfig&);

    void setPhaseOffsets(const OffsetsConfig&) EXCLUDES(mMutex);

    // Signals that a transaction has started, and changes offsets accordingly.
    void setTransactionStart(Scheduler::TransactionStart transactionStart);

    // Signals that a transaction has been completed, so that we can finish
    // special handling for a transaction.
    void onTransactionHandled();

    // Called when we send a refresh rate change to hardware composer, so that
    // we can move into early offsets.
    void onRefreshRateChangeInitiated();

    // Called when we detect from vsync signals that the refresh rate changed.
    // This way we can move out of early offsets if no longer necessary.
    void onRefreshRateChangeCompleted();

    // Called when the display is presenting a new frame. usedRenderEngine
    // should be set to true if RenderEngine was involved with composing the new
    // frame.
    void onRefreshed(bool usedRenderEngine);

    // Returns the offsets that we are currently using
    Offsets getOffsets() const EXCLUDES(mMutex);

private:
    friend class VSyncModulatorTest;
    // Returns the next offsets that we should be using
    const Offsets& getNextOffsets() const REQUIRES(mMutex);
    // Updates offsets and persists them into the scheduler framework.
    void updateOffsets() EXCLUDES(mMutex);
    void updateOffsetsLocked() REQUIRES(mMutex);

    IPhaseOffsetControl& mPhaseOffsetControl;
    const ConnectionHandle mAppConnectionHandle;
    const ConnectionHandle mSfConnectionHandle;

    mutable std::mutex mMutex;
    OffsetsConfig mOffsetsConfig GUARDED_BY(mMutex);

    Offsets mOffsets GUARDED_BY(mMutex){mOffsetsConfig.late};

    std::atomic<Scheduler::TransactionStart> mTransactionStart =
            Scheduler::TransactionStart::Normal;
    std::atomic<bool> mRefreshRateChangePending = false;
    std::atomic<bool> mExplicitEarlyWakeup = false;
    std::atomic<int> mRemainingEarlyFrameCount = 0;
    std::atomic<int> mRemainingRenderEngineUsageCount = 0;
    std::atomic<std::chrono::steady_clock::time_point> mEarlyTxnStartTime = {};
    std::atomic<std::chrono::steady_clock::time_point> mTxnAppliedTime = {};

    bool mTraceDetailedInfo = false;
};

} // namespace android::scheduler
