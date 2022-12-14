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

#undef LOG_TAG
#define LOG_TAG "FrameTimeline"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "FrameTimeline.h"

#include <android-base/stringprintf.h>
#include <utils/Log.h>
#include <utils/Trace.h>

#include <chrono>
#include <cinttypes>
#include <numeric>
#include <unordered_set>

namespace android::frametimeline {

using base::StringAppendF;
using FrameTimelineEvent = perfetto::protos::pbzero::FrameTimelineEvent;
using FrameTimelineDataSource = impl::FrameTimeline::FrameTimelineDataSource;

void dumpTable(std::string& result, TimelineItem predictions, TimelineItem actuals,
               const std::string& indent, PredictionState predictionState, nsecs_t baseTime) {
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "\t\t");
    StringAppendF(&result, "    Start time\t\t|");
    StringAppendF(&result, "    End time\t\t|");
    StringAppendF(&result, "    Present time\n");
    if (predictionState == PredictionState::Valid) {
        // Dump the Predictions only if they are valid
        StringAppendF(&result, "%s", indent.c_str());
        StringAppendF(&result, "Expected\t|");
        std::chrono::nanoseconds startTime(predictions.startTime - baseTime);
        std::chrono::nanoseconds endTime(predictions.endTime - baseTime);
        std::chrono::nanoseconds presentTime(predictions.presentTime - baseTime);
        StringAppendF(&result, "\t%10.2f\t|\t%10.2f\t|\t%10.2f\n",
                      std::chrono::duration<double, std::milli>(startTime).count(),
                      std::chrono::duration<double, std::milli>(endTime).count(),
                      std::chrono::duration<double, std::milli>(presentTime).count());
    }
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Actual  \t|");

    if (actuals.startTime == 0) {
        StringAppendF(&result, "\t\tN/A\t|");
    } else {
        std::chrono::nanoseconds startTime(std::max<nsecs_t>(0, actuals.startTime - baseTime));
        StringAppendF(&result, "\t%10.2f\t|",
                      std::chrono::duration<double, std::milli>(startTime).count());
    }
    if (actuals.endTime <= 0) {
        // Animation leashes can send the endTime as -1
        StringAppendF(&result, "\t\tN/A\t|");
    } else {
        std::chrono::nanoseconds endTime(actuals.endTime - baseTime);
        StringAppendF(&result, "\t%10.2f\t|",
                      std::chrono::duration<double, std::milli>(endTime).count());
    }
    if (actuals.presentTime == 0) {
        StringAppendF(&result, "\t\tN/A\n");
    } else {
        std::chrono::nanoseconds presentTime(std::max<nsecs_t>(0, actuals.presentTime - baseTime));
        StringAppendF(&result, "\t%10.2f\n",
                      std::chrono::duration<double, std::milli>(presentTime).count());
    }

    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "----------------------");
    StringAppendF(&result, "----------------------");
    StringAppendF(&result, "----------------------");
    StringAppendF(&result, "----------------------\n");
}

std::string toString(PredictionState predictionState) {
    switch (predictionState) {
        case PredictionState::Valid:
            return "Valid";
        case PredictionState::Expired:
            return "Expired";
        case PredictionState::None:
            return "None";
    }
}

std::string jankTypeBitmaskToString(int32_t jankType) {
    if (jankType == JankType::None) {
        return "None";
    }

    std::vector<std::string> janks;
    if (jankType & JankType::DisplayHAL) {
        janks.emplace_back("Display HAL");
        jankType &= ~JankType::DisplayHAL;
    }
    if (jankType & JankType::SurfaceFlingerCpuDeadlineMissed) {
        janks.emplace_back("SurfaceFlinger CPU Deadline Missed");
        jankType &= ~JankType::SurfaceFlingerCpuDeadlineMissed;
    }
    if (jankType & JankType::SurfaceFlingerGpuDeadlineMissed) {
        janks.emplace_back("SurfaceFlinger GPU Deadline Missed");
        jankType &= ~JankType::SurfaceFlingerGpuDeadlineMissed;
    }
    if (jankType & JankType::AppDeadlineMissed) {
        janks.emplace_back("App Deadline Missed");
        jankType &= ~JankType::AppDeadlineMissed;
    }
    if (jankType & JankType::PredictionError) {
        janks.emplace_back("Prediction Error");
        jankType &= ~JankType::PredictionError;
    }
    if (jankType & JankType::SurfaceFlingerScheduling) {
        janks.emplace_back("SurfaceFlinger Scheduling");
        jankType &= ~JankType::SurfaceFlingerScheduling;
    }
    if (jankType & JankType::BufferStuffing) {
        janks.emplace_back("Buffer Stuffing");
        jankType &= ~JankType::BufferStuffing;
    }
    if (jankType & JankType::Unknown) {
        janks.emplace_back("Unknown jank");
        jankType &= ~JankType::Unknown;
    }
    if (jankType & JankType::SurfaceFlingerStuffing) {
        janks.emplace_back("SurfaceFlinger Stuffing");
        jankType &= ~JankType::SurfaceFlingerStuffing;
    }

    // jankType should be 0 if all types of jank were checked for.
    LOG_ALWAYS_FATAL_IF(jankType != 0, "Unrecognized jank type value 0x%x", jankType);
    return std::accumulate(janks.begin(), janks.end(), std::string(),
                           [](const std::string& l, const std::string& r) {
                               return l.empty() ? r : l + ", " + r;
                           });
}

std::string toString(FramePresentMetadata presentMetadata) {
    switch (presentMetadata) {
        case FramePresentMetadata::OnTimePresent:
            return "On Time Present";
        case FramePresentMetadata::LatePresent:
            return "Late Present";
        case FramePresentMetadata::EarlyPresent:
            return "Early Present";
        case FramePresentMetadata::UnknownPresent:
            return "Unknown Present";
    }
}

std::string toString(FrameReadyMetadata finishMetadata) {
    switch (finishMetadata) {
        case FrameReadyMetadata::OnTimeFinish:
            return "On Time Finish";
        case FrameReadyMetadata::LateFinish:
            return "Late Finish";
        case FrameReadyMetadata::UnknownFinish:
            return "Unknown Finish";
    }
}

std::string toString(FrameStartMetadata startMetadata) {
    switch (startMetadata) {
        case FrameStartMetadata::OnTimeStart:
            return "On Time Start";
        case FrameStartMetadata::LateStart:
            return "Late Start";
        case FrameStartMetadata::EarlyStart:
            return "Early Start";
        case FrameStartMetadata::UnknownStart:
            return "Unknown Start";
    }
}

std::string toString(SurfaceFrame::PresentState presentState) {
    using PresentState = SurfaceFrame::PresentState;
    switch (presentState) {
        case PresentState::Presented:
            return "Presented";
        case PresentState::Dropped:
            return "Dropped";
        case PresentState::Unknown:
            return "Unknown";
    }
}

FrameTimelineEvent::PresentType toProto(FramePresentMetadata presentMetadata) {
    switch (presentMetadata) {
        case FramePresentMetadata::EarlyPresent:
            return FrameTimelineEvent::PRESENT_EARLY;
        case FramePresentMetadata::LatePresent:
            return FrameTimelineEvent::PRESENT_LATE;
        case FramePresentMetadata::OnTimePresent:
            return FrameTimelineEvent::PRESENT_ON_TIME;
        case FramePresentMetadata::UnknownPresent:
            return FrameTimelineEvent::PRESENT_UNSPECIFIED;
    }
}

FrameTimelineEvent::PredictionType toProto(PredictionState predictionState) {
    switch (predictionState) {
        case PredictionState::Valid:
            return FrameTimelineEvent::PREDICTION_VALID;
        case PredictionState::Expired:
            return FrameTimelineEvent::PREDICTION_EXPIRED;
        case PredictionState::None:
            return FrameTimelineEvent::PREDICTION_UNKNOWN;
    }
}

int32_t jankTypeBitmaskToProto(int32_t jankType) {
    if (jankType == JankType::None) {
        return FrameTimelineEvent::JANK_NONE;
    }

    int32_t protoJank = 0;
    if (jankType & JankType::DisplayHAL) {
        protoJank |= FrameTimelineEvent::JANK_DISPLAY_HAL;
        jankType &= ~JankType::DisplayHAL;
    }
    if (jankType & JankType::SurfaceFlingerCpuDeadlineMissed) {
        protoJank |= FrameTimelineEvent::JANK_SF_CPU_DEADLINE_MISSED;
        jankType &= ~JankType::SurfaceFlingerCpuDeadlineMissed;
    }
    if (jankType & JankType::SurfaceFlingerGpuDeadlineMissed) {
        protoJank |= FrameTimelineEvent::JANK_SF_GPU_DEADLINE_MISSED;
        jankType &= ~JankType::SurfaceFlingerGpuDeadlineMissed;
    }
    if (jankType & JankType::AppDeadlineMissed) {
        protoJank |= FrameTimelineEvent::JANK_APP_DEADLINE_MISSED;
        jankType &= ~JankType::AppDeadlineMissed;
    }
    if (jankType & JankType::PredictionError) {
        protoJank |= FrameTimelineEvent::JANK_PREDICTION_ERROR;
        jankType &= ~JankType::PredictionError;
    }
    if (jankType & JankType::SurfaceFlingerScheduling) {
        protoJank |= FrameTimelineEvent::JANK_SF_SCHEDULING;
        jankType &= ~JankType::SurfaceFlingerScheduling;
    }
    if (jankType & JankType::BufferStuffing) {
        protoJank |= FrameTimelineEvent::JANK_BUFFER_STUFFING;
        jankType &= ~JankType::BufferStuffing;
    }
    if (jankType & JankType::Unknown) {
        protoJank |= FrameTimelineEvent::JANK_UNKNOWN;
        jankType &= ~JankType::Unknown;
    }
    if (jankType & JankType::SurfaceFlingerStuffing) {
        protoJank |= FrameTimelineEvent::JANK_SF_STUFFING;
        jankType &= ~JankType::SurfaceFlingerStuffing;
    }

    // jankType should be 0 if all types of jank were checked for.
    LOG_ALWAYS_FATAL_IF(jankType != 0, "Unrecognized jank type value 0x%x", jankType);
    return protoJank;
}

// Returns the smallest timestamp from the set of predictions and actuals.
nsecs_t getMinTime(PredictionState predictionState, TimelineItem predictions,
                   TimelineItem actuals) {
    nsecs_t minTime = std::numeric_limits<nsecs_t>::max();
    if (predictionState == PredictionState::Valid) {
        // Checking start time for predictions is enough because start time is always lesser than
        // endTime and presentTime.
        minTime = std::min(minTime, predictions.startTime);
    }

    // Need to check startTime, endTime and presentTime for actuals because some frames might not
    // have them set.
    if (actuals.startTime != 0) {
        minTime = std::min(minTime, actuals.startTime);
    }
    if (actuals.endTime != 0) {
        minTime = std::min(minTime, actuals.endTime);
    }
    if (actuals.presentTime != 0) {
        minTime = std::min(minTime, actuals.endTime);
    }
    return minTime;
}

int64_t TraceCookieCounter::getCookieForTracing() {
    return ++mTraceCookie;
}

SurfaceFrame::SurfaceFrame(const FrameTimelineInfo& frameTimelineInfo, pid_t ownerPid,
                           uid_t ownerUid, int32_t layerId, std::string layerName,
                           std::string debugName, PredictionState predictionState,
                           frametimeline::TimelineItem&& predictions,
                           std::shared_ptr<TimeStats> timeStats,
                           JankClassificationThresholds thresholds,
                           TraceCookieCounter* traceCookieCounter, bool isBuffer, GameMode gameMode)
      : mToken(frameTimelineInfo.vsyncId),
        mInputEventId(frameTimelineInfo.inputEventId),
        mOwnerPid(ownerPid),
        mOwnerUid(ownerUid),
        mLayerName(std::move(layerName)),
        mDebugName(std::move(debugName)),
        mLayerId(layerId),
        mPresentState(PresentState::Unknown),
        mPredictionState(predictionState),
        mPredictions(predictions),
        mActuals({0, 0, 0}),
        mTimeStats(timeStats),
        mJankClassificationThresholds(thresholds),
        mTraceCookieCounter(*traceCookieCounter),
        mIsBuffer(isBuffer),
        mGameMode(gameMode) {}

void SurfaceFrame::setActualStartTime(nsecs_t actualStartTime) {
    std::scoped_lock lock(mMutex);
    mActuals.startTime = actualStartTime;
}

void SurfaceFrame::setActualQueueTime(nsecs_t actualQueueTime) {
    std::scoped_lock lock(mMutex);
    mActualQueueTime = actualQueueTime;
}

void SurfaceFrame::setAcquireFenceTime(nsecs_t acquireFenceTime) {
    std::scoped_lock lock(mMutex);
    mActuals.endTime = std::max(acquireFenceTime, mActualQueueTime);
}

void SurfaceFrame::setDropTime(nsecs_t dropTime) {
    std::scoped_lock lock(mMutex);
    mDropTime = dropTime;
}

void SurfaceFrame::setPresentState(PresentState presentState, nsecs_t lastLatchTime) {
    std::scoped_lock lock(mMutex);
    LOG_ALWAYS_FATAL_IF(mPresentState != PresentState::Unknown,
                        "setPresentState called on a SurfaceFrame from Layer - %s, that has a "
                        "PresentState - %s set already.",
                        mDebugName.c_str(), toString(mPresentState).c_str());
    mPresentState = presentState;
    mLastLatchTime = lastLatchTime;
}

void SurfaceFrame::setRenderRate(Fps renderRate) {
    std::lock_guard<std::mutex> lock(mMutex);
    mRenderRate = renderRate;
}

void SurfaceFrame::setGpuComposition() {
    std::scoped_lock lock(mMutex);
    mGpuComposition = true;
}

std::optional<int32_t> SurfaceFrame::getJankType() const {
    std::scoped_lock lock(mMutex);
    if (mPresentState == PresentState::Dropped) {
        // Return no jank if it's a dropped frame since we cannot attribute a jank to a it.
        return JankType::None;
    }
    if (mActuals.presentTime == 0) {
        // Frame hasn't been presented yet.
        return std::nullopt;
    }
    return mJankType;
}

nsecs_t SurfaceFrame::getBaseTime() const {
    std::scoped_lock lock(mMutex);
    return getMinTime(mPredictionState, mPredictions, mActuals);
}

TimelineItem SurfaceFrame::getActuals() const {
    std::scoped_lock lock(mMutex);
    return mActuals;
}

PredictionState SurfaceFrame::getPredictionState() const {
    std::scoped_lock lock(mMutex);
    return mPredictionState;
}

SurfaceFrame::PresentState SurfaceFrame::getPresentState() const {
    std::scoped_lock lock(mMutex);
    return mPresentState;
}

FramePresentMetadata SurfaceFrame::getFramePresentMetadata() const {
    std::scoped_lock lock(mMutex);
    return mFramePresentMetadata;
}

FrameReadyMetadata SurfaceFrame::getFrameReadyMetadata() const {
    std::scoped_lock lock(mMutex);
    return mFrameReadyMetadata;
}

nsecs_t SurfaceFrame::getDropTime() const {
    std::scoped_lock lock(mMutex);
    return mDropTime;
}

void SurfaceFrame::promoteToBuffer() {
    std::scoped_lock lock(mMutex);
    LOG_ALWAYS_FATAL_IF(mIsBuffer == true,
                        "Trying to promote an already promoted BufferSurfaceFrame from layer %s "
                        "with token %" PRId64 "",
                        mDebugName.c_str(), mToken);
    mIsBuffer = true;
}

bool SurfaceFrame::getIsBuffer() const {
    std::scoped_lock lock(mMutex);
    return mIsBuffer;
}

void SurfaceFrame::dump(std::string& result, const std::string& indent, nsecs_t baseTime) const {
    std::scoped_lock lock(mMutex);
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Layer - %s", mDebugName.c_str());
    if (mJankType != JankType::None) {
        // Easily identify a janky Surface Frame in the dump
        StringAppendF(&result, " [*] ");
    }
    StringAppendF(&result, "\n");
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Token: %" PRId64 "\n", mToken);
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Is Buffer?: %d\n", mIsBuffer);
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Owner Pid : %d\n", mOwnerPid);
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Scheduled rendering rate: %d fps\n",
                  mRenderRate ? mRenderRate->getIntValue() : 0);
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Layer ID : %d\n", mLayerId);
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Present State : %s\n", toString(mPresentState).c_str());
    StringAppendF(&result, "%s", indent.c_str());
    if (mPresentState == PresentState::Dropped) {
        std::chrono::nanoseconds dropTime(mDropTime - baseTime);
        StringAppendF(&result, "Drop time : %10f\n",
                      std::chrono::duration<double, std::milli>(dropTime).count());
        StringAppendF(&result, "%s", indent.c_str());
    }
    StringAppendF(&result, "Prediction State : %s\n", toString(mPredictionState).c_str());
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Jank Type : %s\n", jankTypeBitmaskToString(mJankType).c_str());
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Present Metadata : %s\n", toString(mFramePresentMetadata).c_str());
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Finish Metadata: %s\n", toString(mFrameReadyMetadata).c_str());
    std::chrono::nanoseconds latchTime(
            std::max(static_cast<int64_t>(0), mLastLatchTime - baseTime));
    StringAppendF(&result, "%s", indent.c_str());
    StringAppendF(&result, "Last latch time: %10f\n",
                  std::chrono::duration<double, std::milli>(latchTime).count());
    if (mPredictionState == PredictionState::Valid) {
        nsecs_t presentDelta = mActuals.presentTime - mPredictions.presentTime;
        std::chrono::nanoseconds presentDeltaNs(std::abs(presentDelta));
        StringAppendF(&result, "%s", indent.c_str());
        StringAppendF(&result, "Present delta: %10f\n",
                      std::chrono::duration<double, std::milli>(presentDeltaNs).count());
    }
    dumpTable(result, mPredictions, mActuals, indent, mPredictionState, baseTime);
}

std::string SurfaceFrame::miniDump() const {
    std::scoped_lock lock(mMutex);
    std::string result;
    StringAppendF(&result, "Layer - %s\n", mDebugName.c_str());
    StringAppendF(&result, "Token: %" PRId64 "\n", mToken);
    StringAppendF(&result, "Is Buffer?: %d\n", mIsBuffer);
    StringAppendF(&result, "Present State : %s\n", toString(mPresentState).c_str());
    StringAppendF(&result, "Prediction State : %s\n", toString(mPredictionState).c_str());
    StringAppendF(&result, "Jank Type : %s\n", jankTypeBitmaskToString(mJankType).c_str());
    StringAppendF(&result, "Present Metadata : %s\n", toString(mFramePresentMetadata).c_str());
    StringAppendF(&result, "Finish Metadata: %s\n", toString(mFrameReadyMetadata).c_str());
    StringAppendF(&result, "Present time: %" PRId64 "", mActuals.presentTime);
    return result;
}

void SurfaceFrame::classifyJankLocked(int32_t displayFrameJankType, const Fps& refreshRate,
                                      nsecs_t& deadlineDelta) {
    if (mActuals.presentTime == Fence::SIGNAL_TIME_INVALID) {
        // Cannot do any classification for invalid present time.
        mJankType = JankType::Unknown;
        deadlineDelta = -1;
        return;
    }

    if (mPredictionState == PredictionState::Expired) {
        // We classify prediction expired as AppDeadlineMissed as the
        // TokenManager::kMaxTokens we store is large enough to account for a
        // reasonable app, so prediction expire would mean a huge scheduling delay.
        mJankType = JankType::AppDeadlineMissed;
        deadlineDelta = -1;
        return;
    }

    if (mPredictionState == PredictionState::None) {
        // Cannot do jank classification on frames that don't have a token.
        return;
    }

    deadlineDelta = mActuals.endTime - mPredictions.endTime;
    const nsecs_t presentDelta = mActuals.presentTime - mPredictions.presentTime;
    const nsecs_t deltaToVsync = refreshRate.getPeriodNsecs() > 0
            ? std::abs(presentDelta) % refreshRate.getPeriodNsecs()
            : 0;

    if (deadlineDelta > mJankClassificationThresholds.deadlineThreshold) {
        mFrameReadyMetadata = FrameReadyMetadata::LateFinish;
    } else {
        mFrameReadyMetadata = FrameReadyMetadata::OnTimeFinish;
    }

    if (std::abs(presentDelta) > mJankClassificationThresholds.presentThreshold) {
        mFramePresentMetadata = presentDelta > 0 ? FramePresentMetadata::LatePresent
                                                 : FramePresentMetadata::EarlyPresent;
    } else {
        mFramePresentMetadata = FramePresentMetadata::OnTimePresent;
    }

    if (mFramePresentMetadata == FramePresentMetadata::OnTimePresent) {
        // Frames presented on time are not janky.
        mJankType = JankType::None;
    } else if (mFramePresentMetadata == FramePresentMetadata::EarlyPresent) {
        if (mFrameReadyMetadata == FrameReadyMetadata::OnTimeFinish) {
            // Finish on time, Present early
            if (deltaToVsync < mJankClassificationThresholds.presentThreshold ||
                deltaToVsync >= refreshRate.getPeriodNsecs() -
                                mJankClassificationThresholds.presentThreshold) {
                // Delta factor of vsync
                mJankType = JankType::SurfaceFlingerScheduling;
            } else {
                // Delta not a factor of vsync
                mJankType = JankType::PredictionError;
            }
        } else if (mFrameReadyMetadata == FrameReadyMetadata::LateFinish) {
            // Finish late, Present early
            mJankType = JankType::Unknown;
        }
    } else {
        if (mLastLatchTime != 0 && mPredictions.endTime <= mLastLatchTime) {
            // Buffer Stuffing.
            mJankType |= JankType::BufferStuffing;
            // In a stuffed state, the frame could be stuck on a dequeue wait for quite some time.
            // Because of this dequeue wait, it can be hard to tell if a frame was genuinely late.
            // We try to do this by moving the deadline. Since the queue could be stuffed by more
            // than one buffer, we take the last latch time as reference and give one vsync
            // worth of time for the frame to be ready.
            nsecs_t adjustedDeadline = mLastLatchTime + refreshRate.getPeriodNsecs();
            if (adjustedDeadline > mActuals.endTime) {
                mFrameReadyMetadata = FrameReadyMetadata::OnTimeFinish;
            } else {
                mFrameReadyMetadata = FrameReadyMetadata::LateFinish;
            }
        }
        if (mFrameReadyMetadata == FrameReadyMetadata::OnTimeFinish) {
            // Finish on time, Present late
            if (displayFrameJankType != JankType::None) {
                // Propagate displayFrame's jank if it exists
                mJankType |= displayFrameJankType;
            } else {
                if (!(mJankType & JankType::BufferStuffing)) {
                    // In a stuffed state, if the app finishes on time and there is no display frame
                    // jank, only buffer stuffing is the root cause of the jank.
                    if (deltaToVsync < mJankClassificationThresholds.presentThreshold ||
                        deltaToVsync >= refreshRate.getPeriodNsecs() -
                                        mJankClassificationThresholds.presentThreshold) {
                        // Delta factor of vsync
                        mJankType |= JankType::SurfaceFlingerScheduling;
                    } else {
                        // Delta not a factor of vsync
                        mJankType |= JankType::PredictionError;
                    }
                }
            }
        } else if (mFrameReadyMetadata == FrameReadyMetadata::LateFinish) {
            // Finish late, Present late
            mJankType |= JankType::AppDeadlineMissed;
            // Propagate DisplayFrame's jankType if it is janky
            mJankType |= displayFrameJankType;
        }
    }
}

void SurfaceFrame::onPresent(nsecs_t presentTime, int32_t displayFrameJankType, Fps refreshRate,
                             nsecs_t displayDeadlineDelta, nsecs_t displayPresentDelta) {
    std::scoped_lock lock(mMutex);

    if (mPresentState != PresentState::Presented) {
        // No need to update dropped buffers
        return;
    }

    mActuals.presentTime = presentTime;
    nsecs_t deadlineDelta = 0;

    classifyJankLocked(displayFrameJankType, refreshRate, deadlineDelta);

    if (mPredictionState != PredictionState::None) {
        // Only update janky frames if the app used vsync predictions
        mTimeStats->incrementJankyFrames({refreshRate, mRenderRate, mOwnerUid, mLayerName,
                                          mGameMode, mJankType, displayDeadlineDelta,
                                          displayPresentDelta, deadlineDelta});
    }
}

void SurfaceFrame::tracePredictions(int64_t displayFrameToken, nsecs_t monoBootOffset) const {
    int64_t expectedTimelineCookie = mTraceCookieCounter.getCookieForTracing();

    // Expected timeline start
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        std::scoped_lock lock(mMutex);
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_BOOTTIME);
        packet->set_timestamp(static_cast<uint64_t>(mPredictions.startTime + monoBootOffset));

        auto* event = packet->set_frame_timeline_event();
        auto* expectedSurfaceFrameStartEvent = event->set_expected_surface_frame_start();

        expectedSurfaceFrameStartEvent->set_cookie(expectedTimelineCookie);

        expectedSurfaceFrameStartEvent->set_token(mToken);
        expectedSurfaceFrameStartEvent->set_display_frame_token(displayFrameToken);

        expectedSurfaceFrameStartEvent->set_pid(mOwnerPid);
        expectedSurfaceFrameStartEvent->set_layer_name(mDebugName);
    });

    // Expected timeline end
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        std::scoped_lock lock(mMutex);
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_BOOTTIME);
        packet->set_timestamp(static_cast<uint64_t>(mPredictions.endTime + monoBootOffset));

        auto* event = packet->set_frame_timeline_event();
        auto* expectedSurfaceFrameEndEvent = event->set_frame_end();

        expectedSurfaceFrameEndEvent->set_cookie(expectedTimelineCookie);
    });
}

void SurfaceFrame::traceActuals(int64_t displayFrameToken, nsecs_t monoBootOffset) const {
    int64_t actualTimelineCookie = mTraceCookieCounter.getCookieForTracing();

    // Actual timeline start
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        std::scoped_lock lock(mMutex);
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_BOOTTIME);
        // Actual start time is not yet available, so use expected start instead
        if (mPredictionState == PredictionState::Expired) {
            // If prediction is expired, we can't use the predicted start time. Instead, just use a
            // start time a little earlier than the end time so that we have some info about this
            // frame in the trace.
            nsecs_t endTime =
                    (mPresentState == PresentState::Dropped ? mDropTime : mActuals.endTime);
            const auto timestamp = endTime - kPredictionExpiredStartTimeDelta;
            packet->set_timestamp(static_cast<uint64_t>(timestamp + monoBootOffset));
        } else {
            const auto timestamp =
                    mActuals.startTime == 0 ? mPredictions.startTime : mActuals.startTime;
            packet->set_timestamp(static_cast<uint64_t>(timestamp + monoBootOffset));
        }

        auto* event = packet->set_frame_timeline_event();
        auto* actualSurfaceFrameStartEvent = event->set_actual_surface_frame_start();

        actualSurfaceFrameStartEvent->set_cookie(actualTimelineCookie);

        actualSurfaceFrameStartEvent->set_token(mToken);
        actualSurfaceFrameStartEvent->set_display_frame_token(displayFrameToken);

        actualSurfaceFrameStartEvent->set_pid(mOwnerPid);
        actualSurfaceFrameStartEvent->set_layer_name(mDebugName);

        if (mPresentState == PresentState::Dropped) {
            actualSurfaceFrameStartEvent->set_present_type(FrameTimelineEvent::PRESENT_DROPPED);
        } else if (mPresentState == PresentState::Unknown) {
            actualSurfaceFrameStartEvent->set_present_type(FrameTimelineEvent::PRESENT_UNSPECIFIED);
        } else {
            actualSurfaceFrameStartEvent->set_present_type(toProto(mFramePresentMetadata));
        }
        actualSurfaceFrameStartEvent->set_on_time_finish(mFrameReadyMetadata ==
                                                         FrameReadyMetadata::OnTimeFinish);
        actualSurfaceFrameStartEvent->set_gpu_composition(mGpuComposition);
        actualSurfaceFrameStartEvent->set_jank_type(jankTypeBitmaskToProto(mJankType));
        actualSurfaceFrameStartEvent->set_prediction_type(toProto(mPredictionState));
        actualSurfaceFrameStartEvent->set_is_buffer(mIsBuffer);
    });

    // Actual timeline end
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        std::scoped_lock lock(mMutex);
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_BOOTTIME);
        if (mPresentState == PresentState::Dropped) {
            packet->set_timestamp(static_cast<uint64_t>(mDropTime + monoBootOffset));
        } else {
            packet->set_timestamp(static_cast<uint64_t>(mActuals.endTime + monoBootOffset));
        }

        auto* event = packet->set_frame_timeline_event();
        auto* actualSurfaceFrameEndEvent = event->set_frame_end();

        actualSurfaceFrameEndEvent->set_cookie(actualTimelineCookie);
    });
}

/**
 * TODO(b/178637512): add inputEventId to the perfetto trace.
 */
void SurfaceFrame::trace(int64_t displayFrameToken, nsecs_t monoBootOffset) const {
    if (mToken == FrameTimelineInfo::INVALID_VSYNC_ID ||
        displayFrameToken == FrameTimelineInfo::INVALID_VSYNC_ID) {
        // No packets can be traced with a missing token.
        return;
    }
    if (getPredictionState() != PredictionState::Expired) {
        // Expired predictions have zeroed timestamps. This cannot be used in any meaningful way in
        // a trace.
        tracePredictions(displayFrameToken, monoBootOffset);
    }
    traceActuals(displayFrameToken, monoBootOffset);
}

namespace impl {

int64_t TokenManager::generateTokenForPredictions(TimelineItem&& predictions) {
    ATRACE_CALL();
    std::scoped_lock lock(mMutex);
    while (mPredictions.size() >= kMaxTokens) {
        mPredictions.erase(mPredictions.begin());
    }
    const int64_t assignedToken = mCurrentToken++;
    mPredictions[assignedToken] = predictions;
    return assignedToken;
}

std::optional<TimelineItem> TokenManager::getPredictionsForToken(int64_t token) const {
    std::scoped_lock lock(mMutex);
    auto predictionsIterator = mPredictions.find(token);
    if (predictionsIterator != mPredictions.end()) {
        return predictionsIterator->second;
    }
    return {};
}

FrameTimeline::FrameTimeline(std::shared_ptr<TimeStats> timeStats, pid_t surfaceFlingerPid,
                             JankClassificationThresholds thresholds, bool useBootTimeClock)
      : mUseBootTimeClock(useBootTimeClock),
        mMaxDisplayFrames(kDefaultMaxDisplayFrames),
        mTimeStats(std::move(timeStats)),
        mSurfaceFlingerPid(surfaceFlingerPid),
        mJankClassificationThresholds(thresholds) {
    mCurrentDisplayFrame =
            std::make_shared<DisplayFrame>(mTimeStats, thresholds, &mTraceCookieCounter);
}

void FrameTimeline::onBootFinished() {
    perfetto::TracingInitArgs args;
    args.backends = perfetto::kSystemBackend;
    perfetto::Tracing::Initialize(args);
    registerDataSource();
}

void FrameTimeline::registerDataSource() {
    perfetto::DataSourceDescriptor dsd;
    dsd.set_name(kFrameTimelineDataSource);
    FrameTimelineDataSource::Register(dsd);
}

std::shared_ptr<SurfaceFrame> FrameTimeline::createSurfaceFrameForToken(
        const FrameTimelineInfo& frameTimelineInfo, pid_t ownerPid, uid_t ownerUid, int32_t layerId,
        std::string layerName, std::string debugName, bool isBuffer, GameMode gameMode) {
    ATRACE_CALL();
    if (frameTimelineInfo.vsyncId == FrameTimelineInfo::INVALID_VSYNC_ID) {
        return std::make_shared<SurfaceFrame>(frameTimelineInfo, ownerPid, ownerUid, layerId,
                                              std::move(layerName), std::move(debugName),
                                              PredictionState::None, TimelineItem(), mTimeStats,
                                              mJankClassificationThresholds, &mTraceCookieCounter,
                                              isBuffer, gameMode);
    }
    std::optional<TimelineItem> predictions =
            mTokenManager.getPredictionsForToken(frameTimelineInfo.vsyncId);
    if (predictions) {
        return std::make_shared<SurfaceFrame>(frameTimelineInfo, ownerPid, ownerUid, layerId,
                                              std::move(layerName), std::move(debugName),
                                              PredictionState::Valid, std::move(*predictions),
                                              mTimeStats, mJankClassificationThresholds,
                                              &mTraceCookieCounter, isBuffer, gameMode);
    }
    return std::make_shared<SurfaceFrame>(frameTimelineInfo, ownerPid, ownerUid, layerId,
                                          std::move(layerName), std::move(debugName),
                                          PredictionState::Expired, TimelineItem(), mTimeStats,
                                          mJankClassificationThresholds, &mTraceCookieCounter,
                                          isBuffer, gameMode);
}

FrameTimeline::DisplayFrame::DisplayFrame(std::shared_ptr<TimeStats> timeStats,
                                          JankClassificationThresholds thresholds,
                                          TraceCookieCounter* traceCookieCounter)
      : mSurfaceFlingerPredictions(TimelineItem()),
        mSurfaceFlingerActuals(TimelineItem()),
        mTimeStats(timeStats),
        mJankClassificationThresholds(thresholds),
        mTraceCookieCounter(*traceCookieCounter) {
    mSurfaceFrames.reserve(kNumSurfaceFramesInitial);
}

void FrameTimeline::addSurfaceFrame(std::shared_ptr<SurfaceFrame> surfaceFrame) {
    ATRACE_CALL();
    std::scoped_lock lock(mMutex);
    mCurrentDisplayFrame->addSurfaceFrame(surfaceFrame);
}

void FrameTimeline::setSfWakeUp(int64_t token, nsecs_t wakeUpTime, Fps refreshRate) {
    ATRACE_CALL();
    std::scoped_lock lock(mMutex);
    mCurrentDisplayFrame->onSfWakeUp(token, refreshRate,
                                     mTokenManager.getPredictionsForToken(token), wakeUpTime);
}

void FrameTimeline::setSfPresent(nsecs_t sfPresentTime,
                                 const std::shared_ptr<FenceTime>& presentFence,
                                 const std::shared_ptr<FenceTime>& gpuFence) {
    ATRACE_CALL();
    std::scoped_lock lock(mMutex);
    mCurrentDisplayFrame->setActualEndTime(sfPresentTime);
    mCurrentDisplayFrame->setGpuFence(gpuFence);
    mPendingPresentFences.emplace_back(std::make_pair(presentFence, mCurrentDisplayFrame));
    flushPendingPresentFences();
    finalizeCurrentDisplayFrame();
}

void FrameTimeline::DisplayFrame::addSurfaceFrame(std::shared_ptr<SurfaceFrame> surfaceFrame) {
    mSurfaceFrames.push_back(surfaceFrame);
}

void FrameTimeline::DisplayFrame::onSfWakeUp(int64_t token, Fps refreshRate,
                                             std::optional<TimelineItem> predictions,
                                             nsecs_t wakeUpTime) {
    mToken = token;
    mRefreshRate = refreshRate;
    if (!predictions) {
        mPredictionState = PredictionState::Expired;
    } else {
        mPredictionState = PredictionState::Valid;
        mSurfaceFlingerPredictions = *predictions;
    }
    mSurfaceFlingerActuals.startTime = wakeUpTime;
}

void FrameTimeline::DisplayFrame::setPredictions(PredictionState predictionState,
                                                 TimelineItem predictions) {
    mPredictionState = predictionState;
    mSurfaceFlingerPredictions = predictions;
}

void FrameTimeline::DisplayFrame::setActualStartTime(nsecs_t actualStartTime) {
    mSurfaceFlingerActuals.startTime = actualStartTime;
}

void FrameTimeline::DisplayFrame::setActualEndTime(nsecs_t actualEndTime) {
    mSurfaceFlingerActuals.endTime = actualEndTime;
}

void FrameTimeline::DisplayFrame::setGpuFence(const std::shared_ptr<FenceTime>& gpuFence) {
    mGpuFence = gpuFence;
}

void FrameTimeline::DisplayFrame::classifyJank(nsecs_t& deadlineDelta, nsecs_t& deltaToVsync,
                                               nsecs_t previousPresentTime) {
    if (mPredictionState == PredictionState::Expired ||
        mSurfaceFlingerActuals.presentTime == Fence::SIGNAL_TIME_INVALID) {
        // Cannot do jank classification with expired predictions or invalid signal times. Set the
        // deltas to 0 as both negative and positive deltas are used as real values.
        mJankType = JankType::Unknown;
        deadlineDelta = 0;
        deltaToVsync = 0;
        return;
    }

    // Delta between the expected present and the actual present
    const nsecs_t presentDelta =
            mSurfaceFlingerActuals.presentTime - mSurfaceFlingerPredictions.presentTime;
    // Sf actual end time represents the CPU end time. In case of HWC, SF's end time would have
    // included the time for composition. However, for GPU composition, the final end time is max(sf
    // end time, gpu fence time).
    nsecs_t combinedEndTime = mSurfaceFlingerActuals.endTime;
    if (mGpuFence != FenceTime::NO_FENCE) {
        combinedEndTime = std::max(combinedEndTime, mGpuFence->getSignalTime());
    }
    deadlineDelta = combinedEndTime - mSurfaceFlingerPredictions.endTime;

    // How far off was the presentDelta when compared to the vsyncPeriod. Used in checking if there
    // was a prediction error or not.
    deltaToVsync = mRefreshRate.getPeriodNsecs() > 0
            ? std::abs(presentDelta) % mRefreshRate.getPeriodNsecs()
            : 0;

    if (std::abs(presentDelta) > mJankClassificationThresholds.presentThreshold) {
        mFramePresentMetadata = presentDelta > 0 ? FramePresentMetadata::LatePresent
                                                 : FramePresentMetadata::EarlyPresent;
    } else {
        mFramePresentMetadata = FramePresentMetadata::OnTimePresent;
    }

    if (combinedEndTime > mSurfaceFlingerPredictions.endTime) {
        mFrameReadyMetadata = FrameReadyMetadata::LateFinish;
    } else {
        mFrameReadyMetadata = FrameReadyMetadata::OnTimeFinish;
    }

    if (std::abs(mSurfaceFlingerActuals.startTime - mSurfaceFlingerPredictions.startTime) >
        mJankClassificationThresholds.startThreshold) {
        mFrameStartMetadata =
                mSurfaceFlingerActuals.startTime > mSurfaceFlingerPredictions.startTime
                ? FrameStartMetadata::LateStart
                : FrameStartMetadata::EarlyStart;
    }

    if (mFramePresentMetadata != FramePresentMetadata::OnTimePresent) {
        // Do jank classification only if present is not on time
        if (mFramePresentMetadata == FramePresentMetadata::EarlyPresent) {
            if (mFrameReadyMetadata == FrameReadyMetadata::OnTimeFinish) {
                // Finish on time, Present early
                if (deltaToVsync < mJankClassificationThresholds.presentThreshold ||
                    deltaToVsync >= (mRefreshRate.getPeriodNsecs() -
                                     mJankClassificationThresholds.presentThreshold)) {
                    // Delta is a factor of vsync if its within the presentTheshold on either side
                    // of the vsyncPeriod. Example: 0-2ms and 9-11ms are both within the threshold
                    // of the vsyncPeriod if the threshold was 2ms and the vsyncPeriod was 11ms.
                    mJankType = JankType::SurfaceFlingerScheduling;
                } else {
                    // Delta is not a factor of vsync,
                    mJankType = JankType::PredictionError;
                }
            } else if (mFrameReadyMetadata == FrameReadyMetadata::LateFinish) {
                // Finish late, Present early
                mJankType = JankType::SurfaceFlingerScheduling;
            } else {
                // Finish time unknown
                mJankType = JankType::Unknown;
            }
        } else if (mFramePresentMetadata == FramePresentMetadata::LatePresent) {
            if (std::abs(mSurfaceFlingerPredictions.presentTime - previousPresentTime) <=
                        mJankClassificationThresholds.presentThreshold ||
                previousPresentTime > mSurfaceFlingerPredictions.presentTime) {
                // The previous frame was either presented in the current frame's expected vsync or
                // it was presented even later than the current frame's expected vsync.
                mJankType = JankType::SurfaceFlingerStuffing;
            }
            if (mFrameReadyMetadata == FrameReadyMetadata::OnTimeFinish &&
                !(mJankType & JankType::SurfaceFlingerStuffing)) {
                // Finish on time, Present late
                if (deltaToVsync < mJankClassificationThresholds.presentThreshold ||
                    deltaToVsync >= (mRefreshRate.getPeriodNsecs() -
                                     mJankClassificationThresholds.presentThreshold)) {
                    // Delta is a factor of vsync if its within the presentTheshold on either side
                    // of the vsyncPeriod. Example: 0-2ms and 9-11ms are both within the threshold
                    // of the vsyncPeriod if the threshold was 2ms and the vsyncPeriod was 11ms.
                    mJankType = JankType::DisplayHAL;
                } else {
                    // Delta is not a factor of vsync
                    mJankType = JankType::PredictionError;
                }
            } else if (mFrameReadyMetadata == FrameReadyMetadata::LateFinish) {
                if (!(mJankType & JankType::SurfaceFlingerStuffing) ||
                    mSurfaceFlingerActuals.presentTime - previousPresentTime >
                            mRefreshRate.getPeriodNsecs() +
                                    mJankClassificationThresholds.presentThreshold) {
                    // Classify CPU vs GPU if SF wasn't stuffed or if SF was stuffed but this frame
                    // was presented more than a vsync late.
                    if (mGpuFence != FenceTime::NO_FENCE &&
                        mSurfaceFlingerActuals.endTime - mSurfaceFlingerActuals.startTime <
                                mRefreshRate.getPeriodNsecs()) {
                        // If SF was in GPU composition and the CPU work finished before the vsync
                        // period, classify it as GPU deadline missed.
                        mJankType = JankType::SurfaceFlingerGpuDeadlineMissed;
                    } else {
                        mJankType = JankType::SurfaceFlingerCpuDeadlineMissed;
                    }
                }
            } else {
                // Finish time unknown
                mJankType = JankType::Unknown;
            }
        } else {
            // Present unknown
            mJankType = JankType::Unknown;
        }
    }
}

void FrameTimeline::DisplayFrame::onPresent(nsecs_t signalTime, nsecs_t previousPresentTime) {
    mSurfaceFlingerActuals.presentTime = signalTime;
    nsecs_t deadlineDelta = 0;
    nsecs_t deltaToVsync = 0;
    classifyJank(deadlineDelta, deltaToVsync, previousPresentTime);

    for (auto& surfaceFrame : mSurfaceFrames) {
        surfaceFrame->onPresent(signalTime, mJankType, mRefreshRate, deadlineDelta, deltaToVsync);
    }
}

void FrameTimeline::DisplayFrame::tracePredictions(pid_t surfaceFlingerPid,
                                                   nsecs_t monoBootOffset) const {
    int64_t expectedTimelineCookie = mTraceCookieCounter.getCookieForTracing();

    // Expected timeline start
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_BOOTTIME);
        packet->set_timestamp(
                static_cast<uint64_t>(mSurfaceFlingerPredictions.startTime + monoBootOffset));

        auto* event = packet->set_frame_timeline_event();
        auto* expectedDisplayFrameStartEvent = event->set_expected_display_frame_start();

        expectedDisplayFrameStartEvent->set_cookie(expectedTimelineCookie);

        expectedDisplayFrameStartEvent->set_token(mToken);
        expectedDisplayFrameStartEvent->set_pid(surfaceFlingerPid);
    });

    // Expected timeline end
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_BOOTTIME);
        packet->set_timestamp(
                static_cast<uint64_t>(mSurfaceFlingerPredictions.endTime + monoBootOffset));

        auto* event = packet->set_frame_timeline_event();
        auto* expectedDisplayFrameEndEvent = event->set_frame_end();

        expectedDisplayFrameEndEvent->set_cookie(expectedTimelineCookie);
    });
}

void FrameTimeline::DisplayFrame::traceActuals(pid_t surfaceFlingerPid,
                                               nsecs_t monoBootOffset) const {
    int64_t actualTimelineCookie = mTraceCookieCounter.getCookieForTracing();

    // Actual timeline start
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_BOOTTIME);
        packet->set_timestamp(
                static_cast<uint64_t>(mSurfaceFlingerActuals.startTime + monoBootOffset));

        auto* event = packet->set_frame_timeline_event();
        auto* actualDisplayFrameStartEvent = event->set_actual_display_frame_start();

        actualDisplayFrameStartEvent->set_cookie(actualTimelineCookie);

        actualDisplayFrameStartEvent->set_token(mToken);
        actualDisplayFrameStartEvent->set_pid(surfaceFlingerPid);

        actualDisplayFrameStartEvent->set_present_type(toProto(mFramePresentMetadata));
        actualDisplayFrameStartEvent->set_on_time_finish(mFrameReadyMetadata ==
                                                         FrameReadyMetadata::OnTimeFinish);
        actualDisplayFrameStartEvent->set_gpu_composition(mGpuFence != FenceTime::NO_FENCE);
        actualDisplayFrameStartEvent->set_jank_type(jankTypeBitmaskToProto(mJankType));
        actualDisplayFrameStartEvent->set_prediction_type(toProto(mPredictionState));
    });

    // Actual timeline end
    FrameTimelineDataSource::Trace([&](FrameTimelineDataSource::TraceContext ctx) {
        auto packet = ctx.NewTracePacket();
        packet->set_timestamp_clock_id(perfetto::protos::pbzero::BUILTIN_CLOCK_BOOTTIME);
        packet->set_timestamp(
                static_cast<uint64_t>(mSurfaceFlingerActuals.presentTime + monoBootOffset));

        auto* event = packet->set_frame_timeline_event();
        auto* actualDisplayFrameEndEvent = event->set_frame_end();

        actualDisplayFrameEndEvent->set_cookie(actualTimelineCookie);
    });
}

void FrameTimeline::DisplayFrame::trace(pid_t surfaceFlingerPid, nsecs_t monoBootOffset) const {
    if (mToken == FrameTimelineInfo::INVALID_VSYNC_ID) {
        // DisplayFrame should not have an invalid token.
        ALOGE("Cannot trace DisplayFrame with invalid token");
        return;
    }

    if (mPredictionState == PredictionState::Valid) {
        // Expired and unknown predictions have zeroed timestamps. This cannot be used in any
        // meaningful way in a trace.
        tracePredictions(surfaceFlingerPid, monoBootOffset);
    }
    traceActuals(surfaceFlingerPid, monoBootOffset);

    for (auto& surfaceFrame : mSurfaceFrames) {
        surfaceFrame->trace(mToken, monoBootOffset);
    }
}

float FrameTimeline::computeFps(const std::unordered_set<int32_t>& layerIds) {
    if (layerIds.empty()) {
        return 0.0f;
    }

    std::vector<nsecs_t> presentTimes;
    {
        std::scoped_lock lock(mMutex);
        presentTimes.reserve(mDisplayFrames.size());
        for (size_t i = 0; i < mDisplayFrames.size(); i++) {
            const auto& displayFrame = mDisplayFrames[i];
            if (displayFrame->getActuals().presentTime <= 0) {
                continue;
            }
            for (const auto& surfaceFrame : displayFrame->getSurfaceFrames()) {
                if (surfaceFrame->getPresentState() == SurfaceFrame::PresentState::Presented &&
                    layerIds.count(surfaceFrame->getLayerId()) > 0) {
                    // We're looking for DisplayFrames that presents at least one layer from
                    // layerIds, so push the present time and skip looking through the rest of the
                    // SurfaceFrames.
                    presentTimes.push_back(displayFrame->getActuals().presentTime);
                    break;
                }
            }
        }
    }

    // FPS can't be computed when there's fewer than 2 presented frames.
    if (presentTimes.size() <= 1) {
        return 0.0f;
    }

    nsecs_t priorPresentTime = -1;
    nsecs_t totalPresentToPresentWalls = 0;

    for (const nsecs_t presentTime : presentTimes) {
        if (priorPresentTime == -1) {
            priorPresentTime = presentTime;
            continue;
        }

        totalPresentToPresentWalls += (presentTime - priorPresentTime);
        priorPresentTime = presentTime;
    }

    if (CC_UNLIKELY(totalPresentToPresentWalls <= 0)) {
        ALOGW("Invalid total present-to-present duration when computing fps: %" PRId64,
              totalPresentToPresentWalls);
        return 0.0f;
    }

    const constexpr nsecs_t kOneSecond =
            std::chrono::duration_cast<std::chrono::nanoseconds>(1s).count();
    // (10^9 nanoseconds / second) * (N present deltas) / (total nanoseconds in N present deltas) =
    // M frames / second
    return kOneSecond * static_cast<nsecs_t>((presentTimes.size() - 1)) /
            static_cast<float>(totalPresentToPresentWalls);
}

void FrameTimeline::flushPendingPresentFences() {
    // Perfetto is using boottime clock to void drifts when the device goes
    // to suspend.
    const auto monoBootOffset = mUseBootTimeClock
            ? (systemTime(SYSTEM_TIME_BOOTTIME) - systemTime(SYSTEM_TIME_MONOTONIC))
            : 0;

    for (size_t i = 0; i < mPendingPresentFences.size(); i++) {
        const auto& pendingPresentFence = mPendingPresentFences[i];
        nsecs_t signalTime = Fence::SIGNAL_TIME_INVALID;
        if (pendingPresentFence.first && pendingPresentFence.first->isValid()) {
            signalTime = pendingPresentFence.first->getSignalTime();
            if (signalTime == Fence::SIGNAL_TIME_PENDING) {
                continue;
            }
        }
        auto& displayFrame = pendingPresentFence.second;
        displayFrame->onPresent(signalTime, mPreviousPresentTime);
        displayFrame->trace(mSurfaceFlingerPid, monoBootOffset);
        mPreviousPresentTime = signalTime;

        mPendingPresentFences.erase(mPendingPresentFences.begin() + static_cast<int>(i));
        --i;
    }
}

void FrameTimeline::finalizeCurrentDisplayFrame() {
    while (mDisplayFrames.size() >= mMaxDisplayFrames) {
        // We maintain only a fixed number of frames' data. Pop older frames
        mDisplayFrames.pop_front();
    }
    mDisplayFrames.push_back(mCurrentDisplayFrame);
    mCurrentDisplayFrame.reset();
    mCurrentDisplayFrame = std::make_shared<DisplayFrame>(mTimeStats, mJankClassificationThresholds,
                                                          &mTraceCookieCounter);
}

nsecs_t FrameTimeline::DisplayFrame::getBaseTime() const {
    nsecs_t baseTime =
            getMinTime(mPredictionState, mSurfaceFlingerPredictions, mSurfaceFlingerActuals);
    for (const auto& surfaceFrame : mSurfaceFrames) {
        nsecs_t surfaceFrameBaseTime = surfaceFrame->getBaseTime();
        if (surfaceFrameBaseTime != 0) {
            baseTime = std::min(baseTime, surfaceFrameBaseTime);
        }
    }
    return baseTime;
}

void FrameTimeline::DisplayFrame::dumpJank(std::string& result, nsecs_t baseTime,
                                           int displayFrameCount) const {
    if (mJankType == JankType::None) {
        // Check if any Surface Frame has been janky
        bool isJanky = false;
        for (const auto& surfaceFrame : mSurfaceFrames) {
            if (surfaceFrame->getJankType() != JankType::None) {
                isJanky = true;
                break;
            }
        }
        if (!isJanky) {
            return;
        }
    }
    StringAppendF(&result, "Display Frame %d", displayFrameCount);
    dump(result, baseTime);
}

void FrameTimeline::DisplayFrame::dumpAll(std::string& result, nsecs_t baseTime) const {
    dump(result, baseTime);
}

void FrameTimeline::DisplayFrame::dump(std::string& result, nsecs_t baseTime) const {
    if (mJankType != JankType::None) {
        // Easily identify a janky Display Frame in the dump
        StringAppendF(&result, " [*] ");
    }
    StringAppendF(&result, "\n");
    StringAppendF(&result, "Prediction State : %s\n", toString(mPredictionState).c_str());
    StringAppendF(&result, "Jank Type : %s\n", jankTypeBitmaskToString(mJankType).c_str());
    StringAppendF(&result, "Present Metadata : %s\n", toString(mFramePresentMetadata).c_str());
    StringAppendF(&result, "Finish Metadata: %s\n", toString(mFrameReadyMetadata).c_str());
    StringAppendF(&result, "Start Metadata: %s\n", toString(mFrameStartMetadata).c_str());
    std::chrono::nanoseconds vsyncPeriod(mRefreshRate.getPeriodNsecs());
    StringAppendF(&result, "Vsync Period: %10f\n",
                  std::chrono::duration<double, std::milli>(vsyncPeriod).count());
    nsecs_t presentDelta =
            mSurfaceFlingerActuals.presentTime - mSurfaceFlingerPredictions.presentTime;
    std::chrono::nanoseconds presentDeltaNs(std::abs(presentDelta));
    StringAppendF(&result, "Present delta: %10f\n",
                  std::chrono::duration<double, std::milli>(presentDeltaNs).count());
    std::chrono::nanoseconds deltaToVsync(std::abs(presentDelta) % mRefreshRate.getPeriodNsecs());
    StringAppendF(&result, "Present delta %% refreshrate: %10f\n",
                  std::chrono::duration<double, std::milli>(deltaToVsync).count());
    dumpTable(result, mSurfaceFlingerPredictions, mSurfaceFlingerActuals, "", mPredictionState,
              baseTime);
    StringAppendF(&result, "\n");
    std::string indent = "    "; // 4 spaces
    for (const auto& surfaceFrame : mSurfaceFrames) {
        surfaceFrame->dump(result, indent, baseTime);
    }
    StringAppendF(&result, "\n");
}

void FrameTimeline::dumpAll(std::string& result) {
    std::scoped_lock lock(mMutex);
    StringAppendF(&result, "Number of display frames : %d\n", (int)mDisplayFrames.size());
    nsecs_t baseTime = (mDisplayFrames.empty()) ? 0 : mDisplayFrames[0]->getBaseTime();
    for (size_t i = 0; i < mDisplayFrames.size(); i++) {
        StringAppendF(&result, "Display Frame %d", static_cast<int>(i));
        mDisplayFrames[i]->dumpAll(result, baseTime);
    }
}

void FrameTimeline::dumpJank(std::string& result) {
    std::scoped_lock lock(mMutex);
    nsecs_t baseTime = (mDisplayFrames.empty()) ? 0 : mDisplayFrames[0]->getBaseTime();
    for (size_t i = 0; i < mDisplayFrames.size(); i++) {
        mDisplayFrames[i]->dumpJank(result, baseTime, static_cast<int>(i));
    }
}

void FrameTimeline::parseArgs(const Vector<String16>& args, std::string& result) {
    ATRACE_CALL();
    std::unordered_map<std::string, bool> argsMap;
    for (size_t i = 0; i < args.size(); i++) {
        argsMap[std::string(String8(args[i]).c_str())] = true;
    }
    if (argsMap.count("-jank")) {
        dumpJank(result);
    }
    if (argsMap.count("-all")) {
        dumpAll(result);
    }
}

void FrameTimeline::setMaxDisplayFrames(uint32_t size) {
    std::scoped_lock lock(mMutex);

    // The size can either increase or decrease, clear everything, to be consistent
    mDisplayFrames.clear();
    mPendingPresentFences.clear();
    mMaxDisplayFrames = size;
}

void FrameTimeline::reset() {
    setMaxDisplayFrames(kDefaultMaxDisplayFrames);
}

} // namespace impl
} // namespace android::frametimeline
