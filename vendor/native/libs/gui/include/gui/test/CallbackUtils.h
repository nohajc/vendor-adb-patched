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
#pragma once

#include <gtest/gtest.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>
#include <ui/Fence.h>
#include <utils/Timers.h>
#include <chrono>
#include <thread>

using ::std::literals::chrono_literals::operator""ms;
using ::std::literals::chrono_literals::operator""s;

namespace android {

namespace {

struct CallbackData {
    CallbackData() = default;
    CallbackData(nsecs_t time, const sp<Fence>& fence,
                 const std::vector<SurfaceControlStats>& stats)
          : latchTime(time), presentFence(fence), surfaceControlStats(stats) {}

    nsecs_t latchTime;
    sp<Fence> presentFence;
    std::vector<SurfaceControlStats> surfaceControlStats;
};

class ExpectedResult {
public:
    enum Transaction {
        NOT_PRESENTED = 0,
        PRESENTED,
    };

    enum Buffer {
        NOT_ACQUIRED = 0,
        ACQUIRED,
    };

    enum PreviousBuffer {
        NOT_RELEASED = 0,
        RELEASED,
        UNKNOWN,
    };

    void reset() {
        mTransactionResult = ExpectedResult::Transaction::NOT_PRESENTED;
        mExpectedSurfaceResults.clear();
    }

    void addSurface(ExpectedResult::Transaction transactionResult, const sp<SurfaceControl>& layer,
                    ExpectedResult::Buffer bufferResult = ACQUIRED,
                    ExpectedResult::PreviousBuffer previousBufferResult = NOT_RELEASED) {
        mTransactionResult = transactionResult;
        mExpectedSurfaceResults.emplace(std::piecewise_construct, std::forward_as_tuple(layer),
                                        std::forward_as_tuple(bufferResult, previousBufferResult));
    }

    void addSurfaces(ExpectedResult::Transaction transactionResult,
                     const std::vector<sp<SurfaceControl>>& layers,
                     ExpectedResult::Buffer bufferResult = ACQUIRED,
                     ExpectedResult::PreviousBuffer previousBufferResult = NOT_RELEASED) {
        for (const auto& layer : layers) {
            addSurface(transactionResult, layer, bufferResult, previousBufferResult);
        }
    }

    void addExpectedPresentTime(nsecs_t expectedPresentTime) {
        mExpectedPresentTime = expectedPresentTime;
    }

    void addExpectedPresentTimeForVsyncId(nsecs_t expectedPresentTime) {
        mExpectedPresentTimeForVsyncId = expectedPresentTime;
    }

    void verifyCallbackData(const CallbackData& callbackData) const {
        const auto& [latchTime, presentFence, surfaceControlStats] = callbackData;
        if (mTransactionResult == ExpectedResult::Transaction::PRESENTED) {
            ASSERT_GE(latchTime, 0) << "bad latch time";
            ASSERT_NE(presentFence, nullptr);
            if (mExpectedPresentTime >= 0) {
                ASSERT_EQ(presentFence->wait(3000), NO_ERROR);
                ASSERT_GE(presentFence->getSignalTime(), mExpectedPresentTime - nsecs_t(5 * 1e6));
                // if the panel is running at 30 hz, at the worst case, our expected time just
                // misses vsync and we have to wait another 33.3ms
                ASSERT_LE(presentFence->getSignalTime(),
                          mExpectedPresentTime + nsecs_t(66.666666 * 1e6));
            } else if (mExpectedPresentTimeForVsyncId >= 0) {
                ASSERT_EQ(presentFence->wait(3000), NO_ERROR);
                // We give 4ms for prediction error
                ASSERT_GE(presentFence->getSignalTime(),
                          mExpectedPresentTimeForVsyncId - 4'000'000);
            }
        } else {
            ASSERT_EQ(presentFence, nullptr) << "transaction shouldn't have been presented";
            ASSERT_EQ(latchTime, -1) << "unpresented transactions shouldn't be latched";
        }

        ASSERT_EQ(surfaceControlStats.size(), mExpectedSurfaceResults.size())
                << "wrong number of surfaces";

        for (const auto& stats : surfaceControlStats) {
            ASSERT_NE(stats.surfaceControl, nullptr) << "returned null surface control";

            const auto& expectedSurfaceResult = mExpectedSurfaceResults.find(stats.surfaceControl);
            ASSERT_NE(expectedSurfaceResult, mExpectedSurfaceResults.end())
                    << "unexpected surface control";
            expectedSurfaceResult->second.verifySurfaceControlStats(stats, latchTime);
        }
    }

private:
    class ExpectedSurfaceResult {
    public:
        ExpectedSurfaceResult(ExpectedResult::Buffer bufferResult,
                              ExpectedResult::PreviousBuffer previousBufferResult)
              : mBufferResult(bufferResult), mPreviousBufferResult(previousBufferResult) {}

        void verifySurfaceControlStats(const SurfaceControlStats& surfaceControlStats,
                                       nsecs_t latchTime) const {
            const auto& [surfaceControl, latch, acquireTimeOrFence, presentFence,
                         previousReleaseFence, transformHint, frameEvents, ignore] =
                surfaceControlStats;

            ASSERT_TRUE(std::holds_alternative<nsecs_t>(acquireTimeOrFence));
            ASSERT_EQ(std::get<nsecs_t>(acquireTimeOrFence) > 0,
                      mBufferResult == ExpectedResult::Buffer::ACQUIRED)
                    << "bad acquire time";
            ASSERT_LE(std::get<nsecs_t>(acquireTimeOrFence), latchTime)
                    << "acquire time should be <= latch time";

            if (mPreviousBufferResult == ExpectedResult::PreviousBuffer::RELEASED) {
                ASSERT_NE(previousReleaseFence, nullptr)
                        << "failed to set release prev buffer fence";
            } else if (mPreviousBufferResult == ExpectedResult::PreviousBuffer::NOT_RELEASED) {
                ASSERT_EQ(previousReleaseFence, nullptr)
                        << "should not have set released prev buffer fence";
            }
        }

    private:
        ExpectedResult::Buffer mBufferResult;
        ExpectedResult::PreviousBuffer mPreviousBufferResult;
    };

    struct SCHash {
        std::size_t operator()(const sp<SurfaceControl>& sc) const {
            return std::hash<IBinder*>{}(sc->getHandle().get());
        }
    };
    ExpectedResult::Transaction mTransactionResult = ExpectedResult::Transaction::NOT_PRESENTED;
    nsecs_t mExpectedPresentTime = -1;
    nsecs_t mExpectedPresentTimeForVsyncId = -1;
    std::unordered_map<sp<SurfaceControl>, ExpectedSurfaceResult, SCHash> mExpectedSurfaceResults;
};

class CallbackHelper {
public:
    static void function(void* callbackContext, nsecs_t latchTime, const sp<Fence>& presentFence,
                         const std::vector<SurfaceControlStats>& stats) {
        if (!callbackContext) {
            ALOGE("failed to get callback context");
        }
        CallbackHelper* helper = static_cast<CallbackHelper*>(callbackContext);
        std::lock_guard lock(helper->mMutex);
        helper->mCallbackDataQueue.emplace(latchTime, presentFence, stats);
        helper->mConditionVariable.notify_all();
    }

    void getCallbackData(CallbackData* outData) {
        std::unique_lock lock(mMutex);

        if (mCallbackDataQueue.empty()) {
            ASSERT_NE(mConditionVariable.wait_for(lock, std::chrono::seconds(3)),
                      std::cv_status::timeout)
                    << "did not receive callback";
        }

        *outData = std::move(mCallbackDataQueue.front());
        mCallbackDataQueue.pop();
    }

    void verifyFinalState() {
        // Wait to see if there are extra callbacks
        std::this_thread::sleep_for(500ms);

        std::lock_guard lock(mMutex);
        EXPECT_EQ(mCallbackDataQueue.size(), 0U) << "extra callbacks received";
        mCallbackDataQueue = {};
    }

    void* getContext() { return static_cast<void*>(this); }

    std::mutex mMutex;
    std::condition_variable mConditionVariable;
    std::queue<CallbackData> mCallbackDataQueue;
};
} // namespace
} // namespace android
