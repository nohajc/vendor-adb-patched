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
#include <android/gui/IRegionSamplingListener.h>
#include <binder/IBinder.h>
#include <renderengine/ExternalTexture.h>
#include <ui/GraphicBuffer.h>
#include <ui/Rect.h>
#include <utils/StrongPointer.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "Scheduler/OneShotTimer.h"
#include "WpHash.h"

namespace android {

class Layer;
class Scheduler;
class SurfaceFlinger;
struct SamplingOffsetCallback;

using gui::IRegionSamplingListener;

float sampleArea(const uint32_t* data, int32_t width, int32_t height, int32_t stride,
                 uint32_t orientation, const Rect& area);

class RegionSamplingThread : public IBinder::DeathRecipient {
public:
    struct TimingTunables {
        // debug.sf.sampling_duration_ns
        // When asynchronously collecting sample, the duration, at which the sampling should start
        // before a vsync
        std::chrono::nanoseconds mSamplingDuration;
        // debug.sf.sampling_period_ns
        // This is the maximum amount of time the luma recieving client
        // should have to wait for a new luma value after a frame is updated. The inverse of this is
        // roughly the sampling rate. Sampling system rounds up sub-vsync sampling period to vsync
        // period.
        std::chrono::nanoseconds mSamplingPeriod;
        // debug.sf.sampling_timer_timeout_ns
        // This is the interval at which the luma sampling system will check that the luma clients
        // have up to date information. It defaults to the mSamplingPeriod.
        std::chrono::nanoseconds mSamplingTimerTimeout;
    };
    struct EnvironmentTimingTunables : TimingTunables {
        EnvironmentTimingTunables();
    };
    explicit RegionSamplingThread(SurfaceFlinger& flinger, const TimingTunables& tunables);
    explicit RegionSamplingThread(SurfaceFlinger& flinger);

    ~RegionSamplingThread();

    // Add a listener to receive luma notifications. The luma reported via listener will
    // report the median luma for the layers under the stopLayerHandle, in the samplingArea region.
    void addListener(const Rect& samplingArea, const wp<Layer>& stopLayer,
                     const sp<IRegionSamplingListener>& listener);
    // Remove the listener to stop receiving median luma notifications.
    void removeListener(const sp<IRegionSamplingListener>& listener);

    // Notifies sampling engine that composition is done and new content is
    // available, and the deadline for the sampling work on the main thread to
    // be completed without eating the budget of another frame.
    void onCompositionComplete(
            std::optional<std::chrono::steady_clock::time_point> samplingDeadline);

private:
    struct Descriptor {
        Rect area = Rect::EMPTY_RECT;
        wp<Layer> stopLayer;
        sp<IRegionSamplingListener> listener;
    };

    std::vector<float> sampleBuffer(
            const sp<GraphicBuffer>& buffer, const Point& leftTop,
            const std::vector<RegionSamplingThread::Descriptor>& descriptors, uint32_t orientation);

    void doSample(std::optional<std::chrono::steady_clock::time_point> samplingDeadline);
    void binderDied(const wp<IBinder>& who) override;
    void checkForStaleLuma();

    void captureSample();
    void threadMain();

    SurfaceFlinger& mFlinger;
    const TimingTunables mTunables;
    scheduler::OneShotTimer mIdleTimer;

    std::thread mThread;

    std::mutex mThreadControlMutex;
    std::condition_variable_any mCondition;
    bool mRunning GUARDED_BY(mThreadControlMutex) = true;
    bool mSampleRequested GUARDED_BY(mThreadControlMutex) = false;
    std::optional<std::chrono::steady_clock::time_point> mSampleRequestTime
            GUARDED_BY(mThreadControlMutex);
    std::chrono::steady_clock::time_point mLastSampleTime GUARDED_BY(mThreadControlMutex);

    std::mutex mSamplingMutex;
    std::unordered_map<wp<IBinder>, Descriptor, WpHash> mDescriptors GUARDED_BY(mSamplingMutex);
    std::shared_ptr<renderengine::ExternalTexture> mCachedBuffer GUARDED_BY(mSamplingMutex) =
            nullptr;
};

} // namespace android
