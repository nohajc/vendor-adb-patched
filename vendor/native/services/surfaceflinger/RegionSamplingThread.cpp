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
#pragma clang diagnostic ignored "-Wextra"

//#define LOG_NDEBUG 0
#define ATRACE_TAG ATRACE_TAG_GRAPHICS
#undef LOG_TAG
#define LOG_TAG "RegionSamplingThread"

#include "RegionSamplingThread.h"

#include <compositionengine/Display.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <cutils/properties.h>
#include <ftl/future.h>
#include <gui/SpHash.h>
#include <gui/SyncScreenCaptureListener.h>
#include <renderengine/impl/ExternalTexture.h>
#include <ui/DisplayStatInfo.h>
#include <utils/Trace.h>

#include <string>

#include "DisplayDevice.h"
#include "DisplayRenderArea.h"
#include "Layer.h"
#include "Scheduler/VsyncController.h"
#include "SurfaceFlinger.h"

namespace android {
using namespace std::chrono_literals;

using gui::SpHash;

constexpr auto lumaSamplingStepTag = "LumaSamplingStep";
enum class samplingStep {
    noWorkNeeded,
    idleTimerWaiting,
    waitForQuietFrame,
    waitForSamplePhase,
    sample
};

constexpr auto defaultRegionSamplingWorkDuration = 3ms;
constexpr auto defaultRegionSamplingPeriod = 100ms;
constexpr auto defaultRegionSamplingTimerTimeout = 100ms;
constexpr auto maxRegionSamplingDelay = 100ms;
// TODO: (b/127403193) duration to string conversion could probably be constexpr
template <typename Rep, typename Per>
inline std::string toNsString(std::chrono::duration<Rep, Per> t) {
    return std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(t).count());
}

RegionSamplingThread::EnvironmentTimingTunables::EnvironmentTimingTunables() {
    char value[PROPERTY_VALUE_MAX] = {};

    property_get("debug.sf.region_sampling_duration_ns", value,
                 toNsString(defaultRegionSamplingWorkDuration).c_str());
    int const samplingDurationNsRaw = atoi(value);

    property_get("debug.sf.region_sampling_period_ns", value,
                 toNsString(defaultRegionSamplingPeriod).c_str());
    int const samplingPeriodNsRaw = atoi(value);

    property_get("debug.sf.region_sampling_timer_timeout_ns", value,
                 toNsString(defaultRegionSamplingTimerTimeout).c_str());
    int const samplingTimerTimeoutNsRaw = atoi(value);

    if ((samplingPeriodNsRaw < 0) || (samplingTimerTimeoutNsRaw < 0)) {
        ALOGW("User-specified sampling tuning options nonsensical. Using defaults");
        mSamplingDuration = defaultRegionSamplingWorkDuration;
        mSamplingPeriod = defaultRegionSamplingPeriod;
        mSamplingTimerTimeout = defaultRegionSamplingTimerTimeout;
    } else {
        mSamplingDuration = std::chrono::nanoseconds(samplingDurationNsRaw);
        mSamplingPeriod = std::chrono::nanoseconds(samplingPeriodNsRaw);
        mSamplingTimerTimeout = std::chrono::nanoseconds(samplingTimerTimeoutNsRaw);
    }
}

RegionSamplingThread::RegionSamplingThread(SurfaceFlinger& flinger, const TimingTunables& tunables)
      : mFlinger(flinger),
        mTunables(tunables),
        mIdleTimer(
                "RegSampIdle",
                std::chrono::duration_cast<std::chrono::milliseconds>(
                        mTunables.mSamplingTimerTimeout),
                [] {}, [this] { checkForStaleLuma(); }),
        mLastSampleTime(0ns) {
    mThread = std::thread([this]() { threadMain(); });
    pthread_setname_np(mThread.native_handle(), "RegionSampling");
    mIdleTimer.start();
}

RegionSamplingThread::RegionSamplingThread(SurfaceFlinger& flinger)
      : RegionSamplingThread(flinger,
                             TimingTunables{defaultRegionSamplingWorkDuration,
                                            defaultRegionSamplingPeriod,
                                            defaultRegionSamplingTimerTimeout}) {}

RegionSamplingThread::~RegionSamplingThread() {
    mIdleTimer.stop();

    {
        std::lock_guard lock(mThreadControlMutex);
        mRunning = false;
        mCondition.notify_one();
    }

    if (mThread.joinable()) {
        mThread.join();
    }
}

void RegionSamplingThread::addListener(const Rect& samplingArea, const wp<Layer>& stopLayer,
                                       const sp<IRegionSamplingListener>& listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(this);
    std::lock_guard lock(mSamplingMutex);
    mDescriptors.emplace(wp<IBinder>(asBinder), Descriptor{samplingArea, stopLayer, listener});
}

void RegionSamplingThread::removeListener(const sp<IRegionSamplingListener>& listener) {
    std::lock_guard lock(mSamplingMutex);
    mDescriptors.erase(wp<IBinder>(IInterface::asBinder(listener)));
}

void RegionSamplingThread::checkForStaleLuma() {
    std::lock_guard lock(mThreadControlMutex);

    if (mSampleRequestTime.has_value()) {
        ATRACE_INT(lumaSamplingStepTag, static_cast<int>(samplingStep::waitForSamplePhase));
        mSampleRequestTime.reset();
        mFlinger.scheduleSample();
    }
}

void RegionSamplingThread::onCompositionComplete(
        std::optional<std::chrono::steady_clock::time_point> samplingDeadline) {
    doSample(samplingDeadline);
}

void RegionSamplingThread::doSample(
        std::optional<std::chrono::steady_clock::time_point> samplingDeadline) {
    std::lock_guard lock(mThreadControlMutex);
    const auto now = std::chrono::steady_clock::now();
    if (mLastSampleTime + mTunables.mSamplingPeriod > now) {
        // content changed, but we sampled not too long ago, so we need to sample some time in the
        // future.
        ATRACE_INT(lumaSamplingStepTag, static_cast<int>(samplingStep::idleTimerWaiting));
        mSampleRequestTime = now;
        return;
    }
    if (!mSampleRequestTime.has_value() || now - *mSampleRequestTime < maxRegionSamplingDelay) {
        // If there is relatively little time left for surfaceflinger
        // until the next vsync deadline, defer this sampling work
        // to a later frame, when hopefully there will be more time.
        if (samplingDeadline.has_value() && now + mTunables.mSamplingDuration > *samplingDeadline) {
            ATRACE_INT(lumaSamplingStepTag, static_cast<int>(samplingStep::waitForQuietFrame));
            mSampleRequestTime = mSampleRequestTime.value_or(now);
            return;
        }
    }

    ATRACE_INT(lumaSamplingStepTag, static_cast<int>(samplingStep::sample));

    mSampleRequestTime.reset();
    mLastSampleTime = now;

    mIdleTimer.reset();

    mSampleRequested = true;
    mCondition.notify_one();
}

void RegionSamplingThread::binderDied(const wp<IBinder>& who) {
    std::lock_guard lock(mSamplingMutex);
    mDescriptors.erase(who);
}

float sampleArea(const uint32_t* data, int32_t width, int32_t height, int32_t stride,
                 uint32_t orientation, const Rect& sample_area) {
    if (!sample_area.isValid() || (sample_area.getWidth() > width) ||
        (sample_area.getHeight() > height)) {
        ALOGE("invalid sampling region requested");
        return 0.0f;
    }

    const uint32_t pixelCount =
            (sample_area.bottom - sample_area.top) * (sample_area.right - sample_area.left);
    uint32_t accumulatedLuma = 0;

    // Calculates luma with approximation of Rec. 709 primaries
    for (int32_t row = sample_area.top; row < sample_area.bottom; ++row) {
        const uint32_t* rowBase = data + row * stride;
        for (int32_t column = sample_area.left; column < sample_area.right; ++column) {
            uint32_t pixel = rowBase[column];
            const uint32_t r = pixel & 0xFF;
            const uint32_t g = (pixel >> 8) & 0xFF;
            const uint32_t b = (pixel >> 16) & 0xFF;
            const uint32_t luma = (r * 7 + b * 2 + g * 23) >> 5;
            accumulatedLuma += luma;
        }
    }

    return accumulatedLuma / (255.0f * pixelCount);
}

std::vector<float> RegionSamplingThread::sampleBuffer(
        const sp<GraphicBuffer>& buffer, const Point& leftTop,
        const std::vector<RegionSamplingThread::Descriptor>& descriptors, uint32_t orientation) {
    void* data_raw = nullptr;
    buffer->lock(GRALLOC_USAGE_SW_READ_OFTEN, &data_raw);
    std::shared_ptr<uint32_t> data(reinterpret_cast<uint32_t*>(data_raw),
                                   [&buffer](auto) { buffer->unlock(); });
    if (!data) return {};

    const int32_t width = buffer->getWidth();
    const int32_t height = buffer->getHeight();
    const int32_t stride = buffer->getStride();
    std::vector<float> lumas(descriptors.size());
    std::transform(descriptors.begin(), descriptors.end(), lumas.begin(),
                   [&](auto const& descriptor) {
                       return sampleArea(data.get(), width, height, stride, orientation,
                                         descriptor.area - leftTop);
                   });
    return lumas;
}

void RegionSamplingThread::captureSample() {
    ATRACE_CALL();
    std::lock_guard lock(mSamplingMutex);

    if (mDescriptors.empty()) {
        return;
    }

    wp<const DisplayDevice> displayWeak;

    ui::LayerStack layerStack;
    ui::Transform::RotationFlags orientation;
    ui::Size displaySize;

    {
        // TODO(b/159112860): Don't keep sp<DisplayDevice> outside of SF main thread
        const sp<const DisplayDevice> display = mFlinger.getDefaultDisplayDevice();
        displayWeak = display;
        layerStack = display->getLayerStack();
        orientation = ui::Transform::toRotationFlags(display->getOrientation());
        displaySize = display->getSize();
    }

    std::vector<RegionSamplingThread::Descriptor> descriptors;
    Region sampleRegion;
    for (const auto& [listener, descriptor] : mDescriptors) {
        sampleRegion.orSelf(descriptor.area);
        descriptors.emplace_back(descriptor);
    }

    const Rect sampledBounds = sampleRegion.bounds();
    constexpr bool kUseIdentityTransform = false;

    SurfaceFlinger::RenderAreaFuture renderAreaFuture = ftl::defer([=] {
        return DisplayRenderArea::create(displayWeak, sampledBounds, sampledBounds.getSize(),
                                         ui::Dataspace::V0_SRGB, kUseIdentityTransform);
    });

    std::unordered_set<sp<IRegionSamplingListener>, SpHash<IRegionSamplingListener>> listeners;

    auto traverseLayers = [&](const LayerVector::Visitor& visitor) {
        bool stopLayerFound = false;
        auto filterVisitor = [&](Layer* layer) {
            // We don't want to capture any layers beyond the stop layer
            if (stopLayerFound) return;

            // Likewise if we just found a stop layer, set the flag and abort
            for (const auto& [area, stopLayer, listener] : descriptors) {
                if (layer == stopLayer.promote().get()) {
                    stopLayerFound = true;
                    return;
                }
            }

            // Compute the layer's position on the screen
            const Rect bounds = Rect(layer->getBounds());
            const ui::Transform transform = layer->getTransform();
            constexpr bool roundOutwards = true;
            Rect transformed = transform.transform(bounds, roundOutwards);

            // If this layer doesn't intersect with the larger sampledBounds, skip capturing it
            Rect ignore;
            if (!transformed.intersect(sampledBounds, &ignore)) return;

            // If the layer doesn't intersect a sampling area, skip capturing it
            bool intersectsAnyArea = false;
            for (const auto& [area, stopLayer, listener] : descriptors) {
                if (transformed.intersect(area, &ignore)) {
                    intersectsAnyArea = true;
                    listeners.insert(listener);
                }
            }
            if (!intersectsAnyArea) return;

            ALOGV("Traversing [%s] [%d, %d, %d, %d]", layer->getDebugName(), bounds.left,
                  bounds.top, bounds.right, bounds.bottom);
            visitor(layer);
        };
        mFlinger.traverseLayersInLayerStack(layerStack, CaptureArgs::UNSET_UID, filterVisitor);
    };

    std::shared_ptr<renderengine::ExternalTexture> buffer = nullptr;
    if (mCachedBuffer && mCachedBuffer->getBuffer()->getWidth() == sampledBounds.getWidth() &&
        mCachedBuffer->getBuffer()->getHeight() == sampledBounds.getHeight()) {
        buffer = mCachedBuffer;
    } else {
        const uint32_t usage =
                GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;
        sp<GraphicBuffer> graphicBuffer =
                new GraphicBuffer(sampledBounds.getWidth(), sampledBounds.getHeight(),
                                  PIXEL_FORMAT_RGBA_8888, 1, usage, "RegionSamplingThread");
        const status_t bufferStatus = graphicBuffer->initCheck();
        LOG_ALWAYS_FATAL_IF(bufferStatus != OK, "captureSample: Buffer failed to allocate: %d",
                            bufferStatus);
        buffer = std::make_shared<
                renderengine::impl::ExternalTexture>(graphicBuffer, mFlinger.getRenderEngine(),
                                                     renderengine::impl::ExternalTexture::Usage::
                                                             WRITEABLE);
    }

    constexpr bool kRegionSampling = true;
    constexpr bool kGrayscale = false;

    if (const auto fenceResult =
                mFlinger.captureScreenCommon(std::move(renderAreaFuture), traverseLayers, buffer,
                                             kRegionSampling, kGrayscale, nullptr)
                        .get();
        fenceResult.ok()) {
        fenceResult.value()->waitForever(LOG_TAG);
    }

    std::vector<Descriptor> activeDescriptors;
    for (const auto& descriptor : descriptors) {
        if (listeners.count(descriptor.listener) != 0) {
            activeDescriptors.emplace_back(descriptor);
        }
    }

    ALOGV("Sampling %zu descriptors", activeDescriptors.size());
    std::vector<float> lumas = sampleBuffer(buffer->getBuffer(), sampledBounds.leftTop(),
                                            activeDescriptors, orientation);
    if (lumas.size() != activeDescriptors.size()) {
        ALOGW("collected %zu median luma values for %zu descriptors", lumas.size(),
              activeDescriptors.size());
        return;
    }

    for (size_t d = 0; d < activeDescriptors.size(); ++d) {
        activeDescriptors[d].listener->onSampleCollected(lumas[d]);
    }

    mCachedBuffer = buffer;
    ATRACE_INT(lumaSamplingStepTag, static_cast<int>(samplingStep::noWorkNeeded));
}

// NO_THREAD_SAFETY_ANALYSIS is because std::unique_lock presently lacks thread safety annotations.
void RegionSamplingThread::threadMain() NO_THREAD_SAFETY_ANALYSIS {
    std::unique_lock<std::mutex> lock(mThreadControlMutex);
    while (mRunning) {
        if (mSampleRequested) {
            mSampleRequested = false;
            lock.unlock();
            captureSample();
            lock.lock();
        }
        mCondition.wait(lock, [this]() REQUIRES(mThreadControlMutex) {
            return mSampleRequested || !mRunning;
        });
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
