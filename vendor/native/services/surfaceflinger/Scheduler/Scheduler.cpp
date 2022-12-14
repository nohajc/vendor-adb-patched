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

#undef LOG_TAG
#define LOG_TAG "Scheduler"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "Scheduler.h"

#include <android-base/stringprintf.h>
#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <android/hardware/configstore/1.1/ISurfaceFlingerConfigs.h>
#include <configstore/Utils.h>
#include <cutils/properties.h>
#include <input/InputWindow.h>
#include <system/window.h>
#include <ui/DisplayStatInfo.h>
#include <utils/Timers.h>
#include <utils/Trace.h>

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <functional>
#include <memory>
#include <numeric>

#include "../Layer.h"
#include "DispSync.h"
#include "DispSyncSource.h"
#include "EventControlThread.h"
#include "EventThread.h"
#include "InjectVSyncSource.h"
#include "OneShotTimer.h"
#include "SchedulerUtils.h"
#include "SurfaceFlingerProperties.h"
#include "Timer.h"
#include "VSyncDispatchTimerQueue.h"
#include "VSyncPredictor.h"
#include "VSyncReactor.h"

#define RETURN_IF_INVALID_HANDLE(handle, ...)                        \
    do {                                                             \
        if (mConnections.count(handle) == 0) {                       \
            ALOGE("Invalid connection handle %" PRIuPTR, handle.id); \
            return __VA_ARGS__;                                      \
        }                                                            \
    } while (false)

namespace android {

std::unique_ptr<DispSync> createDispSync(bool supportKernelTimer) {
    // TODO (140302863) remove this and use the vsync_reactor system.
    if (property_get_bool("debug.sf.vsync_reactor", true)) {
        // TODO (144707443) tune Predictor tunables.
        static constexpr int defaultRate = 60;
        static constexpr auto initialPeriod =
                std::chrono::duration<nsecs_t, std::ratio<1, defaultRate>>(1);
        static constexpr size_t vsyncTimestampHistorySize = 20;
        static constexpr size_t minimumSamplesForPrediction = 6;
        static constexpr uint32_t discardOutlierPercent = 20;
        auto tracker = std::make_unique<
                scheduler::VSyncPredictor>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                   initialPeriod)
                                                   .count(),
                                           vsyncTimestampHistorySize, minimumSamplesForPrediction,
                                           discardOutlierPercent);

        static constexpr auto vsyncMoveThreshold =
                std::chrono::duration_cast<std::chrono::nanoseconds>(3ms);
        static constexpr auto timerSlack =
                std::chrono::duration_cast<std::chrono::nanoseconds>(500us);
        auto dispatch = std::make_unique<
                scheduler::VSyncDispatchTimerQueue>(std::make_unique<scheduler::Timer>(), *tracker,
                                                    timerSlack.count(), vsyncMoveThreshold.count());

        static constexpr size_t pendingFenceLimit = 20;
        return std::make_unique<scheduler::VSyncReactor>(std::make_unique<scheduler::SystemClock>(),
                                                         std::move(dispatch), std::move(tracker),
                                                         pendingFenceLimit, supportKernelTimer);
    } else {
        return std::make_unique<impl::DispSync>("SchedulerDispSync",
                                                sysprop::running_without_sync_framework(true));
    }
}

Scheduler::Scheduler(impl::EventControlThread::SetVSyncEnabledFunction function,
                     const scheduler::RefreshRateConfigs& refreshRateConfig,
                     ISchedulerCallback& schedulerCallback, bool useContentDetectionV2,
                     bool useContentDetection)
      : mSupportKernelTimer(sysprop::support_kernel_idle_timer(false)),
        mPrimaryDispSync(createDispSync(mSupportKernelTimer)),
        mEventControlThread(new impl::EventControlThread(std::move(function))),
        mSchedulerCallback(schedulerCallback),
        mRefreshRateConfigs(refreshRateConfig),
        mUseContentDetection(useContentDetection),
        mUseContentDetectionV2(useContentDetectionV2) {
    using namespace sysprop;

    if (mUseContentDetectionV2) {
        mLayerHistory = std::make_unique<scheduler::impl::LayerHistoryV2>(refreshRateConfig);
    } else {
        mLayerHistory = std::make_unique<scheduler::impl::LayerHistory>();
    }

    const int setIdleTimerMs = property_get_int32("debug.sf.set_idle_timer_ms", 0);

    if (const auto millis = setIdleTimerMs ? setIdleTimerMs : set_idle_timer_ms(0); millis > 0) {
        const auto callback = mSupportKernelTimer ? &Scheduler::kernelIdleTimerCallback
                                                  : &Scheduler::idleTimerCallback;
        mIdleTimer.emplace(
                std::chrono::milliseconds(millis),
                [this, callback] { std::invoke(callback, this, TimerState::Reset); },
                [this, callback] { std::invoke(callback, this, TimerState::Expired); });
        mIdleTimer->start();
    }

    if (const int64_t millis = set_touch_timer_ms(0); millis > 0) {
        // Touch events are coming to SF every 100ms, so the timer needs to be higher than that
        mTouchTimer.emplace(
                std::chrono::milliseconds(millis),
                [this] { touchTimerCallback(TimerState::Reset); },
                [this] { touchTimerCallback(TimerState::Expired); });
        mTouchTimer->start();
    }

    if (const int64_t millis = set_display_power_timer_ms(0); millis > 0) {
        mDisplayPowerTimer.emplace(
                std::chrono::milliseconds(millis),
                [this] { displayPowerTimerCallback(TimerState::Reset); },
                [this] { displayPowerTimerCallback(TimerState::Expired); });
        mDisplayPowerTimer->start();
    }
}

Scheduler::Scheduler(std::unique_ptr<DispSync> primaryDispSync,
                     std::unique_ptr<EventControlThread> eventControlThread,
                     const scheduler::RefreshRateConfigs& configs,
                     ISchedulerCallback& schedulerCallback, bool useContentDetectionV2,
                     bool useContentDetection)
      : mSupportKernelTimer(false),
        mPrimaryDispSync(std::move(primaryDispSync)),
        mEventControlThread(std::move(eventControlThread)),
        mSchedulerCallback(schedulerCallback),
        mRefreshRateConfigs(configs),
        mUseContentDetection(useContentDetection),
        mUseContentDetectionV2(useContentDetectionV2) {}

Scheduler::~Scheduler() {
    // Ensure the OneShotTimer threads are joined before we start destroying state.
    mDisplayPowerTimer.reset();
    mTouchTimer.reset();
    mIdleTimer.reset();
}

DispSync& Scheduler::getPrimaryDispSync() {
    return *mPrimaryDispSync;
}

std::unique_ptr<VSyncSource> Scheduler::makePrimaryDispSyncSource(const char* name,
                                                                  nsecs_t phaseOffsetNs) {
    return std::make_unique<DispSyncSource>(mPrimaryDispSync.get(), phaseOffsetNs,
                                            true /* traceVsync */, name);
}

Scheduler::ConnectionHandle Scheduler::createConnection(
        const char* connectionName, nsecs_t phaseOffsetNs,
        impl::EventThread::InterceptVSyncsCallback interceptCallback) {
    auto vsyncSource = makePrimaryDispSyncSource(connectionName, phaseOffsetNs);
    auto eventThread = std::make_unique<impl::EventThread>(std::move(vsyncSource),
                                                           std::move(interceptCallback));
    return createConnection(std::move(eventThread));
}

Scheduler::ConnectionHandle Scheduler::createConnection(std::unique_ptr<EventThread> eventThread) {
    const ConnectionHandle handle = ConnectionHandle{mNextConnectionHandleId++};
    ALOGV("Creating a connection handle with ID %" PRIuPTR, handle.id);

    auto connection =
            createConnectionInternal(eventThread.get(), ISurfaceComposer::eConfigChangedSuppress);

    mConnections.emplace(handle, Connection{connection, std::move(eventThread)});
    return handle;
}

sp<EventThreadConnection> Scheduler::createConnectionInternal(
        EventThread* eventThread, ISurfaceComposer::ConfigChanged configChanged) {
    return eventThread->createEventConnection([&] { resync(); }, configChanged);
}

sp<IDisplayEventConnection> Scheduler::createDisplayEventConnection(
        ConnectionHandle handle, ISurfaceComposer::ConfigChanged configChanged) {
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return createConnectionInternal(mConnections[handle].thread.get(), configChanged);
}

sp<EventThreadConnection> Scheduler::getEventConnection(ConnectionHandle handle) {
    RETURN_IF_INVALID_HANDLE(handle, nullptr);
    return mConnections[handle].connection;
}

void Scheduler::onHotplugReceived(ConnectionHandle handle, PhysicalDisplayId displayId,
                                  bool connected) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->onHotplugReceived(displayId, connected);
}

void Scheduler::onScreenAcquired(ConnectionHandle handle) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->onScreenAcquired();
}

void Scheduler::onScreenReleased(ConnectionHandle handle) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->onScreenReleased();
}

void Scheduler::onPrimaryDisplayConfigChanged(ConnectionHandle handle, PhysicalDisplayId displayId,
                                              HwcConfigIndexType configId, nsecs_t vsyncPeriod) {
    std::lock_guard<std::mutex> lock(mFeatureStateLock);
    // Cache the last reported config for primary display.
    mFeatures.cachedConfigChangedParams = {handle, displayId, configId, vsyncPeriod};
    onNonPrimaryDisplayConfigChanged(handle, displayId, configId, vsyncPeriod);
}

void Scheduler::dispatchCachedReportedConfig() {
    const auto configId = *mFeatures.configId;
    const auto vsyncPeriod =
            mRefreshRateConfigs.getRefreshRateFromConfigId(configId).getVsyncPeriod();

    // If there is no change from cached config, there is no need to dispatch an event
    if (configId == mFeatures.cachedConfigChangedParams->configId &&
        vsyncPeriod == mFeatures.cachedConfigChangedParams->vsyncPeriod) {
        return;
    }

    mFeatures.cachedConfigChangedParams->configId = configId;
    mFeatures.cachedConfigChangedParams->vsyncPeriod = vsyncPeriod;
    onNonPrimaryDisplayConfigChanged(mFeatures.cachedConfigChangedParams->handle,
                                     mFeatures.cachedConfigChangedParams->displayId,
                                     mFeatures.cachedConfigChangedParams->configId,
                                     mFeatures.cachedConfigChangedParams->vsyncPeriod);
}

void Scheduler::onNonPrimaryDisplayConfigChanged(ConnectionHandle handle,
                                                 PhysicalDisplayId displayId,
                                                 HwcConfigIndexType configId, nsecs_t vsyncPeriod) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->onConfigChanged(displayId, configId, vsyncPeriod);
}

size_t Scheduler::getEventThreadConnectionCount(ConnectionHandle handle) {
    RETURN_IF_INVALID_HANDLE(handle, 0);
    return mConnections[handle].thread->getEventThreadConnectionCount();
}

void Scheduler::dump(ConnectionHandle handle, std::string& result) const {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections.at(handle).thread->dump(result);
}

void Scheduler::setPhaseOffset(ConnectionHandle handle, nsecs_t phaseOffset) {
    RETURN_IF_INVALID_HANDLE(handle);
    mConnections[handle].thread->setPhaseOffset(phaseOffset);
}

void Scheduler::getDisplayStatInfo(DisplayStatInfo* stats) {
    stats->vsyncTime = mPrimaryDispSync->computeNextRefresh(0, systemTime());
    stats->vsyncPeriod = mPrimaryDispSync->getPeriod();
}

Scheduler::ConnectionHandle Scheduler::enableVSyncInjection(bool enable) {
    if (mInjectVSyncs == enable) {
        return {};
    }

    ALOGV("%s VSYNC injection", enable ? "Enabling" : "Disabling");

    if (!mInjectorConnectionHandle) {
        auto vsyncSource = std::make_unique<InjectVSyncSource>();
        mVSyncInjector = vsyncSource.get();

        auto eventThread =
                std::make_unique<impl::EventThread>(std::move(vsyncSource),
                                                    impl::EventThread::InterceptVSyncsCallback());

        mInjectorConnectionHandle = createConnection(std::move(eventThread));
    }

    mInjectVSyncs = enable;
    return mInjectorConnectionHandle;
}

bool Scheduler::injectVSync(nsecs_t when, nsecs_t expectedVSyncTime) {
    if (!mInjectVSyncs || !mVSyncInjector) {
        return false;
    }

    mVSyncInjector->onInjectSyncEvent(when, expectedVSyncTime);
    return true;
}

void Scheduler::enableHardwareVsync() {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    if (!mPrimaryHWVsyncEnabled && mHWVsyncAvailable) {
        mPrimaryDispSync->beginResync();
        mEventControlThread->setVsyncEnabled(true);
        mPrimaryHWVsyncEnabled = true;
    }
}

void Scheduler::disableHardwareVsync(bool makeUnavailable) {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    if (mPrimaryHWVsyncEnabled) {
        mEventControlThread->setVsyncEnabled(false);
        mPrimaryDispSync->endResync();
        mPrimaryHWVsyncEnabled = false;
    }
    if (makeUnavailable) {
        mHWVsyncAvailable = false;
    }
}

void Scheduler::resyncToHardwareVsync(bool makeAvailable, nsecs_t period) {
    {
        std::lock_guard<std::mutex> lock(mHWVsyncLock);
        if (makeAvailable) {
            mHWVsyncAvailable = makeAvailable;
        } else if (!mHWVsyncAvailable) {
            // Hardware vsync is not currently available, so abort the resync
            // attempt for now
            return;
        }
    }

    if (period <= 0) {
        return;
    }

    setVsyncPeriod(period);
}

void Scheduler::resync() {
    static constexpr nsecs_t kIgnoreDelay = ms2ns(750);

    const nsecs_t now = systemTime();
    const nsecs_t last = mLastResyncTime.exchange(now);

    if (now - last > kIgnoreDelay) {
        resyncToHardwareVsync(false, mRefreshRateConfigs.getCurrentRefreshRate().getVsyncPeriod());
    }
}

void Scheduler::setVsyncPeriod(nsecs_t period) {
    std::lock_guard<std::mutex> lock(mHWVsyncLock);
    mPrimaryDispSync->setPeriod(period);

    if (!mPrimaryHWVsyncEnabled) {
        mPrimaryDispSync->beginResync();
        mEventControlThread->setVsyncEnabled(true);
        mPrimaryHWVsyncEnabled = true;
    }
}

void Scheduler::addResyncSample(nsecs_t timestamp, std::optional<nsecs_t> hwcVsyncPeriod,
                                bool* periodFlushed) {
    bool needsHwVsync = false;
    *periodFlushed = false;
    { // Scope for the lock
        std::lock_guard<std::mutex> lock(mHWVsyncLock);
        if (mPrimaryHWVsyncEnabled) {
            needsHwVsync =
                    mPrimaryDispSync->addResyncSample(timestamp, hwcVsyncPeriod, periodFlushed);
        }
    }

    if (needsHwVsync) {
        enableHardwareVsync();
    } else {
        disableHardwareVsync(false);
    }
}

void Scheduler::addPresentFence(const std::shared_ptr<FenceTime>& fenceTime) {
    if (mPrimaryDispSync->addPresentFence(fenceTime)) {
        enableHardwareVsync();
    } else {
        disableHardwareVsync(false);
    }
}

void Scheduler::setIgnorePresentFences(bool ignore) {
    mPrimaryDispSync->setIgnorePresentFences(ignore);
}

nsecs_t Scheduler::getDispSyncExpectedPresentTime(nsecs_t now) {
    return mPrimaryDispSync->expectedPresentTime(now);
}

void Scheduler::registerLayer(Layer* layer) {
    if (!mLayerHistory) return;

    const auto minFps = mRefreshRateConfigs.getMinRefreshRate().getFps();
    const auto maxFps = mRefreshRateConfigs.getMaxRefreshRate().getFps();

    if (layer->getWindowType() == InputWindowInfo::TYPE_STATUS_BAR) {
        mLayerHistory->registerLayer(layer, minFps, maxFps,
                                     scheduler::LayerHistory::LayerVoteType::NoVote);
    } else if (!mUseContentDetection) {
        // If the content detection feature is off, all layers are registered at Max. We still keep
        // the layer history, since we use it for other features (like Frame Rate API), so layers
        // still need to be registered.
        mLayerHistory->registerLayer(layer, minFps, maxFps,
                                     scheduler::LayerHistory::LayerVoteType::Max);
    } else if (!mUseContentDetectionV2) {
        // In V1 of content detection, all layers are registered as Heuristic (unless it's
        // wallpaper).
        const auto highFps =
                layer->getWindowType() == InputWindowInfo::TYPE_WALLPAPER ? minFps : maxFps;

        mLayerHistory->registerLayer(layer, minFps, highFps,
                                     scheduler::LayerHistory::LayerVoteType::Heuristic);
    } else {
        if (layer->getWindowType() == InputWindowInfo::TYPE_WALLPAPER) {
            // Running Wallpaper at Min is considered as part of content detection.
            mLayerHistory->registerLayer(layer, minFps, maxFps,
                                         scheduler::LayerHistory::LayerVoteType::Min);
        } else {
            mLayerHistory->registerLayer(layer, minFps, maxFps,
                                         scheduler::LayerHistory::LayerVoteType::Heuristic);
        }
    }
}

void Scheduler::recordLayerHistory(Layer* layer, nsecs_t presentTime,
                                   LayerHistory::LayerUpdateType updateType) {
    if (mLayerHistory) {
        mLayerHistory->record(layer, presentTime, systemTime(), updateType);
    }
}

void Scheduler::setConfigChangePending(bool pending) {
    if (mLayerHistory) {
        mLayerHistory->setConfigChangePending(pending);
    }
}

void Scheduler::chooseRefreshRateForContent() {
    if (!mLayerHistory) return;

    ATRACE_CALL();

    scheduler::LayerHistory::Summary summary = mLayerHistory->summarize(systemTime());
    HwcConfigIndexType newConfigId;
    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        if (mFeatures.contentRequirements == summary) {
            return;
        }
        mFeatures.contentRequirements = summary;
        mFeatures.contentDetectionV1 =
                !summary.empty() ? ContentDetectionState::On : ContentDetectionState::Off;

        scheduler::RefreshRateConfigs::GlobalSignals consideredSignals;
        newConfigId = calculateRefreshRateConfigIndexType(&consideredSignals);
        if (mFeatures.configId == newConfigId) {
            // We don't need to change the config, but we might need to send an event
            // about a config change, since it was suppressed due to a previous idleConsidered
            if (!consideredSignals.idle) {
                dispatchCachedReportedConfig();
            }
            return;
        }
        mFeatures.configId = newConfigId;
        auto& newRefreshRate = mRefreshRateConfigs.getRefreshRateFromConfigId(newConfigId);
        mSchedulerCallback.changeRefreshRate(newRefreshRate,
                                             consideredSignals.idle ? ConfigEvent::None
                                                                    : ConfigEvent::Changed);
    }
}

void Scheduler::resetIdleTimer() {
    if (mIdleTimer) {
        mIdleTimer->reset();
    }
}

void Scheduler::notifyTouchEvent() {
    if (!mTouchTimer) return;

    // Touch event will boost the refresh rate to performance.
    // Clear Layer History to get fresh FPS detection.
    // NOTE: Instead of checking all the layers, we should be checking the layer
    // that is currently on top. b/142507166 will give us this capability.
    std::lock_guard<std::mutex> lock(mFeatureStateLock);
    if (mLayerHistory) {
        // Layer History will be cleared based on RefreshRateConfigs::getBestRefreshRate

        mTouchTimer->reset();

        if (mSupportKernelTimer && mIdleTimer) {
            mIdleTimer->reset();
        }
    }
}

void Scheduler::setDisplayPowerState(bool normal) {
    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        mFeatures.isDisplayPowerStateNormal = normal;
    }

    if (mDisplayPowerTimer) {
        mDisplayPowerTimer->reset();
    }

    // Display Power event will boost the refresh rate to performance.
    // Clear Layer History to get fresh FPS detection
    if (mLayerHistory) {
        mLayerHistory->clear();
    }
}

void Scheduler::kernelIdleTimerCallback(TimerState state) {
    ATRACE_INT("ExpiredKernelIdleTimer", static_cast<int>(state));

    // TODO(145561154): cleanup the kernel idle timer implementation and the refresh rate
    // magic number
    const auto& refreshRate = mRefreshRateConfigs.getCurrentRefreshRate();
    constexpr float FPS_THRESHOLD_FOR_KERNEL_TIMER = 65.0f;
    if (state == TimerState::Reset && refreshRate.getFps() > FPS_THRESHOLD_FOR_KERNEL_TIMER) {
        // If we're not in performance mode then the kernel timer shouldn't do
        // anything, as the refresh rate during DPU power collapse will be the
        // same.
        resyncToHardwareVsync(true /* makeAvailable */, refreshRate.getVsyncPeriod());
    } else if (state == TimerState::Expired &&
               refreshRate.getFps() <= FPS_THRESHOLD_FOR_KERNEL_TIMER) {
        // Disable HW VSYNC if the timer expired, as we don't need it enabled if
        // we're not pushing frames, and if we're in PERFORMANCE mode then we'll
        // need to update the DispSync model anyway.
        disableHardwareVsync(false /* makeUnavailable */);
    }

    mSchedulerCallback.kernelTimerChanged(state == TimerState::Expired);
}

void Scheduler::idleTimerCallback(TimerState state) {
    handleTimerStateChanged(&mFeatures.idleTimer, state);
    ATRACE_INT("ExpiredIdleTimer", static_cast<int>(state));
}

void Scheduler::touchTimerCallback(TimerState state) {
    const TouchState touch = state == TimerState::Reset ? TouchState::Active : TouchState::Inactive;
    if (handleTimerStateChanged(&mFeatures.touch, touch)) {
        mLayerHistory->clear();
    }
    ATRACE_INT("TouchState", static_cast<int>(touch));
}

void Scheduler::displayPowerTimerCallback(TimerState state) {
    handleTimerStateChanged(&mFeatures.displayPowerTimer, state);
    ATRACE_INT("ExpiredDisplayPowerTimer", static_cast<int>(state));
}

void Scheduler::dump(std::string& result) const {
    using base::StringAppendF;
    const char* const states[] = {"off", "on"};

    StringAppendF(&result, "+  Idle timer: %s\n",
                  mIdleTimer ? mIdleTimer->dump().c_str() : states[0]);
    StringAppendF(&result, "+  Touch timer: %s\n",
                  mTouchTimer ? mTouchTimer->dump().c_str() : states[0]);
    StringAppendF(&result, "+  Use content detection: %s\n\n",
                  sysprop::use_content_detection_for_refresh_rate(false) ? "on" : "off");
}

template <class T>
bool Scheduler::handleTimerStateChanged(T* currentState, T newState) {
    HwcConfigIndexType newConfigId;
    scheduler::RefreshRateConfigs::GlobalSignals consideredSignals;
    {
        std::lock_guard<std::mutex> lock(mFeatureStateLock);
        if (*currentState == newState) {
            return false;
        }
        *currentState = newState;
        newConfigId = calculateRefreshRateConfigIndexType(&consideredSignals);
        if (mFeatures.configId == newConfigId) {
            // We don't need to change the config, but we might need to send an event
            // about a config change, since it was suppressed due to a previous idleConsidered
            if (!consideredSignals.idle) {
                dispatchCachedReportedConfig();
            }
            return consideredSignals.touch;
        }
        mFeatures.configId = newConfigId;
    }
    const RefreshRate& newRefreshRate = mRefreshRateConfigs.getRefreshRateFromConfigId(newConfigId);
    mSchedulerCallback.changeRefreshRate(newRefreshRate,
                                         consideredSignals.idle ? ConfigEvent::None
                                                                : ConfigEvent::Changed);
    return consideredSignals.touch;
}

HwcConfigIndexType Scheduler::calculateRefreshRateConfigIndexType(
        scheduler::RefreshRateConfigs::GlobalSignals* consideredSignals) {
    ATRACE_CALL();
    if (consideredSignals) *consideredSignals = {};

    // If Display Power is not in normal operation we want to be in performance mode. When coming
    // back to normal mode, a grace period is given with DisplayPowerTimer.
    if (mDisplayPowerTimer &&
        (!mFeatures.isDisplayPowerStateNormal ||
         mFeatures.displayPowerTimer == TimerState::Reset)) {
        return mRefreshRateConfigs.getMaxRefreshRateByPolicy().getConfigId();
    }

    const bool touchActive = mTouchTimer && mFeatures.touch == TouchState::Active;
    const bool idle = mIdleTimer && mFeatures.idleTimer == TimerState::Expired;

    if (!mUseContentDetectionV2) {
        // As long as touch is active we want to be in performance mode.
        if (touchActive) {
            return mRefreshRateConfigs.getMaxRefreshRateByPolicy().getConfigId();
        }

        // If timer has expired as it means there is no new content on the screen.
        if (idle) {
            if (consideredSignals) consideredSignals->idle = true;
            return mRefreshRateConfigs.getMinRefreshRateByPolicy().getConfigId();
        }

        // If content detection is off we choose performance as we don't know the content fps.
        if (mFeatures.contentDetectionV1 == ContentDetectionState::Off) {
            // NOTE: V1 always calls this, but this is not a default behavior for V2.
            return mRefreshRateConfigs.getMaxRefreshRateByPolicy().getConfigId();
        }

        // Content detection is on, find the appropriate refresh rate with minimal error
        return mRefreshRateConfigs.getRefreshRateForContent(mFeatures.contentRequirements)
                .getConfigId();
    }

    return mRefreshRateConfigs
            .getBestRefreshRate(mFeatures.contentRequirements, {.touch = touchActive, .idle = idle},
                                consideredSignals)
            .getConfigId();
}

std::optional<HwcConfigIndexType> Scheduler::getPreferredConfigId() {
    std::lock_guard<std::mutex> lock(mFeatureStateLock);
    // Make sure that the default config ID is first updated, before returned.
    if (mFeatures.configId.has_value()) {
        mFeatures.configId = calculateRefreshRateConfigIndexType();
    }
    return mFeatures.configId;
}

void Scheduler::onNewVsyncPeriodChangeTimeline(const hal::VsyncPeriodChangeTimeline& timeline) {
    if (timeline.refreshRequired) {
        mSchedulerCallback.repaintEverythingForHWC();
    }

    std::lock_guard<std::mutex> lock(mVsyncTimelineLock);
    mLastVsyncPeriodChangeTimeline = std::make_optional(timeline);

    const auto maxAppliedTime = systemTime() + MAX_VSYNC_APPLIED_TIME.count();
    if (timeline.newVsyncAppliedTimeNanos > maxAppliedTime) {
        mLastVsyncPeriodChangeTimeline->newVsyncAppliedTimeNanos = maxAppliedTime;
    }
}

void Scheduler::onDisplayRefreshed(nsecs_t timestamp) {
    bool callRepaint = false;
    {
        std::lock_guard<std::mutex> lock(mVsyncTimelineLock);
        if (mLastVsyncPeriodChangeTimeline && mLastVsyncPeriodChangeTimeline->refreshRequired) {
            if (mLastVsyncPeriodChangeTimeline->refreshTimeNanos < timestamp) {
                mLastVsyncPeriodChangeTimeline->refreshRequired = false;
            } else {
                // We need to send another refresh as refreshTimeNanos is still in the future
                callRepaint = true;
            }
        }
    }

    if (callRepaint) {
        mSchedulerCallback.repaintEverythingForHWC();
    }
}

void Scheduler::onPrimaryDisplayAreaChanged(uint32_t displayArea) {
    if (mLayerHistory) {
        mLayerHistory->setDisplayArea(displayArea);
    }
}

} // namespace android
