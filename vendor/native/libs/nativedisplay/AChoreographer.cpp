/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "Choreographer"
//#define LOG_NDEBUG 0

#include <android-base/thread_annotations.h>
#include <gui/DisplayEventDispatcher.h>
#include <gui/ISurfaceComposer.h>
#include <gui/SurfaceComposerClient.h>
#include <jni.h>
#include <private/android/choreographer.h>
#include <utils/Looper.h>
#include <utils/Timers.h>

#include <cinttypes>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>

namespace {
struct {
    // Global JVM that is provided by zygote
    JavaVM* jvm = nullptr;
    struct {
        jclass clazz;
        jmethodID getInstance;
        jmethodID registerNativeChoreographerForRefreshRateCallbacks;
        jmethodID unregisterNativeChoreographerForRefreshRateCallbacks;
    } displayManagerGlobal;
} gJni;

// Gets the JNIEnv* for this thread, and performs one-off initialization if we
// have never retrieved a JNIEnv* pointer before.
JNIEnv* getJniEnv() {
    if (gJni.jvm == nullptr) {
        ALOGW("AChoreographer: No JVM provided!");
        return nullptr;
    }

    JNIEnv* env = nullptr;
    if (gJni.jvm->GetEnv((void**)&env, JNI_VERSION_1_4) != JNI_OK) {
        ALOGD("Attaching thread to JVM for AChoreographer");
        JavaVMAttachArgs args = {JNI_VERSION_1_4, "AChoreographer_env", NULL};
        jint attachResult = gJni.jvm->AttachCurrentThreadAsDaemon(&env, (void*)&args);
        if (attachResult != JNI_OK) {
            ALOGE("Unable to attach thread. Error: %d", attachResult);
            return nullptr;
        }
    }
    if (env == nullptr) {
        ALOGW("AChoreographer: No JNI env available!");
    }
    return env;
}

inline const char* toString(bool value) {
    return value ? "true" : "false";
}
} // namespace

namespace android {

struct FrameCallback {
    AChoreographer_frameCallback callback;
    AChoreographer_frameCallback64 callback64;
    void* data;
    nsecs_t dueTime;

    inline bool operator<(const FrameCallback& rhs) const {
        // Note that this is intentionally flipped because we want callbacks due sooner to be at
        // the head of the queue
        return dueTime > rhs.dueTime;
    }
};

struct RefreshRateCallback {
    AChoreographer_refreshRateCallback callback;
    void* data;
    bool firstCallbackFired = false;
};

class Choreographer;

struct {
    std::mutex lock;
    std::vector<Choreographer*> ptrs GUARDED_BY(lock);
    bool registeredToDisplayManager GUARDED_BY(lock) = false;

    std::atomic<nsecs_t> mLastKnownVsync = -1;
} gChoreographers;

class Choreographer : public DisplayEventDispatcher, public MessageHandler {
public:
    explicit Choreographer(const sp<Looper>& looper) EXCLUDES(gChoreographers.lock);
    void postFrameCallbackDelayed(AChoreographer_frameCallback cb,
                                  AChoreographer_frameCallback64 cb64, void* data, nsecs_t delay);
    void registerRefreshRateCallback(AChoreographer_refreshRateCallback cb, void* data)
            EXCLUDES(gChoreographers.lock);
    void unregisterRefreshRateCallback(AChoreographer_refreshRateCallback cb, void* data);
    // Drains the queue of pending vsync periods and dispatches refresh rate
    // updates to callbacks.
    // The assumption is that this method is only called on a single
    // processing thread, either by looper or by AChoreographer_handleEvents
    void handleRefreshRateUpdates();
    void scheduleLatestConfigRequest();

    enum {
        MSG_SCHEDULE_CALLBACKS = 0,
        MSG_SCHEDULE_VSYNC = 1,
        MSG_HANDLE_REFRESH_RATE_UPDATES = 2,
    };
    virtual void handleMessage(const Message& message) override;

    static Choreographer* getForThread();
    virtual ~Choreographer() override EXCLUDES(gChoreographers.lock);

private:
    Choreographer(const Choreographer&) = delete;

    void dispatchVsync(nsecs_t timestamp, PhysicalDisplayId displayId, uint32_t count) override;
    void dispatchHotplug(nsecs_t timestamp, PhysicalDisplayId displayId, bool connected) override;
    void dispatchConfigChanged(nsecs_t timestamp, PhysicalDisplayId displayId, int32_t configId,
                               nsecs_t vsyncPeriod) override;
    void dispatchNullEvent(nsecs_t, PhysicalDisplayId) override;

    void scheduleCallbacks();

    std::mutex mLock;
    // Protected by mLock
    std::priority_queue<FrameCallback> mFrameCallbacks;
    std::vector<RefreshRateCallback> mRefreshRateCallbacks;

    nsecs_t mLatestVsyncPeriod = -1;

    const sp<Looper> mLooper;
    const std::thread::id mThreadId;
};

static thread_local Choreographer* gChoreographer;
Choreographer* Choreographer::getForThread() {
    if (gChoreographer == nullptr) {
        sp<Looper> looper = Looper::getForThread();
        if (!looper.get()) {
            ALOGW("No looper prepared for thread");
            return nullptr;
        }
        gChoreographer = new Choreographer(looper);
        status_t result = gChoreographer->initialize();
        if (result != OK) {
            ALOGW("Failed to initialize");
            return nullptr;
        }
    }
    return gChoreographer;
}

Choreographer::Choreographer(const sp<Looper>& looper)
      : DisplayEventDispatcher(looper, ISurfaceComposer::VsyncSource::eVsyncSourceApp,
                               ISurfaceComposer::ConfigChanged::eConfigChangedSuppress),
        mLooper(looper),
        mThreadId(std::this_thread::get_id()) {
    std::lock_guard<std::mutex> _l(gChoreographers.lock);
    gChoreographers.ptrs.push_back(this);
}

Choreographer::~Choreographer() {
    std::lock_guard<std::mutex> _l(gChoreographers.lock);
    gChoreographers.ptrs.erase(std::remove_if(gChoreographers.ptrs.begin(),
                                              gChoreographers.ptrs.end(),
                                              [=](Choreographer* c) { return c == this; }),
                               gChoreographers.ptrs.end());
    // Only poke DisplayManagerGlobal to unregister if we previously registered
    // callbacks.
    if (gChoreographers.ptrs.empty() && gChoreographers.registeredToDisplayManager) {
        JNIEnv* env = getJniEnv();
        if (env == nullptr) {
            ALOGW("JNI environment is unavailable, skipping choreographer cleanup");
            return;
        }
        jobject dmg = env->CallStaticObjectMethod(gJni.displayManagerGlobal.clazz,
                                                  gJni.displayManagerGlobal.getInstance);
        if (dmg == nullptr) {
            ALOGW("DMS is not initialized yet, skipping choreographer cleanup");
        } else {
            env->CallVoidMethod(dmg,
                                gJni.displayManagerGlobal
                                        .unregisterNativeChoreographerForRefreshRateCallbacks);
            env->DeleteLocalRef(dmg);
        }
    }
}

void Choreographer::postFrameCallbackDelayed(
        AChoreographer_frameCallback cb, AChoreographer_frameCallback64 cb64, void* data, nsecs_t delay) {
    nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
    FrameCallback callback{cb, cb64, data, now + delay};
    {
        std::lock_guard<std::mutex> _l{mLock};
        mFrameCallbacks.push(callback);
    }
    if (callback.dueTime <= now) {
        if (std::this_thread::get_id() != mThreadId) {
            if (mLooper != nullptr) {
                Message m{MSG_SCHEDULE_VSYNC};
                mLooper->sendMessage(this, m);
            } else {
                scheduleVsync();
            }
        } else {
            scheduleVsync();
        }
    } else {
        if (mLooper != nullptr) {
            Message m{MSG_SCHEDULE_CALLBACKS};
            mLooper->sendMessageDelayed(delay, this, m);
        } else {
            scheduleCallbacks();
        }
    }
}

void Choreographer::registerRefreshRateCallback(AChoreographer_refreshRateCallback cb, void* data) {
    std::lock_guard<std::mutex> _l{mLock};
    for (const auto& callback : mRefreshRateCallbacks) {
        // Don't re-add callbacks.
        if (cb == callback.callback && data == callback.data) {
            return;
        }
    }
    mRefreshRateCallbacks.emplace_back(
            RefreshRateCallback{.callback = cb, .data = data, .firstCallbackFired = false});
    bool needsRegistration = false;
    {
        std::lock_guard<std::mutex> _l2(gChoreographers.lock);
        needsRegistration = !gChoreographers.registeredToDisplayManager;
    }
    if (needsRegistration) {
        JNIEnv* env = getJniEnv();
        if (env == nullptr) {
            ALOGW("JNI environment is unavailable, skipping registration");
            return;
        }
        jobject dmg = env->CallStaticObjectMethod(gJni.displayManagerGlobal.clazz,
                                                  gJni.displayManagerGlobal.getInstance);
        if (dmg == nullptr) {
            ALOGW("DMS is not initialized yet: skipping registration");
            return;
        } else {
            env->CallVoidMethod(dmg,
                                gJni.displayManagerGlobal
                                        .registerNativeChoreographerForRefreshRateCallbacks,
                                reinterpret_cast<int64_t>(this));
            env->DeleteLocalRef(dmg);
            {
                std::lock_guard<std::mutex> _l2(gChoreographers.lock);
                gChoreographers.registeredToDisplayManager = true;
            }
        }
    } else {
        scheduleLatestConfigRequest();
    }
}

void Choreographer::unregisterRefreshRateCallback(AChoreographer_refreshRateCallback cb,
                                                  void* data) {
    std::lock_guard<std::mutex> _l{mLock};
    mRefreshRateCallbacks.erase(std::remove_if(mRefreshRateCallbacks.begin(),
                                               mRefreshRateCallbacks.end(),
                                               [&](const RefreshRateCallback& callback) {
                                                   return cb == callback.callback &&
                                                           data == callback.data;
                                               }),
                                mRefreshRateCallbacks.end());
}

void Choreographer::scheduleLatestConfigRequest() {
    if (mLooper != nullptr) {
        Message m{MSG_HANDLE_REFRESH_RATE_UPDATES};
        mLooper->sendMessage(this, m);
    } else {
        // If the looper thread is detached from Choreographer, then refresh rate
        // changes will be handled in AChoreographer_handlePendingEvents, so we
        // need to wake up the looper thread by writing to the write-end of the
        // socket the looper is listening on.
        // Fortunately, these events are small so sending packets across the
        // socket should be atomic across processes.
        DisplayEventReceiver::Event event;
        event.header = DisplayEventReceiver::Event::Header{DisplayEventReceiver::DISPLAY_EVENT_NULL,
                                                           PhysicalDisplayId(0), systemTime()};
        injectEvent(event);
    }
}

void Choreographer::scheduleCallbacks() {
    const nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
    nsecs_t dueTime;
    {
        std::lock_guard<std::mutex> _l{mLock};
        // If there are no pending callbacks then don't schedule a vsync
        if (mFrameCallbacks.empty()) {
            return;
        }
        dueTime = mFrameCallbacks.top().dueTime;
    }

    if (dueTime <= now) {
        ALOGV("choreographer %p ~ scheduling vsync", this);
        scheduleVsync();
        return;
    }
}

void Choreographer::handleRefreshRateUpdates() {
    std::vector<RefreshRateCallback> callbacks{};
    const nsecs_t pendingPeriod = gChoreographers.mLastKnownVsync.load();
    const nsecs_t lastPeriod = mLatestVsyncPeriod;
    if (pendingPeriod > 0) {
        mLatestVsyncPeriod = pendingPeriod;
    }
    {
        std::lock_guard<std::mutex> _l{mLock};
        for (auto& cb : mRefreshRateCallbacks) {
            callbacks.push_back(cb);
            cb.firstCallbackFired = true;
        }
    }

    for (auto& cb : callbacks) {
        if (!cb.firstCallbackFired || (pendingPeriod > 0 && pendingPeriod != lastPeriod)) {
            cb.callback(pendingPeriod, cb.data);
        }
    }
}

// TODO(b/74619554): The PhysicalDisplayId is ignored because SF only emits VSYNC events for the
// internal display and DisplayEventReceiver::requestNextVsync only allows requesting VSYNC for
// the internal display implicitly.
void Choreographer::dispatchVsync(nsecs_t timestamp, PhysicalDisplayId, uint32_t) {
    std::vector<FrameCallback> callbacks{};
    {
        std::lock_guard<std::mutex> _l{mLock};
        nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
        while (!mFrameCallbacks.empty() && mFrameCallbacks.top().dueTime < now) {
            callbacks.push_back(mFrameCallbacks.top());
            mFrameCallbacks.pop();
        }
    }
    for (const auto& cb : callbacks) {
        if (cb.callback64 != nullptr) {
            cb.callback64(timestamp, cb.data);
        } else if (cb.callback != nullptr) {
            cb.callback(timestamp, cb.data);
        }
    }
}

void Choreographer::dispatchHotplug(nsecs_t, PhysicalDisplayId displayId, bool connected) {
    ALOGV("choreographer %p ~ received hotplug event (displayId=%"
            ANDROID_PHYSICAL_DISPLAY_ID_FORMAT ", connected=%s), ignoring.",
            this, displayId, toString(connected));
}

// TODO(b/74619554): The PhysicalDisplayId is ignored because currently
// Choreographer only supports dispatching VSYNC events for the internal
// display, so as such Choreographer does not support the notion of multiple
// displays. When multi-display choreographer is properly supported, then
// PhysicalDisplayId should no longer be ignored.
void Choreographer::dispatchConfigChanged(nsecs_t, PhysicalDisplayId displayId, int32_t configId,
                                          nsecs_t) {
    ALOGV("choreographer %p ~ received config change event "
          "(displayId=%" ANDROID_PHYSICAL_DISPLAY_ID_FORMAT ", configId=%d).",
          this, displayId, configId);
}

void Choreographer::dispatchNullEvent(nsecs_t, PhysicalDisplayId) {
    ALOGV("choreographer %p ~ received null event.", this);
    handleRefreshRateUpdates();
}

void Choreographer::handleMessage(const Message& message) {
    switch (message.what) {
    case MSG_SCHEDULE_CALLBACKS:
        scheduleCallbacks();
        break;
    case MSG_SCHEDULE_VSYNC:
        scheduleVsync();
        break;
    case MSG_HANDLE_REFRESH_RATE_UPDATES:
        handleRefreshRateUpdates();
        break;
    }
}

} // namespace android
using namespace android;

static inline Choreographer* AChoreographer_to_Choreographer(AChoreographer* choreographer) {
    return reinterpret_cast<Choreographer*>(choreographer);
}

// Glue for private C api
namespace android {
void AChoreographer_signalRefreshRateCallbacks(nsecs_t vsyncPeriod) EXCLUDES(gChoreographers.lock) {
    std::lock_guard<std::mutex> _l(gChoreographers.lock);
    gChoreographers.mLastKnownVsync.store(vsyncPeriod);
    for (auto c : gChoreographers.ptrs) {
        c->scheduleLatestConfigRequest();
    }
}

void AChoreographer_initJVM(JNIEnv* env) {
    env->GetJavaVM(&gJni.jvm);
    // Now we need to find the java classes.
    jclass dmgClass = env->FindClass("android/hardware/display/DisplayManagerGlobal");
    gJni.displayManagerGlobal.clazz = static_cast<jclass>(env->NewGlobalRef(dmgClass));
    gJni.displayManagerGlobal.getInstance =
            env->GetStaticMethodID(dmgClass, "getInstance",
                                   "()Landroid/hardware/display/DisplayManagerGlobal;");
    gJni.displayManagerGlobal.registerNativeChoreographerForRefreshRateCallbacks =
            env->GetMethodID(dmgClass, "registerNativeChoreographerForRefreshRateCallbacks", "()V");
    gJni.displayManagerGlobal.unregisterNativeChoreographerForRefreshRateCallbacks =
            env->GetMethodID(dmgClass, "unregisterNativeChoreographerForRefreshRateCallbacks",
                             "()V");
}

AChoreographer* AChoreographer_routeGetInstance() {
    return AChoreographer_getInstance();
}
void AChoreographer_routePostFrameCallback(AChoreographer* choreographer,
                                           AChoreographer_frameCallback callback, void* data) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return AChoreographer_postFrameCallback(choreographer, callback, data);
#pragma clang diagnostic pop
}
void AChoreographer_routePostFrameCallbackDelayed(AChoreographer* choreographer,
                                                  AChoreographer_frameCallback callback, void* data,
                                                  long delayMillis) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return AChoreographer_postFrameCallbackDelayed(choreographer, callback, data, delayMillis);
#pragma clang diagnostic pop
}
void AChoreographer_routePostFrameCallback64(AChoreographer* choreographer,
                                             AChoreographer_frameCallback64 callback, void* data) {
    return AChoreographer_postFrameCallback64(choreographer, callback, data);
}
void AChoreographer_routePostFrameCallbackDelayed64(AChoreographer* choreographer,
                                                    AChoreographer_frameCallback64 callback,
                                                    void* data, uint32_t delayMillis) {
    return AChoreographer_postFrameCallbackDelayed64(choreographer, callback, data, delayMillis);
}
void AChoreographer_routeRegisterRefreshRateCallback(AChoreographer* choreographer,
                                                     AChoreographer_refreshRateCallback callback,
                                                     void* data) {
    return AChoreographer_registerRefreshRateCallback(choreographer, callback, data);
}
void AChoreographer_routeUnregisterRefreshRateCallback(AChoreographer* choreographer,
                                                       AChoreographer_refreshRateCallback callback,
                                                       void* data) {
    return AChoreographer_unregisterRefreshRateCallback(choreographer, callback, data);
}

} // namespace android

/* Glue for the NDK interface */

static inline const Choreographer* AChoreographer_to_Choreographer(
        const AChoreographer* choreographer) {
    return reinterpret_cast<const Choreographer*>(choreographer);
}

static inline AChoreographer* Choreographer_to_AChoreographer(Choreographer* choreographer) {
    return reinterpret_cast<AChoreographer*>(choreographer);
}

AChoreographer* AChoreographer_getInstance() {
    return Choreographer_to_AChoreographer(Choreographer::getForThread());
}

void AChoreographer_postFrameCallback(AChoreographer* choreographer,
        AChoreographer_frameCallback callback, void* data) {
    AChoreographer_to_Choreographer(choreographer)->postFrameCallbackDelayed(
            callback, nullptr, data, 0);
}
void AChoreographer_postFrameCallbackDelayed(AChoreographer* choreographer,
        AChoreographer_frameCallback callback, void* data, long delayMillis) {
    AChoreographer_to_Choreographer(choreographer)->postFrameCallbackDelayed(
            callback, nullptr, data, ms2ns(delayMillis));
}
void AChoreographer_postFrameCallback64(AChoreographer* choreographer,
        AChoreographer_frameCallback64 callback, void* data) {
    AChoreographer_to_Choreographer(choreographer)->postFrameCallbackDelayed(
            nullptr, callback, data, 0);
}
void AChoreographer_postFrameCallbackDelayed64(AChoreographer* choreographer,
        AChoreographer_frameCallback64 callback, void* data, uint32_t delayMillis) {
    AChoreographer_to_Choreographer(choreographer)->postFrameCallbackDelayed(
            nullptr, callback, data, ms2ns(delayMillis));
}
void AChoreographer_registerRefreshRateCallback(AChoreographer* choreographer,
                                                AChoreographer_refreshRateCallback callback,
                                                void* data) {
    AChoreographer_to_Choreographer(choreographer)->registerRefreshRateCallback(callback, data);
}
void AChoreographer_unregisterRefreshRateCallback(AChoreographer* choreographer,
                                                  AChoreographer_refreshRateCallback callback,
                                                  void* data) {
    AChoreographer_to_Choreographer(choreographer)->unregisterRefreshRateCallback(callback, data);
}

AChoreographer* AChoreographer_create() {
    Choreographer* choreographer = new Choreographer(nullptr);
    status_t result = choreographer->initialize();
    if (result != OK) {
        ALOGW("Failed to initialize");
        return nullptr;
    }
    return Choreographer_to_AChoreographer(choreographer);
}

void AChoreographer_destroy(AChoreographer* choreographer) {
    if (choreographer == nullptr) {
        return;
    }

    delete AChoreographer_to_Choreographer(choreographer);
}

int AChoreographer_getFd(const AChoreographer* choreographer) {
    return AChoreographer_to_Choreographer(choreographer)->getFd();
}

void AChoreographer_handlePendingEvents(AChoreographer* choreographer, void* data) {
    // Pass dummy fd and events args to handleEvent, since the underlying
    // DisplayEventDispatcher doesn't need them outside of validating that a
    // Looper instance didn't break, but these args circumvent those checks.
    Choreographer* impl = AChoreographer_to_Choreographer(choreographer);
    impl->handleEvent(-1, Looper::EVENT_INPUT, data);
}
