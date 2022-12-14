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

#ifndef _UI_INPUT_CLASSIFIER_H
#define _UI_INPUT_CLASSIFIER_H

#include <android-base/thread_annotations.h>
#include <future>
#include <thread>
#include <unordered_map>

#include <aidl/android/hardware/input/processor/IInputProcessor.h>
#include "BlockingQueue.h"
#include "InputListener.h"
namespace android {

enum class ClassifierEventType : uint8_t {
    MOTION = 0,
    DEVICE_RESET = 1,
    HAL_RESET = 2,
    EXIT = 3,
};

struct ClassifierEvent {
    ClassifierEventType type;
    std::unique_ptr<NotifyArgs> args;

    ClassifierEvent(ClassifierEventType type, std::unique_ptr<NotifyArgs> args);
    ClassifierEvent(std::unique_ptr<NotifyMotionArgs> args);
    ClassifierEvent(std::unique_ptr<NotifyDeviceResetArgs> args);
    ClassifierEvent(ClassifierEvent&& other);
    ClassifierEvent& operator=(ClassifierEvent&& other);

    // Convenience function to create a HAL_RESET event
    static ClassifierEvent createHalResetEvent();
    // Convenience function to create an EXIT event
    static ClassifierEvent createExitEvent();

    std::optional<int32_t> getDeviceId() const;
};

// --- Interfaces ---

/**
 * Interface for adding a MotionClassification to NotifyMotionArgs.
 *
 * To implement, override the classify function.
 */
class MotionClassifierInterface {
public:
    MotionClassifierInterface() { }
    virtual ~MotionClassifierInterface() { }
    /**
     * Based on the motion event described by NotifyMotionArgs,
     * provide a MotionClassification for the current gesture.
     */
    virtual MotionClassification classify(const NotifyMotionArgs& args) = 0;
    /**
     * Reset all internal HAL state.
     */
    virtual void reset() = 0;
    /**
     * Reset HAL state for a specific device.
     */
    virtual void reset(const NotifyDeviceResetArgs& args) = 0;

    /**
     * Dump the state of the motion classifier
     */
    virtual void dump(std::string& dump) = 0;
};

/**
 * Base interface for an InputListener stage.
 * Provides classification to events.
 */
class InputClassifierInterface : public InputListenerInterface {
public:
    virtual void setMotionClassifierEnabled(bool enabled) = 0;
    /**
     * Dump the state of the input classifier.
     * This method may be called on any thread (usually by the input manager).
     */
    virtual void dump(std::string& dump) = 0;

    /* Called by the heatbeat to ensures that the classifier has not deadlocked. */
    virtual void monitor() = 0;

    InputClassifierInterface() { }
    virtual ~InputClassifierInterface() { }
};

// --- Implementations ---

class ScopedDeathRecipient {
public:
    explicit ScopedDeathRecipient(AIBinder_DeathRecipient_onBinderDied onBinderDied, void* cookie);
    ScopedDeathRecipient(const ScopedDeathRecipient&) = delete;
    ScopedDeathRecipient& operator=(ScopedDeathRecipient const&) = delete;
    void linkToDeath(AIBinder* binder);
    ~ScopedDeathRecipient();

private:
    AIBinder_DeathRecipient* mRecipient;
    void* mCookie;
};

/**
 * Implementation of MotionClassifierInterface that calls the InputClassifier HAL
 * in order to determine the classification for the current gesture.
 *
 * The InputClassifier HAL may keep track of the entire gesture in order to determine
 * the classification, and may be hardware-specific. It may use the data in
 * NotifyMotionArgs::videoFrames field to drive the classification decisions.
 * The HAL is called from a separate thread.
 */
class MotionClassifier final : public MotionClassifierInterface {
public:
    /*
     * Create an instance of MotionClassifier.
     * The death recipient, if provided, will be subscribed to the HAL death.
     * The death recipient could be used to destroy MotionClassifier.
     *
     * This function should be called asynchronously, because getService takes a long time.
     */
    static std::unique_ptr<MotionClassifierInterface> create(
            std::shared_ptr<aidl::android::hardware::input::processor::IInputProcessor> service);

    ~MotionClassifier();

    /**
     * Classifies events asynchronously; that is, it doesn't block events on a classification,
     * but instead sends them over to the classifier HAL. After a classification of a specific
     * event is determined, MotionClassifier then marks the next event in the stream with this
     * classification.
     *
     * Therefore, it is acceptable to have the classifications be delayed by 1-2 events
     * in a particular gesture.
     */
    virtual MotionClassification classify(const NotifyMotionArgs& args) override;
    virtual void reset() override;
    virtual void reset(const NotifyDeviceResetArgs& args) override;

    virtual void dump(std::string& dump) override;

private:
    friend class MotionClassifierTest; // to create MotionClassifier with a test HAL implementation
    explicit MotionClassifier(
            std::shared_ptr<aidl::android::hardware::input::processor::IInputProcessor> service);

    // The events that need to be sent to the HAL.
    BlockingQueue<ClassifierEvent> mEvents;
    /**
     * Add an event to the queue mEvents.
     */
    void enqueueEvent(ClassifierEvent&& event);
    /**
     * Thread that will communicate with InputClassifier HAL.
     * This should be the only thread that communicates with InputClassifier HAL,
     * because this thread is allowed to block on the HAL calls.
     */
    std::thread mHalThread;
    /**
     * Process events and call the InputClassifier HAL
     */
    void processEvents();
    /**
     * Access to the InputProcessor HAL. May be null if init() hasn't completed yet.
     * When init() successfully completes, mService is guaranteed to remain non-null and to not
     * change its value until MotionClassifier is destroyed.
     * This variable is *not* guarded by mLock in the InputClassifier thread, because
     * that thread knows exactly when this variable is initialized.
     * When accessed in any other thread, mService is checked for nullness with a lock.
     */
    std::shared_ptr<aidl::android::hardware::input::processor::IInputProcessor> mService;
    std::mutex mLock;
    /**
     * Per-device input classifications. Should only be accessed using the
     * getClassification / setClassification methods.
     */
    std::unordered_map<int32_t /*deviceId*/, MotionClassification>
            mClassifications GUARDED_BY(mLock);
    /**
     * Set the current classification for a given device.
     */
    void setClassification(int32_t deviceId, MotionClassification classification);
    /**
     * Get the current classification for a given device.
     */
    MotionClassification getClassification(int32_t deviceId);
    void updateClassification(int32_t deviceId, nsecs_t eventTime,
            MotionClassification classification);
    /**
     * Clear all current classifications
     */
    void clearClassifications();
    /**
     * Per-device times when the last ACTION_DOWN was received.
     * Used to reject late classifications that do not belong to the current gesture.
     *
     * Accessed indirectly by both InputClassifier thread and the thread that receives notifyMotion.
     */
    std::unordered_map<int32_t /*deviceId*/, nsecs_t /*downTime*/> mLastDownTimes GUARDED_BY(mLock);

    void updateLastDownTime(int32_t deviceId, nsecs_t downTime);

    void clearDeviceState(int32_t deviceId);

    /**
     * Exit the InputClassifier HAL thread.
     * Useful for tests to ensure proper cleanup.
     */
    void requestExit();
    /**
     * Return string status of mService
     */
    const char* getServiceStatus() REQUIRES(mLock);
};

/**
 * Implementation of the InputClassifierInterface.
 * Represents a separate stage of input processing. All of the input events go through this stage.
 * Acts as a passthrough for all input events except for motion events.
 * The events of motion type are sent to MotionClassifier.
 */
class InputClassifier : public InputClassifierInterface {
public:
    explicit InputClassifier(InputListenerInterface& listener);

    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) override;
    void notifyKey(const NotifyKeyArgs* args) override;
    void notifyMotion(const NotifyMotionArgs* args) override;
    void notifySwitch(const NotifySwitchArgs* args) override;
    void notifySensor(const NotifySensorArgs* args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs* args) override;
    void notifyDeviceReset(const NotifyDeviceResetArgs* args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs* args) override;

    void dump(std::string& dump) override;
    void monitor() override;

    ~InputClassifier();

    // Called from InputManager
    void setMotionClassifierEnabled(bool enabled) override;

private:
    // Protect access to mMotionClassifier, since it may become null via a hidl callback
    std::mutex mLock;
    // The next stage to pass input events to
    QueuedInputListener mQueuedListener;

    std::unique_ptr<MotionClassifierInterface> mMotionClassifier GUARDED_BY(mLock);
    std::future<void> mInitializeMotionClassifier GUARDED_BY(mLock);

    /**
     * Set the value of mMotionClassifier.
     * This is called from 2 different threads:
     * 1) mInitializeMotionClassifierThread, when we have constructed a MotionClassifier
     * 2) A binder thread of the HalDeathRecipient, which is created when HAL dies. This would cause
     *    mMotionClassifier to become nullptr.
     */
    void setMotionClassifierLocked(std::unique_ptr<MotionClassifierInterface> motionClassifier)
            REQUIRES(mLock);

    static void onBinderDied(void* cookie);

    std::unique_ptr<ScopedDeathRecipient> mHalDeathRecipient GUARDED_BY(mLock);
};

} // namespace android
#endif
