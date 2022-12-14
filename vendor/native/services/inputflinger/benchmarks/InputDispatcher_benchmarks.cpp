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

#include <benchmark/benchmark.h>

#include <binder/Binder.h>
#include "../dispatcher/InputDispatcher.h"

namespace android::inputdispatcher {

// An arbitrary device id.
static const int32_t DEVICE_ID = 1;

// An arbitrary injector pid / uid pair that has permission to inject events.
static const int32_t INJECTOR_PID = 999;
static const int32_t INJECTOR_UID = 1001;

static constexpr std::chrono::duration INJECT_EVENT_TIMEOUT = 5s;
static constexpr std::chrono::nanoseconds DISPATCHING_TIMEOUT = 100ms;

static nsecs_t now() {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

// --- FakeInputDispatcherPolicy ---

class FakeInputDispatcherPolicy : public InputDispatcherPolicyInterface {
public:
    FakeInputDispatcherPolicy() {}

protected:
    virtual ~FakeInputDispatcherPolicy() {}

private:
    virtual void notifyConfigurationChanged(nsecs_t) override {}

    virtual nsecs_t notifyAnr(const sp<InputApplicationHandle>&, const sp<IBinder>&,
                              const std::string& name) override {
        ALOGE("The window is not responding : %s", name.c_str());
        return 0;
    }

    virtual void notifyInputChannelBroken(const sp<IBinder>&) override {}

    virtual void notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) override {}

    virtual void getDispatcherConfiguration(InputDispatcherConfiguration* outConfig) override {
        *outConfig = mConfig;
    }

    virtual bool filterInputEvent(const InputEvent* inputEvent, uint32_t policyFlags) override {
        return true;
    }

    virtual void interceptKeyBeforeQueueing(const KeyEvent*, uint32_t&) override {}

    virtual void interceptMotionBeforeQueueing(int32_t, nsecs_t, uint32_t&) override {}

    virtual nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent*,
                                                  uint32_t) override {
        return 0;
    }

    virtual bool dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent*, uint32_t,
                                      KeyEvent*) override {
        return false;
    }

    virtual void notifySwitch(nsecs_t, uint32_t, uint32_t, uint32_t) override {}

    virtual void pokeUserActivity(nsecs_t, int32_t) override {}

    virtual bool checkInjectEventsPermissionNonReentrant(int32_t, int32_t) override {
        return false;
    }

    virtual void onPointerDownOutsideFocus(const sp<IBinder>& newToken) override {}

    InputDispatcherConfiguration mConfig;
};

class FakeApplicationHandle : public InputApplicationHandle {
public:
    FakeApplicationHandle() {}
    virtual ~FakeApplicationHandle() {}

    virtual bool updateInfo() {
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT.count();
        return true;
    }
};

class FakeInputReceiver {
public:
    void consumeEvent() {
        uint32_t consumeSeq;
        InputEvent* event;

        std::chrono::time_point start = std::chrono::steady_clock::now();
        status_t result = WOULD_BLOCK;
        while (result == WOULD_BLOCK) {
            std::chrono::duration elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > 10ms) {
                ALOGE("Waited too long for consumer to produce an event, giving up");
                break;
            }
            result = mConsumer->consume(&mEventFactory, true /*consumeBatches*/, -1, &consumeSeq,
                                        &event);
        }
        if (result != OK) {
            ALOGE("Received result = %d from consume()", result);
        }
        result = mConsumer->sendFinishedSignal(consumeSeq, true);
        if (result != OK) {
            ALOGE("Received result = %d from sendFinishedSignal", result);
        }
    }

protected:
    explicit FakeInputReceiver(const sp<InputDispatcher>& dispatcher, const std::string name)
          : mDispatcher(dispatcher) {
        InputChannel::openInputChannelPair(name, mServerChannel, mClientChannel);
        mConsumer = std::make_unique<InputConsumer>(mClientChannel);
    }

    virtual ~FakeInputReceiver() {}

    sp<InputDispatcher> mDispatcher;
    sp<InputChannel> mServerChannel, mClientChannel;
    std::unique_ptr<InputConsumer> mConsumer;
    PreallocatedInputEventFactory mEventFactory;
};

class FakeWindowHandle : public InputWindowHandle, public FakeInputReceiver {
public:
    static const int32_t WIDTH = 200;
    static const int32_t HEIGHT = 200;

    FakeWindowHandle(const sp<InputApplicationHandle>& inputApplicationHandle,
                     const sp<InputDispatcher>& dispatcher, const std::string name)
          : FakeInputReceiver(dispatcher, name), mFrame(Rect(0, 0, WIDTH, HEIGHT)) {
        mDispatcher->registerInputChannel(mServerChannel);

        inputApplicationHandle->updateInfo();
        mInfo.applicationInfo = *inputApplicationHandle->getInfo();
    }

    virtual bool updateInfo() override {
        mInfo.token = mServerChannel->getConnectionToken();
        mInfo.name = "FakeWindowHandle";
        mInfo.layoutParamsFlags = 0;
        mInfo.layoutParamsType = InputWindowInfo::TYPE_APPLICATION;
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT.count();
        mInfo.frameLeft = mFrame.left;
        mInfo.frameTop = mFrame.top;
        mInfo.frameRight = mFrame.right;
        mInfo.frameBottom = mFrame.bottom;
        mInfo.globalScaleFactor = 1.0;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(mFrame);
        mInfo.visible = true;
        mInfo.canReceiveKeys = true;
        mInfo.hasFocus = true;
        mInfo.hasWallpaper = false;
        mInfo.paused = false;
        mInfo.ownerPid = INJECTOR_PID;
        mInfo.ownerUid = INJECTOR_UID;
        mInfo.inputFeatures = 0;
        mInfo.displayId = ADISPLAY_ID_DEFAULT;

        return true;
    }

protected:
    Rect mFrame;
};

static MotionEvent generateMotionEvent() {
    PointerProperties pointerProperties[1];
    PointerCoords pointerCoords[1];

    pointerProperties[0].clear();
    pointerProperties[0].id = 0;
    pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

    pointerCoords[0].clear();
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 100);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 100);

    const nsecs_t currentTime = now();

    MotionEvent event;
    event.initialize(InputEvent::nextId(), DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN,
                     ADISPLAY_ID_DEFAULT, INVALID_HMAC, AMOTION_EVENT_ACTION_DOWN,
                     /* actionButton */ 0, /* flags */ 0,
                     /* edgeFlags */ 0, AMETA_NONE, /* buttonState */ 0, MotionClassification::NONE,
                     1 /* xScale */, 1 /* yScale */,
                     /* xOffset */ 0, /* yOffset */ 0, /* xPrecision */ 0,
                     /* yPrecision */ 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, currentTime, currentTime,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    return event;
}

static NotifyMotionArgs generateMotionArgs() {
    PointerProperties pointerProperties[1];
    PointerCoords pointerCoords[1];

    pointerProperties[0].clear();
    pointerProperties[0].id = 0;
    pointerProperties[0].toolType = AMOTION_EVENT_TOOL_TYPE_FINGER;

    pointerCoords[0].clear();
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 100);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 100);

    const nsecs_t currentTime = now();
    // Define a valid motion event.
    NotifyMotionArgs args(/* id */ 0, currentTime, DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN,
                          ADISPLAY_ID_DEFAULT, POLICY_FLAG_PASS_TO_USER, AMOTION_EVENT_ACTION_DOWN,
                          /* actionButton */ 0, /* flags */ 0, AMETA_NONE, /* buttonState */ 0,
                          MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                          pointerProperties, pointerCoords,
                          /* xPrecision */ 0, /* yPrecision */ 0,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION, currentTime, /* videoFrames */ {});

    return args;
}

static void benchmarkNotifyMotion(benchmark::State& state) {
    // Create dispatcher
    sp<FakeInputDispatcherPolicy> fakePolicy = new FakeInputDispatcherPolicy();
    sp<InputDispatcher> dispatcher = new InputDispatcher(fakePolicy);
    dispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
    dispatcher->start();

    // Create a window that will receive motion events
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window = new FakeWindowHandle(application, dispatcher, "Fake Window");

    dispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    NotifyMotionArgs motionArgs = generateMotionArgs();

    for (auto _ : state) {
        // Send ACTION_DOWN
        motionArgs.action = AMOTION_EVENT_ACTION_DOWN;
        motionArgs.id = 0;
        motionArgs.downTime = now();
        motionArgs.eventTime = motionArgs.downTime;
        dispatcher->notifyMotion(&motionArgs);

        // Send ACTION_UP
        motionArgs.action = AMOTION_EVENT_ACTION_UP;
        motionArgs.id = 1;
        motionArgs.eventTime = now();
        dispatcher->notifyMotion(&motionArgs);

        window->consumeEvent();
        window->consumeEvent();
    }

    dispatcher->stop();
}

static void benchmarkInjectMotion(benchmark::State& state) {
    // Create dispatcher
    sp<FakeInputDispatcherPolicy> fakePolicy = new FakeInputDispatcherPolicy();
    sp<InputDispatcher> dispatcher = new InputDispatcher(fakePolicy);
    dispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
    dispatcher->start();

    // Create a window that will receive motion events
    sp<FakeApplicationHandle> application = new FakeApplicationHandle();
    sp<FakeWindowHandle> window = new FakeWindowHandle(application, dispatcher, "Fake Window");

    dispatcher->setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    for (auto _ : state) {
        MotionEvent event = generateMotionEvent();
        // Send ACTION_DOWN
        dispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                     INPUT_EVENT_INJECTION_SYNC_NONE, INJECT_EVENT_TIMEOUT,
                                     POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);

        // Send ACTION_UP
        event.setAction(AMOTION_EVENT_ACTION_UP);
        dispatcher->injectInputEvent(&event, INJECTOR_PID, INJECTOR_UID,
                                     INPUT_EVENT_INJECTION_SYNC_NONE, INJECT_EVENT_TIMEOUT,
                                     POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);

        window->consumeEvent();
        window->consumeEvent();
    }

    dispatcher->stop();
}

BENCHMARK(benchmarkNotifyMotion);
BENCHMARK(benchmarkInjectMotion);

} // namespace android::inputdispatcher

BENCHMARK_MAIN();
