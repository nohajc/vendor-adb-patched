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

#include <android/os/IInputConstants.h>
#include <binder/Binder.h>
#include <gui/constants.h>
#include "../dispatcher/InputDispatcher.h"

using android::base::Result;
using android::gui::WindowInfo;
using android::gui::WindowInfoHandle;
using android::os::IInputConstants;
using android::os::InputEventInjectionResult;
using android::os::InputEventInjectionSync;

namespace android::inputdispatcher {

// An arbitrary device id.
constexpr int32_t DEVICE_ID = 1;

// The default pid and uid for windows created by the test.
constexpr int32_t WINDOW_PID = 999;
constexpr int32_t WINDOW_UID = 1001;

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
    void notifyConfigurationChanged(nsecs_t) override {}

    void notifyNoFocusedWindowAnr(
            const std::shared_ptr<InputApplicationHandle>& applicationHandle) override {
        ALOGE("There is no focused window for %s", applicationHandle->getName().c_str());
    }

    void notifyWindowUnresponsive(const sp<IBinder>& connectionToken, std::optional<int32_t> pid,
                                  const std::string& reason) override {
        ALOGE("Window is not responding: %s", reason.c_str());
    }

    void notifyWindowResponsive(const sp<IBinder>& connectionToken,
                                std::optional<int32_t> pid) override {}

    void notifyInputChannelBroken(const sp<IBinder>&) override {}

    void notifyFocusChanged(const sp<IBinder>&, const sp<IBinder>&) override {}

    void notifySensorEvent(int32_t deviceId, InputDeviceSensorType sensorType,
                           InputDeviceSensorAccuracy accuracy, nsecs_t timestamp,
                           const std::vector<float>& values) override {}

    void notifySensorAccuracy(int32_t deviceId, InputDeviceSensorType sensorType,
                              InputDeviceSensorAccuracy accuracy) override {}

    void notifyVibratorState(int32_t deviceId, bool isOn) override {}

    void notifyUntrustedTouch(const std::string& obscuringPackage) override {}

    void getDispatcherConfiguration(InputDispatcherConfiguration* outConfig) override {
        *outConfig = mConfig;
    }

    bool filterInputEvent(const InputEvent* inputEvent, uint32_t policyFlags) override {
        return true;
    }

    void interceptKeyBeforeQueueing(const KeyEvent*, uint32_t&) override {}

    void interceptMotionBeforeQueueing(int32_t, nsecs_t, uint32_t&) override {}

    nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent*, uint32_t) override {
        return 0;
    }

    bool dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent*, uint32_t, KeyEvent*) override {
        return false;
    }

    void notifySwitch(nsecs_t, uint32_t, uint32_t, uint32_t) override {}

    void pokeUserActivity(nsecs_t, int32_t, int32_t) override {}

    void onPointerDownOutsideFocus(const sp<IBinder>& newToken) override {}

    void setPointerCapture(const PointerCaptureRequest&) override {}

    void notifyDropWindow(const sp<IBinder>&, float x, float y) override {}

    InputDispatcherConfiguration mConfig;
};

class FakeApplicationHandle : public InputApplicationHandle {
public:
    FakeApplicationHandle() {}
    virtual ~FakeApplicationHandle() {}

    virtual bool updateInfo() {
        mInfo.dispatchingTimeoutMillis =
                std::chrono::duration_cast<std::chrono::milliseconds>(DISPATCHING_TIMEOUT).count();
        return true;
    }
};

class FakeInputReceiver {
public:
    void consumeEvent() {
        uint32_t consumeSeq = 0;
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
    explicit FakeInputReceiver(InputDispatcher& dispatcher, const std::string name) {
        Result<std::unique_ptr<InputChannel>> channelResult = dispatcher.createInputChannel(name);
        LOG_ALWAYS_FATAL_IF(!channelResult.ok());
        mClientChannel = std::move(*channelResult);
        mConsumer = std::make_unique<InputConsumer>(mClientChannel);
    }

    virtual ~FakeInputReceiver() {}

    std::shared_ptr<InputChannel> mClientChannel;
    std::unique_ptr<InputConsumer> mConsumer;
    PreallocatedInputEventFactory mEventFactory;
};

class FakeWindowHandle : public WindowInfoHandle, public FakeInputReceiver {
public:
    static const int32_t WIDTH = 200;
    static const int32_t HEIGHT = 200;

    FakeWindowHandle(const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle,
                     InputDispatcher& dispatcher, const std::string name)
          : FakeInputReceiver(dispatcher, name), mFrame(Rect(0, 0, WIDTH, HEIGHT)) {
        inputApplicationHandle->updateInfo();
        updateInfo();
        mInfo.applicationInfo = *inputApplicationHandle->getInfo();
    }

    void updateInfo() {
        mInfo.token = mClientChannel->getConnectionToken();
        mInfo.name = "FakeWindowHandle";
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT;
        mInfo.frameLeft = mFrame.left;
        mInfo.frameTop = mFrame.top;
        mInfo.frameRight = mFrame.right;
        mInfo.frameBottom = mFrame.bottom;
        mInfo.globalScaleFactor = 1.0;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(mFrame);
        mInfo.ownerPid = WINDOW_PID;
        mInfo.ownerUid = WINDOW_UID;
        mInfo.displayId = ADISPLAY_ID_DEFAULT;
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

    ui::Transform identityTransform;
    MotionEvent event;
    event.initialize(IInputConstants::INVALID_INPUT_EVENT_ID, DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN,
                     ADISPLAY_ID_DEFAULT, INVALID_HMAC, AMOTION_EVENT_ACTION_DOWN,
                     /* actionButton */ 0, /* flags */ 0,
                     /* edgeFlags */ 0, AMETA_NONE, /* buttonState */ 0, MotionClassification::NONE,
                     identityTransform, /* xPrecision */ 0,
                     /* yPrecision */ 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, currentTime,
                     currentTime,
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
    NotifyMotionArgs args(IInputConstants::INVALID_INPUT_EVENT_ID, currentTime, currentTime,
                          DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, ADISPLAY_ID_DEFAULT,
                          POLICY_FLAG_PASS_TO_USER, AMOTION_EVENT_ACTION_DOWN,
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
    InputDispatcher dispatcher(fakePolicy);
    dispatcher.setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
    dispatcher.start();

    // Create a window that will receive motion events
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = new FakeWindowHandle(application, dispatcher, "Fake Window");

    dispatcher.setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    NotifyMotionArgs motionArgs = generateMotionArgs();

    for (auto _ : state) {
        // Send ACTION_DOWN
        motionArgs.action = AMOTION_EVENT_ACTION_DOWN;
        motionArgs.downTime = now();
        motionArgs.eventTime = motionArgs.downTime;
        dispatcher.notifyMotion(&motionArgs);

        // Send ACTION_UP
        motionArgs.action = AMOTION_EVENT_ACTION_UP;
        motionArgs.eventTime = now();
        dispatcher.notifyMotion(&motionArgs);

        window->consumeEvent();
        window->consumeEvent();
    }

    dispatcher.stop();
}

static void benchmarkInjectMotion(benchmark::State& state) {
    // Create dispatcher
    sp<FakeInputDispatcherPolicy> fakePolicy = new FakeInputDispatcherPolicy();
    InputDispatcher dispatcher(fakePolicy);
    dispatcher.setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
    dispatcher.start();

    // Create a window that will receive motion events
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = new FakeWindowHandle(application, dispatcher, "Fake Window");

    dispatcher.setInputWindows({{ADISPLAY_ID_DEFAULT, {window}}});

    for (auto _ : state) {
        MotionEvent event = generateMotionEvent();
        // Send ACTION_DOWN
        dispatcher.injectInputEvent(&event, {} /*targetUid*/, InputEventInjectionSync::NONE,
                                    INJECT_EVENT_TIMEOUT,
                                    POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);

        // Send ACTION_UP
        event.setAction(AMOTION_EVENT_ACTION_UP);
        dispatcher.injectInputEvent(&event, {} /*targetUid*/, InputEventInjectionSync::NONE,
                                    INJECT_EVENT_TIMEOUT,
                                    POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);

        window->consumeEvent();
        window->consumeEvent();
    }

    dispatcher.stop();
}

static void benchmarkOnWindowInfosChanged(benchmark::State& state) {
    // Create dispatcher
    sp<FakeInputDispatcherPolicy> fakePolicy = new FakeInputDispatcherPolicy();
    InputDispatcher dispatcher(fakePolicy);
    dispatcher.setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
    dispatcher.start();

    // Create a window
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window = new FakeWindowHandle(application, dispatcher, "Fake Window");

    std::vector<gui::WindowInfo> windowInfos{*window->getInfo()};
    gui::DisplayInfo info;
    info.displayId = window->getInfo()->displayId;
    std::vector<gui::DisplayInfo> displayInfos{info};

    for (auto _ : state) {
        dispatcher.onWindowInfosChanged(windowInfos, displayInfos);
        dispatcher.onWindowInfosChanged({} /*windowInfos*/, {} /*displayInfos*/);
    }
    dispatcher.stop();
}

BENCHMARK(benchmarkNotifyMotion);
BENCHMARK(benchmarkInjectMotion);
BENCHMARK(benchmarkOnWindowInfosChanged);

} // namespace android::inputdispatcher

BENCHMARK_MAIN();
