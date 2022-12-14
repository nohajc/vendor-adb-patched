/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _UI_INPUT_MANAGER_H
#define _UI_INPUT_MANAGER_H

/**
 * Native input manager.
 */

#include "InputClassifier.h"
#include "InputReaderBase.h"
#include "include/UnwantedInteractionBlockerInterface.h"

#include <InputDispatcherInterface.h>
#include <InputDispatcherPolicyInterface.h>
#include <input/Input.h>
#include <input/InputTransport.h>

#include <android/os/BnInputFlinger.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

using android::os::BnInputFlinger;

namespace android {
class InputChannel;
class InputDispatcherThread;

/*
 * The input manager is the core of the system event processing.
 *
 * The input manager has three components.
 *
 * 1. The InputReader class starts a thread that reads and preprocesses raw input events, applies
 *    policy, and posts messages to a queue managed by the UnwantedInteractionBlocker.
 * 2. The UnwantedInteractionBlocker is responsible for removing unwanted interactions. For example,
 *    this could be a palm on the screen. This stage would alter the event stream to remove either
 *    partially (some of the pointers) or fully (all touches) the unwanted interaction. The events
 *    are processed on the InputReader thread, without any additional queue. The events are then
 *    posted to the queue managed by the InputClassifier.
 * 3. The InputClassifier class starts a thread to communicate with the device-specific
 *    classifiers. It then waits on the queue of events from UnwantedInteractionBlocker, applies
 *    a classification to them, and queues them for the InputDispatcher.
 * 4. The InputDispatcher class starts a thread that waits for new events on the
 *    previous queue and asynchronously dispatches them to applications.
 *
 * By design, none of these classes share any internal state.  Moreover, all communication is
 * done one way from the InputReader to the InputDispatcher and never the reverse.  All
 * classes may interact with the InputDispatchPolicy, however.
 *
 * The InputManager class never makes any calls into Java itself.  Instead, the
 * InputDispatchPolicy is responsible for performing all external interactions with the
 * system, including calling DVM services.
 */
class InputManagerInterface : public virtual RefBase {
protected:
    InputManagerInterface() { }
    virtual ~InputManagerInterface() { }

public:
    /* Starts the input threads. */
    virtual status_t start() = 0;

    /* Stops the input threads and waits for them to exit. */
    virtual status_t stop() = 0;

    /* Gets the input reader. */
    virtual InputReaderInterface& getReader() = 0;

    /* Gets the unwanted interaction blocker. */
    virtual UnwantedInteractionBlockerInterface& getUnwantedInteractionBlocker() = 0;

    /* Gets the input classifier */
    virtual InputClassifierInterface& getClassifier() = 0;

    /* Gets the input dispatcher. */
    virtual InputDispatcherInterface& getDispatcher() = 0;

    /* Check that the input stages have not deadlocked. */
    virtual void monitor() = 0;
};

class InputManager : public InputManagerInterface, public BnInputFlinger {
protected:
    ~InputManager() override;

public:
    InputManager(
            const sp<InputReaderPolicyInterface>& readerPolicy,
            const sp<InputDispatcherPolicyInterface>& dispatcherPolicy);

    status_t start() override;
    status_t stop() override;

    InputReaderInterface& getReader() override;
    UnwantedInteractionBlockerInterface& getUnwantedInteractionBlocker() override;
    InputClassifierInterface& getClassifier() override;
    InputDispatcherInterface& getDispatcher() override;
    void monitor() override;

    status_t dump(int fd, const Vector<String16>& args) override;
    binder::Status createInputChannel(const std::string& name, InputChannel* outChannel) override;
    binder::Status removeInputChannel(const sp<IBinder>& connectionToken) override;
    binder::Status setFocusedWindow(const gui::FocusRequest&) override;

private:
    std::unique_ptr<InputReaderInterface> mReader;

    std::unique_ptr<UnwantedInteractionBlockerInterface> mBlocker;

    std::unique_ptr<InputClassifierInterface> mClassifier;

    std::unique_ptr<InputDispatcherInterface> mDispatcher;
};

} // namespace android

#endif // _UI_INPUT_MANAGER_H
