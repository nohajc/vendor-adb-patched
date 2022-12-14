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

#define LOG_TAG "InputManager"

//#define LOG_NDEBUG 0

#include "InputManager.h"
#include "InputDispatcherFactory.h"
#include "InputReaderFactory.h"
#include "UnwantedInteractionBlocker.h"

#include <binder/IPCThreadState.h>

#include <log/log.h>
#include <unordered_map>

#include <private/android_filesystem_config.h>

namespace android {

using gui::FocusRequest;

static int32_t exceptionCodeFromStatusT(status_t status) {
    switch (status) {
        case OK:
            return binder::Status::EX_NONE;
        case INVALID_OPERATION:
            return binder::Status::EX_UNSUPPORTED_OPERATION;
        case BAD_VALUE:
        case BAD_TYPE:
        case NAME_NOT_FOUND:
            return binder::Status::EX_ILLEGAL_ARGUMENT;
        case NO_INIT:
            return binder::Status::EX_ILLEGAL_STATE;
        case PERMISSION_DENIED:
            return binder::Status::EX_SECURITY;
        default:
            return binder::Status::EX_TRANSACTION_FAILED;
    }
}

/**
 * The event flow is via the "InputListener" interface, as follows:
 * InputReader -> UnwantedInteractionBlocker -> InputClassifier -> InputDispatcher
 */
InputManager::InputManager(
        const sp<InputReaderPolicyInterface>& readerPolicy,
        const sp<InputDispatcherPolicyInterface>& dispatcherPolicy) {
    mDispatcher = createInputDispatcher(dispatcherPolicy);
    mClassifier = std::make_unique<InputClassifier>(*mDispatcher);
    mBlocker = std::make_unique<UnwantedInteractionBlocker>(*mClassifier);
    mReader = createInputReader(readerPolicy, *mBlocker);
}

InputManager::~InputManager() {
    stop();
}

status_t InputManager::start() {
    status_t result = mDispatcher->start();
    if (result) {
        ALOGE("Could not start InputDispatcher thread due to error %d.", result);
        return result;
    }

    result = mReader->start();
    if (result) {
        ALOGE("Could not start InputReader due to error %d.", result);

        mDispatcher->stop();
        return result;
    }

    return OK;
}

status_t InputManager::stop() {
    status_t status = OK;

    status_t result = mReader->stop();
    if (result) {
        ALOGW("Could not stop InputReader due to error %d.", result);
        status = result;
    }

    result = mDispatcher->stop();
    if (result) {
        ALOGW("Could not stop InputDispatcher thread due to error %d.", result);
        status = result;
    }

    return status;
}

InputReaderInterface& InputManager::getReader() {
    return *mReader;
}

UnwantedInteractionBlockerInterface& InputManager::getUnwantedInteractionBlocker() {
    return *mBlocker;
}

InputClassifierInterface& InputManager::getClassifier() {
    return *mClassifier;
}

InputDispatcherInterface& InputManager::getDispatcher() {
    return *mDispatcher;
}

void InputManager::monitor() {
    mReader->monitor();
    mBlocker->monitor();
    mClassifier->monitor();
    mDispatcher->monitor();
}

// Used by tests only.
binder::Status InputManager::createInputChannel(const std::string& name, InputChannel* outChannel) {
    IPCThreadState* ipc = IPCThreadState::self();
    const int uid = ipc->getCallingUid();
    if (uid != AID_SHELL && uid != AID_ROOT) {
        ALOGE("Invalid attempt to register input channel over IPC"
                "from non shell/root entity (PID: %d)", ipc->getCallingPid());
        return binder::Status::ok();
    }

    base::Result<std::unique_ptr<InputChannel>> channel = mDispatcher->createInputChannel(name);
    if (!channel.ok()) {
        return binder::Status::fromExceptionCode(exceptionCodeFromStatusT(channel.error().code()),
                                                 channel.error().message().c_str());
    }
    (*channel)->copyTo(*outChannel);
    return binder::Status::ok();
}

binder::Status InputManager::removeInputChannel(const sp<IBinder>& connectionToken) {
    mDispatcher->removeInputChannel(connectionToken);
    return binder::Status::ok();
}

status_t InputManager::dump(int fd, const Vector<String16>& args) {
    std::string dump;

    dump += " InputFlinger dump\n";

    ::write(fd, dump.c_str(), dump.size());
    return NO_ERROR;
}

binder::Status InputManager::setFocusedWindow(const FocusRequest& request) {
    mDispatcher->setFocusedWindow(request);
    return binder::Status::ok();
}

} // namespace android
