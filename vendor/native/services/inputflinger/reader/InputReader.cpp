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

#include "Macros.h"

#include "InputReader.h"

#include <android-base/stringprintf.h>
#include <errno.h>
#include <input/Keyboard.h>
#include <input/VirtualKeyMap.h>
#include <inttypes.h>
#include <limits.h>
#include <log/log.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <utils/Errors.h>
#include <utils/Thread.h>

#include "InputDevice.h"

using android::base::StringPrintf;

namespace android {

// --- InputReader ---

InputReader::InputReader(std::shared_ptr<EventHubInterface> eventHub,
                         const sp<InputReaderPolicyInterface>& policy,
                         const sp<InputListenerInterface>& listener)
      : mContext(this),
        mEventHub(eventHub),
        mPolicy(policy),
        mGlobalMetaState(0),
        mGeneration(1),
        mNextInputDeviceId(END_RESERVED_ID),
        mDisableVirtualKeysTimeout(LLONG_MIN),
        mNextTimeout(LLONG_MAX),
        mConfigurationChangesToRefresh(0) {
    mQueuedListener = new QueuedInputListener(listener);

    { // acquire lock
        AutoMutex _l(mLock);

        refreshConfigurationLocked(0);
        updateGlobalMetaStateLocked();
    } // release lock
}

InputReader::~InputReader() {}

status_t InputReader::start() {
    if (mThread) {
        return ALREADY_EXISTS;
    }
    mThread = std::make_unique<InputThread>(
            "InputReader", [this]() { loopOnce(); }, [this]() { mEventHub->wake(); });
    return OK;
}

status_t InputReader::stop() {
    if (mThread && mThread->isCallingThread()) {
        ALOGE("InputReader cannot be stopped from its own thread!");
        return INVALID_OPERATION;
    }
    mThread.reset();
    return OK;
}

void InputReader::loopOnce() {
    int32_t oldGeneration;
    int32_t timeoutMillis;
    bool inputDevicesChanged = false;
    std::vector<InputDeviceInfo> inputDevices;
    { // acquire lock
        AutoMutex _l(mLock);

        oldGeneration = mGeneration;
        timeoutMillis = -1;

        uint32_t changes = mConfigurationChangesToRefresh;
        if (changes) {
            mConfigurationChangesToRefresh = 0;
            timeoutMillis = 0;
            refreshConfigurationLocked(changes);
        } else if (mNextTimeout != LLONG_MAX) {
            nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
            timeoutMillis = toMillisecondTimeoutDelay(now, mNextTimeout);
        }
    } // release lock

    size_t count = mEventHub->getEvents(timeoutMillis, mEventBuffer, EVENT_BUFFER_SIZE);

    { // acquire lock
        AutoMutex _l(mLock);
        mReaderIsAliveCondition.broadcast();

        if (count) {
            processEventsLocked(mEventBuffer, count);
        }

        if (mNextTimeout != LLONG_MAX) {
            nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
            if (now >= mNextTimeout) {
#if DEBUG_RAW_EVENTS
                ALOGD("Timeout expired, latency=%0.3fms", (now - mNextTimeout) * 0.000001f);
#endif
                mNextTimeout = LLONG_MAX;
                timeoutExpiredLocked(now);
            }
        }

        if (oldGeneration != mGeneration) {
            inputDevicesChanged = true;
            getInputDevicesLocked(inputDevices);
        }
    } // release lock

    // Send out a message that the describes the changed input devices.
    if (inputDevicesChanged) {
        mPolicy->notifyInputDevicesChanged(inputDevices);
    }

    // Flush queued events out to the listener.
    // This must happen outside of the lock because the listener could potentially call
    // back into the InputReader's methods, such as getScanCodeState, or become blocked
    // on another thread similarly waiting to acquire the InputReader lock thereby
    // resulting in a deadlock.  This situation is actually quite plausible because the
    // listener is actually the input dispatcher, which calls into the window manager,
    // which occasionally calls into the input reader.
    mQueuedListener->flush();
}

void InputReader::processEventsLocked(const RawEvent* rawEvents, size_t count) {
    for (const RawEvent* rawEvent = rawEvents; count;) {
        int32_t type = rawEvent->type;
        size_t batchSize = 1;
        if (type < EventHubInterface::FIRST_SYNTHETIC_EVENT) {
            int32_t deviceId = rawEvent->deviceId;
            while (batchSize < count) {
                if (rawEvent[batchSize].type >= EventHubInterface::FIRST_SYNTHETIC_EVENT ||
                    rawEvent[batchSize].deviceId != deviceId) {
                    break;
                }
                batchSize += 1;
            }
#if DEBUG_RAW_EVENTS
            ALOGD("BatchSize: %zu Count: %zu", batchSize, count);
#endif
            processEventsForDeviceLocked(deviceId, rawEvent, batchSize);
        } else {
            switch (rawEvent->type) {
                case EventHubInterface::DEVICE_ADDED:
                    addDeviceLocked(rawEvent->when, rawEvent->deviceId);
                    break;
                case EventHubInterface::DEVICE_REMOVED:
                    removeDeviceLocked(rawEvent->when, rawEvent->deviceId);
                    break;
                case EventHubInterface::FINISHED_DEVICE_SCAN:
                    handleConfigurationChangedLocked(rawEvent->when);
                    break;
                default:
                    ALOG_ASSERT(false); // can't happen
                    break;
            }
        }
        count -= batchSize;
        rawEvent += batchSize;
    }
}

void InputReader::addDeviceLocked(nsecs_t when, int32_t eventHubId) {
    if (mDevices.find(eventHubId) != mDevices.end()) {
        ALOGW("Ignoring spurious device added event for eventHubId %d.", eventHubId);
        return;
    }

    InputDeviceIdentifier identifier = mEventHub->getDeviceIdentifier(eventHubId);
    std::shared_ptr<InputDevice> device = createDeviceLocked(eventHubId, identifier);
    device->configure(when, &mConfig, 0);
    device->reset(when);

    if (device->isIgnored()) {
        ALOGI("Device added: id=%d, eventHubId=%d, name='%s', descriptor='%s' "
              "(ignored non-input device)",
              device->getId(), eventHubId, identifier.name.c_str(), identifier.descriptor.c_str());
    } else {
        ALOGI("Device added: id=%d, eventHubId=%d, name='%s', descriptor='%s',sources=0x%08x",
              device->getId(), eventHubId, identifier.name.c_str(), identifier.descriptor.c_str(),
              device->getSources());
    }

    mDevices.emplace(eventHubId, device);
    // Add device to device to EventHub ids map.
    const auto mapIt = mDeviceToEventHubIdsMap.find(device);
    if (mapIt == mDeviceToEventHubIdsMap.end()) {
        std::vector<int32_t> ids = {eventHubId};
        mDeviceToEventHubIdsMap.emplace(device, ids);
    } else {
        mapIt->second.push_back(eventHubId);
    }
    bumpGenerationLocked();

    if (device->getClasses() & INPUT_DEVICE_CLASS_EXTERNAL_STYLUS) {
        notifyExternalStylusPresenceChanged();
    }
}

void InputReader::removeDeviceLocked(nsecs_t when, int32_t eventHubId) {
    auto deviceIt = mDevices.find(eventHubId);
    if (deviceIt == mDevices.end()) {
        ALOGW("Ignoring spurious device removed event for eventHubId %d.", eventHubId);
        return;
    }

    std::shared_ptr<InputDevice> device = std::move(deviceIt->second);
    mDevices.erase(deviceIt);
    // Erase device from device to EventHub ids map.
    auto mapIt = mDeviceToEventHubIdsMap.find(device);
    if (mapIt != mDeviceToEventHubIdsMap.end()) {
        std::vector<int32_t>& eventHubIds = mapIt->second;
        eventHubIds.erase(std::remove_if(eventHubIds.begin(), eventHubIds.end(),
                                         [eventHubId](int32_t eId) { return eId == eventHubId; }),
                          eventHubIds.end());
        if (eventHubIds.size() == 0) {
            mDeviceToEventHubIdsMap.erase(mapIt);
        }
    }
    bumpGenerationLocked();

    if (device->isIgnored()) {
        ALOGI("Device removed: id=%d, eventHubId=%d, name='%s', descriptor='%s' "
              "(ignored non-input device)",
              device->getId(), eventHubId, device->getName().c_str(),
              device->getDescriptor().c_str());
    } else {
        ALOGI("Device removed: id=%d, eventHubId=%d, name='%s', descriptor='%s', sources=0x%08x",
              device->getId(), eventHubId, device->getName().c_str(),
              device->getDescriptor().c_str(), device->getSources());
    }

    device->removeEventHubDevice(eventHubId);

    if (device->getClasses() & INPUT_DEVICE_CLASS_EXTERNAL_STYLUS) {
        notifyExternalStylusPresenceChanged();
    }

    if (device->hasEventHubDevices()) {
        device->configure(when, &mConfig, 0);
    }
    device->reset(when);
}

std::shared_ptr<InputDevice> InputReader::createDeviceLocked(
        int32_t eventHubId, const InputDeviceIdentifier& identifier) {
    auto deviceIt = std::find_if(mDevices.begin(), mDevices.end(), [identifier](auto& devicePair) {
        return devicePair.second->getDescriptor().size() && identifier.descriptor.size() &&
                devicePair.second->getDescriptor() == identifier.descriptor;
    });

    std::shared_ptr<InputDevice> device;
    if (deviceIt != mDevices.end()) {
        device = deviceIt->second;
    } else {
        int32_t deviceId = (eventHubId < END_RESERVED_ID) ? eventHubId : nextInputDeviceIdLocked();
        device = std::make_shared<InputDevice>(&mContext, deviceId, bumpGenerationLocked(),
                                               identifier);
    }
    device->addEventHubDevice(eventHubId);
    return device;
}

void InputReader::processEventsForDeviceLocked(int32_t eventHubId, const RawEvent* rawEvents,
                                               size_t count) {
    auto deviceIt = mDevices.find(eventHubId);
    if (deviceIt == mDevices.end()) {
        ALOGW("Discarding event for unknown eventHubId %d.", eventHubId);
        return;
    }

    std::shared_ptr<InputDevice>& device = deviceIt->second;
    if (device->isIgnored()) {
        // ALOGD("Discarding event for ignored deviceId %d.", deviceId);
        return;
    }

    device->process(rawEvents, count);
}

InputDevice* InputReader::findInputDevice(int32_t deviceId) {
    auto deviceIt =
            std::find_if(mDevices.begin(), mDevices.end(), [deviceId](const auto& devicePair) {
                return devicePair.second->getId() == deviceId;
            });
    if (deviceIt != mDevices.end()) {
        return deviceIt->second.get();
    }
    return nullptr;
}

void InputReader::timeoutExpiredLocked(nsecs_t when) {
    for (auto& devicePair : mDevices) {
        std::shared_ptr<InputDevice>& device = devicePair.second;
        if (!device->isIgnored()) {
            device->timeoutExpired(when);
        }
    }
}

int32_t InputReader::nextInputDeviceIdLocked() {
    return ++mNextInputDeviceId;
}

void InputReader::handleConfigurationChangedLocked(nsecs_t when) {
    // Reset global meta state because it depends on the list of all configured devices.
    updateGlobalMetaStateLocked();

    // Enqueue configuration changed.
    NotifyConfigurationChangedArgs args(mContext.getNextId(), when);
    mQueuedListener->notifyConfigurationChanged(&args);
}

void InputReader::refreshConfigurationLocked(uint32_t changes) {
    mPolicy->getReaderConfiguration(&mConfig);
    mEventHub->setExcludedDevices(mConfig.excludedDeviceNames);

    if (changes) {
        ALOGI("Reconfiguring input devices, changes=%s",
              InputReaderConfiguration::changesToString(changes).c_str());
        nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);

        if (changes & InputReaderConfiguration::CHANGE_DISPLAY_INFO) {
            updatePointerDisplayLocked();
        }

        if (changes & InputReaderConfiguration::CHANGE_MUST_REOPEN) {
            mEventHub->requestReopenDevices();
        } else {
            for (auto& devicePair : mDevices) {
                std::shared_ptr<InputDevice>& device = devicePair.second;
                device->configure(now, &mConfig, changes);
            }
        }
    }
}

void InputReader::updateGlobalMetaStateLocked() {
    mGlobalMetaState = 0;

    for (auto& devicePair : mDevices) {
        std::shared_ptr<InputDevice>& device = devicePair.second;
        mGlobalMetaState |= device->getMetaState();
    }
}

int32_t InputReader::getGlobalMetaStateLocked() {
    return mGlobalMetaState;
}

void InputReader::notifyExternalStylusPresenceChanged() {
    refreshConfigurationLocked(InputReaderConfiguration::CHANGE_EXTERNAL_STYLUS_PRESENCE);
}

void InputReader::getExternalStylusDevicesLocked(std::vector<InputDeviceInfo>& outDevices) {
    for (auto& devicePair : mDevices) {
        std::shared_ptr<InputDevice>& device = devicePair.second;
        if (device->getClasses() & INPUT_DEVICE_CLASS_EXTERNAL_STYLUS && !device->isIgnored()) {
            InputDeviceInfo info;
            device->getDeviceInfo(&info);
            outDevices.push_back(info);
        }
    }
}

void InputReader::dispatchExternalStylusState(const StylusState& state) {
    for (auto& devicePair : mDevices) {
        std::shared_ptr<InputDevice>& device = devicePair.second;
        device->updateExternalStylusState(state);
    }
}

void InputReader::disableVirtualKeysUntilLocked(nsecs_t time) {
    mDisableVirtualKeysTimeout = time;
}

bool InputReader::shouldDropVirtualKeyLocked(nsecs_t now, int32_t keyCode, int32_t scanCode) {
    if (now < mDisableVirtualKeysTimeout) {
        ALOGI("Dropping virtual key from device because virtual keys are "
              "temporarily disabled for the next %0.3fms.  keyCode=%d, scanCode=%d",
              (mDisableVirtualKeysTimeout - now) * 0.000001, keyCode, scanCode);
        return true;
    } else {
        return false;
    }
}

std::shared_ptr<PointerControllerInterface> InputReader::getPointerControllerLocked(
        int32_t deviceId) {
    std::shared_ptr<PointerControllerInterface> controller = mPointerController.lock();
    if (controller == nullptr) {
        controller = mPolicy->obtainPointerController(deviceId);
        mPointerController = controller;
        updatePointerDisplayLocked();
    }
    return controller;
}

void InputReader::updatePointerDisplayLocked() {
    std::shared_ptr<PointerControllerInterface> controller = mPointerController.lock();
    if (controller == nullptr) {
        return;
    }

    std::optional<DisplayViewport> viewport =
            mConfig.getDisplayViewportById(mConfig.defaultPointerDisplayId);
    if (!viewport) {
        ALOGW("Can't find the designated viewport with ID %" PRId32 " to update cursor input "
              "mapper. Fall back to default display",
              mConfig.defaultPointerDisplayId);
        viewport = mConfig.getDisplayViewportById(ADISPLAY_ID_DEFAULT);
    }
    if (!viewport) {
        ALOGE("Still can't find a viable viewport to update cursor input mapper. Skip setting it to"
              " PointerController.");
        return;
    }

    controller->setDisplayViewport(*viewport);
}

void InputReader::fadePointerLocked() {
    std::shared_ptr<PointerControllerInterface> controller = mPointerController.lock();
    if (controller != nullptr) {
        controller->fade(PointerControllerInterface::Transition::GRADUAL);
    }
}

void InputReader::requestTimeoutAtTimeLocked(nsecs_t when) {
    if (when < mNextTimeout) {
        mNextTimeout = when;
        mEventHub->wake();
    }
}

int32_t InputReader::bumpGenerationLocked() {
    return ++mGeneration;
}

void InputReader::getInputDevices(std::vector<InputDeviceInfo>& outInputDevices) {
    AutoMutex _l(mLock);
    getInputDevicesLocked(outInputDevices);
}

void InputReader::getInputDevicesLocked(std::vector<InputDeviceInfo>& outInputDevices) {
    outInputDevices.clear();

    for (const auto& [device, eventHubIds] : mDeviceToEventHubIdsMap) {
        if (!device->isIgnored()) {
            InputDeviceInfo info;
            device->getDeviceInfo(&info);
            outInputDevices.push_back(info);
        }
    }
}

int32_t InputReader::getKeyCodeState(int32_t deviceId, uint32_t sourceMask, int32_t keyCode) {
    AutoMutex _l(mLock);

    return getStateLocked(deviceId, sourceMask, keyCode, &InputDevice::getKeyCodeState);
}

int32_t InputReader::getScanCodeState(int32_t deviceId, uint32_t sourceMask, int32_t scanCode) {
    AutoMutex _l(mLock);

    return getStateLocked(deviceId, sourceMask, scanCode, &InputDevice::getScanCodeState);
}

int32_t InputReader::getSwitchState(int32_t deviceId, uint32_t sourceMask, int32_t switchCode) {
    AutoMutex _l(mLock);

    return getStateLocked(deviceId, sourceMask, switchCode, &InputDevice::getSwitchState);
}

int32_t InputReader::getStateLocked(int32_t deviceId, uint32_t sourceMask, int32_t code,
                                    GetStateFunc getStateFunc) {
    int32_t result = AKEY_STATE_UNKNOWN;
    if (deviceId >= 0) {
        InputDevice* device = findInputDevice(deviceId);
        if (device && !device->isIgnored() && sourcesMatchMask(device->getSources(), sourceMask)) {
            result = (device->*getStateFunc)(sourceMask, code);
        }
    } else {
        for (auto& devicePair : mDevices) {
            std::shared_ptr<InputDevice>& device = devicePair.second;
            if (!device->isIgnored() && sourcesMatchMask(device->getSources(), sourceMask)) {
                // If any device reports AKEY_STATE_DOWN or AKEY_STATE_VIRTUAL, return that
                // value.  Otherwise, return AKEY_STATE_UP as long as one device reports it.
                int32_t currentResult = (device.get()->*getStateFunc)(sourceMask, code);
                if (currentResult >= AKEY_STATE_DOWN) {
                    return currentResult;
                } else if (currentResult == AKEY_STATE_UP) {
                    result = currentResult;
                }
            }
        }
    }
    return result;
}

void InputReader::toggleCapsLockState(int32_t deviceId) {
    InputDevice* device = findInputDevice(deviceId);
    if (!device) {
        ALOGW("Ignoring toggleCapsLock for unknown deviceId %" PRId32 ".", deviceId);
        return;
    }

    if (device->isIgnored()) {
        return;
    }

    device->updateMetaState(AKEYCODE_CAPS_LOCK);
}

bool InputReader::hasKeys(int32_t deviceId, uint32_t sourceMask, size_t numCodes,
                          const int32_t* keyCodes, uint8_t* outFlags) {
    AutoMutex _l(mLock);

    memset(outFlags, 0, numCodes);
    return markSupportedKeyCodesLocked(deviceId, sourceMask, numCodes, keyCodes, outFlags);
}

bool InputReader::markSupportedKeyCodesLocked(int32_t deviceId, uint32_t sourceMask,
                                              size_t numCodes, const int32_t* keyCodes,
                                              uint8_t* outFlags) {
    bool result = false;
    if (deviceId >= 0) {
        InputDevice* device = findInputDevice(deviceId);
        if (device && !device->isIgnored() && sourcesMatchMask(device->getSources(), sourceMask)) {
            result = device->markSupportedKeyCodes(sourceMask, numCodes, keyCodes, outFlags);
        }
    } else {
        for (auto& devicePair : mDevices) {
            std::shared_ptr<InputDevice>& device = devicePair.second;
            if (!device->isIgnored() && sourcesMatchMask(device->getSources(), sourceMask)) {
                result |= device->markSupportedKeyCodes(sourceMask, numCodes, keyCodes, outFlags);
            }
        }
    }
    return result;
}

void InputReader::requestRefreshConfiguration(uint32_t changes) {
    AutoMutex _l(mLock);

    if (changes) {
        bool needWake = !mConfigurationChangesToRefresh;
        mConfigurationChangesToRefresh |= changes;

        if (needWake) {
            mEventHub->wake();
        }
    }
}

void InputReader::vibrate(int32_t deviceId, const nsecs_t* pattern, size_t patternSize,
                          ssize_t repeat, int32_t token) {
    AutoMutex _l(mLock);
    InputDevice* device = findInputDevice(deviceId);
    if (device) {
        device->vibrate(pattern, patternSize, repeat, token);
    }
}

void InputReader::cancelVibrate(int32_t deviceId, int32_t token) {
    AutoMutex _l(mLock);

    InputDevice* device = findInputDevice(deviceId);
    if (device) {
        device->cancelVibrate(token);
    }
}

bool InputReader::isInputDeviceEnabled(int32_t deviceId) {
    AutoMutex _l(mLock);

    InputDevice* device = findInputDevice(deviceId);
    if (device) {
        return device->isEnabled();
    }
    ALOGW("Ignoring invalid device id %" PRId32 ".", deviceId);
    return false;
}

bool InputReader::canDispatchToDisplay(int32_t deviceId, int32_t displayId) {
    AutoMutex _l(mLock);

    InputDevice* device = findInputDevice(deviceId);
    if (!device) {
        ALOGW("Ignoring invalid device id %" PRId32 ".", deviceId);
        return false;
    }

    if (!device->isEnabled()) {
        ALOGW("Ignoring disabled device %s", device->getName().c_str());
        return false;
    }

    std::optional<int32_t> associatedDisplayId = device->getAssociatedDisplayId();
    // No associated display. By default, can dispatch to all displays.
    if (!associatedDisplayId) {
        return true;
    }

    if (*associatedDisplayId == ADISPLAY_ID_NONE) {
        ALOGW("Device %s is associated with display ADISPLAY_ID_NONE.", device->getName().c_str());
        return true;
    }

    return *associatedDisplayId == displayId;
}

void InputReader::dump(std::string& dump) {
    AutoMutex _l(mLock);

    mEventHub->dump(dump);
    dump += "\n";

    dump += StringPrintf("Input Reader State (Nums of device: %zu):\n",
                         mDeviceToEventHubIdsMap.size());

    for (const auto& devicePair : mDeviceToEventHubIdsMap) {
        const std::shared_ptr<InputDevice>& device = devicePair.first;
        std::string eventHubDevStr = INDENT "EventHub Devices: [ ";
        for (const auto& eId : devicePair.second) {
            eventHubDevStr += StringPrintf("%d ", eId);
        }
        eventHubDevStr += "] \n";
        device->dump(dump, eventHubDevStr);
    }

    dump += INDENT "Configuration:\n";
    dump += INDENT2 "ExcludedDeviceNames: [";
    for (size_t i = 0; i < mConfig.excludedDeviceNames.size(); i++) {
        if (i != 0) {
            dump += ", ";
        }
        dump += mConfig.excludedDeviceNames[i];
    }
    dump += "]\n";
    dump += StringPrintf(INDENT2 "VirtualKeyQuietTime: %0.1fms\n",
                         mConfig.virtualKeyQuietTime * 0.000001f);

    dump += StringPrintf(INDENT2 "PointerVelocityControlParameters: "
                                 "scale=%0.3f, lowThreshold=%0.3f, highThreshold=%0.3f, "
                                 "acceleration=%0.3f\n",
                         mConfig.pointerVelocityControlParameters.scale,
                         mConfig.pointerVelocityControlParameters.lowThreshold,
                         mConfig.pointerVelocityControlParameters.highThreshold,
                         mConfig.pointerVelocityControlParameters.acceleration);

    dump += StringPrintf(INDENT2 "WheelVelocityControlParameters: "
                                 "scale=%0.3f, lowThreshold=%0.3f, highThreshold=%0.3f, "
                                 "acceleration=%0.3f\n",
                         mConfig.wheelVelocityControlParameters.scale,
                         mConfig.wheelVelocityControlParameters.lowThreshold,
                         mConfig.wheelVelocityControlParameters.highThreshold,
                         mConfig.wheelVelocityControlParameters.acceleration);

    dump += StringPrintf(INDENT2 "PointerGesture:\n");
    dump += StringPrintf(INDENT3 "Enabled: %s\n", toString(mConfig.pointerGesturesEnabled));
    dump += StringPrintf(INDENT3 "QuietInterval: %0.1fms\n",
                         mConfig.pointerGestureQuietInterval * 0.000001f);
    dump += StringPrintf(INDENT3 "DragMinSwitchSpeed: %0.1fpx/s\n",
                         mConfig.pointerGestureDragMinSwitchSpeed);
    dump += StringPrintf(INDENT3 "TapInterval: %0.1fms\n",
                         mConfig.pointerGestureTapInterval * 0.000001f);
    dump += StringPrintf(INDENT3 "TapDragInterval: %0.1fms\n",
                         mConfig.pointerGestureTapDragInterval * 0.000001f);
    dump += StringPrintf(INDENT3 "TapSlop: %0.1fpx\n", mConfig.pointerGestureTapSlop);
    dump += StringPrintf(INDENT3 "MultitouchSettleInterval: %0.1fms\n",
                         mConfig.pointerGestureMultitouchSettleInterval * 0.000001f);
    dump += StringPrintf(INDENT3 "MultitouchMinDistance: %0.1fpx\n",
                         mConfig.pointerGestureMultitouchMinDistance);
    dump += StringPrintf(INDENT3 "SwipeTransitionAngleCosine: %0.1f\n",
                         mConfig.pointerGestureSwipeTransitionAngleCosine);
    dump += StringPrintf(INDENT3 "SwipeMaxWidthRatio: %0.1f\n",
                         mConfig.pointerGestureSwipeMaxWidthRatio);
    dump += StringPrintf(INDENT3 "MovementSpeedRatio: %0.1f\n",
                         mConfig.pointerGestureMovementSpeedRatio);
    dump += StringPrintf(INDENT3 "ZoomSpeedRatio: %0.1f\n", mConfig.pointerGestureZoomSpeedRatio);

    dump += INDENT3 "Viewports:\n";
    mConfig.dump(dump);
}

void InputReader::monitor() {
    // Acquire and release the lock to ensure that the reader has not deadlocked.
    mLock.lock();
    mEventHub->wake();
    mReaderIsAliveCondition.wait(mLock);
    mLock.unlock();

    // Check the EventHub
    mEventHub->monitor();
}

// --- InputReader::ContextImpl ---

InputReader::ContextImpl::ContextImpl(InputReader* reader)
      : mReader(reader), mIdGenerator(IdGenerator::Source::INPUT_READER) {}

void InputReader::ContextImpl::updateGlobalMetaState() {
    // lock is already held by the input loop
    mReader->updateGlobalMetaStateLocked();
}

int32_t InputReader::ContextImpl::getGlobalMetaState() {
    // lock is already held by the input loop
    return mReader->getGlobalMetaStateLocked();
}

void InputReader::ContextImpl::disableVirtualKeysUntil(nsecs_t time) {
    // lock is already held by the input loop
    mReader->disableVirtualKeysUntilLocked(time);
}

bool InputReader::ContextImpl::shouldDropVirtualKey(nsecs_t now, int32_t keyCode,
                                                    int32_t scanCode) {
    // lock is already held by the input loop
    return mReader->shouldDropVirtualKeyLocked(now, keyCode, scanCode);
}

void InputReader::ContextImpl::fadePointer() {
    // lock is already held by the input loop
    mReader->fadePointerLocked();
}

std::shared_ptr<PointerControllerInterface> InputReader::ContextImpl::getPointerController(
        int32_t deviceId) {
    // lock is already held by the input loop
    return mReader->getPointerControllerLocked(deviceId);
}

void InputReader::ContextImpl::requestTimeoutAtTime(nsecs_t when) {
    // lock is already held by the input loop
    mReader->requestTimeoutAtTimeLocked(when);
}

int32_t InputReader::ContextImpl::bumpGeneration() {
    // lock is already held by the input loop
    return mReader->bumpGenerationLocked();
}

void InputReader::ContextImpl::getExternalStylusDevices(std::vector<InputDeviceInfo>& outDevices) {
    // lock is already held by whatever called refreshConfigurationLocked
    mReader->getExternalStylusDevicesLocked(outDevices);
}

void InputReader::ContextImpl::dispatchExternalStylusState(const StylusState& state) {
    mReader->dispatchExternalStylusState(state);
}

InputReaderPolicyInterface* InputReader::ContextImpl::getPolicy() {
    return mReader->mPolicy.get();
}

InputListenerInterface* InputReader::ContextImpl::getListener() {
    return mReader->mQueuedListener.get();
}

EventHubInterface* InputReader::ContextImpl::getEventHub() {
    return mReader->mEventHub.get();
}

int32_t InputReader::ContextImpl::getNextId() {
    return mIdGenerator.nextId();
}

} // namespace android
