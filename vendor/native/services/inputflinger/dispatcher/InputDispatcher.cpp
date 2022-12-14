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

#define LOG_TAG "InputDispatcher"
#define ATRACE_TAG ATRACE_TAG_INPUT

#define LOG_NDEBUG 1

// Log detailed debug messages about each inbound event notification to the dispatcher.
#define DEBUG_INBOUND_EVENT_DETAILS 0

// Log detailed debug messages about each outbound event processed by the dispatcher.
#define DEBUG_OUTBOUND_EVENT_DETAILS 0

// Log debug messages about the dispatch cycle.
#define DEBUG_DISPATCH_CYCLE 0

// Log debug messages about registrations.
#define DEBUG_REGISTRATION 0

// Log debug messages about input event injection.
#define DEBUG_INJECTION 0

// Log debug messages about input focus tracking.
static constexpr bool DEBUG_FOCUS = false;

// Log debug messages about the app switch latency optimization.
#define DEBUG_APP_SWITCH 0

// Log debug messages about hover events.
#define DEBUG_HOVER 0

#include "InputDispatcher.h"

#include "Connection.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <statslog.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include <queue>
#include <sstream>

#include <android-base/chrono_utils.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <binder/Binder.h>
#include <input/InputDevice.h>
#include <log/log.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <powermanager/PowerManager.h>
#include <utils/Trace.h>

#define INDENT "  "
#define INDENT2 "    "
#define INDENT3 "      "
#define INDENT4 "        "

using android::base::HwTimeoutMultiplier;
using android::base::StringPrintf;

namespace android::inputdispatcher {

// Default input dispatching timeout if there is no focused application or paused window
// from which to determine an appropriate dispatching timeout.
const std::chrono::nanoseconds DEFAULT_INPUT_DISPATCHING_TIMEOUT = 5s * HwTimeoutMultiplier();

// Amount of time to allow for all pending events to be processed when an app switch
// key is on the way.  This is used to preempt input dispatch and drop input events
// when an application takes too long to respond and the user has pressed an app switch key.
constexpr nsecs_t APP_SWITCH_TIMEOUT = 500 * 1000000LL; // 0.5sec

// Amount of time to allow for an event to be dispatched (measured since its eventTime)
// before considering it stale and dropping it.
constexpr nsecs_t STALE_EVENT_TIMEOUT = 10000 * 1000000LL; // 10sec

// Log a warning when an event takes longer than this to process, even if an ANR does not occur.
constexpr nsecs_t SLOW_EVENT_PROCESSING_WARNING_TIMEOUT = 2000 * 1000000LL; // 2sec

// Log a warning when an interception call takes longer than this to process.
constexpr std::chrono::milliseconds SLOW_INTERCEPTION_THRESHOLD = 50ms;

// Additional key latency in case a connection is still processing some motion events.
// This will help with the case when a user touched a button that opens a new window,
// and gives us the chance to dispatch the key to this new window.
constexpr std::chrono::nanoseconds KEY_WAITING_FOR_EVENTS_TIMEOUT = 500ms;

// Number of recent events to keep for debugging purposes.
constexpr size_t RECENT_QUEUE_MAX_SIZE = 10;

static inline nsecs_t now() {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

static inline const char* toString(bool value) {
    return value ? "true" : "false";
}

static inline int32_t getMotionEventActionPointerIndex(int32_t action) {
    return (action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK) >>
            AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
}

static bool isValidKeyAction(int32_t action) {
    switch (action) {
        case AKEY_EVENT_ACTION_DOWN:
        case AKEY_EVENT_ACTION_UP:
            return true;
        default:
            return false;
    }
}

static bool validateKeyEvent(int32_t action) {
    if (!isValidKeyAction(action)) {
        ALOGE("Key event has invalid action code 0x%x", action);
        return false;
    }
    return true;
}

static bool isValidMotionAction(int32_t action, int32_t actionButton, int32_t pointerCount) {
    switch (action & AMOTION_EVENT_ACTION_MASK) {
        case AMOTION_EVENT_ACTION_DOWN:
        case AMOTION_EVENT_ACTION_UP:
        case AMOTION_EVENT_ACTION_CANCEL:
        case AMOTION_EVENT_ACTION_MOVE:
        case AMOTION_EVENT_ACTION_OUTSIDE:
        case AMOTION_EVENT_ACTION_HOVER_ENTER:
        case AMOTION_EVENT_ACTION_HOVER_MOVE:
        case AMOTION_EVENT_ACTION_HOVER_EXIT:
        case AMOTION_EVENT_ACTION_SCROLL:
            return true;
        case AMOTION_EVENT_ACTION_POINTER_DOWN:
        case AMOTION_EVENT_ACTION_POINTER_UP: {
            int32_t index = getMotionEventActionPointerIndex(action);
            return index >= 0 && index < pointerCount;
        }
        case AMOTION_EVENT_ACTION_BUTTON_PRESS:
        case AMOTION_EVENT_ACTION_BUTTON_RELEASE:
            return actionButton != 0;
        default:
            return false;
    }
}

static bool validateMotionEvent(int32_t action, int32_t actionButton, size_t pointerCount,
                                const PointerProperties* pointerProperties) {
    if (!isValidMotionAction(action, actionButton, pointerCount)) {
        ALOGE("Motion event has invalid action code 0x%x", action);
        return false;
    }
    if (pointerCount < 1 || pointerCount > MAX_POINTERS) {
        ALOGE("Motion event has invalid pointer count %zu; value must be between 1 and %d.",
              pointerCount, MAX_POINTERS);
        return false;
    }
    BitSet32 pointerIdBits;
    for (size_t i = 0; i < pointerCount; i++) {
        int32_t id = pointerProperties[i].id;
        if (id < 0 || id > MAX_POINTER_ID) {
            ALOGE("Motion event has invalid pointer id %d; value must be between 0 and %d", id,
                  MAX_POINTER_ID);
            return false;
        }
        if (pointerIdBits.hasBit(id)) {
            ALOGE("Motion event has duplicate pointer id %d", id);
            return false;
        }
        pointerIdBits.markBit(id);
    }
    return true;
}

static void dumpRegion(std::string& dump, const Region& region) {
    if (region.isEmpty()) {
        dump += "<empty>";
        return;
    }

    bool first = true;
    Region::const_iterator cur = region.begin();
    Region::const_iterator const tail = region.end();
    while (cur != tail) {
        if (first) {
            first = false;
        } else {
            dump += "|";
        }
        dump += StringPrintf("[%d,%d][%d,%d]", cur->left, cur->top, cur->right, cur->bottom);
        cur++;
    }
}

/**
 * Find the entry in std::unordered_map by key, and return it.
 * If the entry is not found, return a default constructed entry.
 *
 * Useful when the entries are vectors, since an empty vector will be returned
 * if the entry is not found.
 * Also useful when the entries are sp<>. If an entry is not found, nullptr is returned.
 */
template <typename K, typename V>
static V getValueByKey(const std::unordered_map<K, V>& map, K key) {
    auto it = map.find(key);
    return it != map.end() ? it->second : V{};
}

/**
 * Find the entry in std::unordered_map by value, and remove it.
 * If more than one entry has the same value, then all matching
 * key-value pairs will be removed.
 *
 * Return true if at least one value has been removed.
 */
template <typename K, typename V>
static bool removeByValue(std::unordered_map<K, V>& map, const V& value) {
    bool removed = false;
    for (auto it = map.begin(); it != map.end();) {
        if (it->second == value) {
            it = map.erase(it);
            removed = true;
        } else {
            it++;
        }
    }
    return removed;
}

static bool haveSameToken(const sp<InputWindowHandle>& first, const sp<InputWindowHandle>& second) {
    if (first == second) {
        return true;
    }

    if (first == nullptr || second == nullptr) {
        return false;
    }

    return first->getToken() == second->getToken();
}

static bool isStaleEvent(nsecs_t currentTime, const EventEntry& entry) {
    return currentTime - entry.eventTime >= STALE_EVENT_TIMEOUT;
}

static std::unique_ptr<DispatchEntry> createDispatchEntry(const InputTarget& inputTarget,
                                                          EventEntry* eventEntry,
                                                          int32_t inputTargetFlags) {
    if (inputTarget.useDefaultPointerInfo()) {
        const PointerInfo& pointerInfo = inputTarget.getDefaultPointerInfo();
        return std::make_unique<DispatchEntry>(eventEntry, // increments ref
                                               inputTargetFlags, pointerInfo.xOffset,
                                               pointerInfo.yOffset, inputTarget.globalScaleFactor,
                                               pointerInfo.windowXScale, pointerInfo.windowYScale);
    }

    ALOG_ASSERT(eventEntry->type == EventEntry::Type::MOTION);
    const MotionEntry& motionEntry = static_cast<const MotionEntry&>(*eventEntry);

    PointerCoords pointerCoords[motionEntry.pointerCount];

    // Use the first pointer information to normalize all other pointers. This could be any pointer
    // as long as all other pointers are normalized to the same value and the final DispatchEntry
    // uses the offset and scale for the normalized pointer.
    const PointerInfo& firstPointerInfo =
            inputTarget.pointerInfos[inputTarget.pointerIds.firstMarkedBit()];

    // Iterate through all pointers in the event to normalize against the first.
    for (uint32_t pointerIndex = 0; pointerIndex < motionEntry.pointerCount; pointerIndex++) {
        const PointerProperties& pointerProperties = motionEntry.pointerProperties[pointerIndex];
        uint32_t pointerId = uint32_t(pointerProperties.id);
        const PointerInfo& currPointerInfo = inputTarget.pointerInfos[pointerId];

        // The scale factor is the ratio of the current pointers scale to the normalized scale.
        float scaleXDiff = currPointerInfo.windowXScale / firstPointerInfo.windowXScale;
        float scaleYDiff = currPointerInfo.windowYScale / firstPointerInfo.windowYScale;

        pointerCoords[pointerIndex].copyFrom(motionEntry.pointerCoords[pointerIndex]);
        // First apply the current pointers offset to set the window at 0,0
        pointerCoords[pointerIndex].applyOffset(currPointerInfo.xOffset, currPointerInfo.yOffset);
        // Next scale the coordinates.
        pointerCoords[pointerIndex].scale(1, scaleXDiff, scaleYDiff);
        // Lastly, offset the coordinates so they're in the normalized pointer's frame.
        pointerCoords[pointerIndex].applyOffset(-firstPointerInfo.xOffset,
                                                -firstPointerInfo.yOffset);
    }

    MotionEntry* combinedMotionEntry =
            new MotionEntry(motionEntry.id, motionEntry.eventTime, motionEntry.deviceId,
                            motionEntry.source, motionEntry.displayId, motionEntry.policyFlags,
                            motionEntry.action, motionEntry.actionButton, motionEntry.flags,
                            motionEntry.metaState, motionEntry.buttonState,
                            motionEntry.classification, motionEntry.edgeFlags,
                            motionEntry.xPrecision, motionEntry.yPrecision,
                            motionEntry.xCursorPosition, motionEntry.yCursorPosition,
                            motionEntry.downTime, motionEntry.pointerCount,
                            motionEntry.pointerProperties, pointerCoords, 0 /* xOffset */,
                            0 /* yOffset */);

    if (motionEntry.injectionState) {
        combinedMotionEntry->injectionState = motionEntry.injectionState;
        combinedMotionEntry->injectionState->refCount += 1;
    }

    std::unique_ptr<DispatchEntry> dispatchEntry =
            std::make_unique<DispatchEntry>(combinedMotionEntry, // increments ref
                                            inputTargetFlags, firstPointerInfo.xOffset,
                                            firstPointerInfo.yOffset, inputTarget.globalScaleFactor,
                                            firstPointerInfo.windowXScale,
                                            firstPointerInfo.windowYScale);
    combinedMotionEntry->release();
    return dispatchEntry;
}

static void addGestureMonitors(const std::vector<Monitor>& monitors,
                               std::vector<TouchedMonitor>& outTouchedMonitors, float xOffset = 0,
                               float yOffset = 0) {
    if (monitors.empty()) {
        return;
    }
    outTouchedMonitors.reserve(monitors.size() + outTouchedMonitors.size());
    for (const Monitor& monitor : monitors) {
        outTouchedMonitors.emplace_back(monitor, xOffset, yOffset);
    }
}

static std::array<uint8_t, 128> getRandomKey() {
    std::array<uint8_t, 128> key;
    if (RAND_bytes(key.data(), key.size()) != 1) {
        LOG_ALWAYS_FATAL("Can't generate HMAC key");
    }
    return key;
}

// --- HmacKeyManager ---

HmacKeyManager::HmacKeyManager() : mHmacKey(getRandomKey()) {}

std::array<uint8_t, 32> HmacKeyManager::sign(const VerifiedInputEvent& event) const {
    size_t size;
    switch (event.type) {
        case VerifiedInputEvent::Type::KEY: {
            size = sizeof(VerifiedKeyEvent);
            break;
        }
        case VerifiedInputEvent::Type::MOTION: {
            size = sizeof(VerifiedMotionEvent);
            break;
        }
    }
    const uint8_t* start = reinterpret_cast<const uint8_t*>(&event);
    return sign(start, size);
}

std::array<uint8_t, 32> HmacKeyManager::sign(const uint8_t* data, size_t size) const {
    // SHA256 always generates 32-bytes result
    std::array<uint8_t, 32> hash;
    unsigned int hashLen = 0;
    uint8_t* result =
            HMAC(EVP_sha256(), mHmacKey.data(), mHmacKey.size(), data, size, hash.data(), &hashLen);
    if (result == nullptr) {
        ALOGE("Could not sign the data using HMAC");
        return INVALID_HMAC;
    }

    if (hashLen != hash.size()) {
        ALOGE("HMAC-SHA256 has unexpected length");
        return INVALID_HMAC;
    }

    return hash;
}

// --- InputDispatcher ---

InputDispatcher::InputDispatcher(const sp<InputDispatcherPolicyInterface>& policy)
      : mPolicy(policy),
        mPendingEvent(nullptr),
        mLastDropReason(DropReason::NOT_DROPPED),
        mIdGenerator(IdGenerator::Source::INPUT_DISPATCHER),
        mAppSwitchSawKeyDown(false),
        mAppSwitchDueTime(LONG_LONG_MAX),
        mNextUnblockedEvent(nullptr),
        mDispatchEnabled(false),
        mDispatchFrozen(false),
        mInputFilterEnabled(false),
        // mInTouchMode will be initialized by the WindowManager to the default device config.
        // To avoid leaking stack in case that call never comes, and for tests,
        // initialize it here anyways.
        mInTouchMode(true),
        mFocusedDisplayId(ADISPLAY_ID_DEFAULT) {
    mLooper = new Looper(false);
    mReporter = createInputReporter();

    mKeyRepeatState.lastKeyEntry = nullptr;

    policy->getDispatcherConfiguration(&mConfig);
}

InputDispatcher::~InputDispatcher() {
    { // acquire lock
        std::scoped_lock _l(mLock);

        resetKeyRepeatLocked();
        releasePendingEventLocked();
        drainInboundQueueLocked();
    }

    while (!mConnectionsByFd.empty()) {
        sp<Connection> connection = mConnectionsByFd.begin()->second;
        unregisterInputChannel(connection->inputChannel);
    }
}

status_t InputDispatcher::start() {
    if (mThread) {
        return ALREADY_EXISTS;
    }
    mThread = std::make_unique<InputThread>(
            "InputDispatcher", [this]() { dispatchOnce(); }, [this]() { mLooper->wake(); });
    return OK;
}

status_t InputDispatcher::stop() {
    if (mThread && mThread->isCallingThread()) {
        ALOGE("InputDispatcher cannot be stopped from its own thread!");
        return INVALID_OPERATION;
    }
    mThread.reset();
    return OK;
}

void InputDispatcher::dispatchOnce() {
    nsecs_t nextWakeupTime = LONG_LONG_MAX;
    { // acquire lock
        std::scoped_lock _l(mLock);
        mDispatcherIsAlive.notify_all();

        // Run a dispatch loop if there are no pending commands.
        // The dispatch loop might enqueue commands to run afterwards.
        if (!haveCommandsLocked()) {
            dispatchOnceInnerLocked(&nextWakeupTime);
        }

        // Run all pending commands if there are any.
        // If any commands were run then force the next poll to wake up immediately.
        if (runCommandsLockedInterruptible()) {
            nextWakeupTime = LONG_LONG_MIN;
        }

        // If we are still waiting for ack on some events,
        // we might have to wake up earlier to check if an app is anr'ing.
        const nsecs_t nextAnrCheck = processAnrsLocked();
        nextWakeupTime = std::min(nextWakeupTime, nextAnrCheck);

        // We are about to enter an infinitely long sleep, because we have no commands or
        // pending or queued events
        if (nextWakeupTime == LONG_LONG_MAX) {
            mDispatcherEnteredIdle.notify_all();
        }
    } // release lock

    // Wait for callback or timeout or wake.  (make sure we round up, not down)
    nsecs_t currentTime = now();
    int timeoutMillis = toMillisecondTimeoutDelay(currentTime, nextWakeupTime);
    mLooper->pollOnce(timeoutMillis);
}

/**
 * Raise ANR if there is no focused window.
 * Before the ANR is raised, do a final state check:
 * 1. The currently focused application must be the same one we are waiting for.
 * 2. Ensure we still don't have a focused window.
 */
void InputDispatcher::processNoFocusedWindowAnrLocked() {
    // Check if the application that we are waiting for is still focused.
    sp<InputApplicationHandle> focusedApplication =
            getValueByKey(mFocusedApplicationHandlesByDisplay, mAwaitedApplicationDisplayId);
    if (focusedApplication == nullptr ||
        focusedApplication->getApplicationToken() !=
                mAwaitedFocusedApplication->getApplicationToken()) {
        // Unexpected because we should have reset the ANR timer when focused application changed
        ALOGE("Waited for a focused window, but focused application has already changed to %s",
              focusedApplication->getName().c_str());
        return; // The focused application has changed.
    }

    const sp<InputWindowHandle>& focusedWindowHandle =
            getFocusedWindowHandleLocked(mAwaitedApplicationDisplayId);
    if (focusedWindowHandle != nullptr) {
        return; // We now have a focused window. No need for ANR.
    }
    onAnrLocked(mAwaitedFocusedApplication);
}

/**
 * Check if any of the connections' wait queues have events that are too old.
 * If we waited for events to be ack'ed for more than the window timeout, raise an ANR.
 * Return the time at which we should wake up next.
 */
nsecs_t InputDispatcher::processAnrsLocked() {
    const nsecs_t currentTime = now();
    nsecs_t nextAnrCheck = LONG_LONG_MAX;
    // Check if we are waiting for a focused window to appear. Raise ANR if waited too long
    if (mNoFocusedWindowTimeoutTime.has_value() && mAwaitedFocusedApplication != nullptr) {
        if (currentTime >= *mNoFocusedWindowTimeoutTime) {
            processNoFocusedWindowAnrLocked();
            mAwaitedFocusedApplication.clear();
            mNoFocusedWindowTimeoutTime = std::nullopt;
            return LONG_LONG_MIN;
        } else {
            // Keep waiting
            const nsecs_t millisRemaining = ns2ms(*mNoFocusedWindowTimeoutTime - currentTime);
            ALOGW("Still no focused window. Will drop the event in %" PRId64 "ms", millisRemaining);
            nextAnrCheck = *mNoFocusedWindowTimeoutTime;
        }
    }

    // Check if any connection ANRs are due
    nextAnrCheck = std::min(nextAnrCheck, mAnrTracker.firstTimeout());
    if (currentTime < nextAnrCheck) { // most likely scenario
        return nextAnrCheck;          // everything is normal. Let's check again at nextAnrCheck
    }

    // If we reached here, we have an unresponsive connection.
    sp<Connection> connection = getConnectionLocked(mAnrTracker.firstToken());
    if (connection == nullptr) {
        ALOGE("Could not find connection for entry %" PRId64, mAnrTracker.firstTimeout());
        return nextAnrCheck;
    }
    connection->responsive = false;
    // Stop waking up for this unresponsive connection
    mAnrTracker.eraseToken(connection->inputChannel->getConnectionToken());
    onAnrLocked(*connection);
    return LONG_LONG_MIN;
}

nsecs_t InputDispatcher::getDispatchingTimeoutLocked(const sp<IBinder>& token) {
    sp<InputWindowHandle> window = getWindowHandleLocked(token);
    if (window != nullptr) {
        return window->getDispatchingTimeout(DEFAULT_INPUT_DISPATCHING_TIMEOUT).count();
    }
    return DEFAULT_INPUT_DISPATCHING_TIMEOUT.count();
}

void InputDispatcher::dispatchOnceInnerLocked(nsecs_t* nextWakeupTime) {
    nsecs_t currentTime = now();

    // Reset the key repeat timer whenever normal dispatch is suspended while the
    // device is in a non-interactive state.  This is to ensure that we abort a key
    // repeat if the device is just coming out of sleep.
    if (!mDispatchEnabled) {
        resetKeyRepeatLocked();
    }

    // If dispatching is frozen, do not process timeouts or try to deliver any new events.
    if (mDispatchFrozen) {
        if (DEBUG_FOCUS) {
            ALOGD("Dispatch frozen.  Waiting some more.");
        }
        return;
    }

    // Optimize latency of app switches.
    // Essentially we start a short timeout when an app switch key (HOME / ENDCALL) has
    // been pressed.  When it expires, we preempt dispatch and drop all other pending events.
    bool isAppSwitchDue = mAppSwitchDueTime <= currentTime;
    if (mAppSwitchDueTime < *nextWakeupTime) {
        *nextWakeupTime = mAppSwitchDueTime;
    }

    // Ready to start a new event.
    // If we don't already have a pending event, go grab one.
    if (!mPendingEvent) {
        if (mInboundQueue.empty()) {
            if (isAppSwitchDue) {
                // The inbound queue is empty so the app switch key we were waiting
                // for will never arrive.  Stop waiting for it.
                resetPendingAppSwitchLocked(false);
                isAppSwitchDue = false;
            }

            // Synthesize a key repeat if appropriate.
            if (mKeyRepeatState.lastKeyEntry) {
                if (currentTime >= mKeyRepeatState.nextRepeatTime) {
                    mPendingEvent = synthesizeKeyRepeatLocked(currentTime);
                } else {
                    if (mKeyRepeatState.nextRepeatTime < *nextWakeupTime) {
                        *nextWakeupTime = mKeyRepeatState.nextRepeatTime;
                    }
                }
            }

            // Nothing to do if there is no pending event.
            if (!mPendingEvent) {
                return;
            }
        } else {
            // Inbound queue has at least one entry.
            mPendingEvent = mInboundQueue.front();
            mInboundQueue.pop_front();
            traceInboundQueueLengthLocked();
        }

        // Poke user activity for this event.
        if (mPendingEvent->policyFlags & POLICY_FLAG_PASS_TO_USER) {
            pokeUserActivityLocked(*mPendingEvent);
        }
    }

    // Now we have an event to dispatch.
    // All events are eventually dequeued and processed this way, even if we intend to drop them.
    ALOG_ASSERT(mPendingEvent != nullptr);
    bool done = false;
    DropReason dropReason = DropReason::NOT_DROPPED;
    if (!(mPendingEvent->policyFlags & POLICY_FLAG_PASS_TO_USER)) {
        dropReason = DropReason::POLICY;
    } else if (!mDispatchEnabled) {
        dropReason = DropReason::DISABLED;
    }

    if (mNextUnblockedEvent == mPendingEvent) {
        mNextUnblockedEvent = nullptr;
    }

    switch (mPendingEvent->type) {
        case EventEntry::Type::CONFIGURATION_CHANGED: {
            ConfigurationChangedEntry* typedEntry =
                    static_cast<ConfigurationChangedEntry*>(mPendingEvent);
            done = dispatchConfigurationChangedLocked(currentTime, typedEntry);
            dropReason = DropReason::NOT_DROPPED; // configuration changes are never dropped
            break;
        }

        case EventEntry::Type::DEVICE_RESET: {
            DeviceResetEntry* typedEntry = static_cast<DeviceResetEntry*>(mPendingEvent);
            done = dispatchDeviceResetLocked(currentTime, typedEntry);
            dropReason = DropReason::NOT_DROPPED; // device resets are never dropped
            break;
        }

        case EventEntry::Type::FOCUS: {
            FocusEntry* typedEntry = static_cast<FocusEntry*>(mPendingEvent);
            dispatchFocusLocked(currentTime, typedEntry);
            done = true;
            dropReason = DropReason::NOT_DROPPED; // focus events are never dropped
            break;
        }

        case EventEntry::Type::KEY: {
            KeyEntry* typedEntry = static_cast<KeyEntry*>(mPendingEvent);
            if (isAppSwitchDue) {
                if (isAppSwitchKeyEvent(*typedEntry)) {
                    resetPendingAppSwitchLocked(true);
                    isAppSwitchDue = false;
                } else if (dropReason == DropReason::NOT_DROPPED) {
                    dropReason = DropReason::APP_SWITCH;
                }
            }
            if (dropReason == DropReason::NOT_DROPPED && isStaleEvent(currentTime, *typedEntry)) {
                dropReason = DropReason::STALE;
            }
            if (dropReason == DropReason::NOT_DROPPED && mNextUnblockedEvent) {
                dropReason = DropReason::BLOCKED;
            }
            done = dispatchKeyLocked(currentTime, typedEntry, &dropReason, nextWakeupTime);
            break;
        }

        case EventEntry::Type::MOTION: {
            MotionEntry* typedEntry = static_cast<MotionEntry*>(mPendingEvent);
            if (dropReason == DropReason::NOT_DROPPED && isAppSwitchDue) {
                dropReason = DropReason::APP_SWITCH;
            }
            if (dropReason == DropReason::NOT_DROPPED && isStaleEvent(currentTime, *typedEntry)) {
                dropReason = DropReason::STALE;
            }
            if (dropReason == DropReason::NOT_DROPPED && mNextUnblockedEvent) {
                dropReason = DropReason::BLOCKED;
            }
            done = dispatchMotionLocked(currentTime, typedEntry, &dropReason, nextWakeupTime);
            break;
        }
    }

    if (done) {
        if (dropReason != DropReason::NOT_DROPPED) {
            dropInboundEventLocked(*mPendingEvent, dropReason);
        }
        mLastDropReason = dropReason;

        releasePendingEventLocked();
        *nextWakeupTime = LONG_LONG_MIN; // force next poll to wake up immediately
    }
}

/**
 * Return true if the events preceding this incoming motion event should be dropped
 * Return false otherwise (the default behaviour)
 */
bool InputDispatcher::shouldPruneInboundQueueLocked(const MotionEntry& motionEntry) {
    const bool isPointerDownEvent = motionEntry.action == AMOTION_EVENT_ACTION_DOWN &&
            (motionEntry.source & AINPUT_SOURCE_CLASS_POINTER);

    // Optimize case where the current application is unresponsive and the user
    // decides to touch a window in a different application.
    // If the application takes too long to catch up then we drop all events preceding
    // the touch into the other window.
    if (isPointerDownEvent && mAwaitedFocusedApplication != nullptr) {
        int32_t displayId = motionEntry.displayId;
        int32_t x = static_cast<int32_t>(
                motionEntry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X));
        int32_t y = static_cast<int32_t>(
                motionEntry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y));
        sp<InputWindowHandle> touchedWindowHandle =
                findTouchedWindowAtLocked(displayId, x, y, nullptr);
        if (touchedWindowHandle != nullptr &&
            touchedWindowHandle->getApplicationToken() !=
                    mAwaitedFocusedApplication->getApplicationToken()) {
            // User touched a different application than the one we are waiting on.
            ALOGI("Pruning input queue because user touched a different application while waiting "
                  "for %s",
                  mAwaitedFocusedApplication->getName().c_str());
            return true;
        }

        // Alternatively, maybe there's a gesture monitor that could handle this event
        std::vector<TouchedMonitor> gestureMonitors =
                findTouchedGestureMonitorsLocked(displayId, {});
        for (TouchedMonitor& gestureMonitor : gestureMonitors) {
            sp<Connection> connection =
                    getConnectionLocked(gestureMonitor.monitor.inputChannel->getConnectionToken());
            if (connection != nullptr && connection->responsive) {
                // This monitor could take more input. Drop all events preceding this
                // event, so that gesture monitor could get a chance to receive the stream
                ALOGW("Pruning the input queue because %s is unresponsive, but we have a "
                      "responsive gesture monitor that may handle the event",
                      mAwaitedFocusedApplication->getName().c_str());
                return true;
            }
        }
    }

    // Prevent getting stuck: if we have a pending key event, and some motion events that have not
    // yet been processed by some connections, the dispatcher will wait for these motion
    // events to be processed before dispatching the key event. This is because these motion events
    // may cause a new window to be launched, which the user might expect to receive focus.
    // To prevent waiting forever for such events, just send the key to the currently focused window
    if (isPointerDownEvent && mKeyIsWaitingForEventsTimeout) {
        ALOGD("Received a new pointer down event, stop waiting for events to process and "
              "just send the pending key event to the focused window.");
        mKeyIsWaitingForEventsTimeout = now();
    }
    return false;
}

bool InputDispatcher::enqueueInboundEventLocked(EventEntry* entry) {
    bool needWake = mInboundQueue.empty();
    mInboundQueue.push_back(entry);
    traceInboundQueueLengthLocked();

    switch (entry->type) {
        case EventEntry::Type::KEY: {
            // Optimize app switch latency.
            // If the application takes too long to catch up then we drop all events preceding
            // the app switch key.
            const KeyEntry& keyEntry = static_cast<const KeyEntry&>(*entry);
            if (isAppSwitchKeyEvent(keyEntry)) {
                if (keyEntry.action == AKEY_EVENT_ACTION_DOWN) {
                    mAppSwitchSawKeyDown = true;
                } else if (keyEntry.action == AKEY_EVENT_ACTION_UP) {
                    if (mAppSwitchSawKeyDown) {
#if DEBUG_APP_SWITCH
                        ALOGD("App switch is pending!");
#endif
                        mAppSwitchDueTime = keyEntry.eventTime + APP_SWITCH_TIMEOUT;
                        mAppSwitchSawKeyDown = false;
                        needWake = true;
                    }
                }
            }
            break;
        }

        case EventEntry::Type::MOTION: {
            if (shouldPruneInboundQueueLocked(static_cast<MotionEntry&>(*entry))) {
                mNextUnblockedEvent = entry;
                needWake = true;
            }
            break;
        }
        case EventEntry::Type::FOCUS: {
            LOG_ALWAYS_FATAL("Focus events should be inserted using enqueueFocusEventLocked");
            break;
        }
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET: {
            // nothing to do
            break;
        }
    }

    return needWake;
}

void InputDispatcher::addRecentEventLocked(EventEntry* entry) {
    entry->refCount += 1;
    mRecentQueue.push_back(entry);
    if (mRecentQueue.size() > RECENT_QUEUE_MAX_SIZE) {
        mRecentQueue.front()->release();
        mRecentQueue.pop_front();
    }
}

sp<InputWindowHandle> InputDispatcher::findTouchedWindowAtLocked(int32_t displayId, int32_t x,
                                                                 int32_t y, TouchState* touchState,
                                                                 bool addOutsideTargets,
                                                                 bool addPortalWindows) {
    if ((addPortalWindows || addOutsideTargets) && touchState == nullptr) {
        LOG_ALWAYS_FATAL(
                "Must provide a valid touch state if adding portal windows or outside targets");
    }
    // Traverse windows from front to back to find touched window.
    const std::vector<sp<InputWindowHandle>> windowHandles = getWindowHandlesLocked(displayId);
    for (const sp<InputWindowHandle>& windowHandle : windowHandles) {
        const InputWindowInfo* windowInfo = windowHandle->getInfo();
        if (windowInfo->displayId == displayId) {
            int32_t flags = windowInfo->layoutParamsFlags;

            if (windowInfo->visible) {
                if (!(flags & InputWindowInfo::FLAG_NOT_TOUCHABLE)) {
                    bool isTouchModal = (flags &
                                         (InputWindowInfo::FLAG_NOT_FOCUSABLE |
                                          InputWindowInfo::FLAG_NOT_TOUCH_MODAL)) == 0;
                    if (isTouchModal || windowInfo->touchableRegionContainsPoint(x, y)) {
                        int32_t portalToDisplayId = windowInfo->portalToDisplayId;
                        if (portalToDisplayId != ADISPLAY_ID_NONE &&
                            portalToDisplayId != displayId) {
                            if (addPortalWindows) {
                                // For the monitoring channels of the display.
                                touchState->addPortalWindow(windowHandle);
                            }
                            return findTouchedWindowAtLocked(portalToDisplayId, x, y, touchState,
                                                             addOutsideTargets, addPortalWindows);
                        }
                        // Found window.
                        return windowHandle;
                    }
                }

                if (addOutsideTargets && (flags & InputWindowInfo::FLAG_WATCH_OUTSIDE_TOUCH)) {
                    touchState->addOrUpdateWindow(windowHandle,
                                                  InputTarget::FLAG_DISPATCH_AS_OUTSIDE,
                                                  BitSet32(0));
                }
            }
        }
    }
    return nullptr;
}

std::vector<TouchedMonitor> InputDispatcher::findTouchedGestureMonitorsLocked(
        int32_t displayId, const std::vector<sp<InputWindowHandle>>& portalWindows) const {
    std::vector<TouchedMonitor> touchedMonitors;

    std::vector<Monitor> monitors = getValueByKey(mGestureMonitorsByDisplay, displayId);
    addGestureMonitors(monitors, touchedMonitors);
    for (const sp<InputWindowHandle>& portalWindow : portalWindows) {
        const InputWindowInfo* windowInfo = portalWindow->getInfo();
        monitors = getValueByKey(mGestureMonitorsByDisplay, windowInfo->portalToDisplayId);
        addGestureMonitors(monitors, touchedMonitors, -windowInfo->frameLeft,
                           -windowInfo->frameTop);
    }
    return touchedMonitors;
}

void InputDispatcher::dropInboundEventLocked(const EventEntry& entry, DropReason dropReason) {
    const char* reason;
    switch (dropReason) {
        case DropReason::POLICY:
#if DEBUG_INBOUND_EVENT_DETAILS
            ALOGD("Dropped event because policy consumed it.");
#endif
            reason = "inbound event was dropped because the policy consumed it";
            break;
        case DropReason::DISABLED:
            if (mLastDropReason != DropReason::DISABLED) {
                ALOGI("Dropped event because input dispatch is disabled.");
            }
            reason = "inbound event was dropped because input dispatch is disabled";
            break;
        case DropReason::APP_SWITCH:
            ALOGI("Dropped event because of pending overdue app switch.");
            reason = "inbound event was dropped because of pending overdue app switch";
            break;
        case DropReason::BLOCKED:
            ALOGI("Dropped event because the current application is not responding and the user "
                  "has started interacting with a different application.");
            reason = "inbound event was dropped because the current application is not responding "
                     "and the user has started interacting with a different application";
            break;
        case DropReason::STALE:
            ALOGI("Dropped event because it is stale.");
            reason = "inbound event was dropped because it is stale";
            break;
        case DropReason::NOT_DROPPED: {
            LOG_ALWAYS_FATAL("Should not be dropping a NOT_DROPPED event");
            return;
        }
    }

    switch (entry.type) {
        case EventEntry::Type::KEY: {
            CancelationOptions options(CancelationOptions::CANCEL_NON_POINTER_EVENTS, reason);
            synthesizeCancelationEventsForAllConnectionsLocked(options);
            break;
        }
        case EventEntry::Type::MOTION: {
            const MotionEntry& motionEntry = static_cast<const MotionEntry&>(entry);
            if (motionEntry.source & AINPUT_SOURCE_CLASS_POINTER) {
                CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS, reason);
                synthesizeCancelationEventsForAllConnectionsLocked(options);
            } else {
                CancelationOptions options(CancelationOptions::CANCEL_NON_POINTER_EVENTS, reason);
                synthesizeCancelationEventsForAllConnectionsLocked(options);
            }
            break;
        }
        case EventEntry::Type::FOCUS:
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET: {
            LOG_ALWAYS_FATAL("Should not drop %s events", EventEntry::typeToString(entry.type));
            break;
        }
    }
}

static bool isAppSwitchKeyCode(int32_t keyCode) {
    return keyCode == AKEYCODE_HOME || keyCode == AKEYCODE_ENDCALL ||
            keyCode == AKEYCODE_APP_SWITCH;
}

bool InputDispatcher::isAppSwitchKeyEvent(const KeyEntry& keyEntry) {
    return !(keyEntry.flags & AKEY_EVENT_FLAG_CANCELED) && isAppSwitchKeyCode(keyEntry.keyCode) &&
            (keyEntry.policyFlags & POLICY_FLAG_TRUSTED) &&
            (keyEntry.policyFlags & POLICY_FLAG_PASS_TO_USER);
}

bool InputDispatcher::isAppSwitchPendingLocked() {
    return mAppSwitchDueTime != LONG_LONG_MAX;
}

void InputDispatcher::resetPendingAppSwitchLocked(bool handled) {
    mAppSwitchDueTime = LONG_LONG_MAX;

#if DEBUG_APP_SWITCH
    if (handled) {
        ALOGD("App switch has arrived.");
    } else {
        ALOGD("App switch was abandoned.");
    }
#endif
}

bool InputDispatcher::haveCommandsLocked() const {
    return !mCommandQueue.empty();
}

bool InputDispatcher::runCommandsLockedInterruptible() {
    if (mCommandQueue.empty()) {
        return false;
    }

    do {
        std::unique_ptr<CommandEntry> commandEntry = std::move(mCommandQueue.front());
        mCommandQueue.pop_front();
        Command command = commandEntry->command;
        command(*this, commandEntry.get()); // commands are implicitly 'LockedInterruptible'

        commandEntry->connection.clear();
    } while (!mCommandQueue.empty());
    return true;
}

void InputDispatcher::postCommandLocked(std::unique_ptr<CommandEntry> commandEntry) {
    mCommandQueue.push_back(std::move(commandEntry));
}

void InputDispatcher::drainInboundQueueLocked() {
    while (!mInboundQueue.empty()) {
        EventEntry* entry = mInboundQueue.front();
        mInboundQueue.pop_front();
        releaseInboundEventLocked(entry);
    }
    traceInboundQueueLengthLocked();
}

void InputDispatcher::releasePendingEventLocked() {
    if (mPendingEvent) {
        releaseInboundEventLocked(mPendingEvent);
        mPendingEvent = nullptr;
    }
}

void InputDispatcher::releaseInboundEventLocked(EventEntry* entry) {
    InjectionState* injectionState = entry->injectionState;
    if (injectionState && injectionState->injectionResult == INPUT_EVENT_INJECTION_PENDING) {
#if DEBUG_DISPATCH_CYCLE
        ALOGD("Injected inbound event was dropped.");
#endif
        setInjectionResult(entry, INPUT_EVENT_INJECTION_FAILED);
    }
    if (entry == mNextUnblockedEvent) {
        mNextUnblockedEvent = nullptr;
    }
    addRecentEventLocked(entry);
    entry->release();
}

void InputDispatcher::resetKeyRepeatLocked() {
    if (mKeyRepeatState.lastKeyEntry) {
        mKeyRepeatState.lastKeyEntry->release();
        mKeyRepeatState.lastKeyEntry = nullptr;
    }
}

KeyEntry* InputDispatcher::synthesizeKeyRepeatLocked(nsecs_t currentTime) {
    KeyEntry* entry = mKeyRepeatState.lastKeyEntry;

    // Reuse the repeated key entry if it is otherwise unreferenced.
    uint32_t policyFlags = entry->policyFlags &
            (POLICY_FLAG_RAW_MASK | POLICY_FLAG_PASS_TO_USER | POLICY_FLAG_TRUSTED);
    if (entry->refCount == 1) {
        entry->recycle();
        entry->id = mIdGenerator.nextId();
        entry->eventTime = currentTime;
        entry->policyFlags = policyFlags;
        entry->repeatCount += 1;
    } else {
        KeyEntry* newEntry =
                new KeyEntry(mIdGenerator.nextId(), currentTime, entry->deviceId, entry->source,
                             entry->displayId, policyFlags, entry->action, entry->flags,
                             entry->keyCode, entry->scanCode, entry->metaState,
                             entry->repeatCount + 1, entry->downTime);

        mKeyRepeatState.lastKeyEntry = newEntry;
        entry->release();

        entry = newEntry;
    }
    entry->syntheticRepeat = true;

    // Increment reference count since we keep a reference to the event in
    // mKeyRepeatState.lastKeyEntry in addition to the one we return.
    entry->refCount += 1;

    mKeyRepeatState.nextRepeatTime = currentTime + mConfig.keyRepeatDelay;
    return entry;
}

bool InputDispatcher::dispatchConfigurationChangedLocked(nsecs_t currentTime,
                                                         ConfigurationChangedEntry* entry) {
#if DEBUG_OUTBOUND_EVENT_DETAILS
    ALOGD("dispatchConfigurationChanged - eventTime=%" PRId64, entry->eventTime);
#endif

    // Reset key repeating in case a keyboard device was added or removed or something.
    resetKeyRepeatLocked();

    // Enqueue a command to run outside the lock to tell the policy that the configuration changed.
    std::unique_ptr<CommandEntry> commandEntry = std::make_unique<CommandEntry>(
            &InputDispatcher::doNotifyConfigurationChangedLockedInterruptible);
    commandEntry->eventTime = entry->eventTime;
    postCommandLocked(std::move(commandEntry));
    return true;
}

bool InputDispatcher::dispatchDeviceResetLocked(nsecs_t currentTime, DeviceResetEntry* entry) {
#if DEBUG_OUTBOUND_EVENT_DETAILS
    ALOGD("dispatchDeviceReset - eventTime=%" PRId64 ", deviceId=%d", entry->eventTime,
          entry->deviceId);
#endif

    // Reset key repeating in case a keyboard device was disabled or enabled.
    if (mKeyRepeatState.lastKeyEntry && mKeyRepeatState.lastKeyEntry->deviceId == entry->deviceId) {
        resetKeyRepeatLocked();
    }

    CancelationOptions options(CancelationOptions::CANCEL_ALL_EVENTS, "device was reset");
    options.deviceId = entry->deviceId;
    synthesizeCancelationEventsForAllConnectionsLocked(options);
    return true;
}

void InputDispatcher::enqueueFocusEventLocked(const InputWindowHandle& window, bool hasFocus) {
    if (mPendingEvent != nullptr) {
        // Move the pending event to the front of the queue. This will give the chance
        // for the pending event to get dispatched to the newly focused window
        mInboundQueue.push_front(mPendingEvent);
        mPendingEvent = nullptr;
    }

    FocusEntry* focusEntry =
            new FocusEntry(mIdGenerator.nextId(), now(), window.getToken(), hasFocus);

    // This event should go to the front of the queue, but behind all other focus events
    // Find the last focus event, and insert right after it
    std::deque<EventEntry*>::reverse_iterator it =
            std::find_if(mInboundQueue.rbegin(), mInboundQueue.rend(),
                         [](EventEntry* event) { return event->type == EventEntry::Type::FOCUS; });

    // Maintain the order of focus events. Insert the entry after all other focus events.
    mInboundQueue.insert(it.base(), focusEntry);
}

void InputDispatcher::dispatchFocusLocked(nsecs_t currentTime, FocusEntry* entry) {
    sp<InputChannel> channel = getInputChannelLocked(entry->connectionToken);
    if (channel == nullptr) {
        return; // Window has gone away
    }
    InputTarget target;
    target.inputChannel = channel;
    target.flags = InputTarget::FLAG_DISPATCH_AS_IS;
    entry->dispatchInProgress = true;

    dispatchEventLocked(currentTime, entry, {target});
}

bool InputDispatcher::dispatchKeyLocked(nsecs_t currentTime, KeyEntry* entry,
                                        DropReason* dropReason, nsecs_t* nextWakeupTime) {
    // Preprocessing.
    if (!entry->dispatchInProgress) {
        if (entry->repeatCount == 0 && entry->action == AKEY_EVENT_ACTION_DOWN &&
            (entry->policyFlags & POLICY_FLAG_TRUSTED) &&
            (!(entry->policyFlags & POLICY_FLAG_DISABLE_KEY_REPEAT))) {
            if (mKeyRepeatState.lastKeyEntry &&
                mKeyRepeatState.lastKeyEntry->keyCode == entry->keyCode) {
                // We have seen two identical key downs in a row which indicates that the device
                // driver is automatically generating key repeats itself.  We take note of the
                // repeat here, but we disable our own next key repeat timer since it is clear that
                // we will not need to synthesize key repeats ourselves.
                entry->repeatCount = mKeyRepeatState.lastKeyEntry->repeatCount + 1;
                resetKeyRepeatLocked();
                mKeyRepeatState.nextRepeatTime = LONG_LONG_MAX; // don't generate repeats ourselves
            } else {
                // Not a repeat.  Save key down state in case we do see a repeat later.
                resetKeyRepeatLocked();
                mKeyRepeatState.nextRepeatTime = entry->eventTime + mConfig.keyRepeatTimeout;
            }
            mKeyRepeatState.lastKeyEntry = entry;
            entry->refCount += 1;
        } else if (!entry->syntheticRepeat) {
            resetKeyRepeatLocked();
        }

        if (entry->repeatCount == 1) {
            entry->flags |= AKEY_EVENT_FLAG_LONG_PRESS;
        } else {
            entry->flags &= ~AKEY_EVENT_FLAG_LONG_PRESS;
        }

        entry->dispatchInProgress = true;

        logOutboundKeyDetails("dispatchKey - ", *entry);
    }

    // Handle case where the policy asked us to try again later last time.
    if (entry->interceptKeyResult == KeyEntry::INTERCEPT_KEY_RESULT_TRY_AGAIN_LATER) {
        if (currentTime < entry->interceptKeyWakeupTime) {
            if (entry->interceptKeyWakeupTime < *nextWakeupTime) {
                *nextWakeupTime = entry->interceptKeyWakeupTime;
            }
            return false; // wait until next wakeup
        }
        entry->interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_UNKNOWN;
        entry->interceptKeyWakeupTime = 0;
    }

    // Give the policy a chance to intercept the key.
    if (entry->interceptKeyResult == KeyEntry::INTERCEPT_KEY_RESULT_UNKNOWN) {
        if (entry->policyFlags & POLICY_FLAG_PASS_TO_USER) {
            std::unique_ptr<CommandEntry> commandEntry = std::make_unique<CommandEntry>(
                    &InputDispatcher::doInterceptKeyBeforeDispatchingLockedInterruptible);
            sp<InputWindowHandle> focusedWindowHandle =
                    getValueByKey(mFocusedWindowHandlesByDisplay, getTargetDisplayId(*entry));
            if (focusedWindowHandle != nullptr) {
                commandEntry->inputChannel = getInputChannelLocked(focusedWindowHandle->getToken());
            }
            commandEntry->keyEntry = entry;
            postCommandLocked(std::move(commandEntry));
            entry->refCount += 1;
            return false; // wait for the command to run
        } else {
            entry->interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_CONTINUE;
        }
    } else if (entry->interceptKeyResult == KeyEntry::INTERCEPT_KEY_RESULT_SKIP) {
        if (*dropReason == DropReason::NOT_DROPPED) {
            *dropReason = DropReason::POLICY;
        }
    }

    // Clean up if dropping the event.
    if (*dropReason != DropReason::NOT_DROPPED) {
        setInjectionResult(entry,
                           *dropReason == DropReason::POLICY ? INPUT_EVENT_INJECTION_SUCCEEDED
                                                             : INPUT_EVENT_INJECTION_FAILED);
        mReporter->reportDroppedKey(entry->id);
        return true;
    }

    // Identify targets.
    std::vector<InputTarget> inputTargets;
    int32_t injectionResult =
            findFocusedWindowTargetsLocked(currentTime, *entry, inputTargets, nextWakeupTime);
    if (injectionResult == INPUT_EVENT_INJECTION_PENDING) {
        return false;
    }

    setInjectionResult(entry, injectionResult);
    if (injectionResult != INPUT_EVENT_INJECTION_SUCCEEDED) {
        return true;
    }

    // Add monitor channels from event's or focused display.
    addGlobalMonitoringTargetsLocked(inputTargets, getTargetDisplayId(*entry));

    // Dispatch the key.
    dispatchEventLocked(currentTime, entry, inputTargets);
    return true;
}

void InputDispatcher::logOutboundKeyDetails(const char* prefix, const KeyEntry& entry) {
#if DEBUG_OUTBOUND_EVENT_DETAILS
    ALOGD("%seventTime=%" PRId64 ", deviceId=%d, source=0x%x, displayId=%" PRId32 ", "
          "policyFlags=0x%x, action=0x%x, flags=0x%x, keyCode=0x%x, scanCode=0x%x, "
          "metaState=0x%x, repeatCount=%d, downTime=%" PRId64,
          prefix, entry.eventTime, entry.deviceId, entry.source, entry.displayId, entry.policyFlags,
          entry.action, entry.flags, entry.keyCode, entry.scanCode, entry.metaState,
          entry.repeatCount, entry.downTime);
#endif
}

bool InputDispatcher::dispatchMotionLocked(nsecs_t currentTime, MotionEntry* entry,
                                           DropReason* dropReason, nsecs_t* nextWakeupTime) {
    ATRACE_CALL();
    // Preprocessing.
    if (!entry->dispatchInProgress) {
        entry->dispatchInProgress = true;

        logOutboundMotionDetails("dispatchMotion - ", *entry);
    }

    // Clean up if dropping the event.
    if (*dropReason != DropReason::NOT_DROPPED) {
        setInjectionResult(entry,
                           *dropReason == DropReason::POLICY ? INPUT_EVENT_INJECTION_SUCCEEDED
                                                             : INPUT_EVENT_INJECTION_FAILED);
        return true;
    }

    bool isPointerEvent = entry->source & AINPUT_SOURCE_CLASS_POINTER;

    // Identify targets.
    std::vector<InputTarget> inputTargets;

    bool conflictingPointerActions = false;
    int32_t injectionResult;
    if (isPointerEvent) {
        // Pointer event.  (eg. touchscreen)
        injectionResult =
                findTouchedWindowTargetsLocked(currentTime, *entry, inputTargets, nextWakeupTime,
                                               &conflictingPointerActions);
    } else {
        // Non touch event.  (eg. trackball)
        injectionResult =
                findFocusedWindowTargetsLocked(currentTime, *entry, inputTargets, nextWakeupTime);
    }
    if (injectionResult == INPUT_EVENT_INJECTION_PENDING) {
        return false;
    }

    setInjectionResult(entry, injectionResult);
    if (injectionResult == INPUT_EVENT_INJECTION_PERMISSION_DENIED) {
        ALOGW("Permission denied, dropping the motion (isPointer=%s)", toString(isPointerEvent));
        return true;
    }
    if (injectionResult != INPUT_EVENT_INJECTION_SUCCEEDED) {
        CancelationOptions::Mode mode(isPointerEvent
                                              ? CancelationOptions::CANCEL_POINTER_EVENTS
                                              : CancelationOptions::CANCEL_NON_POINTER_EVENTS);
        CancelationOptions options(mode, "input event injection failed");
        synthesizeCancelationEventsForMonitorsLocked(options);
        return true;
    }

    // Add monitor channels from event's or focused display.
    addGlobalMonitoringTargetsLocked(inputTargets, getTargetDisplayId(*entry));

    if (isPointerEvent) {
        std::unordered_map<int32_t, TouchState>::iterator it =
                mTouchStatesByDisplay.find(entry->displayId);
        if (it != mTouchStatesByDisplay.end()) {
            const TouchState& state = it->second;
            if (!state.portalWindows.empty()) {
                // The event has gone through these portal windows, so we add monitoring targets of
                // the corresponding displays as well.
                for (size_t i = 0; i < state.portalWindows.size(); i++) {
                    const InputWindowInfo* windowInfo = state.portalWindows[i]->getInfo();
                    addGlobalMonitoringTargetsLocked(inputTargets, windowInfo->portalToDisplayId,
                                                     -windowInfo->frameLeft, -windowInfo->frameTop);
                }
            }
        }
    }

    // Dispatch the motion.
    if (conflictingPointerActions) {
        CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS,
                                   "conflicting pointer actions");
        synthesizeCancelationEventsForAllConnectionsLocked(options);
    }
    dispatchEventLocked(currentTime, entry, inputTargets);
    return true;
}

void InputDispatcher::logOutboundMotionDetails(const char* prefix, const MotionEntry& entry) {
#if DEBUG_OUTBOUND_EVENT_DETAILS
    ALOGD("%seventTime=%" PRId64 ", deviceId=%d, source=0x%x, displayId=%" PRId32
          ", policyFlags=0x%x, "
          "action=0x%x, actionButton=0x%x, flags=0x%x, "
          "metaState=0x%x, buttonState=0x%x,"
          "edgeFlags=0x%x, xPrecision=%f, yPrecision=%f, downTime=%" PRId64,
          prefix, entry.eventTime, entry.deviceId, entry.source, entry.displayId, entry.policyFlags,
          entry.action, entry.actionButton, entry.flags, entry.metaState, entry.buttonState,
          entry.edgeFlags, entry.xPrecision, entry.yPrecision, entry.downTime);

    for (uint32_t i = 0; i < entry.pointerCount; i++) {
        ALOGD("  Pointer %d: id=%d, toolType=%d, "
              "x=%f, y=%f, pressure=%f, size=%f, "
              "touchMajor=%f, touchMinor=%f, toolMajor=%f, toolMinor=%f, "
              "orientation=%f",
              i, entry.pointerProperties[i].id, entry.pointerProperties[i].toolType,
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_X),
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_Y),
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_PRESSURE),
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_SIZE),
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR),
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR),
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR),
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR),
              entry.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION));
    }
#endif
}

void InputDispatcher::dispatchEventLocked(nsecs_t currentTime, EventEntry* eventEntry,
                                          const std::vector<InputTarget>& inputTargets) {
    ATRACE_CALL();
#if DEBUG_DISPATCH_CYCLE
    ALOGD("dispatchEventToCurrentInputTargets");
#endif

    ALOG_ASSERT(eventEntry->dispatchInProgress); // should already have been set to true

    pokeUserActivityLocked(*eventEntry);

    for (const InputTarget& inputTarget : inputTargets) {
        sp<Connection> connection =
                getConnectionLocked(inputTarget.inputChannel->getConnectionToken());
        if (connection != nullptr) {
            prepareDispatchCycleLocked(currentTime, connection, eventEntry, inputTarget);
        } else {
            if (DEBUG_FOCUS) {
                ALOGD("Dropping event delivery to target with channel '%s' because it "
                      "is no longer registered with the input dispatcher.",
                      inputTarget.inputChannel->getName().c_str());
            }
        }
    }
}

void InputDispatcher::cancelEventsForAnrLocked(const sp<Connection>& connection) {
    // We will not be breaking any connections here, even if the policy wants us to abort dispatch.
    // If the policy decides to close the app, we will get a channel removal event via
    // unregisterInputChannel, and will clean up the connection that way. We are already not
    // sending new pointers to the connection when it blocked, but focused events will continue to
    // pile up.
    ALOGW("Canceling events for %s because it is unresponsive",
          connection->inputChannel->getName().c_str());
    if (connection->status == Connection::STATUS_NORMAL) {
        CancelationOptions options(CancelationOptions::CANCEL_ALL_EVENTS,
                                   "application not responding");
        synthesizeCancelationEventsForConnectionLocked(connection, options);
    }
}

void InputDispatcher::resetNoFocusedWindowTimeoutLocked() {
    if (DEBUG_FOCUS) {
        ALOGD("Resetting ANR timeouts.");
    }

    // Reset input target wait timeout.
    mNoFocusedWindowTimeoutTime = std::nullopt;
    mAwaitedFocusedApplication.clear();
}

/**
 * Get the display id that the given event should go to. If this event specifies a valid display id,
 * then it should be dispatched to that display. Otherwise, the event goes to the focused display.
 * Focused display is the display that the user most recently interacted with.
 */
int32_t InputDispatcher::getTargetDisplayId(const EventEntry& entry) {
    int32_t displayId;
    switch (entry.type) {
        case EventEntry::Type::KEY: {
            const KeyEntry& keyEntry = static_cast<const KeyEntry&>(entry);
            displayId = keyEntry.displayId;
            break;
        }
        case EventEntry::Type::MOTION: {
            const MotionEntry& motionEntry = static_cast<const MotionEntry&>(entry);
            displayId = motionEntry.displayId;
            break;
        }
        case EventEntry::Type::FOCUS:
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET: {
            ALOGE("%s events do not have a target display", EventEntry::typeToString(entry.type));
            return ADISPLAY_ID_NONE;
        }
    }
    return displayId == ADISPLAY_ID_NONE ? mFocusedDisplayId : displayId;
}

bool InputDispatcher::shouldWaitToSendKeyLocked(nsecs_t currentTime,
                                                const char* focusedWindowName) {
    if (mAnrTracker.empty()) {
        // already processed all events that we waited for
        mKeyIsWaitingForEventsTimeout = std::nullopt;
        return false;
    }

    if (!mKeyIsWaitingForEventsTimeout.has_value()) {
        // Start the timer
        ALOGD("Waiting to send key to %s because there are unprocessed events that may cause "
              "focus to change",
              focusedWindowName);
        mKeyIsWaitingForEventsTimeout = currentTime + KEY_WAITING_FOR_EVENTS_TIMEOUT.count();
        return true;
    }

    // We still have pending events, and already started the timer
    if (currentTime < *mKeyIsWaitingForEventsTimeout) {
        return true; // Still waiting
    }

    // Waited too long, and some connection still hasn't processed all motions
    // Just send the key to the focused window
    ALOGW("Dispatching key to %s even though there are other unprocessed events",
          focusedWindowName);
    mKeyIsWaitingForEventsTimeout = std::nullopt;
    return false;
}

int32_t InputDispatcher::findFocusedWindowTargetsLocked(nsecs_t currentTime,
                                                        const EventEntry& entry,
                                                        std::vector<InputTarget>& inputTargets,
                                                        nsecs_t* nextWakeupTime) {
    std::string reason;

    int32_t displayId = getTargetDisplayId(entry);
    sp<InputWindowHandle> focusedWindowHandle =
            getValueByKey(mFocusedWindowHandlesByDisplay, displayId);
    sp<InputApplicationHandle> focusedApplicationHandle =
            getValueByKey(mFocusedApplicationHandlesByDisplay, displayId);

    // If there is no currently focused window and no focused application
    // then drop the event.
    if (focusedWindowHandle == nullptr && focusedApplicationHandle == nullptr) {
        ALOGI("Dropping %s event because there is no focused window or focused application in "
              "display %" PRId32 ".",
              EventEntry::typeToString(entry.type), displayId);
        return INPUT_EVENT_INJECTION_FAILED;
    }

    // Compatibility behavior: raise ANR if there is a focused application, but no focused window.
    // Only start counting when we have a focused event to dispatch. The ANR is canceled if we
    // start interacting with another application via touch (app switch). This code can be removed
    // if the "no focused window ANR" is moved to the policy. Input doesn't know whether
    // an app is expected to have a focused window.
    if (focusedWindowHandle == nullptr && focusedApplicationHandle != nullptr) {
        if (!mNoFocusedWindowTimeoutTime.has_value()) {
            // We just discovered that there's no focused window. Start the ANR timer
            const nsecs_t timeout = focusedApplicationHandle->getDispatchingTimeout(
                    DEFAULT_INPUT_DISPATCHING_TIMEOUT.count());
            mNoFocusedWindowTimeoutTime = currentTime + timeout;
            mAwaitedFocusedApplication = focusedApplicationHandle;
            mAwaitedApplicationDisplayId = displayId;
            ALOGW("Waiting because no window has focus but %s may eventually add a "
                  "window when it finishes starting up. Will wait for %" PRId64 "ms",
                  mAwaitedFocusedApplication->getName().c_str(), ns2ms(timeout));
            *nextWakeupTime = *mNoFocusedWindowTimeoutTime;
            return INPUT_EVENT_INJECTION_PENDING;
        } else if (currentTime > *mNoFocusedWindowTimeoutTime) {
            // Already raised ANR. Drop the event
            ALOGE("Dropping %s event because there is no focused window",
                  EventEntry::typeToString(entry.type));
            return INPUT_EVENT_INJECTION_FAILED;
        } else {
            // Still waiting for the focused window
            return INPUT_EVENT_INJECTION_PENDING;
        }
    }

    // we have a valid, non-null focused window
    resetNoFocusedWindowTimeoutLocked();

    // Check permissions.
    if (!checkInjectionPermission(focusedWindowHandle, entry.injectionState)) {
        return INPUT_EVENT_INJECTION_PERMISSION_DENIED;
    }

    if (focusedWindowHandle->getInfo()->paused) {
        ALOGI("Waiting because %s is paused", focusedWindowHandle->getName().c_str());
        return INPUT_EVENT_INJECTION_PENDING;
    }

    // If the event is a key event, then we must wait for all previous events to
    // complete before delivering it because previous events may have the
    // side-effect of transferring focus to a different window and we want to
    // ensure that the following keys are sent to the new window.
    //
    // Suppose the user touches a button in a window then immediately presses "A".
    // If the button causes a pop-up window to appear then we want to ensure that
    // the "A" key is delivered to the new pop-up window.  This is because users
    // often anticipate pending UI changes when typing on a keyboard.
    // To obtain this behavior, we must serialize key events with respect to all
    // prior input events.
    if (entry.type == EventEntry::Type::KEY) {
        if (shouldWaitToSendKeyLocked(currentTime, focusedWindowHandle->getName().c_str())) {
            *nextWakeupTime = *mKeyIsWaitingForEventsTimeout;
            return INPUT_EVENT_INJECTION_PENDING;
        }
    }

    // Success!  Output targets.
    addWindowTargetLocked(focusedWindowHandle,
                          InputTarget::FLAG_FOREGROUND | InputTarget::FLAG_DISPATCH_AS_IS,
                          BitSet32(0), inputTargets);

    // Done.
    return INPUT_EVENT_INJECTION_SUCCEEDED;
}

/**
 * Given a list of monitors, remove the ones we cannot find a connection for, and the ones
 * that are currently unresponsive.
 */
std::vector<TouchedMonitor> InputDispatcher::selectResponsiveMonitorsLocked(
        const std::vector<TouchedMonitor>& monitors) const {
    std::vector<TouchedMonitor> responsiveMonitors;
    std::copy_if(monitors.begin(), monitors.end(), std::back_inserter(responsiveMonitors),
                 [this](const TouchedMonitor& monitor) REQUIRES(mLock) {
                     sp<Connection> connection = getConnectionLocked(
                             monitor.monitor.inputChannel->getConnectionToken());
                     if (connection == nullptr) {
                         ALOGE("Could not find connection for monitor %s",
                               monitor.monitor.inputChannel->getName().c_str());
                         return false;
                     }
                     if (!connection->responsive) {
                         ALOGW("Unresponsive monitor %s will not get the new gesture",
                               connection->inputChannel->getName().c_str());
                         return false;
                     }
                     return true;
                 });
    return responsiveMonitors;
}

int32_t InputDispatcher::findTouchedWindowTargetsLocked(nsecs_t currentTime,
                                                        const MotionEntry& entry,
                                                        std::vector<InputTarget>& inputTargets,
                                                        nsecs_t* nextWakeupTime,
                                                        bool* outConflictingPointerActions) {
    ATRACE_CALL();
    enum InjectionPermission {
        INJECTION_PERMISSION_UNKNOWN,
        INJECTION_PERMISSION_GRANTED,
        INJECTION_PERMISSION_DENIED
    };

    // For security reasons, we defer updating the touch state until we are sure that
    // event injection will be allowed.
    int32_t displayId = entry.displayId;
    int32_t action = entry.action;
    int32_t maskedAction = action & AMOTION_EVENT_ACTION_MASK;

    // Update the touch state as needed based on the properties of the touch event.
    int32_t injectionResult = INPUT_EVENT_INJECTION_PENDING;
    InjectionPermission injectionPermission = INJECTION_PERMISSION_UNKNOWN;
    sp<InputWindowHandle> newHoverWindowHandle;

    // Copy current touch state into tempTouchState.
    // This state will be used to update mTouchStatesByDisplay at the end of this function.
    // If no state for the specified display exists, then our initial state will be empty.
    const TouchState* oldState = nullptr;
    TouchState tempTouchState;
    std::unordered_map<int32_t, TouchState>::iterator oldStateIt =
            mTouchStatesByDisplay.find(displayId);
    if (oldStateIt != mTouchStatesByDisplay.end()) {
        oldState = &(oldStateIt->second);
        tempTouchState.copyFrom(*oldState);
    }

    bool isSplit = tempTouchState.split;
    bool switchedDevice = tempTouchState.deviceId >= 0 && tempTouchState.displayId >= 0 &&
            (tempTouchState.deviceId != entry.deviceId || tempTouchState.source != entry.source ||
             tempTouchState.displayId != displayId);
    bool isHoverAction = (maskedAction == AMOTION_EVENT_ACTION_HOVER_MOVE ||
                          maskedAction == AMOTION_EVENT_ACTION_HOVER_ENTER ||
                          maskedAction == AMOTION_EVENT_ACTION_HOVER_EXIT);
    bool newGesture = (maskedAction == AMOTION_EVENT_ACTION_DOWN ||
                       maskedAction == AMOTION_EVENT_ACTION_SCROLL || isHoverAction);
    const bool isFromMouse = entry.source == AINPUT_SOURCE_MOUSE;
    bool wrongDevice = false;
    if (newGesture) {
        bool down = maskedAction == AMOTION_EVENT_ACTION_DOWN;
        if (switchedDevice && tempTouchState.down && !down && !isHoverAction) {
            ALOGI("Dropping event because a pointer for a different device is already down "
                  "in display %" PRId32,
                  displayId);
            // TODO: test multiple simultaneous input streams.
            injectionResult = INPUT_EVENT_INJECTION_FAILED;
            switchedDevice = false;
            wrongDevice = true;
            goto Failed;
        }
        tempTouchState.reset();
        tempTouchState.down = down;
        tempTouchState.deviceId = entry.deviceId;
        tempTouchState.source = entry.source;
        tempTouchState.displayId = displayId;
        isSplit = false;
    } else if (switchedDevice && maskedAction == AMOTION_EVENT_ACTION_MOVE) {
        ALOGI("Dropping move event because a pointer for a different device is already active "
              "in display %" PRId32,
              displayId);
        // TODO: test multiple simultaneous input streams.
        injectionResult = INPUT_EVENT_INJECTION_PERMISSION_DENIED;
        switchedDevice = false;
        wrongDevice = true;
        goto Failed;
    }

    if (newGesture || (isSplit && maskedAction == AMOTION_EVENT_ACTION_POINTER_DOWN)) {
        /* Case 1: New splittable pointer going down, or need target for hover or scroll. */

        int32_t x;
        int32_t y;
        int32_t pointerIndex = getMotionEventActionPointerIndex(action);
        // Always dispatch mouse events to cursor position.
        if (isFromMouse) {
            x = int32_t(entry.xCursorPosition);
            y = int32_t(entry.yCursorPosition);
        } else {
            x = int32_t(entry.pointerCoords[pointerIndex].getAxisValue(AMOTION_EVENT_AXIS_X));
            y = int32_t(entry.pointerCoords[pointerIndex].getAxisValue(AMOTION_EVENT_AXIS_Y));
        }
        bool isDown = maskedAction == AMOTION_EVENT_ACTION_DOWN;
        sp<InputWindowHandle> newTouchedWindowHandle =
                findTouchedWindowAtLocked(displayId, x, y, &tempTouchState,
                                          isDown /*addOutsideTargets*/, true /*addPortalWindows*/);

        std::vector<TouchedMonitor> newGestureMonitors = isDown
                ? findTouchedGestureMonitorsLocked(displayId, tempTouchState.portalWindows)
                : std::vector<TouchedMonitor>{};

        // Figure out whether splitting will be allowed for this window.
        if (newTouchedWindowHandle != nullptr &&
            newTouchedWindowHandle->getInfo()->supportsSplitTouch()) {
            // New window supports splitting, but we should never split mouse events.
            isSplit = !isFromMouse;
        } else if (isSplit) {
            // New window does not support splitting but we have already split events.
            // Ignore the new window.
            newTouchedWindowHandle = nullptr;
        }

        // Handle the case where we did not find a window.
        if (newTouchedWindowHandle == nullptr) {
            // Try to assign the pointer to the first foreground window we find, if there is one.
            newTouchedWindowHandle = tempTouchState.getFirstForegroundWindowHandle();
        }

        if (newTouchedWindowHandle != nullptr && newTouchedWindowHandle->getInfo()->paused) {
            ALOGI("Not sending touch event to %s because it is paused",
                  newTouchedWindowHandle->getName().c_str());
            newTouchedWindowHandle = nullptr;
        }

        if (newTouchedWindowHandle != nullptr) {
            sp<Connection> connection = getConnectionLocked(newTouchedWindowHandle->getToken());
            if (connection == nullptr) {
                ALOGI("Could not find connection for %s",
                      newTouchedWindowHandle->getName().c_str());
                newTouchedWindowHandle = nullptr;
            } else if (!connection->responsive) {
                // don't send the new touch to an unresponsive window
                ALOGW("Unresponsive window %s will not get the new gesture at %" PRIu64,
                      newTouchedWindowHandle->getName().c_str(), entry.eventTime);
                newTouchedWindowHandle = nullptr;
            }
        }

        // Also don't send the new touch event to unresponsive gesture monitors
        newGestureMonitors = selectResponsiveMonitorsLocked(newGestureMonitors);

        if (newTouchedWindowHandle == nullptr && newGestureMonitors.empty()) {
            ALOGI("Dropping event because there is no touchable window or gesture monitor at "
                  "(%d, %d) in display %" PRId32 ".",
                  x, y, displayId);
            injectionResult = INPUT_EVENT_INJECTION_FAILED;
            goto Failed;
        }

        if (newTouchedWindowHandle != nullptr) {
            // Set target flags.
            int32_t targetFlags = InputTarget::FLAG_FOREGROUND | InputTarget::FLAG_DISPATCH_AS_IS;
            if (isSplit) {
                targetFlags |= InputTarget::FLAG_SPLIT;
            }
            if (isWindowObscuredAtPointLocked(newTouchedWindowHandle, x, y)) {
                targetFlags |= InputTarget::FLAG_WINDOW_IS_OBSCURED;
            } else if (isWindowObscuredLocked(newTouchedWindowHandle)) {
                targetFlags |= InputTarget::FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
            }

            // Update hover state.
            if (isHoverAction) {
                newHoverWindowHandle = newTouchedWindowHandle;
            } else if (maskedAction == AMOTION_EVENT_ACTION_SCROLL) {
                newHoverWindowHandle = mLastHoverWindowHandle;
            }

            // Update the temporary touch state.
            BitSet32 pointerIds;
            if (isSplit) {
                uint32_t pointerId = entry.pointerProperties[pointerIndex].id;
                pointerIds.markBit(pointerId);
            }
            tempTouchState.addOrUpdateWindow(newTouchedWindowHandle, targetFlags, pointerIds);
        }

        tempTouchState.addGestureMonitors(newGestureMonitors);
    } else {
        /* Case 2: Pointer move, up, cancel or non-splittable pointer down. */

        // If the pointer is not currently down, then ignore the event.
        if (!tempTouchState.down) {
            if (DEBUG_FOCUS) {
                ALOGD("Dropping event because the pointer is not down or we previously "
                      "dropped the pointer down event in display %" PRId32,
                      displayId);
            }
            injectionResult = INPUT_EVENT_INJECTION_FAILED;
            goto Failed;
        }

        // Check whether touches should slip outside of the current foreground window.
        if (maskedAction == AMOTION_EVENT_ACTION_MOVE && entry.pointerCount == 1 &&
            tempTouchState.isSlippery()) {
            int32_t x = int32_t(entry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X));
            int32_t y = int32_t(entry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y));

            sp<InputWindowHandle> oldTouchedWindowHandle =
                    tempTouchState.getFirstForegroundWindowHandle();
            sp<InputWindowHandle> newTouchedWindowHandle =
                    findTouchedWindowAtLocked(displayId, x, y, &tempTouchState);
            if (oldTouchedWindowHandle != newTouchedWindowHandle &&
                oldTouchedWindowHandle != nullptr && newTouchedWindowHandle != nullptr) {
                if (DEBUG_FOCUS) {
                    ALOGD("Touch is slipping out of window %s into window %s in display %" PRId32,
                          oldTouchedWindowHandle->getName().c_str(),
                          newTouchedWindowHandle->getName().c_str(), displayId);
                }
                // Make a slippery exit from the old window.
                tempTouchState.addOrUpdateWindow(oldTouchedWindowHandle,
                                                 InputTarget::FLAG_DISPATCH_AS_SLIPPERY_EXIT,
                                                 BitSet32(0));

                // Make a slippery entrance into the new window.
                if (newTouchedWindowHandle->getInfo()->supportsSplitTouch()) {
                    isSplit = true;
                }

                int32_t targetFlags =
                        InputTarget::FLAG_FOREGROUND | InputTarget::FLAG_DISPATCH_AS_SLIPPERY_ENTER;
                if (isSplit) {
                    targetFlags |= InputTarget::FLAG_SPLIT;
                }
                if (isWindowObscuredAtPointLocked(newTouchedWindowHandle, x, y)) {
                    targetFlags |= InputTarget::FLAG_WINDOW_IS_OBSCURED;
                }

                BitSet32 pointerIds;
                if (isSplit) {
                    pointerIds.markBit(entry.pointerProperties[0].id);
                }
                tempTouchState.addOrUpdateWindow(newTouchedWindowHandle, targetFlags, pointerIds);
            }
        }
    }

    if (newHoverWindowHandle != mLastHoverWindowHandle) {
        // Let the previous window know that the hover sequence is over.
        if (mLastHoverWindowHandle != nullptr) {
#if DEBUG_HOVER
            ALOGD("Sending hover exit event to window %s.",
                  mLastHoverWindowHandle->getName().c_str());
#endif
            tempTouchState.addOrUpdateWindow(mLastHoverWindowHandle,
                                             InputTarget::FLAG_DISPATCH_AS_HOVER_EXIT, BitSet32(0));
        }

        // Let the new window know that the hover sequence is starting.
        if (newHoverWindowHandle != nullptr) {
#if DEBUG_HOVER
            ALOGD("Sending hover enter event to window %s.",
                  newHoverWindowHandle->getName().c_str());
#endif
            tempTouchState.addOrUpdateWindow(newHoverWindowHandle,
                                             InputTarget::FLAG_DISPATCH_AS_HOVER_ENTER,
                                             BitSet32(0));
        }
    }

    // Check permission to inject into all touched foreground windows and ensure there
    // is at least one touched foreground window.
    {
        bool haveForegroundWindow = false;
        for (const TouchedWindow& touchedWindow : tempTouchState.windows) {
            if (touchedWindow.targetFlags & InputTarget::FLAG_FOREGROUND) {
                haveForegroundWindow = true;
                if (!checkInjectionPermission(touchedWindow.windowHandle, entry.injectionState)) {
                    injectionResult = INPUT_EVENT_INJECTION_PERMISSION_DENIED;
                    injectionPermission = INJECTION_PERMISSION_DENIED;
                    goto Failed;
                }
            }
        }
        bool hasGestureMonitor = !tempTouchState.gestureMonitors.empty();
        if (!haveForegroundWindow && !hasGestureMonitor) {
            ALOGI("Dropping event because there is no touched foreground window in display "
                  "%" PRId32 " or gesture monitor to receive it.",
                  displayId);
            injectionResult = INPUT_EVENT_INJECTION_FAILED;
            goto Failed;
        }

        // Permission granted to injection into all touched foreground windows.
        injectionPermission = INJECTION_PERMISSION_GRANTED;
    }

    // Check whether windows listening for outside touches are owned by the same UID. If it is
    // set the policy flag that we will not reveal coordinate information to this window.
    if (maskedAction == AMOTION_EVENT_ACTION_DOWN) {
        sp<InputWindowHandle> foregroundWindowHandle =
                tempTouchState.getFirstForegroundWindowHandle();
        if (foregroundWindowHandle) {
            const int32_t foregroundWindowUid = foregroundWindowHandle->getInfo()->ownerUid;
            for (const TouchedWindow& touchedWindow : tempTouchState.windows) {
                if (touchedWindow.targetFlags & InputTarget::FLAG_DISPATCH_AS_OUTSIDE) {
                    sp<InputWindowHandle> inputWindowHandle = touchedWindow.windowHandle;
                    if (inputWindowHandle->getInfo()->ownerUid != foregroundWindowUid) {
                        tempTouchState.addOrUpdateWindow(inputWindowHandle,
                                                         InputTarget::FLAG_ZERO_COORDS,
                                                         BitSet32(0));
                    }
                }
            }
        }
    }

    // If this is the first pointer going down and the touched window has a wallpaper
    // then also add the touched wallpaper windows so they are locked in for the duration
    // of the touch gesture.
    // We do not collect wallpapers during HOVER_MOVE or SCROLL because the wallpaper
    // engine only supports touch events.  We would need to add a mechanism similar
    // to View.onGenericMotionEvent to enable wallpapers to handle these events.
    if (maskedAction == AMOTION_EVENT_ACTION_DOWN) {
        sp<InputWindowHandle> foregroundWindowHandle =
                tempTouchState.getFirstForegroundWindowHandle();
        if (foregroundWindowHandle && foregroundWindowHandle->getInfo()->hasWallpaper) {
            const std::vector<sp<InputWindowHandle>> windowHandles =
                    getWindowHandlesLocked(displayId);
            for (const sp<InputWindowHandle>& windowHandle : windowHandles) {
                const InputWindowInfo* info = windowHandle->getInfo();
                if (info->displayId == displayId &&
                    windowHandle->getInfo()->layoutParamsType == InputWindowInfo::TYPE_WALLPAPER) {
                    tempTouchState
                            .addOrUpdateWindow(windowHandle,
                                               InputTarget::FLAG_WINDOW_IS_OBSCURED |
                                                       InputTarget::
                                                               FLAG_WINDOW_IS_PARTIALLY_OBSCURED |
                                                       InputTarget::FLAG_DISPATCH_AS_IS,
                                               BitSet32(0));
                }
            }
        }
    }

    // Success!  Output targets.
    injectionResult = INPUT_EVENT_INJECTION_SUCCEEDED;

    for (const TouchedWindow& touchedWindow : tempTouchState.windows) {
        addWindowTargetLocked(touchedWindow.windowHandle, touchedWindow.targetFlags,
                              touchedWindow.pointerIds, inputTargets);
    }

    for (const TouchedMonitor& touchedMonitor : tempTouchState.gestureMonitors) {
        addMonitoringTargetLocked(touchedMonitor.monitor, touchedMonitor.xOffset,
                                  touchedMonitor.yOffset, inputTargets);
    }

    // Drop the outside or hover touch windows since we will not care about them
    // in the next iteration.
    tempTouchState.filterNonAsIsTouchWindows();

Failed:
    // Check injection permission once and for all.
    if (injectionPermission == INJECTION_PERMISSION_UNKNOWN) {
        if (checkInjectionPermission(nullptr, entry.injectionState)) {
            injectionPermission = INJECTION_PERMISSION_GRANTED;
        } else {
            injectionPermission = INJECTION_PERMISSION_DENIED;
        }
    }

    if (injectionPermission != INJECTION_PERMISSION_GRANTED) {
        return injectionResult;
    }

    // Update final pieces of touch state if the injector had permission.
    if (!wrongDevice) {
        if (switchedDevice) {
            if (DEBUG_FOCUS) {
                ALOGD("Conflicting pointer actions: Switched to a different device.");
            }
            *outConflictingPointerActions = true;
        }

        if (isHoverAction) {
            // Started hovering, therefore no longer down.
            if (oldState && oldState->down) {
                if (DEBUG_FOCUS) {
                    ALOGD("Conflicting pointer actions: Hover received while pointer was "
                          "down.");
                }
                *outConflictingPointerActions = true;
            }
            tempTouchState.reset();
            if (maskedAction == AMOTION_EVENT_ACTION_HOVER_ENTER ||
                maskedAction == AMOTION_EVENT_ACTION_HOVER_MOVE) {
                tempTouchState.deviceId = entry.deviceId;
                tempTouchState.source = entry.source;
                tempTouchState.displayId = displayId;
            }
        } else if (maskedAction == AMOTION_EVENT_ACTION_UP ||
                   maskedAction == AMOTION_EVENT_ACTION_CANCEL) {
            // All pointers up or canceled.
            tempTouchState.reset();
        } else if (maskedAction == AMOTION_EVENT_ACTION_DOWN) {
            // First pointer went down.
            if (oldState && oldState->down) {
                if (DEBUG_FOCUS) {
                    ALOGD("Conflicting pointer actions: Down received while already down.");
                }
                *outConflictingPointerActions = true;
            }
        } else if (maskedAction == AMOTION_EVENT_ACTION_POINTER_UP) {
            // One pointer went up.
            if (isSplit) {
                int32_t pointerIndex = getMotionEventActionPointerIndex(action);
                uint32_t pointerId = entry.pointerProperties[pointerIndex].id;

                for (size_t i = 0; i < tempTouchState.windows.size();) {
                    TouchedWindow& touchedWindow = tempTouchState.windows[i];
                    if (touchedWindow.targetFlags & InputTarget::FLAG_SPLIT) {
                        touchedWindow.pointerIds.clearBit(pointerId);
                        if (touchedWindow.pointerIds.isEmpty()) {
                            tempTouchState.windows.erase(tempTouchState.windows.begin() + i);
                            continue;
                        }
                    }
                    i += 1;
                }
            }
        }

        // Save changes unless the action was scroll in which case the temporary touch
        // state was only valid for this one action.
        if (maskedAction != AMOTION_EVENT_ACTION_SCROLL) {
            if (tempTouchState.displayId >= 0) {
                mTouchStatesByDisplay[displayId] = tempTouchState;
            } else {
                mTouchStatesByDisplay.erase(displayId);
            }
        }

        // Update hover state.
        mLastHoverWindowHandle = newHoverWindowHandle;
    }

    return injectionResult;
}

void InputDispatcher::addWindowTargetLocked(const sp<InputWindowHandle>& windowHandle,
                                            int32_t targetFlags, BitSet32 pointerIds,
                                            std::vector<InputTarget>& inputTargets) {
    std::vector<InputTarget>::iterator it =
            std::find_if(inputTargets.begin(), inputTargets.end(),
                         [&windowHandle](const InputTarget& inputTarget) {
                             return inputTarget.inputChannel->getConnectionToken() ==
                                     windowHandle->getToken();
                         });

    const InputWindowInfo* windowInfo = windowHandle->getInfo();

    if (it == inputTargets.end()) {
        InputTarget inputTarget;
        sp<InputChannel> inputChannel = getInputChannelLocked(windowHandle->getToken());
        if (inputChannel == nullptr) {
            ALOGW("Window %s already unregistered input channel", windowHandle->getName().c_str());
            return;
        }
        inputTarget.inputChannel = inputChannel;
        inputTarget.flags = targetFlags;
        inputTarget.globalScaleFactor = windowInfo->globalScaleFactor;
        inputTargets.push_back(inputTarget);
        it = inputTargets.end() - 1;
    }

    ALOG_ASSERT(it->flags == targetFlags);
    ALOG_ASSERT(it->globalScaleFactor == windowInfo->globalScaleFactor);

    it->addPointers(pointerIds, -windowInfo->frameLeft, -windowInfo->frameTop,
                    windowInfo->windowXScale, windowInfo->windowYScale);
}

void InputDispatcher::addGlobalMonitoringTargetsLocked(std::vector<InputTarget>& inputTargets,
                                                       int32_t displayId, float xOffset,
                                                       float yOffset) {
    std::unordered_map<int32_t, std::vector<Monitor>>::const_iterator it =
            mGlobalMonitorsByDisplay.find(displayId);

    if (it != mGlobalMonitorsByDisplay.end()) {
        const std::vector<Monitor>& monitors = it->second;
        for (const Monitor& monitor : monitors) {
            addMonitoringTargetLocked(monitor, xOffset, yOffset, inputTargets);
        }
    }
}

void InputDispatcher::addMonitoringTargetLocked(const Monitor& monitor, float xOffset,
                                                float yOffset,
                                                std::vector<InputTarget>& inputTargets) {
    InputTarget target;
    target.inputChannel = monitor.inputChannel;
    target.flags = InputTarget::FLAG_DISPATCH_AS_IS;
    target.setDefaultPointerInfo(xOffset, yOffset, 1 /* windowXScale */, 1 /* windowYScale */);
    inputTargets.push_back(target);
}

bool InputDispatcher::checkInjectionPermission(const sp<InputWindowHandle>& windowHandle,
                                               const InjectionState* injectionState) {
    if (injectionState &&
        (windowHandle == nullptr ||
         windowHandle->getInfo()->ownerUid != injectionState->injectorUid) &&
        !hasInjectionPermission(injectionState->injectorPid, injectionState->injectorUid)) {
        if (windowHandle != nullptr) {
            ALOGW("Permission denied: injecting event from pid %d uid %d to window %s "
                  "owned by uid %d",
                  injectionState->injectorPid, injectionState->injectorUid,
                  windowHandle->getName().c_str(), windowHandle->getInfo()->ownerUid);
        } else {
            ALOGW("Permission denied: injecting event from pid %d uid %d",
                  injectionState->injectorPid, injectionState->injectorUid);
        }
        return false;
    }
    return true;
}

/**
 * Indicate whether one window handle should be considered as obscuring
 * another window handle. We only check a few preconditions. Actually
 * checking the bounds is left to the caller.
 */
static bool canBeObscuredBy(const sp<InputWindowHandle>& windowHandle,
                            const sp<InputWindowHandle>& otherHandle) {
    // Compare by token so cloned layers aren't counted
    if (haveSameToken(windowHandle, otherHandle)) {
        return false;
    }
    auto info = windowHandle->getInfo();
    auto otherInfo = otherHandle->getInfo();
    if (!otherInfo->visible) {
        return false;
    } else if (info->ownerPid == otherInfo->ownerPid) {
        // If ownerPid is the same we don't generate occlusion events as there
        // is no in-process security boundary.
        return false;
    } else if (otherInfo->isTrustedOverlay()) {
        return false;
    } else if (otherInfo->displayId != info->displayId) {
        return false;
    }
    return true;
}

bool InputDispatcher::isWindowObscuredAtPointLocked(const sp<InputWindowHandle>& windowHandle,
                                                    int32_t x, int32_t y) const {
    int32_t displayId = windowHandle->getInfo()->displayId;
    const std::vector<sp<InputWindowHandle>> windowHandles = getWindowHandlesLocked(displayId);
    for (const sp<InputWindowHandle>& otherHandle : windowHandles) {
        if (windowHandle == otherHandle) {
            break; // All future windows are below us. Exit early.
        }
        const InputWindowInfo* otherInfo = otherHandle->getInfo();
          if (canBeObscuredBy(windowHandle, otherHandle) &&
            otherInfo->frameContainsPoint(x, y)) {
            return true;
        }
    }
    return false;
}

bool InputDispatcher::isWindowObscuredLocked(const sp<InputWindowHandle>& windowHandle) const {
    int32_t displayId = windowHandle->getInfo()->displayId;
    const std::vector<sp<InputWindowHandle>> windowHandles = getWindowHandlesLocked(displayId);
    const InputWindowInfo* windowInfo = windowHandle->getInfo();
    for (const sp<InputWindowHandle>& otherHandle : windowHandles) {
        if (windowHandle == otherHandle) {
            break; // All future windows are below us. Exit early.
        }

        const InputWindowInfo* otherInfo = otherHandle->getInfo();
        if (canBeObscuredBy(windowHandle, otherHandle) &&
            otherInfo->overlaps(windowInfo)) {
            return true;
        }
    }
    return false;
}

std::string InputDispatcher::getApplicationWindowLabel(
        const sp<InputApplicationHandle>& applicationHandle,
        const sp<InputWindowHandle>& windowHandle) {
    if (applicationHandle != nullptr) {
        if (windowHandle != nullptr) {
            return applicationHandle->getName() + " - " + windowHandle->getName();
        } else {
            return applicationHandle->getName();
        }
    } else if (windowHandle != nullptr) {
        return windowHandle->getInfo()->applicationInfo.name + " - " + windowHandle->getName();
    } else {
        return "<unknown application or window>";
    }
}

void InputDispatcher::pokeUserActivityLocked(const EventEntry& eventEntry) {
    if (eventEntry.type == EventEntry::Type::FOCUS) {
        // Focus events are passed to apps, but do not represent user activity.
        return;
    }
    int32_t displayId = getTargetDisplayId(eventEntry);
    sp<InputWindowHandle> focusedWindowHandle =
            getValueByKey(mFocusedWindowHandlesByDisplay, displayId);
    if (focusedWindowHandle != nullptr) {
        const InputWindowInfo* info = focusedWindowHandle->getInfo();
        if (info->inputFeatures & InputWindowInfo::INPUT_FEATURE_DISABLE_USER_ACTIVITY) {
#if DEBUG_DISPATCH_CYCLE
            ALOGD("Not poking user activity: disabled by window '%s'.", info->name.c_str());
#endif
            return;
        }
    }

    int32_t eventType = USER_ACTIVITY_EVENT_OTHER;
    switch (eventEntry.type) {
        case EventEntry::Type::MOTION: {
            const MotionEntry& motionEntry = static_cast<const MotionEntry&>(eventEntry);
            if (motionEntry.action == AMOTION_EVENT_ACTION_CANCEL) {
                return;
            }

            if (MotionEvent::isTouchEvent(motionEntry.source, motionEntry.action)) {
                eventType = USER_ACTIVITY_EVENT_TOUCH;
            }
            break;
        }
        case EventEntry::Type::KEY: {
            const KeyEntry& keyEntry = static_cast<const KeyEntry&>(eventEntry);
            if (keyEntry.flags & AKEY_EVENT_FLAG_CANCELED) {
                return;
            }
            eventType = USER_ACTIVITY_EVENT_BUTTON;
            break;
        }
        case EventEntry::Type::FOCUS:
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET: {
            LOG_ALWAYS_FATAL("%s events are not user activity",
                             EventEntry::typeToString(eventEntry.type));
            break;
        }
    }

    std::unique_ptr<CommandEntry> commandEntry =
            std::make_unique<CommandEntry>(&InputDispatcher::doPokeUserActivityLockedInterruptible);
    commandEntry->eventTime = eventEntry.eventTime;
    commandEntry->userActivityEventType = eventType;
    postCommandLocked(std::move(commandEntry));
}

void InputDispatcher::prepareDispatchCycleLocked(nsecs_t currentTime,
                                                 const sp<Connection>& connection,
                                                 EventEntry* eventEntry,
                                                 const InputTarget& inputTarget) {
    if (ATRACE_ENABLED()) {
        std::string message =
                StringPrintf("prepareDispatchCycleLocked(inputChannel=%s, id=0x%" PRIx32 ")",
                             connection->getInputChannelName().c_str(), eventEntry->id);
        ATRACE_NAME(message.c_str());
    }
#if DEBUG_DISPATCH_CYCLE
    ALOGD("channel '%s' ~ prepareDispatchCycle - flags=0x%08x, "
          "globalScaleFactor=%f, pointerIds=0x%x %s",
          connection->getInputChannelName().c_str(), inputTarget.flags,
          inputTarget.globalScaleFactor, inputTarget.pointerIds.value,
          inputTarget.getPointerInfoString().c_str());
#endif

    // Skip this event if the connection status is not normal.
    // We don't want to enqueue additional outbound events if the connection is broken.
    if (connection->status != Connection::STATUS_NORMAL) {
#if DEBUG_DISPATCH_CYCLE
        ALOGD("channel '%s' ~ Dropping event because the channel status is %s",
              connection->getInputChannelName().c_str(), connection->getStatusLabel());
#endif
        return;
    }

    // Split a motion event if needed.
    if (inputTarget.flags & InputTarget::FLAG_SPLIT) {
        LOG_ALWAYS_FATAL_IF(eventEntry->type != EventEntry::Type::MOTION,
                            "Entry type %s should not have FLAG_SPLIT",
                            EventEntry::typeToString(eventEntry->type));

        const MotionEntry& originalMotionEntry = static_cast<const MotionEntry&>(*eventEntry);
        if (inputTarget.pointerIds.count() != originalMotionEntry.pointerCount) {
            MotionEntry* splitMotionEntry =
                    splitMotionEvent(originalMotionEntry, inputTarget.pointerIds);
            if (!splitMotionEntry) {
                return; // split event was dropped
            }
            if (DEBUG_FOCUS) {
                ALOGD("channel '%s' ~ Split motion event.",
                      connection->getInputChannelName().c_str());
                logOutboundMotionDetails("  ", *splitMotionEntry);
            }
            enqueueDispatchEntriesLocked(currentTime, connection, splitMotionEntry, inputTarget);
            splitMotionEntry->release();
            return;
        }
    }

    // Not splitting.  Enqueue dispatch entries for the event as is.
    enqueueDispatchEntriesLocked(currentTime, connection, eventEntry, inputTarget);
}

void InputDispatcher::enqueueDispatchEntriesLocked(nsecs_t currentTime,
                                                   const sp<Connection>& connection,
                                                   EventEntry* eventEntry,
                                                   const InputTarget& inputTarget) {
    if (ATRACE_ENABLED()) {
        std::string message =
                StringPrintf("enqueueDispatchEntriesLocked(inputChannel=%s, id=0x%" PRIx32 ")",
                             connection->getInputChannelName().c_str(), eventEntry->id);
        ATRACE_NAME(message.c_str());
    }

    bool wasEmpty = connection->outboundQueue.empty();

    // Enqueue dispatch entries for the requested modes.
    enqueueDispatchEntryLocked(connection, eventEntry, inputTarget,
                               InputTarget::FLAG_DISPATCH_AS_HOVER_EXIT);
    enqueueDispatchEntryLocked(connection, eventEntry, inputTarget,
                               InputTarget::FLAG_DISPATCH_AS_OUTSIDE);
    enqueueDispatchEntryLocked(connection, eventEntry, inputTarget,
                               InputTarget::FLAG_DISPATCH_AS_HOVER_ENTER);
    enqueueDispatchEntryLocked(connection, eventEntry, inputTarget,
                               InputTarget::FLAG_DISPATCH_AS_IS);
    enqueueDispatchEntryLocked(connection, eventEntry, inputTarget,
                               InputTarget::FLAG_DISPATCH_AS_SLIPPERY_EXIT);
    enqueueDispatchEntryLocked(connection, eventEntry, inputTarget,
                               InputTarget::FLAG_DISPATCH_AS_SLIPPERY_ENTER);

    // If the outbound queue was previously empty, start the dispatch cycle going.
    if (wasEmpty && !connection->outboundQueue.empty()) {
        startDispatchCycleLocked(currentTime, connection);
    }
}

void InputDispatcher::enqueueDispatchEntryLocked(const sp<Connection>& connection,
                                                 EventEntry* eventEntry,
                                                 const InputTarget& inputTarget,
                                                 int32_t dispatchMode) {
    if (ATRACE_ENABLED()) {
        std::string message = StringPrintf("enqueueDispatchEntry(inputChannel=%s, dispatchMode=%s)",
                                           connection->getInputChannelName().c_str(),
                                           dispatchModeToString(dispatchMode).c_str());
        ATRACE_NAME(message.c_str());
    }
    int32_t inputTargetFlags = inputTarget.flags;
    if (!(inputTargetFlags & dispatchMode)) {
        return;
    }
    inputTargetFlags = (inputTargetFlags & ~InputTarget::FLAG_DISPATCH_MASK) | dispatchMode;

    // This is a new event.
    // Enqueue a new dispatch entry onto the outbound queue for this connection.
    std::unique_ptr<DispatchEntry> dispatchEntry =
            createDispatchEntry(inputTarget, eventEntry, inputTargetFlags);

    // Use the eventEntry from dispatchEntry since the entry may have changed and can now be a
    // different EventEntry than what was passed in.
    EventEntry* newEntry = dispatchEntry->eventEntry;
    // Apply target flags and update the connection's input state.
    switch (newEntry->type) {
        case EventEntry::Type::KEY: {
            const KeyEntry& keyEntry = static_cast<const KeyEntry&>(*newEntry);
            dispatchEntry->resolvedEventId = keyEntry.id;
            dispatchEntry->resolvedAction = keyEntry.action;
            dispatchEntry->resolvedFlags = keyEntry.flags;

            if (!connection->inputState.trackKey(keyEntry, dispatchEntry->resolvedAction,
                                                 dispatchEntry->resolvedFlags)) {
#if DEBUG_DISPATCH_CYCLE
                ALOGD("channel '%s' ~ enqueueDispatchEntryLocked: skipping inconsistent key event",
                      connection->getInputChannelName().c_str());
#endif
                return; // skip the inconsistent event
            }
            break;
        }

        case EventEntry::Type::MOTION: {
            const MotionEntry& motionEntry = static_cast<const MotionEntry&>(*newEntry);
            // Assign a default value to dispatchEntry that will never be generated by InputReader,
            // and assign a InputDispatcher value if it doesn't change in the if-else chain below.
            constexpr int32_t DEFAULT_RESOLVED_EVENT_ID =
                    static_cast<int32_t>(IdGenerator::Source::OTHER);
            dispatchEntry->resolvedEventId = DEFAULT_RESOLVED_EVENT_ID;
            if (dispatchMode & InputTarget::FLAG_DISPATCH_AS_OUTSIDE) {
                dispatchEntry->resolvedAction = AMOTION_EVENT_ACTION_OUTSIDE;
            } else if (dispatchMode & InputTarget::FLAG_DISPATCH_AS_HOVER_EXIT) {
                dispatchEntry->resolvedAction = AMOTION_EVENT_ACTION_HOVER_EXIT;
            } else if (dispatchMode & InputTarget::FLAG_DISPATCH_AS_HOVER_ENTER) {
                dispatchEntry->resolvedAction = AMOTION_EVENT_ACTION_HOVER_ENTER;
            } else if (dispatchMode & InputTarget::FLAG_DISPATCH_AS_SLIPPERY_EXIT) {
                dispatchEntry->resolvedAction = AMOTION_EVENT_ACTION_CANCEL;
            } else if (dispatchMode & InputTarget::FLAG_DISPATCH_AS_SLIPPERY_ENTER) {
                dispatchEntry->resolvedAction = AMOTION_EVENT_ACTION_DOWN;
            } else {
                dispatchEntry->resolvedAction = motionEntry.action;
                dispatchEntry->resolvedEventId = motionEntry.id;
            }
            if (dispatchEntry->resolvedAction == AMOTION_EVENT_ACTION_HOVER_MOVE &&
                !connection->inputState.isHovering(motionEntry.deviceId, motionEntry.source,
                                                   motionEntry.displayId)) {
#if DEBUG_DISPATCH_CYCLE
                ALOGD("channel '%s' ~ enqueueDispatchEntryLocked: filling in missing hover enter "
                      "event",
                      connection->getInputChannelName().c_str());
#endif
                dispatchEntry->resolvedAction = AMOTION_EVENT_ACTION_HOVER_ENTER;
            }

            dispatchEntry->resolvedFlags = motionEntry.flags;
            if (dispatchEntry->targetFlags & InputTarget::FLAG_WINDOW_IS_OBSCURED) {
                dispatchEntry->resolvedFlags |= AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED;
            }
            if (dispatchEntry->targetFlags & InputTarget::FLAG_WINDOW_IS_PARTIALLY_OBSCURED) {
                dispatchEntry->resolvedFlags |= AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
            }

            if (!connection->inputState.trackMotion(motionEntry, dispatchEntry->resolvedAction,
                                                    dispatchEntry->resolvedFlags)) {
#if DEBUG_DISPATCH_CYCLE
                ALOGD("channel '%s' ~ enqueueDispatchEntryLocked: skipping inconsistent motion "
                      "event",
                      connection->getInputChannelName().c_str());
#endif
                return; // skip the inconsistent event
            }

            dispatchEntry->resolvedEventId =
                    dispatchEntry->resolvedEventId == DEFAULT_RESOLVED_EVENT_ID
                    ? mIdGenerator.nextId()
                    : motionEntry.id;
            if (ATRACE_ENABLED() && dispatchEntry->resolvedEventId != motionEntry.id) {
                std::string message = StringPrintf("Transmute MotionEvent(id=0x%" PRIx32
                                                   ") to MotionEvent(id=0x%" PRIx32 ").",
                                                   motionEntry.id, dispatchEntry->resolvedEventId);
                ATRACE_NAME(message.c_str());
            }

            dispatchPointerDownOutsideFocus(motionEntry.source, dispatchEntry->resolvedAction,
                                            inputTarget.inputChannel->getConnectionToken());

            break;
        }
        case EventEntry::Type::FOCUS: {
            break;
        }
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET: {
            LOG_ALWAYS_FATAL("%s events should not go to apps",
                             EventEntry::typeToString(newEntry->type));
            break;
        }
    }

    // Remember that we are waiting for this dispatch to complete.
    if (dispatchEntry->hasForegroundTarget()) {
        incrementPendingForegroundDispatches(newEntry);
    }

    // Enqueue the dispatch entry.
    connection->outboundQueue.push_back(dispatchEntry.release());
    traceOutboundQueueLength(connection);
}

void InputDispatcher::dispatchPointerDownOutsideFocus(uint32_t source, int32_t action,
                                                      const sp<IBinder>& newToken) {
    int32_t maskedAction = action & AMOTION_EVENT_ACTION_MASK;
    uint32_t maskedSource = source & AINPUT_SOURCE_CLASS_MASK;
    if (maskedSource != AINPUT_SOURCE_CLASS_POINTER || maskedAction != AMOTION_EVENT_ACTION_DOWN) {
        return;
    }

    sp<InputWindowHandle> inputWindowHandle = getWindowHandleLocked(newToken);
    if (inputWindowHandle == nullptr) {
        return;
    }

    sp<InputWindowHandle> focusedWindowHandle =
            getValueByKey(mFocusedWindowHandlesByDisplay, mFocusedDisplayId);

    bool hasFocusChanged = !focusedWindowHandle || focusedWindowHandle->getToken() != newToken;

    if (!hasFocusChanged) {
        return;
    }

    std::unique_ptr<CommandEntry> commandEntry = std::make_unique<CommandEntry>(
            &InputDispatcher::doOnPointerDownOutsideFocusLockedInterruptible);
    commandEntry->newToken = newToken;
    postCommandLocked(std::move(commandEntry));
}

void InputDispatcher::startDispatchCycleLocked(nsecs_t currentTime,
                                               const sp<Connection>& connection) {
    if (ATRACE_ENABLED()) {
        std::string message = StringPrintf("startDispatchCycleLocked(inputChannel=%s)",
                                           connection->getInputChannelName().c_str());
        ATRACE_NAME(message.c_str());
    }
#if DEBUG_DISPATCH_CYCLE
    ALOGD("channel '%s' ~ startDispatchCycle", connection->getInputChannelName().c_str());
#endif

    while (connection->status == Connection::STATUS_NORMAL && !connection->outboundQueue.empty()) {
        DispatchEntry* dispatchEntry = connection->outboundQueue.front();
        dispatchEntry->deliveryTime = currentTime;
        const nsecs_t timeout =
                getDispatchingTimeoutLocked(connection->inputChannel->getConnectionToken());
        dispatchEntry->timeoutTime = currentTime + timeout;

        // Publish the event.
        status_t status;
        EventEntry* eventEntry = dispatchEntry->eventEntry;
        switch (eventEntry->type) {
            case EventEntry::Type::KEY: {
                const KeyEntry* keyEntry = static_cast<KeyEntry*>(eventEntry);
                std::array<uint8_t, 32> hmac = getSignature(*keyEntry, *dispatchEntry);

                // Publish the key event.
                status =
                        connection->inputPublisher
                                .publishKeyEvent(dispatchEntry->seq, dispatchEntry->resolvedEventId,
                                                 keyEntry->deviceId, keyEntry->source,
                                                 keyEntry->displayId, std::move(hmac),
                                                 dispatchEntry->resolvedAction,
                                                 dispatchEntry->resolvedFlags, keyEntry->keyCode,
                                                 keyEntry->scanCode, keyEntry->metaState,
                                                 keyEntry->repeatCount, keyEntry->downTime,
                                                 keyEntry->eventTime);
                break;
            }

            case EventEntry::Type::MOTION: {
                MotionEntry* motionEntry = static_cast<MotionEntry*>(eventEntry);

                PointerCoords scaledCoords[MAX_POINTERS];
                const PointerCoords* usingCoords = motionEntry->pointerCoords;

                // Set the X and Y offset and X and Y scale depending on the input source.
                float xOffset = 0.0f, yOffset = 0.0f;
                float xScale = 1.0f, yScale = 1.0f;
                if ((motionEntry->source & AINPUT_SOURCE_CLASS_POINTER) &&
                    !(dispatchEntry->targetFlags & InputTarget::FLAG_ZERO_COORDS)) {
                    float globalScaleFactor = dispatchEntry->globalScaleFactor;
                    xScale = dispatchEntry->windowXScale;
                    yScale = dispatchEntry->windowYScale;
                    xOffset = dispatchEntry->xOffset * xScale;
                    yOffset = dispatchEntry->yOffset * yScale;
                    if (globalScaleFactor != 1.0f) {
                        for (uint32_t i = 0; i < motionEntry->pointerCount; i++) {
                            scaledCoords[i] = motionEntry->pointerCoords[i];
                            // Don't apply window scale here since we don't want scale to affect raw
                            // coordinates. The scale will be sent back to the client and applied
                            // later when requesting relative coordinates.
                            scaledCoords[i].scale(globalScaleFactor, 1 /* windowXScale */,
                                                  1 /* windowYScale */);
                        }
                        usingCoords = scaledCoords;
                    }
                } else {
                    // We don't want the dispatch target to know.
                    if (dispatchEntry->targetFlags & InputTarget::FLAG_ZERO_COORDS) {
                        for (uint32_t i = 0; i < motionEntry->pointerCount; i++) {
                            scaledCoords[i].clear();
                        }
                        usingCoords = scaledCoords;
                    }
                }

                std::array<uint8_t, 32> hmac = getSignature(*motionEntry, *dispatchEntry);

                // Publish the motion event.
                status = connection->inputPublisher
                                 .publishMotionEvent(dispatchEntry->seq,
                                                     dispatchEntry->resolvedEventId,
                                                     motionEntry->deviceId, motionEntry->source,
                                                     motionEntry->displayId, std::move(hmac),
                                                     dispatchEntry->resolvedAction,
                                                     motionEntry->actionButton,
                                                     dispatchEntry->resolvedFlags,
                                                     motionEntry->edgeFlags, motionEntry->metaState,
                                                     motionEntry->buttonState,
                                                     motionEntry->classification, xScale, yScale,
                                                     xOffset, yOffset, motionEntry->xPrecision,
                                                     motionEntry->yPrecision,
                                                     motionEntry->xCursorPosition,
                                                     motionEntry->yCursorPosition,
                                                     motionEntry->downTime, motionEntry->eventTime,
                                                     motionEntry->pointerCount,
                                                     motionEntry->pointerProperties, usingCoords);
                reportTouchEventForStatistics(*motionEntry);
                break;
            }
            case EventEntry::Type::FOCUS: {
                FocusEntry* focusEntry = static_cast<FocusEntry*>(eventEntry);
                status = connection->inputPublisher.publishFocusEvent(dispatchEntry->seq,
                                                                      focusEntry->id,
                                                                      focusEntry->hasFocus,
                                                                      mInTouchMode);
                break;
            }

            case EventEntry::Type::CONFIGURATION_CHANGED:
            case EventEntry::Type::DEVICE_RESET: {
                LOG_ALWAYS_FATAL("Should never start dispatch cycles for %s events",
                                 EventEntry::typeToString(eventEntry->type));
                return;
            }
        }

        // Check the result.
        if (status) {
            if (status == WOULD_BLOCK) {
                if (connection->waitQueue.empty()) {
                    ALOGE("channel '%s' ~ Could not publish event because the pipe is full. "
                          "This is unexpected because the wait queue is empty, so the pipe "
                          "should be empty and we shouldn't have any problems writing an "
                          "event to it, status=%d",
                          connection->getInputChannelName().c_str(), status);
                    abortBrokenDispatchCycleLocked(currentTime, connection, true /*notify*/);
                } else {
                    // Pipe is full and we are waiting for the app to finish process some events
                    // before sending more events to it.
#if DEBUG_DISPATCH_CYCLE
                    ALOGD("channel '%s' ~ Could not publish event because the pipe is full, "
                          "waiting for the application to catch up",
                          connection->getInputChannelName().c_str());
#endif
                }
            } else {
                ALOGE("channel '%s' ~ Could not publish event due to an unexpected error, "
                      "status=%d",
                      connection->getInputChannelName().c_str(), status);
                abortBrokenDispatchCycleLocked(currentTime, connection, true /*notify*/);
            }
            return;
        }

        // Re-enqueue the event on the wait queue.
        connection->outboundQueue.erase(std::remove(connection->outboundQueue.begin(),
                                                    connection->outboundQueue.end(),
                                                    dispatchEntry));
        traceOutboundQueueLength(connection);
        connection->waitQueue.push_back(dispatchEntry);
        if (connection->responsive) {
            mAnrTracker.insert(dispatchEntry->timeoutTime,
                               connection->inputChannel->getConnectionToken());
        }
        traceWaitQueueLength(connection);
    }
}

const std::array<uint8_t, 32> InputDispatcher::getSignature(
        const MotionEntry& motionEntry, const DispatchEntry& dispatchEntry) const {
    int32_t actionMasked = dispatchEntry.resolvedAction & AMOTION_EVENT_ACTION_MASK;
    if ((actionMasked == AMOTION_EVENT_ACTION_UP) || (actionMasked == AMOTION_EVENT_ACTION_DOWN)) {
        // Only sign events up and down events as the purely move events
        // are tied to their up/down counterparts so signing would be redundant.
        VerifiedMotionEvent verifiedEvent = verifiedMotionEventFromMotionEntry(motionEntry);
        verifiedEvent.actionMasked = actionMasked;
        verifiedEvent.flags = dispatchEntry.resolvedFlags & VERIFIED_MOTION_EVENT_FLAGS;
        return mHmacKeyManager.sign(verifiedEvent);
    }
    return INVALID_HMAC;
}

const std::array<uint8_t, 32> InputDispatcher::getSignature(
        const KeyEntry& keyEntry, const DispatchEntry& dispatchEntry) const {
    VerifiedKeyEvent verifiedEvent = verifiedKeyEventFromKeyEntry(keyEntry);
    verifiedEvent.flags = dispatchEntry.resolvedFlags & VERIFIED_KEY_EVENT_FLAGS;
    verifiedEvent.action = dispatchEntry.resolvedAction;
    return mHmacKeyManager.sign(verifiedEvent);
}

void InputDispatcher::finishDispatchCycleLocked(nsecs_t currentTime,
                                                const sp<Connection>& connection, uint32_t seq,
                                                bool handled) {
#if DEBUG_DISPATCH_CYCLE
    ALOGD("channel '%s' ~ finishDispatchCycle - seq=%u, handled=%s",
          connection->getInputChannelName().c_str(), seq, toString(handled));
#endif

    if (connection->status == Connection::STATUS_BROKEN ||
        connection->status == Connection::STATUS_ZOMBIE) {
        return;
    }

    // Notify other system components and prepare to start the next dispatch cycle.
    onDispatchCycleFinishedLocked(currentTime, connection, seq, handled);
}

void InputDispatcher::abortBrokenDispatchCycleLocked(nsecs_t currentTime,
                                                     const sp<Connection>& connection,
                                                     bool notify) {
#if DEBUG_DISPATCH_CYCLE
    ALOGD("channel '%s' ~ abortBrokenDispatchCycle - notify=%s",
          connection->getInputChannelName().c_str(), toString(notify));
#endif

    // Clear the dispatch queues.
    drainDispatchQueue(connection->outboundQueue);
    traceOutboundQueueLength(connection);
    drainDispatchQueue(connection->waitQueue);
    traceWaitQueueLength(connection);

    // The connection appears to be unrecoverably broken.
    // Ignore already broken or zombie connections.
    if (connection->status == Connection::STATUS_NORMAL) {
        connection->status = Connection::STATUS_BROKEN;

        if (notify) {
            // Notify other system components.
            onDispatchCycleBrokenLocked(currentTime, connection);
        }
    }
}

void InputDispatcher::drainDispatchQueue(std::deque<DispatchEntry*>& queue) {
    while (!queue.empty()) {
        DispatchEntry* dispatchEntry = queue.front();
        queue.pop_front();
        releaseDispatchEntry(dispatchEntry);
    }
}

void InputDispatcher::releaseDispatchEntry(DispatchEntry* dispatchEntry) {
    if (dispatchEntry->hasForegroundTarget()) {
        decrementPendingForegroundDispatches(dispatchEntry->eventEntry);
    }
    delete dispatchEntry;
}

int InputDispatcher::handleReceiveCallback(int fd, int events, void* data) {
    InputDispatcher* d = static_cast<InputDispatcher*>(data);

    { // acquire lock
        std::scoped_lock _l(d->mLock);

        if (d->mConnectionsByFd.find(fd) == d->mConnectionsByFd.end()) {
            ALOGE("Received spurious receive callback for unknown input channel.  "
                  "fd=%d, events=0x%x",
                  fd, events);
            return 0; // remove the callback
        }

        bool notify;
        sp<Connection> connection = d->mConnectionsByFd[fd];
        if (!(events & (ALOOPER_EVENT_ERROR | ALOOPER_EVENT_HANGUP))) {
            if (!(events & ALOOPER_EVENT_INPUT)) {
                ALOGW("channel '%s' ~ Received spurious callback for unhandled poll event.  "
                      "events=0x%x",
                      connection->getInputChannelName().c_str(), events);
                return 1;
            }

            nsecs_t currentTime = now();
            bool gotOne = false;
            status_t status;
            for (;;) {
                uint32_t seq;
                bool handled;
                status = connection->inputPublisher.receiveFinishedSignal(&seq, &handled);
                if (status) {
                    break;
                }
                d->finishDispatchCycleLocked(currentTime, connection, seq, handled);
                gotOne = true;
            }
            if (gotOne) {
                d->runCommandsLockedInterruptible();
                if (status == WOULD_BLOCK) {
                    return 1;
                }
            }

            notify = status != DEAD_OBJECT || !connection->monitor;
            if (notify) {
                ALOGE("channel '%s' ~ Failed to receive finished signal.  status=%d",
                      connection->getInputChannelName().c_str(), status);
            }
        } else {
            // Monitor channels are never explicitly unregistered.
            // We do it automatically when the remote endpoint is closed so don't warn
            // about them.
            const bool stillHaveWindowHandle =
                    d->getWindowHandleLocked(connection->inputChannel->getConnectionToken()) !=
                    nullptr;
            notify = !connection->monitor && stillHaveWindowHandle;
            if (notify) {
                ALOGW("channel '%s' ~ Consumer closed input channel or an error occurred.  "
                      "events=0x%x",
                      connection->getInputChannelName().c_str(), events);
            }
        }

        // Unregister the channel.
        d->unregisterInputChannelLocked(connection->inputChannel, notify);
        return 0; // remove the callback
    }             // release lock
}

void InputDispatcher::synthesizeCancelationEventsForAllConnectionsLocked(
        const CancelationOptions& options) {
    for (const auto& pair : mConnectionsByFd) {
        synthesizeCancelationEventsForConnectionLocked(pair.second, options);
    }
}

void InputDispatcher::synthesizeCancelationEventsForMonitorsLocked(
        const CancelationOptions& options) {
    synthesizeCancelationEventsForMonitorsLocked(options, mGlobalMonitorsByDisplay);
    synthesizeCancelationEventsForMonitorsLocked(options, mGestureMonitorsByDisplay);
}

void InputDispatcher::synthesizeCancelationEventsForMonitorsLocked(
        const CancelationOptions& options,
        std::unordered_map<int32_t, std::vector<Monitor>>& monitorsByDisplay) {
    for (const auto& it : monitorsByDisplay) {
        const std::vector<Monitor>& monitors = it.second;
        for (const Monitor& monitor : monitors) {
            synthesizeCancelationEventsForInputChannelLocked(monitor.inputChannel, options);
        }
    }
}

void InputDispatcher::synthesizeCancelationEventsForInputChannelLocked(
        const sp<InputChannel>& channel, const CancelationOptions& options) {
    sp<Connection> connection = getConnectionLocked(channel->getConnectionToken());
    if (connection == nullptr) {
        return;
    }

    synthesizeCancelationEventsForConnectionLocked(connection, options);
}

void InputDispatcher::synthesizeCancelationEventsForConnectionLocked(
        const sp<Connection>& connection, const CancelationOptions& options) {
    if (connection->status == Connection::STATUS_BROKEN) {
        return;
    }

    nsecs_t currentTime = now();

    std::vector<EventEntry*> cancelationEvents =
            connection->inputState.synthesizeCancelationEvents(currentTime, options);

    if (cancelationEvents.empty()) {
        return;
    }
#if DEBUG_OUTBOUND_EVENT_DETAILS
    ALOGD("channel '%s' ~ Synthesized %zu cancelation events to bring channel back in sync "
          "with reality: %s, mode=%d.",
          connection->getInputChannelName().c_str(), cancelationEvents.size(), options.reason,
          options.mode);
#endif

    InputTarget target;
    sp<InputWindowHandle> windowHandle =
            getWindowHandleLocked(connection->inputChannel->getConnectionToken());
    if (windowHandle != nullptr) {
        const InputWindowInfo* windowInfo = windowHandle->getInfo();
        target.setDefaultPointerInfo(-windowInfo->frameLeft, -windowInfo->frameTop,
                                     windowInfo->windowXScale, windowInfo->windowYScale);
        target.globalScaleFactor = windowInfo->globalScaleFactor;
    }
    target.inputChannel = connection->inputChannel;
    target.flags = InputTarget::FLAG_DISPATCH_AS_IS;

    for (size_t i = 0; i < cancelationEvents.size(); i++) {
        EventEntry* cancelationEventEntry = cancelationEvents[i];
        switch (cancelationEventEntry->type) {
            case EventEntry::Type::KEY: {
                logOutboundKeyDetails("cancel - ",
                                      static_cast<const KeyEntry&>(*cancelationEventEntry));
                break;
            }
            case EventEntry::Type::MOTION: {
                logOutboundMotionDetails("cancel - ",
                                         static_cast<const MotionEntry&>(*cancelationEventEntry));
                break;
            }
            case EventEntry::Type::FOCUS: {
                LOG_ALWAYS_FATAL("Canceling focus events is not supported");
                break;
            }
            case EventEntry::Type::CONFIGURATION_CHANGED:
            case EventEntry::Type::DEVICE_RESET: {
                LOG_ALWAYS_FATAL("%s event should not be found inside Connections's queue",
                                 EventEntry::typeToString(cancelationEventEntry->type));
                break;
            }
        }

        enqueueDispatchEntryLocked(connection, cancelationEventEntry, // increments ref
                                   target, InputTarget::FLAG_DISPATCH_AS_IS);

        cancelationEventEntry->release();
    }

    startDispatchCycleLocked(currentTime, connection);
}

void InputDispatcher::synthesizePointerDownEventsForConnectionLocked(
        const sp<Connection>& connection) {
    if (connection->status == Connection::STATUS_BROKEN) {
        return;
    }

    nsecs_t currentTime = now();

    std::vector<EventEntry*> downEvents =
            connection->inputState.synthesizePointerDownEvents(currentTime);

    if (downEvents.empty()) {
        return;
    }

#if DEBUG_OUTBOUND_EVENT_DETAILS
        ALOGD("channel '%s' ~ Synthesized %zu down events to ensure consistent event stream.",
              connection->getInputChannelName().c_str(), downEvents.size());
#endif

    InputTarget target;
    sp<InputWindowHandle> windowHandle =
            getWindowHandleLocked(connection->inputChannel->getConnectionToken());
    if (windowHandle != nullptr) {
        const InputWindowInfo* windowInfo = windowHandle->getInfo();
        target.setDefaultPointerInfo(-windowInfo->frameLeft, -windowInfo->frameTop,
                                     windowInfo->windowXScale, windowInfo->windowYScale);
        target.globalScaleFactor = windowInfo->globalScaleFactor;
    }
    target.inputChannel = connection->inputChannel;
    target.flags = InputTarget::FLAG_DISPATCH_AS_IS;

    for (EventEntry* downEventEntry : downEvents) {
        switch (downEventEntry->type) {
            case EventEntry::Type::MOTION: {
                logOutboundMotionDetails("down - ",
                        static_cast<const MotionEntry&>(*downEventEntry));
                break;
            }

            case EventEntry::Type::KEY:
            case EventEntry::Type::FOCUS:
            case EventEntry::Type::CONFIGURATION_CHANGED:
            case EventEntry::Type::DEVICE_RESET: {
                LOG_ALWAYS_FATAL("%s event should not be found inside Connections's queue",
                                     EventEntry::typeToString(downEventEntry->type));
                break;
            }
        }

        enqueueDispatchEntryLocked(connection, downEventEntry, // increments ref
                                   target, InputTarget::FLAG_DISPATCH_AS_IS);

        downEventEntry->release();
    }

    startDispatchCycleLocked(currentTime, connection);
}

MotionEntry* InputDispatcher::splitMotionEvent(const MotionEntry& originalMotionEntry,
                                               BitSet32 pointerIds) {
    ALOG_ASSERT(pointerIds.value != 0);

    uint32_t splitPointerIndexMap[MAX_POINTERS];
    PointerProperties splitPointerProperties[MAX_POINTERS];
    PointerCoords splitPointerCoords[MAX_POINTERS];

    uint32_t originalPointerCount = originalMotionEntry.pointerCount;
    uint32_t splitPointerCount = 0;

    for (uint32_t originalPointerIndex = 0; originalPointerIndex < originalPointerCount;
         originalPointerIndex++) {
        const PointerProperties& pointerProperties =
                originalMotionEntry.pointerProperties[originalPointerIndex];
        uint32_t pointerId = uint32_t(pointerProperties.id);
        if (pointerIds.hasBit(pointerId)) {
            splitPointerIndexMap[splitPointerCount] = originalPointerIndex;
            splitPointerProperties[splitPointerCount].copyFrom(pointerProperties);
            splitPointerCoords[splitPointerCount].copyFrom(
                    originalMotionEntry.pointerCoords[originalPointerIndex]);
            splitPointerCount += 1;
        }
    }

    if (splitPointerCount != pointerIds.count()) {
        // This is bad.  We are missing some of the pointers that we expected to deliver.
        // Most likely this indicates that we received an ACTION_MOVE events that has
        // different pointer ids than we expected based on the previous ACTION_DOWN
        // or ACTION_POINTER_DOWN events that caused us to decide to split the pointers
        // in this way.
        ALOGW("Dropping split motion event because the pointer count is %d but "
              "we expected there to be %d pointers.  This probably means we received "
              "a broken sequence of pointer ids from the input device.",
              splitPointerCount, pointerIds.count());
        return nullptr;
    }

    int32_t action = originalMotionEntry.action;
    int32_t maskedAction = action & AMOTION_EVENT_ACTION_MASK;
    if (maskedAction == AMOTION_EVENT_ACTION_POINTER_DOWN ||
        maskedAction == AMOTION_EVENT_ACTION_POINTER_UP) {
        int32_t originalPointerIndex = getMotionEventActionPointerIndex(action);
        const PointerProperties& pointerProperties =
                originalMotionEntry.pointerProperties[originalPointerIndex];
        uint32_t pointerId = uint32_t(pointerProperties.id);
        if (pointerIds.hasBit(pointerId)) {
            if (pointerIds.count() == 1) {
                // The first/last pointer went down/up.
                action = maskedAction == AMOTION_EVENT_ACTION_POINTER_DOWN
                        ? AMOTION_EVENT_ACTION_DOWN
                        : AMOTION_EVENT_ACTION_UP;
            } else {
                // A secondary pointer went down/up.
                uint32_t splitPointerIndex = 0;
                while (pointerId != uint32_t(splitPointerProperties[splitPointerIndex].id)) {
                    splitPointerIndex += 1;
                }
                action = maskedAction |
                        (splitPointerIndex << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
            }
        } else {
            // An unrelated pointer changed.
            action = AMOTION_EVENT_ACTION_MOVE;
        }
    }

    int32_t newId = mIdGenerator.nextId();
    if (ATRACE_ENABLED()) {
        std::string message = StringPrintf("Split MotionEvent(id=0x%" PRIx32
                                           ") to MotionEvent(id=0x%" PRIx32 ").",
                                           originalMotionEntry.id, newId);
        ATRACE_NAME(message.c_str());
    }
    MotionEntry* splitMotionEntry =
            new MotionEntry(newId, originalMotionEntry.eventTime, originalMotionEntry.deviceId,
                            originalMotionEntry.source, originalMotionEntry.displayId,
                            originalMotionEntry.policyFlags, action,
                            originalMotionEntry.actionButton, originalMotionEntry.flags,
                            originalMotionEntry.metaState, originalMotionEntry.buttonState,
                            originalMotionEntry.classification, originalMotionEntry.edgeFlags,
                            originalMotionEntry.xPrecision, originalMotionEntry.yPrecision,
                            originalMotionEntry.xCursorPosition,
                            originalMotionEntry.yCursorPosition, originalMotionEntry.downTime,
                            splitPointerCount, splitPointerProperties, splitPointerCoords, 0, 0);

    if (originalMotionEntry.injectionState) {
        splitMotionEntry->injectionState = originalMotionEntry.injectionState;
        splitMotionEntry->injectionState->refCount += 1;
    }

    return splitMotionEntry;
}

void InputDispatcher::notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) {
#if DEBUG_INBOUND_EVENT_DETAILS
    ALOGD("notifyConfigurationChanged - eventTime=%" PRId64, args->eventTime);
#endif

    bool needWake;
    { // acquire lock
        std::scoped_lock _l(mLock);

        ConfigurationChangedEntry* newEntry =
                new ConfigurationChangedEntry(args->id, args->eventTime);
        needWake = enqueueInboundEventLocked(newEntry);
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
}

/**
 * If one of the meta shortcuts is detected, process them here:
 *     Meta + Backspace -> generate BACK
 *     Meta + Enter -> generate HOME
 * This will potentially overwrite keyCode and metaState.
 */
void InputDispatcher::accelerateMetaShortcuts(const int32_t deviceId, const int32_t action,
                                              int32_t& keyCode, int32_t& metaState) {
    if (metaState & AMETA_META_ON && action == AKEY_EVENT_ACTION_DOWN) {
        int32_t newKeyCode = AKEYCODE_UNKNOWN;
        if (keyCode == AKEYCODE_DEL) {
            newKeyCode = AKEYCODE_BACK;
        } else if (keyCode == AKEYCODE_ENTER) {
            newKeyCode = AKEYCODE_HOME;
        }
        if (newKeyCode != AKEYCODE_UNKNOWN) {
            std::scoped_lock _l(mLock);
            struct KeyReplacement replacement = {keyCode, deviceId};
            mReplacedKeys[replacement] = newKeyCode;
            keyCode = newKeyCode;
            metaState &= ~(AMETA_META_ON | AMETA_META_LEFT_ON | AMETA_META_RIGHT_ON);
        }
    } else if (action == AKEY_EVENT_ACTION_UP) {
        // In order to maintain a consistent stream of up and down events, check to see if the key
        // going up is one we've replaced in a down event and haven't yet replaced in an up event,
        // even if the modifier was released between the down and the up events.
        std::scoped_lock _l(mLock);
        struct KeyReplacement replacement = {keyCode, deviceId};
        auto replacementIt = mReplacedKeys.find(replacement);
        if (replacementIt != mReplacedKeys.end()) {
            keyCode = replacementIt->second;
            mReplacedKeys.erase(replacementIt);
            metaState &= ~(AMETA_META_ON | AMETA_META_LEFT_ON | AMETA_META_RIGHT_ON);
        }
    }
}

void InputDispatcher::notifyKey(const NotifyKeyArgs* args) {
#if DEBUG_INBOUND_EVENT_DETAILS
    ALOGD("notifyKey - eventTime=%" PRId64 ", deviceId=%d, source=0x%x, displayId=%" PRId32
          "policyFlags=0x%x, action=0x%x, "
          "flags=0x%x, keyCode=0x%x, scanCode=0x%x, metaState=0x%x, downTime=%" PRId64,
          args->eventTime, args->deviceId, args->source, args->displayId, args->policyFlags,
          args->action, args->flags, args->keyCode, args->scanCode, args->metaState,
          args->downTime);
#endif
    if (!validateKeyEvent(args->action)) {
        return;
    }

    uint32_t policyFlags = args->policyFlags;
    int32_t flags = args->flags;
    int32_t metaState = args->metaState;
    // InputDispatcher tracks and generates key repeats on behalf of
    // whatever notifies it, so repeatCount should always be set to 0
    constexpr int32_t repeatCount = 0;
    if ((policyFlags & POLICY_FLAG_VIRTUAL) || (flags & AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY)) {
        policyFlags |= POLICY_FLAG_VIRTUAL;
        flags |= AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY;
    }
    if (policyFlags & POLICY_FLAG_FUNCTION) {
        metaState |= AMETA_FUNCTION_ON;
    }

    policyFlags |= POLICY_FLAG_TRUSTED;

    int32_t keyCode = args->keyCode;
    accelerateMetaShortcuts(args->deviceId, args->action, keyCode, metaState);

    KeyEvent event;
    event.initialize(args->id, args->deviceId, args->source, args->displayId, INVALID_HMAC,
                     args->action, flags, keyCode, args->scanCode, metaState, repeatCount,
                     args->downTime, args->eventTime);

    android::base::Timer t;
    mPolicy->interceptKeyBeforeQueueing(&event, /*byref*/ policyFlags);
    if (t.duration() > SLOW_INTERCEPTION_THRESHOLD) {
        ALOGW("Excessive delay in interceptKeyBeforeQueueing; took %s ms",
              std::to_string(t.duration().count()).c_str());
    }

    bool needWake;
    { // acquire lock
        mLock.lock();

        if (shouldSendKeyToInputFilterLocked(args)) {
            mLock.unlock();

            policyFlags |= POLICY_FLAG_FILTERED;
            if (!mPolicy->filterInputEvent(&event, policyFlags)) {
                return; // event was consumed by the filter
            }

            mLock.lock();
        }

        KeyEntry* newEntry =
                new KeyEntry(args->id, args->eventTime, args->deviceId, args->source,
                             args->displayId, policyFlags, args->action, flags, keyCode,
                             args->scanCode, metaState, repeatCount, args->downTime);

        needWake = enqueueInboundEventLocked(newEntry);
        mLock.unlock();
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
}

bool InputDispatcher::shouldSendKeyToInputFilterLocked(const NotifyKeyArgs* args) {
    return mInputFilterEnabled;
}

void InputDispatcher::notifyMotion(const NotifyMotionArgs* args) {
#if DEBUG_INBOUND_EVENT_DETAILS
    ALOGD("notifyMotion - id=%" PRIx32 " eventTime=%" PRId64 ", deviceId=%d, source=0x%x, "
          "displayId=%" PRId32 ", policyFlags=0x%x, "
          "action=0x%x, actionButton=0x%x, flags=0x%x, metaState=0x%x, buttonState=0x%x, "
          "edgeFlags=0x%x, xPrecision=%f, yPrecision=%f, xCursorPosition=%f, "
          "yCursorPosition=%f, downTime=%" PRId64,
          args->id, args->eventTime, args->deviceId, args->source, args->displayId,
          args->policyFlags, args->action, args->actionButton, args->flags, args->metaState,
          args->buttonState, args->edgeFlags, args->xPrecision, args->yPrecision,
          args->xCursorPosition, args->yCursorPosition, args->downTime);
    for (uint32_t i = 0; i < args->pointerCount; i++) {
        ALOGD("  Pointer %d: id=%d, toolType=%d, "
              "x=%f, y=%f, pressure=%f, size=%f, "
              "touchMajor=%f, touchMinor=%f, toolMajor=%f, toolMinor=%f, "
              "orientation=%f",
              i, args->pointerProperties[i].id, args->pointerProperties[i].toolType,
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_X),
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_Y),
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_PRESSURE),
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_SIZE),
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR),
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR),
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOOL_MAJOR),
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOOL_MINOR),
              args->pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION));
    }
#endif
    if (!validateMotionEvent(args->action, args->actionButton, args->pointerCount,
                             args->pointerProperties)) {
        return;
    }

    uint32_t policyFlags = args->policyFlags;
    policyFlags |= POLICY_FLAG_TRUSTED;

    android::base::Timer t;
    mPolicy->interceptMotionBeforeQueueing(args->displayId, args->eventTime, /*byref*/ policyFlags);
    if (t.duration() > SLOW_INTERCEPTION_THRESHOLD) {
        ALOGW("Excessive delay in interceptMotionBeforeQueueing; took %s ms",
              std::to_string(t.duration().count()).c_str());
    }

    bool needWake;
    { // acquire lock
        mLock.lock();

        if (shouldSendMotionToInputFilterLocked(args)) {
            mLock.unlock();

            MotionEvent event;
            event.initialize(args->id, args->deviceId, args->source, args->displayId, INVALID_HMAC,
                             args->action, args->actionButton, args->flags, args->edgeFlags,
                             args->metaState, args->buttonState, args->classification, 1 /*xScale*/,
                             1 /*yScale*/, 0 /* xOffset */, 0 /* yOffset */, args->xPrecision,
                             args->yPrecision, args->xCursorPosition, args->yCursorPosition,
                             args->downTime, args->eventTime, args->pointerCount,
                             args->pointerProperties, args->pointerCoords);

            policyFlags |= POLICY_FLAG_FILTERED;
            if (!mPolicy->filterInputEvent(&event, policyFlags)) {
                return; // event was consumed by the filter
            }

            mLock.lock();
        }

        // Just enqueue a new motion event.
        MotionEntry* newEntry =
                new MotionEntry(args->id, args->eventTime, args->deviceId, args->source,
                                args->displayId, policyFlags, args->action, args->actionButton,
                                args->flags, args->metaState, args->buttonState,
                                args->classification, args->edgeFlags, args->xPrecision,
                                args->yPrecision, args->xCursorPosition, args->yCursorPosition,
                                args->downTime, args->pointerCount, args->pointerProperties,
                                args->pointerCoords, 0, 0);

        needWake = enqueueInboundEventLocked(newEntry);
        mLock.unlock();
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
}

bool InputDispatcher::shouldSendMotionToInputFilterLocked(const NotifyMotionArgs* args) {
    return mInputFilterEnabled;
}

void InputDispatcher::notifySwitch(const NotifySwitchArgs* args) {
#if DEBUG_INBOUND_EVENT_DETAILS
    ALOGD("notifySwitch - eventTime=%" PRId64 ", policyFlags=0x%x, switchValues=0x%08x, "
          "switchMask=0x%08x",
          args->eventTime, args->policyFlags, args->switchValues, args->switchMask);
#endif

    uint32_t policyFlags = args->policyFlags;
    policyFlags |= POLICY_FLAG_TRUSTED;
    mPolicy->notifySwitch(args->eventTime, args->switchValues, args->switchMask, policyFlags);
}

void InputDispatcher::notifyDeviceReset(const NotifyDeviceResetArgs* args) {
#if DEBUG_INBOUND_EVENT_DETAILS
    ALOGD("notifyDeviceReset - eventTime=%" PRId64 ", deviceId=%d", args->eventTime,
          args->deviceId);
#endif

    bool needWake;
    { // acquire lock
        std::scoped_lock _l(mLock);

        DeviceResetEntry* newEntry =
                new DeviceResetEntry(args->id, args->eventTime, args->deviceId);
        needWake = enqueueInboundEventLocked(newEntry);
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
}

int32_t InputDispatcher::injectInputEvent(const InputEvent* event, int32_t injectorPid,
                                          int32_t injectorUid, int32_t syncMode,
                                          std::chrono::milliseconds timeout, uint32_t policyFlags) {
#if DEBUG_INBOUND_EVENT_DETAILS
    ALOGD("injectInputEvent - eventType=%d, injectorPid=%d, injectorUid=%d, "
          "syncMode=%d, timeout=%lld, policyFlags=0x%08x",
          event->getType(), injectorPid, injectorUid, syncMode, timeout.count(), policyFlags);
#endif

    nsecs_t endTime = now() + std::chrono::duration_cast<std::chrono::nanoseconds>(timeout).count();

    policyFlags |= POLICY_FLAG_INJECTED;
    if (hasInjectionPermission(injectorPid, injectorUid)) {
        policyFlags |= POLICY_FLAG_TRUSTED;
    }

    std::queue<EventEntry*> injectedEntries;
    switch (event->getType()) {
        case AINPUT_EVENT_TYPE_KEY: {
            const KeyEvent& incomingKey = static_cast<const KeyEvent&>(*event);
            int32_t action = incomingKey.getAction();
            if (!validateKeyEvent(action)) {
                return INPUT_EVENT_INJECTION_FAILED;
            }

            int32_t flags = incomingKey.getFlags();
            int32_t keyCode = incomingKey.getKeyCode();
            int32_t metaState = incomingKey.getMetaState();
            accelerateMetaShortcuts(VIRTUAL_KEYBOARD_ID, action,
                                    /*byref*/ keyCode, /*byref*/ metaState);
            KeyEvent keyEvent;
            keyEvent.initialize(incomingKey.getId(), VIRTUAL_KEYBOARD_ID, incomingKey.getSource(),
                                incomingKey.getDisplayId(), INVALID_HMAC, action, flags, keyCode,
                                incomingKey.getScanCode(), metaState, incomingKey.getRepeatCount(),
                                incomingKey.getDownTime(), incomingKey.getEventTime());

            if (flags & AKEY_EVENT_FLAG_VIRTUAL_HARD_KEY) {
                policyFlags |= POLICY_FLAG_VIRTUAL;
            }

            if (!(policyFlags & POLICY_FLAG_FILTERED)) {
                android::base::Timer t;
                mPolicy->interceptKeyBeforeQueueing(&keyEvent, /*byref*/ policyFlags);
                if (t.duration() > SLOW_INTERCEPTION_THRESHOLD) {
                    ALOGW("Excessive delay in interceptKeyBeforeQueueing; took %s ms",
                          std::to_string(t.duration().count()).c_str());
                }
            }

            mLock.lock();
            KeyEntry* injectedEntry =
                    new KeyEntry(incomingKey.getId(), incomingKey.getEventTime(),
                                 VIRTUAL_KEYBOARD_ID, incomingKey.getSource(),
                                 incomingKey.getDisplayId(), policyFlags, action, flags, keyCode,
                                 incomingKey.getScanCode(), metaState, incomingKey.getRepeatCount(),
                                 incomingKey.getDownTime());
            injectedEntries.push(injectedEntry);
            break;
        }

        case AINPUT_EVENT_TYPE_MOTION: {
            const MotionEvent* motionEvent = static_cast<const MotionEvent*>(event);
            int32_t action = motionEvent->getAction();
            size_t pointerCount = motionEvent->getPointerCount();
            const PointerProperties* pointerProperties = motionEvent->getPointerProperties();
            int32_t actionButton = motionEvent->getActionButton();
            int32_t displayId = motionEvent->getDisplayId();
            if (!validateMotionEvent(action, actionButton, pointerCount, pointerProperties)) {
                return INPUT_EVENT_INJECTION_FAILED;
            }

            if (!(policyFlags & POLICY_FLAG_FILTERED)) {
                nsecs_t eventTime = motionEvent->getEventTime();
                android::base::Timer t;
                mPolicy->interceptMotionBeforeQueueing(displayId, eventTime, /*byref*/ policyFlags);
                if (t.duration() > SLOW_INTERCEPTION_THRESHOLD) {
                    ALOGW("Excessive delay in interceptMotionBeforeQueueing; took %s ms",
                          std::to_string(t.duration().count()).c_str());
                }
            }

            mLock.lock();
            const nsecs_t* sampleEventTimes = motionEvent->getSampleEventTimes();
            const PointerCoords* samplePointerCoords = motionEvent->getSamplePointerCoords();
            MotionEntry* injectedEntry =
                    new MotionEntry(motionEvent->getId(), *sampleEventTimes, VIRTUAL_KEYBOARD_ID,
                                    motionEvent->getSource(), motionEvent->getDisplayId(),
                                    policyFlags, action, actionButton, motionEvent->getFlags(),
                                    motionEvent->getMetaState(), motionEvent->getButtonState(),
                                    motionEvent->getClassification(), motionEvent->getEdgeFlags(),
                                    motionEvent->getXPrecision(), motionEvent->getYPrecision(),
                                    motionEvent->getRawXCursorPosition(),
                                    motionEvent->getRawYCursorPosition(),
                                    motionEvent->getDownTime(), uint32_t(pointerCount),
                                    pointerProperties, samplePointerCoords,
                                    motionEvent->getXOffset(), motionEvent->getYOffset());
            injectedEntries.push(injectedEntry);
            for (size_t i = motionEvent->getHistorySize(); i > 0; i--) {
                sampleEventTimes += 1;
                samplePointerCoords += pointerCount;
                MotionEntry* nextInjectedEntry =
                        new MotionEntry(motionEvent->getId(), *sampleEventTimes,
                                        VIRTUAL_KEYBOARD_ID, motionEvent->getSource(),
                                        motionEvent->getDisplayId(), policyFlags, action,
                                        actionButton, motionEvent->getFlags(),
                                        motionEvent->getMetaState(), motionEvent->getButtonState(),
                                        motionEvent->getClassification(),
                                        motionEvent->getEdgeFlags(), motionEvent->getXPrecision(),
                                        motionEvent->getYPrecision(),
                                        motionEvent->getRawXCursorPosition(),
                                        motionEvent->getRawYCursorPosition(),
                                        motionEvent->getDownTime(), uint32_t(pointerCount),
                                        pointerProperties, samplePointerCoords,
                                        motionEvent->getXOffset(), motionEvent->getYOffset());
                injectedEntries.push(nextInjectedEntry);
            }
            break;
        }

        default:
            ALOGW("Cannot inject %s events", inputEventTypeToString(event->getType()));
            return INPUT_EVENT_INJECTION_FAILED;
    }

    InjectionState* injectionState = new InjectionState(injectorPid, injectorUid);
    if (syncMode == INPUT_EVENT_INJECTION_SYNC_NONE) {
        injectionState->injectionIsAsync = true;
    }

    injectionState->refCount += 1;
    injectedEntries.back()->injectionState = injectionState;

    bool needWake = false;
    while (!injectedEntries.empty()) {
        needWake |= enqueueInboundEventLocked(injectedEntries.front());
        injectedEntries.pop();
    }

    mLock.unlock();

    if (needWake) {
        mLooper->wake();
    }

    int32_t injectionResult;
    { // acquire lock
        std::unique_lock _l(mLock);

        if (syncMode == INPUT_EVENT_INJECTION_SYNC_NONE) {
            injectionResult = INPUT_EVENT_INJECTION_SUCCEEDED;
        } else {
            for (;;) {
                injectionResult = injectionState->injectionResult;
                if (injectionResult != INPUT_EVENT_INJECTION_PENDING) {
                    break;
                }

                nsecs_t remainingTimeout = endTime - now();
                if (remainingTimeout <= 0) {
#if DEBUG_INJECTION
                    ALOGD("injectInputEvent - Timed out waiting for injection result "
                          "to become available.");
#endif
                    injectionResult = INPUT_EVENT_INJECTION_TIMED_OUT;
                    break;
                }

                mInjectionResultAvailable.wait_for(_l, std::chrono::nanoseconds(remainingTimeout));
            }

            if (injectionResult == INPUT_EVENT_INJECTION_SUCCEEDED &&
                syncMode == INPUT_EVENT_INJECTION_SYNC_WAIT_FOR_FINISHED) {
                while (injectionState->pendingForegroundDispatches != 0) {
#if DEBUG_INJECTION
                    ALOGD("injectInputEvent - Waiting for %d pending foreground dispatches.",
                          injectionState->pendingForegroundDispatches);
#endif
                    nsecs_t remainingTimeout = endTime - now();
                    if (remainingTimeout <= 0) {
#if DEBUG_INJECTION
                        ALOGD("injectInputEvent - Timed out waiting for pending foreground "
                              "dispatches to finish.");
#endif
                        injectionResult = INPUT_EVENT_INJECTION_TIMED_OUT;
                        break;
                    }

                    mInjectionSyncFinished.wait_for(_l, std::chrono::nanoseconds(remainingTimeout));
                }
            }
        }

        injectionState->release();
    } // release lock

#if DEBUG_INJECTION
    ALOGD("injectInputEvent - Finished with result %d. injectorPid=%d, injectorUid=%d",
          injectionResult, injectorPid, injectorUid);
#endif

    return injectionResult;
}

std::unique_ptr<VerifiedInputEvent> InputDispatcher::verifyInputEvent(const InputEvent& event) {
    std::array<uint8_t, 32> calculatedHmac;
    std::unique_ptr<VerifiedInputEvent> result;
    switch (event.getType()) {
        case AINPUT_EVENT_TYPE_KEY: {
            const KeyEvent& keyEvent = static_cast<const KeyEvent&>(event);
            VerifiedKeyEvent verifiedKeyEvent = verifiedKeyEventFromKeyEvent(keyEvent);
            result = std::make_unique<VerifiedKeyEvent>(verifiedKeyEvent);
            calculatedHmac = mHmacKeyManager.sign(verifiedKeyEvent);
            break;
        }
        case AINPUT_EVENT_TYPE_MOTION: {
            const MotionEvent& motionEvent = static_cast<const MotionEvent&>(event);
            VerifiedMotionEvent verifiedMotionEvent =
                    verifiedMotionEventFromMotionEvent(motionEvent);
            result = std::make_unique<VerifiedMotionEvent>(verifiedMotionEvent);
            calculatedHmac = mHmacKeyManager.sign(verifiedMotionEvent);
            break;
        }
        default: {
            ALOGE("Cannot verify events of type %" PRId32, event.getType());
            return nullptr;
        }
    }
    if (calculatedHmac == INVALID_HMAC) {
        return nullptr;
    }
    if (calculatedHmac != event.getHmac()) {
        return nullptr;
    }
    return result;
}

bool InputDispatcher::hasInjectionPermission(int32_t injectorPid, int32_t injectorUid) {
    return injectorUid == 0 ||
            mPolicy->checkInjectEventsPermissionNonReentrant(injectorPid, injectorUid);
}

void InputDispatcher::setInjectionResult(EventEntry* entry, int32_t injectionResult) {
    InjectionState* injectionState = entry->injectionState;
    if (injectionState) {
#if DEBUG_INJECTION
        ALOGD("Setting input event injection result to %d.  "
              "injectorPid=%d, injectorUid=%d",
              injectionResult, injectionState->injectorPid, injectionState->injectorUid);
#endif

        if (injectionState->injectionIsAsync && !(entry->policyFlags & POLICY_FLAG_FILTERED)) {
            // Log the outcome since the injector did not wait for the injection result.
            switch (injectionResult) {
                case INPUT_EVENT_INJECTION_SUCCEEDED:
                    ALOGV("Asynchronous input event injection succeeded.");
                    break;
                case INPUT_EVENT_INJECTION_FAILED:
                    ALOGW("Asynchronous input event injection failed.");
                    break;
                case INPUT_EVENT_INJECTION_PERMISSION_DENIED:
                    ALOGW("Asynchronous input event injection permission denied.");
                    break;
                case INPUT_EVENT_INJECTION_TIMED_OUT:
                    ALOGW("Asynchronous input event injection timed out.");
                    break;
            }
        }

        injectionState->injectionResult = injectionResult;
        mInjectionResultAvailable.notify_all();
    }
}

void InputDispatcher::incrementPendingForegroundDispatches(EventEntry* entry) {
    InjectionState* injectionState = entry->injectionState;
    if (injectionState) {
        injectionState->pendingForegroundDispatches += 1;
    }
}

void InputDispatcher::decrementPendingForegroundDispatches(EventEntry* entry) {
    InjectionState* injectionState = entry->injectionState;
    if (injectionState) {
        injectionState->pendingForegroundDispatches -= 1;

        if (injectionState->pendingForegroundDispatches == 0) {
            mInjectionSyncFinished.notify_all();
        }
    }
}

std::vector<sp<InputWindowHandle>> InputDispatcher::getWindowHandlesLocked(
        int32_t displayId) const {
    return getValueByKey(mWindowHandlesByDisplay, displayId);
}

sp<InputWindowHandle> InputDispatcher::getFocusedWindowHandleLocked(int displayId) const {
    return getValueByKey(mFocusedWindowHandlesByDisplay, displayId);
}

sp<InputWindowHandle> InputDispatcher::getWindowHandleLocked(
        const sp<IBinder>& windowHandleToken) const {
    if (windowHandleToken == nullptr) {
        return nullptr;
    }

    for (auto& it : mWindowHandlesByDisplay) {
        const std::vector<sp<InputWindowHandle>> windowHandles = it.second;
        for (const sp<InputWindowHandle>& windowHandle : windowHandles) {
            if (windowHandle->getToken() == windowHandleToken) {
                return windowHandle;
            }
        }
    }
    return nullptr;
}

bool InputDispatcher::hasWindowHandleLocked(const sp<InputWindowHandle>& windowHandle) const {
    for (auto& it : mWindowHandlesByDisplay) {
        const std::vector<sp<InputWindowHandle>> windowHandles = it.second;
        for (const sp<InputWindowHandle>& handle : windowHandles) {
            if (handle->getId() == windowHandle->getId() &&
                handle->getToken() == windowHandle->getToken()) {
                if (windowHandle->getInfo()->displayId != it.first) {
                    ALOGE("Found window %s in display %" PRId32
                          ", but it should belong to display %" PRId32,
                          windowHandle->getName().c_str(), it.first,
                          windowHandle->getInfo()->displayId);
                }
                return true;
            }
        }
    }
    return false;
}

sp<InputChannel> InputDispatcher::getInputChannelLocked(const sp<IBinder>& token) const {
    size_t count = mInputChannelsByToken.count(token);
    if (count == 0) {
        return nullptr;
    }
    return mInputChannelsByToken.at(token);
}

void InputDispatcher::updateWindowHandlesForDisplayLocked(
        const std::vector<sp<InputWindowHandle>>& inputWindowHandles, int32_t displayId) {
    if (inputWindowHandles.empty()) {
        // Remove all handles on a display if there are no windows left.
        mWindowHandlesByDisplay.erase(displayId);
        return;
    }

    // Since we compare the pointer of input window handles across window updates, we need
    // to make sure the handle object for the same window stays unchanged across updates.
    const std::vector<sp<InputWindowHandle>>& oldHandles = getWindowHandlesLocked(displayId);
    std::unordered_map<int32_t /*id*/, sp<InputWindowHandle>> oldHandlesById;
    for (const sp<InputWindowHandle>& handle : oldHandles) {
        oldHandlesById[handle->getId()] = handle;
    }

    std::vector<sp<InputWindowHandle>> newHandles;
    for (const sp<InputWindowHandle>& handle : inputWindowHandles) {
        if (!handle->updateInfo()) {
            // handle no longer valid
            continue;
        }

        const InputWindowInfo* info = handle->getInfo();
        if ((getInputChannelLocked(handle->getToken()) == nullptr &&
             info->portalToDisplayId == ADISPLAY_ID_NONE)) {
            const bool noInputChannel =
                    info->inputFeatures & InputWindowInfo::INPUT_FEATURE_NO_INPUT_CHANNEL;
            const bool canReceiveInput =
                    !(info->layoutParamsFlags & InputWindowInfo::FLAG_NOT_TOUCHABLE) ||
                    !(info->layoutParamsFlags & InputWindowInfo::FLAG_NOT_FOCUSABLE);
            if (canReceiveInput && !noInputChannel) {
                ALOGV("Window handle %s has no registered input channel",
                      handle->getName().c_str());
                continue;
            }
        }

        if (info->displayId != displayId) {
            ALOGE("Window %s updated by wrong display %d, should belong to display %d",
                  handle->getName().c_str(), displayId, info->displayId);
            continue;
        }

        if ((oldHandlesById.find(handle->getId()) != oldHandlesById.end()) &&
                (oldHandlesById.at(handle->getId())->getToken() == handle->getToken())) {
            const sp<InputWindowHandle>& oldHandle = oldHandlesById.at(handle->getId());
            oldHandle->updateFrom(handle);
            newHandles.push_back(oldHandle);
        } else {
            newHandles.push_back(handle);
        }
    }

    // Insert or replace
    mWindowHandlesByDisplay[displayId] = newHandles;
}

void InputDispatcher::setInputWindows(
        const std::unordered_map<int32_t, std::vector<sp<InputWindowHandle>>>& handlesPerDisplay) {
    { // acquire lock
        std::scoped_lock _l(mLock);
        for (auto const& i : handlesPerDisplay) {
            setInputWindowsLocked(i.second, i.first);
        }
    }
    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
}

/**
 * Called from InputManagerService, update window handle list by displayId that can receive input.
 * A window handle contains information about InputChannel, Touch Region, Types, Focused,...
 * If set an empty list, remove all handles from the specific display.
 * For focused handle, check if need to change and send a cancel event to previous one.
 * For removed handle, check if need to send a cancel event if already in touch.
 */
void InputDispatcher::setInputWindowsLocked(
        const std::vector<sp<InputWindowHandle>>& inputWindowHandles, int32_t displayId) {
    if (DEBUG_FOCUS) {
        std::string windowList;
        for (const sp<InputWindowHandle>& iwh : inputWindowHandles) {
            windowList += iwh->getName() + " ";
        }
        ALOGD("setInputWindows displayId=%" PRId32 " %s", displayId, windowList.c_str());
    }

    // Copy old handles for release if they are no longer present.
    const std::vector<sp<InputWindowHandle>> oldWindowHandles = getWindowHandlesLocked(displayId);

    updateWindowHandlesForDisplayLocked(inputWindowHandles, displayId);

    sp<InputWindowHandle> newFocusedWindowHandle = nullptr;
    bool foundHoveredWindow = false;
    for (const sp<InputWindowHandle>& windowHandle : getWindowHandlesLocked(displayId)) {
        // Set newFocusedWindowHandle to the top most focused window instead of the last one
        if (!newFocusedWindowHandle && windowHandle->getInfo()->hasFocus &&
            windowHandle->getInfo()->visible) {
            newFocusedWindowHandle = windowHandle;
        }
        if (windowHandle == mLastHoverWindowHandle) {
            foundHoveredWindow = true;
        }
    }

    if (!foundHoveredWindow) {
        mLastHoverWindowHandle = nullptr;
    }

    sp<InputWindowHandle> oldFocusedWindowHandle =
            getValueByKey(mFocusedWindowHandlesByDisplay, displayId);

    if (!haveSameToken(oldFocusedWindowHandle, newFocusedWindowHandle)) {
        if (oldFocusedWindowHandle != nullptr) {
            if (DEBUG_FOCUS) {
                ALOGD("Focus left window: %s in display %" PRId32,
                      oldFocusedWindowHandle->getName().c_str(), displayId);
            }
            sp<InputChannel> focusedInputChannel =
                    getInputChannelLocked(oldFocusedWindowHandle->getToken());
            if (focusedInputChannel != nullptr) {
                CancelationOptions options(CancelationOptions::CANCEL_NON_POINTER_EVENTS,
                                           "focus left window");
                synthesizeCancelationEventsForInputChannelLocked(focusedInputChannel, options);
                enqueueFocusEventLocked(*oldFocusedWindowHandle, false /*hasFocus*/);
            }
            mFocusedWindowHandlesByDisplay.erase(displayId);
        }
        if (newFocusedWindowHandle != nullptr) {
            if (DEBUG_FOCUS) {
                ALOGD("Focus entered window: %s in display %" PRId32,
                      newFocusedWindowHandle->getName().c_str(), displayId);
            }
            mFocusedWindowHandlesByDisplay[displayId] = newFocusedWindowHandle;
            enqueueFocusEventLocked(*newFocusedWindowHandle, true /*hasFocus*/);
        }

        if (mFocusedDisplayId == displayId) {
            onFocusChangedLocked(oldFocusedWindowHandle, newFocusedWindowHandle);
        }
    }

    std::unordered_map<int32_t, TouchState>::iterator stateIt =
            mTouchStatesByDisplay.find(displayId);
    if (stateIt != mTouchStatesByDisplay.end()) {
        TouchState& state = stateIt->second;
        for (size_t i = 0; i < state.windows.size();) {
            TouchedWindow& touchedWindow = state.windows[i];
            if (!hasWindowHandleLocked(touchedWindow.windowHandle)) {
                if (DEBUG_FOCUS) {
                    ALOGD("Touched window was removed: %s in display %" PRId32,
                          touchedWindow.windowHandle->getName().c_str(), displayId);
                }
                sp<InputChannel> touchedInputChannel =
                        getInputChannelLocked(touchedWindow.windowHandle->getToken());
                if (touchedInputChannel != nullptr) {
                    CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS,
                                               "touched window was removed");
                    synthesizeCancelationEventsForInputChannelLocked(touchedInputChannel, options);
                }
                state.windows.erase(state.windows.begin() + i);
            } else {
                ++i;
            }
        }
    }

    // Release information for windows that are no longer present.
    // This ensures that unused input channels are released promptly.
    // Otherwise, they might stick around until the window handle is destroyed
    // which might not happen until the next GC.
    for (const sp<InputWindowHandle>& oldWindowHandle : oldWindowHandles) {
        if (!hasWindowHandleLocked(oldWindowHandle)) {
            if (DEBUG_FOCUS) {
                ALOGD("Window went away: %s", oldWindowHandle->getName().c_str());
            }
            oldWindowHandle->releaseChannel();
        }
    }
}

void InputDispatcher::setFocusedApplication(
        int32_t displayId, const sp<InputApplicationHandle>& inputApplicationHandle) {
    if (DEBUG_FOCUS) {
        ALOGD("setFocusedApplication displayId=%" PRId32 " %s", displayId,
              inputApplicationHandle ? inputApplicationHandle->getName().c_str() : "<nullptr>");
    }
    { // acquire lock
        std::scoped_lock _l(mLock);

        sp<InputApplicationHandle> oldFocusedApplicationHandle =
                getValueByKey(mFocusedApplicationHandlesByDisplay, displayId);

        if (oldFocusedApplicationHandle == mAwaitedFocusedApplication &&
            inputApplicationHandle != oldFocusedApplicationHandle) {
            resetNoFocusedWindowTimeoutLocked();
        }

        if (inputApplicationHandle != nullptr && inputApplicationHandle->updateInfo()) {
            if (oldFocusedApplicationHandle != inputApplicationHandle) {
                mFocusedApplicationHandlesByDisplay[displayId] = inputApplicationHandle;
            }
        } else if (oldFocusedApplicationHandle != nullptr) {
            oldFocusedApplicationHandle.clear();
            mFocusedApplicationHandlesByDisplay.erase(displayId);
        }
    } // release lock

    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
}

/**
 * Sets the focused display, which is responsible for receiving focus-dispatched input events where
 * the display not specified.
 *
 * We track any unreleased events for each window. If a window loses the ability to receive the
 * released event, we will send a cancel event to it. So when the focused display is changed, we
 * cancel all the unreleased display-unspecified events for the focused window on the old focused
 * display. The display-specified events won't be affected.
 */
void InputDispatcher::setFocusedDisplay(int32_t displayId) {
    if (DEBUG_FOCUS) {
        ALOGD("setFocusedDisplay displayId=%" PRId32, displayId);
    }
    { // acquire lock
        std::scoped_lock _l(mLock);

        if (mFocusedDisplayId != displayId) {
            sp<InputWindowHandle> oldFocusedWindowHandle =
                    getValueByKey(mFocusedWindowHandlesByDisplay, mFocusedDisplayId);
            if (oldFocusedWindowHandle != nullptr) {
                sp<InputChannel> inputChannel =
                        getInputChannelLocked(oldFocusedWindowHandle->getToken());
                if (inputChannel != nullptr) {
                    CancelationOptions
                            options(CancelationOptions::CANCEL_NON_POINTER_EVENTS,
                                    "The display which contains this window no longer has focus.");
                    options.displayId = ADISPLAY_ID_NONE;
                    synthesizeCancelationEventsForInputChannelLocked(inputChannel, options);
                }
            }
            mFocusedDisplayId = displayId;

            // Sanity check
            sp<InputWindowHandle> newFocusedWindowHandle =
                    getValueByKey(mFocusedWindowHandlesByDisplay, displayId);
            onFocusChangedLocked(oldFocusedWindowHandle, newFocusedWindowHandle);

            if (newFocusedWindowHandle == nullptr) {
                ALOGW("Focused display #%" PRId32 " does not have a focused window.", displayId);
                if (!mFocusedWindowHandlesByDisplay.empty()) {
                    ALOGE("But another display has a focused window:");
                    for (auto& it : mFocusedWindowHandlesByDisplay) {
                        const int32_t displayId = it.first;
                        const sp<InputWindowHandle>& windowHandle = it.second;
                        ALOGE("Display #%" PRId32 " has focused window: '%s'\n", displayId,
                              windowHandle->getName().c_str());
                    }
                }
            }
        }

        if (DEBUG_FOCUS) {
            logDispatchStateLocked();
        }
    } // release lock

    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
}

void InputDispatcher::setInputDispatchMode(bool enabled, bool frozen) {
    if (DEBUG_FOCUS) {
        ALOGD("setInputDispatchMode: enabled=%d, frozen=%d", enabled, frozen);
    }

    bool changed;
    { // acquire lock
        std::scoped_lock _l(mLock);

        if (mDispatchEnabled != enabled || mDispatchFrozen != frozen) {
            if (mDispatchFrozen && !frozen) {
                resetNoFocusedWindowTimeoutLocked();
            }

            if (mDispatchEnabled && !enabled) {
                resetAndDropEverythingLocked("dispatcher is being disabled");
            }

            mDispatchEnabled = enabled;
            mDispatchFrozen = frozen;
            changed = true;
        } else {
            changed = false;
        }

        if (DEBUG_FOCUS) {
            logDispatchStateLocked();
        }
    } // release lock

    if (changed) {
        // Wake up poll loop since it may need to make new input dispatching choices.
        mLooper->wake();
    }
}

void InputDispatcher::setInputFilterEnabled(bool enabled) {
    if (DEBUG_FOCUS) {
        ALOGD("setInputFilterEnabled: enabled=%d", enabled);
    }

    { // acquire lock
        std::scoped_lock _l(mLock);

        if (mInputFilterEnabled == enabled) {
            return;
        }

        mInputFilterEnabled = enabled;
        resetAndDropEverythingLocked("input filter is being enabled or disabled");
    } // release lock

    // Wake up poll loop since there might be work to do to drop everything.
    mLooper->wake();
}

void InputDispatcher::setInTouchMode(bool inTouchMode) {
    std::scoped_lock lock(mLock);
    mInTouchMode = inTouchMode;
}

bool InputDispatcher::transferTouchFocus(const sp<IBinder>& fromToken, const sp<IBinder>& toToken) {
    if (fromToken == toToken) {
        if (DEBUG_FOCUS) {
            ALOGD("Trivial transfer to same window.");
        }
        return true;
    }

    { // acquire lock
        std::scoped_lock _l(mLock);

        sp<InputWindowHandle> fromWindowHandle = getWindowHandleLocked(fromToken);
        sp<InputWindowHandle> toWindowHandle = getWindowHandleLocked(toToken);
        if (fromWindowHandle == nullptr || toWindowHandle == nullptr) {
            ALOGW("Cannot transfer focus because from or to window not found.");
            return false;
        }
        if (DEBUG_FOCUS) {
            ALOGD("transferTouchFocus: fromWindowHandle=%s, toWindowHandle=%s",
                  fromWindowHandle->getName().c_str(), toWindowHandle->getName().c_str());
        }
        if (fromWindowHandle->getInfo()->displayId != toWindowHandle->getInfo()->displayId) {
            if (DEBUG_FOCUS) {
                ALOGD("Cannot transfer focus because windows are on different displays.");
            }
            return false;
        }

        bool found = false;
        for (std::pair<const int32_t, TouchState>& pair : mTouchStatesByDisplay) {
            TouchState& state = pair.second;
            for (size_t i = 0; i < state.windows.size(); i++) {
                const TouchedWindow& touchedWindow = state.windows[i];
                if (touchedWindow.windowHandle == fromWindowHandle) {
                    int32_t oldTargetFlags = touchedWindow.targetFlags;
                    BitSet32 pointerIds = touchedWindow.pointerIds;

                    state.windows.erase(state.windows.begin() + i);

                    int32_t newTargetFlags = oldTargetFlags &
                            (InputTarget::FLAG_FOREGROUND | InputTarget::FLAG_SPLIT |
                             InputTarget::FLAG_DISPATCH_AS_IS);
                    state.addOrUpdateWindow(toWindowHandle, newTargetFlags, pointerIds);

                    found = true;
                    goto Found;
                }
            }
        }
    Found:

        if (!found) {
            if (DEBUG_FOCUS) {
                ALOGD("Focus transfer failed because from window did not have focus.");
            }
            return false;
        }

        sp<Connection> fromConnection = getConnectionLocked(fromToken);
        sp<Connection> toConnection = getConnectionLocked(toToken);
        if (fromConnection != nullptr && toConnection != nullptr) {
            fromConnection->inputState.mergePointerStateTo(toConnection->inputState);
            CancelationOptions
                    options(CancelationOptions::CANCEL_POINTER_EVENTS,
                            "transferring touch focus from this window to another window");
            synthesizeCancelationEventsForConnectionLocked(fromConnection, options);
            synthesizePointerDownEventsForConnectionLocked(toConnection);
        }

        if (DEBUG_FOCUS) {
            logDispatchStateLocked();
        }
    } // release lock

    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
    return true;
}

void InputDispatcher::resetAndDropEverythingLocked(const char* reason) {
    if (DEBUG_FOCUS) {
        ALOGD("Resetting and dropping all events (%s).", reason);
    }

    CancelationOptions options(CancelationOptions::CANCEL_ALL_EVENTS, reason);
    synthesizeCancelationEventsForAllConnectionsLocked(options);

    resetKeyRepeatLocked();
    releasePendingEventLocked();
    drainInboundQueueLocked();
    resetNoFocusedWindowTimeoutLocked();

    mAnrTracker.clear();
    mTouchStatesByDisplay.clear();
    mLastHoverWindowHandle.clear();
    mReplacedKeys.clear();
}

void InputDispatcher::logDispatchStateLocked() {
    std::string dump;
    dumpDispatchStateLocked(dump);

    std::istringstream stream(dump);
    std::string line;

    while (std::getline(stream, line, '\n')) {
        ALOGD("%s", line.c_str());
    }
}

void InputDispatcher::dumpDispatchStateLocked(std::string& dump) {
    dump += StringPrintf(INDENT "DispatchEnabled: %s\n", toString(mDispatchEnabled));
    dump += StringPrintf(INDENT "DispatchFrozen: %s\n", toString(mDispatchFrozen));
    dump += StringPrintf(INDENT "InputFilterEnabled: %s\n", toString(mInputFilterEnabled));
    dump += StringPrintf(INDENT "FocusedDisplayId: %" PRId32 "\n", mFocusedDisplayId);

    if (!mFocusedApplicationHandlesByDisplay.empty()) {
        dump += StringPrintf(INDENT "FocusedApplications:\n");
        for (auto& it : mFocusedApplicationHandlesByDisplay) {
            const int32_t displayId = it.first;
            const sp<InputApplicationHandle>& applicationHandle = it.second;
            dump += StringPrintf(INDENT2 "displayId=%" PRId32
                                         ", name='%s', dispatchingTimeout=%" PRId64 "ms\n",
                                 displayId, applicationHandle->getName().c_str(),
                                 ns2ms(applicationHandle
                                               ->getDispatchingTimeout(
                                                       DEFAULT_INPUT_DISPATCHING_TIMEOUT)
                                               .count()));
        }
    } else {
        dump += StringPrintf(INDENT "FocusedApplications: <none>\n");
    }

    if (!mFocusedWindowHandlesByDisplay.empty()) {
        dump += StringPrintf(INDENT "FocusedWindows:\n");
        for (auto& it : mFocusedWindowHandlesByDisplay) {
            const int32_t displayId = it.first;
            const sp<InputWindowHandle>& windowHandle = it.second;
            dump += StringPrintf(INDENT2 "displayId=%" PRId32 ", name='%s'\n", displayId,
                                 windowHandle->getName().c_str());
        }
    } else {
        dump += StringPrintf(INDENT "FocusedWindows: <none>\n");
    }

    if (!mTouchStatesByDisplay.empty()) {
        dump += StringPrintf(INDENT "TouchStatesByDisplay:\n");
        for (const std::pair<int32_t, TouchState>& pair : mTouchStatesByDisplay) {
            const TouchState& state = pair.second;
            dump += StringPrintf(INDENT2 "%d: down=%s, split=%s, deviceId=%d, source=0x%08x\n",
                                 state.displayId, toString(state.down), toString(state.split),
                                 state.deviceId, state.source);
            if (!state.windows.empty()) {
                dump += INDENT3 "Windows:\n";
                for (size_t i = 0; i < state.windows.size(); i++) {
                    const TouchedWindow& touchedWindow = state.windows[i];
                    dump += StringPrintf(INDENT4
                                         "%zu: name='%s', pointerIds=0x%0x, targetFlags=0x%x\n",
                                         i, touchedWindow.windowHandle->getName().c_str(),
                                         touchedWindow.pointerIds.value, touchedWindow.targetFlags);
                }
            } else {
                dump += INDENT3 "Windows: <none>\n";
            }
            if (!state.portalWindows.empty()) {
                dump += INDENT3 "Portal windows:\n";
                for (size_t i = 0; i < state.portalWindows.size(); i++) {
                    const sp<InputWindowHandle> portalWindowHandle = state.portalWindows[i];
                    dump += StringPrintf(INDENT4 "%zu: name='%s'\n", i,
                                         portalWindowHandle->getName().c_str());
                }
            }
        }
    } else {
        dump += INDENT "TouchStates: <no displays touched>\n";
    }

    if (!mWindowHandlesByDisplay.empty()) {
        for (auto& it : mWindowHandlesByDisplay) {
            const std::vector<sp<InputWindowHandle>> windowHandles = it.second;
            dump += StringPrintf(INDENT "Display: %" PRId32 "\n", it.first);
            if (!windowHandles.empty()) {
                dump += INDENT2 "Windows:\n";
                for (size_t i = 0; i < windowHandles.size(); i++) {
                    const sp<InputWindowHandle>& windowHandle = windowHandles[i];
                    const InputWindowInfo* windowInfo = windowHandle->getInfo();

                    dump += StringPrintf(INDENT3 "%zu: name='%s', displayId=%d, "
                                                 "portalToDisplayId=%d, paused=%s, hasFocus=%s, "
                                                 "hasWallpaper=%s, visible=%s, canReceiveKeys=%s, "
                                                 "flags=0x%08x, type=0x%08x, "
                                                 "frame=[%d,%d][%d,%d], globalScale=%f, "
                                                 "windowScale=(%f,%f), touchableRegion=",
                                         i, windowInfo->name.c_str(), windowInfo->displayId,
                                         windowInfo->portalToDisplayId,
                                         toString(windowInfo->paused),
                                         toString(windowInfo->hasFocus),
                                         toString(windowInfo->hasWallpaper),
                                         toString(windowInfo->visible),
                                         toString(windowInfo->canReceiveKeys),
                                         windowInfo->layoutParamsFlags,
                                         windowInfo->layoutParamsType, windowInfo->frameLeft,
                                         windowInfo->frameTop, windowInfo->frameRight,
                                         windowInfo->frameBottom, windowInfo->globalScaleFactor,
                                         windowInfo->windowXScale, windowInfo->windowYScale);
                    dumpRegion(dump, windowInfo->touchableRegion);
                    dump += StringPrintf(", inputFeatures=0x%08x", windowInfo->inputFeatures);
                    dump += StringPrintf(", ownerPid=%d, ownerUid=%d, dispatchingTimeout=%" PRId64
                                         "ms\n",
                                         windowInfo->ownerPid, windowInfo->ownerUid,
                                         ns2ms(windowInfo->dispatchingTimeout));
                }
            } else {
                dump += INDENT2 "Windows: <none>\n";
            }
        }
    } else {
        dump += INDENT "Displays: <none>\n";
    }

    if (!mGlobalMonitorsByDisplay.empty() || !mGestureMonitorsByDisplay.empty()) {
        for (auto& it : mGlobalMonitorsByDisplay) {
            const std::vector<Monitor>& monitors = it.second;
            dump += StringPrintf(INDENT "Global monitors in display %" PRId32 ":\n", it.first);
            dumpMonitors(dump, monitors);
        }
        for (auto& it : mGestureMonitorsByDisplay) {
            const std::vector<Monitor>& monitors = it.second;
            dump += StringPrintf(INDENT "Gesture monitors in display %" PRId32 ":\n", it.first);
            dumpMonitors(dump, monitors);
        }
    } else {
        dump += INDENT "Monitors: <none>\n";
    }

    nsecs_t currentTime = now();

    // Dump recently dispatched or dropped events from oldest to newest.
    if (!mRecentQueue.empty()) {
        dump += StringPrintf(INDENT "RecentQueue: length=%zu\n", mRecentQueue.size());
        for (EventEntry* entry : mRecentQueue) {
            dump += INDENT2;
            entry->appendDescription(dump);
            dump += StringPrintf(", age=%" PRId64 "ms\n", ns2ms(currentTime - entry->eventTime));
        }
    } else {
        dump += INDENT "RecentQueue: <empty>\n";
    }

    // Dump event currently being dispatched.
    if (mPendingEvent) {
        dump += INDENT "PendingEvent:\n";
        dump += INDENT2;
        mPendingEvent->appendDescription(dump);
        dump += StringPrintf(", age=%" PRId64 "ms\n",
                             ns2ms(currentTime - mPendingEvent->eventTime));
    } else {
        dump += INDENT "PendingEvent: <none>\n";
    }

    // Dump inbound events from oldest to newest.
    if (!mInboundQueue.empty()) {
        dump += StringPrintf(INDENT "InboundQueue: length=%zu\n", mInboundQueue.size());
        for (EventEntry* entry : mInboundQueue) {
            dump += INDENT2;
            entry->appendDescription(dump);
            dump += StringPrintf(", age=%" PRId64 "ms\n", ns2ms(currentTime - entry->eventTime));
        }
    } else {
        dump += INDENT "InboundQueue: <empty>\n";
    }

    if (!mReplacedKeys.empty()) {
        dump += INDENT "ReplacedKeys:\n";
        for (const std::pair<KeyReplacement, int32_t>& pair : mReplacedKeys) {
            const KeyReplacement& replacement = pair.first;
            int32_t newKeyCode = pair.second;
            dump += StringPrintf(INDENT2 "originalKeyCode=%d, deviceId=%d -> newKeyCode=%d\n",
                                 replacement.keyCode, replacement.deviceId, newKeyCode);
        }
    } else {
        dump += INDENT "ReplacedKeys: <empty>\n";
    }

    if (!mConnectionsByFd.empty()) {
        dump += INDENT "Connections:\n";
        for (const auto& pair : mConnectionsByFd) {
            const sp<Connection>& connection = pair.second;
            dump += StringPrintf(INDENT2 "%i: channelName='%s', windowName='%s', "
                                         "status=%s, monitor=%s, responsive=%s\n",
                                 pair.first, connection->getInputChannelName().c_str(),
                                 connection->getWindowName().c_str(), connection->getStatusLabel(),
                                 toString(connection->monitor), toString(connection->responsive));

            if (!connection->outboundQueue.empty()) {
                dump += StringPrintf(INDENT3 "OutboundQueue: length=%zu\n",
                                     connection->outboundQueue.size());
                for (DispatchEntry* entry : connection->outboundQueue) {
                    dump.append(INDENT4);
                    entry->eventEntry->appendDescription(dump);
                    dump += StringPrintf(", targetFlags=0x%08x, resolvedAction=%d, age=%" PRId64
                                         "ms\n",
                                         entry->targetFlags, entry->resolvedAction,
                                         ns2ms(currentTime - entry->eventEntry->eventTime));
                }
            } else {
                dump += INDENT3 "OutboundQueue: <empty>\n";
            }

            if (!connection->waitQueue.empty()) {
                dump += StringPrintf(INDENT3 "WaitQueue: length=%zu\n",
                                     connection->waitQueue.size());
                for (DispatchEntry* entry : connection->waitQueue) {
                    dump += INDENT4;
                    entry->eventEntry->appendDescription(dump);
                    dump += StringPrintf(", targetFlags=0x%08x, resolvedAction=%d, "
                                         "age=%" PRId64 "ms, wait=%" PRId64 "ms\n",
                                         entry->targetFlags, entry->resolvedAction,
                                         ns2ms(currentTime - entry->eventEntry->eventTime),
                                         ns2ms(currentTime - entry->deliveryTime));
                }
            } else {
                dump += INDENT3 "WaitQueue: <empty>\n";
            }
        }
    } else {
        dump += INDENT "Connections: <none>\n";
    }

    if (isAppSwitchPendingLocked()) {
        dump += StringPrintf(INDENT "AppSwitch: pending, due in %" PRId64 "ms\n",
                             ns2ms(mAppSwitchDueTime - now()));
    } else {
        dump += INDENT "AppSwitch: not pending\n";
    }

    dump += INDENT "Configuration:\n";
    dump += StringPrintf(INDENT2 "KeyRepeatDelay: %" PRId64 "ms\n", ns2ms(mConfig.keyRepeatDelay));
    dump += StringPrintf(INDENT2 "KeyRepeatTimeout: %" PRId64 "ms\n",
                         ns2ms(mConfig.keyRepeatTimeout));
}

void InputDispatcher::dumpMonitors(std::string& dump, const std::vector<Monitor>& monitors) {
    const size_t numMonitors = monitors.size();
    for (size_t i = 0; i < numMonitors; i++) {
        const Monitor& monitor = monitors[i];
        const sp<InputChannel>& channel = monitor.inputChannel;
        dump += StringPrintf(INDENT2 "%zu: '%s', ", i, channel->getName().c_str());
        dump += "\n";
    }
}

status_t InputDispatcher::registerInputChannel(const sp<InputChannel>& inputChannel) {
#if DEBUG_REGISTRATION
    ALOGD("channel '%s' ~ registerInputChannel", inputChannel->getName().c_str());
#endif

    { // acquire lock
        std::scoped_lock _l(mLock);
        sp<Connection> existingConnection = getConnectionLocked(inputChannel->getConnectionToken());
        if (existingConnection != nullptr) {
            ALOGW("Attempted to register already registered input channel '%s'",
                  inputChannel->getName().c_str());
            return BAD_VALUE;
        }

        sp<Connection> connection = new Connection(inputChannel, false /*monitor*/, mIdGenerator);

        int fd = inputChannel->getFd();
        mConnectionsByFd[fd] = connection;
        mInputChannelsByToken[inputChannel->getConnectionToken()] = inputChannel;

        mLooper->addFd(fd, 0, ALOOPER_EVENT_INPUT, handleReceiveCallback, this);
    } // release lock

    // Wake the looper because some connections have changed.
    mLooper->wake();
    return OK;
}

status_t InputDispatcher::registerInputMonitor(const sp<InputChannel>& inputChannel,
                                               int32_t displayId, bool isGestureMonitor) {
    { // acquire lock
        std::scoped_lock _l(mLock);

        if (displayId < 0) {
            ALOGW("Attempted to register input monitor without a specified display.");
            return BAD_VALUE;
        }

        if (inputChannel->getConnectionToken() == nullptr) {
            ALOGW("Attempted to register input monitor without an identifying token.");
            return BAD_VALUE;
        }

        sp<Connection> connection = new Connection(inputChannel, true /*monitor*/, mIdGenerator);

        const int fd = inputChannel->getFd();
        mConnectionsByFd[fd] = connection;
        mInputChannelsByToken[inputChannel->getConnectionToken()] = inputChannel;

        auto& monitorsByDisplay =
                isGestureMonitor ? mGestureMonitorsByDisplay : mGlobalMonitorsByDisplay;
        monitorsByDisplay[displayId].emplace_back(inputChannel);

        mLooper->addFd(fd, 0, ALOOPER_EVENT_INPUT, handleReceiveCallback, this);
    }
    // Wake the looper because some connections have changed.
    mLooper->wake();
    return OK;
}

status_t InputDispatcher::unregisterInputChannel(const sp<InputChannel>& inputChannel) {
#if DEBUG_REGISTRATION
    ALOGD("channel '%s' ~ unregisterInputChannel", inputChannel->getName().c_str());
#endif

    { // acquire lock
        std::scoped_lock _l(mLock);

        status_t status = unregisterInputChannelLocked(inputChannel, false /*notify*/);
        if (status) {
            return status;
        }
    } // release lock

    // Wake the poll loop because removing the connection may have changed the current
    // synchronization state.
    mLooper->wake();
    return OK;
}

status_t InputDispatcher::unregisterInputChannelLocked(const sp<InputChannel>& inputChannel,
                                                       bool notify) {
    sp<Connection> connection = getConnectionLocked(inputChannel->getConnectionToken());
    if (connection == nullptr) {
        ALOGW("Attempted to unregister already unregistered input channel '%s'",
              inputChannel->getName().c_str());
        return BAD_VALUE;
    }

    removeConnectionLocked(connection);
    mInputChannelsByToken.erase(inputChannel->getConnectionToken());

    if (connection->monitor) {
        removeMonitorChannelLocked(inputChannel);
    }

    mLooper->removeFd(inputChannel->getFd());

    nsecs_t currentTime = now();
    abortBrokenDispatchCycleLocked(currentTime, connection, notify);

    connection->status = Connection::STATUS_ZOMBIE;
    return OK;
}

void InputDispatcher::removeMonitorChannelLocked(const sp<InputChannel>& inputChannel) {
    removeMonitorChannelLocked(inputChannel, mGlobalMonitorsByDisplay);
    removeMonitorChannelLocked(inputChannel, mGestureMonitorsByDisplay);
}

void InputDispatcher::removeMonitorChannelLocked(
        const sp<InputChannel>& inputChannel,
        std::unordered_map<int32_t, std::vector<Monitor>>& monitorsByDisplay) {
    for (auto it = monitorsByDisplay.begin(); it != monitorsByDisplay.end();) {
        std::vector<Monitor>& monitors = it->second;
        const size_t numMonitors = monitors.size();
        for (size_t i = 0; i < numMonitors; i++) {
            if (monitors[i].inputChannel == inputChannel) {
                monitors.erase(monitors.begin() + i);
                break;
            }
        }
        if (monitors.empty()) {
            it = monitorsByDisplay.erase(it);
        } else {
            ++it;
        }
    }
}

status_t InputDispatcher::pilferPointers(const sp<IBinder>& token) {
    { // acquire lock
        std::scoped_lock _l(mLock);
        std::optional<int32_t> foundDisplayId = findGestureMonitorDisplayByTokenLocked(token);

        if (!foundDisplayId) {
            ALOGW("Attempted to pilfer pointers from an un-registered monitor or invalid token");
            return BAD_VALUE;
        }
        int32_t displayId = foundDisplayId.value();

        std::unordered_map<int32_t, TouchState>::iterator stateIt =
                mTouchStatesByDisplay.find(displayId);
        if (stateIt == mTouchStatesByDisplay.end()) {
            ALOGW("Failed to pilfer pointers: no pointers on display %" PRId32 ".", displayId);
            return BAD_VALUE;
        }

        TouchState& state = stateIt->second;
        std::optional<int32_t> foundDeviceId;
        for (const TouchedMonitor& touchedMonitor : state.gestureMonitors) {
            if (touchedMonitor.monitor.inputChannel->getConnectionToken() == token) {
                foundDeviceId = state.deviceId;
            }
        }
        if (!foundDeviceId || !state.down) {
            ALOGW("Attempted to pilfer points from a monitor without any on-going pointer streams."
                  " Ignoring.");
            return BAD_VALUE;
        }
        int32_t deviceId = foundDeviceId.value();

        // Send cancel events to all the input channels we're stealing from.
        CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS,
                                   "gesture monitor stole pointer stream");
        options.deviceId = deviceId;
        options.displayId = displayId;
        for (const TouchedWindow& window : state.windows) {
            sp<InputChannel> channel = getInputChannelLocked(window.windowHandle->getToken());
            if (channel != nullptr) {
                synthesizeCancelationEventsForInputChannelLocked(channel, options);
            }
        }
        // Then clear the current touch state so we stop dispatching to them as well.
        state.filterNonMonitors();
    }
    return OK;
}

std::optional<int32_t> InputDispatcher::findGestureMonitorDisplayByTokenLocked(
        const sp<IBinder>& token) {
    for (const auto& it : mGestureMonitorsByDisplay) {
        const std::vector<Monitor>& monitors = it.second;
        for (const Monitor& monitor : monitors) {
            if (monitor.inputChannel->getConnectionToken() == token) {
                return it.first;
            }
        }
    }
    return std::nullopt;
}

sp<Connection> InputDispatcher::getConnectionLocked(const sp<IBinder>& inputConnectionToken) const {
    if (inputConnectionToken == nullptr) {
        return nullptr;
    }

    for (const auto& pair : mConnectionsByFd) {
        const sp<Connection>& connection = pair.second;
        if (connection->inputChannel->getConnectionToken() == inputConnectionToken) {
            return connection;
        }
    }

    return nullptr;
}

void InputDispatcher::removeConnectionLocked(const sp<Connection>& connection) {
    mAnrTracker.eraseToken(connection->inputChannel->getConnectionToken());
    removeByValue(mConnectionsByFd, connection);
}

void InputDispatcher::onDispatchCycleFinishedLocked(nsecs_t currentTime,
                                                    const sp<Connection>& connection, uint32_t seq,
                                                    bool handled) {
    std::unique_ptr<CommandEntry> commandEntry = std::make_unique<CommandEntry>(
            &InputDispatcher::doDispatchCycleFinishedLockedInterruptible);
    commandEntry->connection = connection;
    commandEntry->eventTime = currentTime;
    commandEntry->seq = seq;
    commandEntry->handled = handled;
    postCommandLocked(std::move(commandEntry));
}

void InputDispatcher::onDispatchCycleBrokenLocked(nsecs_t currentTime,
                                                  const sp<Connection>& connection) {
    ALOGE("channel '%s' ~ Channel is unrecoverably broken and will be disposed!",
          connection->getInputChannelName().c_str());

    std::unique_ptr<CommandEntry> commandEntry = std::make_unique<CommandEntry>(
            &InputDispatcher::doNotifyInputChannelBrokenLockedInterruptible);
    commandEntry->connection = connection;
    postCommandLocked(std::move(commandEntry));
}

void InputDispatcher::onFocusChangedLocked(const sp<InputWindowHandle>& oldFocus,
                                           const sp<InputWindowHandle>& newFocus) {
    sp<IBinder> oldToken = oldFocus != nullptr ? oldFocus->getToken() : nullptr;
    sp<IBinder> newToken = newFocus != nullptr ? newFocus->getToken() : nullptr;
    std::unique_ptr<CommandEntry> commandEntry = std::make_unique<CommandEntry>(
            &InputDispatcher::doNotifyFocusChangedLockedInterruptible);
    commandEntry->oldToken = oldToken;
    commandEntry->newToken = newToken;
    postCommandLocked(std::move(commandEntry));
}

void InputDispatcher::onAnrLocked(const Connection& connection) {
    // Since we are allowing the policy to extend the timeout, maybe the waitQueue
    // is already healthy again. Don't raise ANR in this situation
    if (connection.waitQueue.empty()) {
        ALOGI("Not raising ANR because the connection %s has recovered",
              connection.inputChannel->getName().c_str());
        return;
    }
    /**
     * The "oldestEntry" is the entry that was first sent to the application. That entry, however,
     * may not be the one that caused the timeout to occur. One possibility is that window timeout
     * has changed. This could cause newer entries to time out before the already dispatched
     * entries. In that situation, the newest entries caused ANR. But in all likelihood, the app
     * processes the events linearly. So providing information about the oldest entry seems to be
     * most useful.
     */
    DispatchEntry* oldestEntry = *connection.waitQueue.begin();
    const nsecs_t currentWait = now() - oldestEntry->deliveryTime;
    std::string reason =
            android::base::StringPrintf("%s is not responding. Waited %" PRId64 "ms for %s",
                                        connection.inputChannel->getName().c_str(),
                                        ns2ms(currentWait),
                                        oldestEntry->eventEntry->getDescription().c_str());

    updateLastAnrStateLocked(getWindowHandleLocked(connection.inputChannel->getConnectionToken()),
                             reason);

    std::unique_ptr<CommandEntry> commandEntry =
            std::make_unique<CommandEntry>(&InputDispatcher::doNotifyAnrLockedInterruptible);
    commandEntry->inputApplicationHandle = nullptr;
    commandEntry->inputChannel = connection.inputChannel;
    commandEntry->reason = std::move(reason);
    postCommandLocked(std::move(commandEntry));
}

void InputDispatcher::onAnrLocked(const sp<InputApplicationHandle>& application) {
    std::string reason = android::base::StringPrintf("%s does not have a focused window",
                                                     application->getName().c_str());

    updateLastAnrStateLocked(application, reason);

    std::unique_ptr<CommandEntry> commandEntry =
            std::make_unique<CommandEntry>(&InputDispatcher::doNotifyAnrLockedInterruptible);
    commandEntry->inputApplicationHandle = application;
    commandEntry->inputChannel = nullptr;
    commandEntry->reason = std::move(reason);
    postCommandLocked(std::move(commandEntry));
}

void InputDispatcher::updateLastAnrStateLocked(const sp<InputWindowHandle>& window,
                                               const std::string& reason) {
    const std::string windowLabel = getApplicationWindowLabel(nullptr, window);
    updateLastAnrStateLocked(windowLabel, reason);
}

void InputDispatcher::updateLastAnrStateLocked(const sp<InputApplicationHandle>& application,
                                               const std::string& reason) {
    const std::string windowLabel = getApplicationWindowLabel(application, nullptr);
    updateLastAnrStateLocked(windowLabel, reason);
}

void InputDispatcher::updateLastAnrStateLocked(const std::string& windowLabel,
                                               const std::string& reason) {
    // Capture a record of the InputDispatcher state at the time of the ANR.
    time_t t = time(nullptr);
    struct tm tm;
    localtime_r(&t, &tm);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%F %T", &tm);
    mLastAnrState.clear();
    mLastAnrState += INDENT "ANR:\n";
    mLastAnrState += StringPrintf(INDENT2 "Time: %s\n", timestr);
    mLastAnrState += StringPrintf(INDENT2 "Reason: %s\n", reason.c_str());
    mLastAnrState += StringPrintf(INDENT2 "Window: %s\n", windowLabel.c_str());
    dumpDispatchStateLocked(mLastAnrState);
}

void InputDispatcher::doNotifyConfigurationChangedLockedInterruptible(CommandEntry* commandEntry) {
    mLock.unlock();

    mPolicy->notifyConfigurationChanged(commandEntry->eventTime);

    mLock.lock();
}

void InputDispatcher::doNotifyInputChannelBrokenLockedInterruptible(CommandEntry* commandEntry) {
    sp<Connection> connection = commandEntry->connection;

    if (connection->status != Connection::STATUS_ZOMBIE) {
        mLock.unlock();

        mPolicy->notifyInputChannelBroken(connection->inputChannel->getConnectionToken());

        mLock.lock();
    }
}

void InputDispatcher::doNotifyFocusChangedLockedInterruptible(CommandEntry* commandEntry) {
    sp<IBinder> oldToken = commandEntry->oldToken;
    sp<IBinder> newToken = commandEntry->newToken;
    mLock.unlock();
    mPolicy->notifyFocusChanged(oldToken, newToken);
    mLock.lock();
}

void InputDispatcher::doNotifyAnrLockedInterruptible(CommandEntry* commandEntry) {
    sp<IBinder> token =
            commandEntry->inputChannel ? commandEntry->inputChannel->getConnectionToken() : nullptr;
    mLock.unlock();

    const nsecs_t timeoutExtension =
            mPolicy->notifyAnr(commandEntry->inputApplicationHandle, token, commandEntry->reason);

    mLock.lock();

    if (timeoutExtension > 0) {
        extendAnrTimeoutsLocked(commandEntry->inputApplicationHandle, token, timeoutExtension);
    } else {
        // stop waking up for events in this connection, it is already not responding
        sp<Connection> connection = getConnectionLocked(token);
        if (connection == nullptr) {
            return;
        }
        cancelEventsForAnrLocked(connection);
    }
}

void InputDispatcher::extendAnrTimeoutsLocked(const sp<InputApplicationHandle>& application,
                                              const sp<IBinder>& connectionToken,
                                              nsecs_t timeoutExtension) {
    if (connectionToken == nullptr && application != nullptr) {
        // The ANR happened because there's no focused window
        mNoFocusedWindowTimeoutTime = now() + timeoutExtension;
        mAwaitedFocusedApplication = application;
    }

    sp<Connection> connection = getConnectionLocked(connectionToken);
    if (connection == nullptr) {
        // It's possible that the connection already disappeared. No action necessary.
        return;
    }

    ALOGI("Raised ANR, but the policy wants to keep waiting on %s for %" PRId64 "ms longer",
          connection->inputChannel->getName().c_str(), ns2ms(timeoutExtension));

    connection->responsive = true;
    const nsecs_t newTimeout = now() + timeoutExtension;
    for (DispatchEntry* entry : connection->waitQueue) {
        if (newTimeout >= entry->timeoutTime) {
            // Already removed old entries when connection was marked unresponsive
            entry->timeoutTime = newTimeout;
            mAnrTracker.insert(entry->timeoutTime, connectionToken);
        }
    }
}

void InputDispatcher::doInterceptKeyBeforeDispatchingLockedInterruptible(
        CommandEntry* commandEntry) {
    KeyEntry* entry = commandEntry->keyEntry;
    KeyEvent event = createKeyEvent(*entry);

    mLock.unlock();

    android::base::Timer t;
    sp<IBinder> token = commandEntry->inputChannel != nullptr
            ? commandEntry->inputChannel->getConnectionToken()
            : nullptr;
    nsecs_t delay = mPolicy->interceptKeyBeforeDispatching(token, &event, entry->policyFlags);
    if (t.duration() > SLOW_INTERCEPTION_THRESHOLD) {
        ALOGW("Excessive delay in interceptKeyBeforeDispatching; took %s ms",
              std::to_string(t.duration().count()).c_str());
    }

    mLock.lock();

    if (delay < 0) {
        entry->interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_SKIP;
    } else if (!delay) {
        entry->interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_CONTINUE;
    } else {
        entry->interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_TRY_AGAIN_LATER;
        entry->interceptKeyWakeupTime = now() + delay;
    }
    entry->release();
}

void InputDispatcher::doOnPointerDownOutsideFocusLockedInterruptible(CommandEntry* commandEntry) {
    mLock.unlock();
    mPolicy->onPointerDownOutsideFocus(commandEntry->newToken);
    mLock.lock();
}

/**
 * Connection is responsive if it has no events in the waitQueue that are older than the
 * current time.
 */
static bool isConnectionResponsive(const Connection& connection) {
    const nsecs_t currentTime = now();
    for (const DispatchEntry* entry : connection.waitQueue) {
        if (entry->timeoutTime < currentTime) {
            return false;
        }
    }
    return true;
}

void InputDispatcher::doDispatchCycleFinishedLockedInterruptible(CommandEntry* commandEntry) {
    sp<Connection> connection = commandEntry->connection;
    const nsecs_t finishTime = commandEntry->eventTime;
    uint32_t seq = commandEntry->seq;
    const bool handled = commandEntry->handled;

    // Handle post-event policy actions.
    std::deque<DispatchEntry*>::iterator dispatchEntryIt = connection->findWaitQueueEntry(seq);
    if (dispatchEntryIt == connection->waitQueue.end()) {
        return;
    }
    DispatchEntry* dispatchEntry = *dispatchEntryIt;
    const nsecs_t eventDuration = finishTime - dispatchEntry->deliveryTime;
    if (eventDuration > SLOW_EVENT_PROCESSING_WARNING_TIMEOUT) {
        ALOGI("%s spent %" PRId64 "ms processing %s", connection->getWindowName().c_str(),
              ns2ms(eventDuration), dispatchEntry->eventEntry->getDescription().c_str());
    }
    reportDispatchStatistics(std::chrono::nanoseconds(eventDuration), *connection, handled);

    bool restartEvent;
    if (dispatchEntry->eventEntry->type == EventEntry::Type::KEY) {
        KeyEntry* keyEntry = static_cast<KeyEntry*>(dispatchEntry->eventEntry);
        restartEvent =
                afterKeyEventLockedInterruptible(connection, dispatchEntry, keyEntry, handled);
    } else if (dispatchEntry->eventEntry->type == EventEntry::Type::MOTION) {
        MotionEntry* motionEntry = static_cast<MotionEntry*>(dispatchEntry->eventEntry);
        restartEvent = afterMotionEventLockedInterruptible(connection, dispatchEntry, motionEntry,
                                                           handled);
    } else {
        restartEvent = false;
    }

    // Dequeue the event and start the next cycle.
    // Because the lock might have been released, it is possible that the
    // contents of the wait queue to have been drained, so we need to double-check
    // a few things.
    dispatchEntryIt = connection->findWaitQueueEntry(seq);
    if (dispatchEntryIt != connection->waitQueue.end()) {
        dispatchEntry = *dispatchEntryIt;
        connection->waitQueue.erase(dispatchEntryIt);
        mAnrTracker.erase(dispatchEntry->timeoutTime,
                          connection->inputChannel->getConnectionToken());
        if (!connection->responsive) {
            connection->responsive = isConnectionResponsive(*connection);
        }
        traceWaitQueueLength(connection);
        if (restartEvent && connection->status == Connection::STATUS_NORMAL) {
            connection->outboundQueue.push_front(dispatchEntry);
            traceOutboundQueueLength(connection);
        } else {
            releaseDispatchEntry(dispatchEntry);
        }
    }

    // Start the next dispatch cycle for this connection.
    startDispatchCycleLocked(now(), connection);
}

bool InputDispatcher::afterKeyEventLockedInterruptible(const sp<Connection>& connection,
                                                       DispatchEntry* dispatchEntry,
                                                       KeyEntry* keyEntry, bool handled) {
    if (keyEntry->flags & AKEY_EVENT_FLAG_FALLBACK) {
        if (!handled) {
            // Report the key as unhandled, since the fallback was not handled.
            mReporter->reportUnhandledKey(keyEntry->id);
        }
        return false;
    }

    // Get the fallback key state.
    // Clear it out after dispatching the UP.
    int32_t originalKeyCode = keyEntry->keyCode;
    int32_t fallbackKeyCode = connection->inputState.getFallbackKey(originalKeyCode);
    if (keyEntry->action == AKEY_EVENT_ACTION_UP) {
        connection->inputState.removeFallbackKey(originalKeyCode);
    }

    if (handled || !dispatchEntry->hasForegroundTarget()) {
        // If the application handles the original key for which we previously
        // generated a fallback or if the window is not a foreground window,
        // then cancel the associated fallback key, if any.
        if (fallbackKeyCode != -1) {
            // Dispatch the unhandled key to the policy with the cancel flag.
#if DEBUG_OUTBOUND_EVENT_DETAILS
            ALOGD("Unhandled key event: Asking policy to cancel fallback action.  "
                  "keyCode=%d, action=%d, repeatCount=%d, policyFlags=0x%08x",
                  keyEntry->keyCode, keyEntry->action, keyEntry->repeatCount,
                  keyEntry->policyFlags);
#endif
            KeyEvent event = createKeyEvent(*keyEntry);
            event.setFlags(event.getFlags() | AKEY_EVENT_FLAG_CANCELED);

            mLock.unlock();

            mPolicy->dispatchUnhandledKey(connection->inputChannel->getConnectionToken(), &event,
                                          keyEntry->policyFlags, &event);

            mLock.lock();

            // Cancel the fallback key.
            if (fallbackKeyCode != AKEYCODE_UNKNOWN) {
                CancelationOptions options(CancelationOptions::CANCEL_FALLBACK_EVENTS,
                                           "application handled the original non-fallback key "
                                           "or is no longer a foreground target, "
                                           "canceling previously dispatched fallback key");
                options.keyCode = fallbackKeyCode;
                synthesizeCancelationEventsForConnectionLocked(connection, options);
            }
            connection->inputState.removeFallbackKey(originalKeyCode);
        }
    } else {
        // If the application did not handle a non-fallback key, first check
        // that we are in a good state to perform unhandled key event processing
        // Then ask the policy what to do with it.
        bool initialDown = keyEntry->action == AKEY_EVENT_ACTION_DOWN && keyEntry->repeatCount == 0;
        if (fallbackKeyCode == -1 && !initialDown) {
#if DEBUG_OUTBOUND_EVENT_DETAILS
            ALOGD("Unhandled key event: Skipping unhandled key event processing "
                  "since this is not an initial down.  "
                  "keyCode=%d, action=%d, repeatCount=%d, policyFlags=0x%08x",
                  originalKeyCode, keyEntry->action, keyEntry->repeatCount, keyEntry->policyFlags);
#endif
            return false;
        }

        // Dispatch the unhandled key to the policy.
#if DEBUG_OUTBOUND_EVENT_DETAILS
        ALOGD("Unhandled key event: Asking policy to perform fallback action.  "
              "keyCode=%d, action=%d, repeatCount=%d, policyFlags=0x%08x",
              keyEntry->keyCode, keyEntry->action, keyEntry->repeatCount, keyEntry->policyFlags);
#endif
        KeyEvent event = createKeyEvent(*keyEntry);

        mLock.unlock();

        bool fallback =
                mPolicy->dispatchUnhandledKey(connection->inputChannel->getConnectionToken(),
                                              &event, keyEntry->policyFlags, &event);

        mLock.lock();

        if (connection->status != Connection::STATUS_NORMAL) {
            connection->inputState.removeFallbackKey(originalKeyCode);
            return false;
        }

        // Latch the fallback keycode for this key on an initial down.
        // The fallback keycode cannot change at any other point in the lifecycle.
        if (initialDown) {
            if (fallback) {
                fallbackKeyCode = event.getKeyCode();
            } else {
                fallbackKeyCode = AKEYCODE_UNKNOWN;
            }
            connection->inputState.setFallbackKey(originalKeyCode, fallbackKeyCode);
        }

        ALOG_ASSERT(fallbackKeyCode != -1);

        // Cancel the fallback key if the policy decides not to send it anymore.
        // We will continue to dispatch the key to the policy but we will no
        // longer dispatch a fallback key to the application.
        if (fallbackKeyCode != AKEYCODE_UNKNOWN &&
            (!fallback || fallbackKeyCode != event.getKeyCode())) {
#if DEBUG_OUTBOUND_EVENT_DETAILS
            if (fallback) {
                ALOGD("Unhandled key event: Policy requested to send key %d"
                      "as a fallback for %d, but on the DOWN it had requested "
                      "to send %d instead.  Fallback canceled.",
                      event.getKeyCode(), originalKeyCode, fallbackKeyCode);
            } else {
                ALOGD("Unhandled key event: Policy did not request fallback for %d, "
                      "but on the DOWN it had requested to send %d.  "
                      "Fallback canceled.",
                      originalKeyCode, fallbackKeyCode);
            }
#endif

            CancelationOptions options(CancelationOptions::CANCEL_FALLBACK_EVENTS,
                                       "canceling fallback, policy no longer desires it");
            options.keyCode = fallbackKeyCode;
            synthesizeCancelationEventsForConnectionLocked(connection, options);

            fallback = false;
            fallbackKeyCode = AKEYCODE_UNKNOWN;
            if (keyEntry->action != AKEY_EVENT_ACTION_UP) {
                connection->inputState.setFallbackKey(originalKeyCode, fallbackKeyCode);
            }
        }

#if DEBUG_OUTBOUND_EVENT_DETAILS
        {
            std::string msg;
            const KeyedVector<int32_t, int32_t>& fallbackKeys =
                    connection->inputState.getFallbackKeys();
            for (size_t i = 0; i < fallbackKeys.size(); i++) {
                msg += StringPrintf(", %d->%d", fallbackKeys.keyAt(i), fallbackKeys.valueAt(i));
            }
            ALOGD("Unhandled key event: %zu currently tracked fallback keys%s.",
                  fallbackKeys.size(), msg.c_str());
        }
#endif

        if (fallback) {
            // Restart the dispatch cycle using the fallback key.
            keyEntry->eventTime = event.getEventTime();
            keyEntry->deviceId = event.getDeviceId();
            keyEntry->source = event.getSource();
            keyEntry->displayId = event.getDisplayId();
            keyEntry->flags = event.getFlags() | AKEY_EVENT_FLAG_FALLBACK;
            keyEntry->keyCode = fallbackKeyCode;
            keyEntry->scanCode = event.getScanCode();
            keyEntry->metaState = event.getMetaState();
            keyEntry->repeatCount = event.getRepeatCount();
            keyEntry->downTime = event.getDownTime();
            keyEntry->syntheticRepeat = false;

#if DEBUG_OUTBOUND_EVENT_DETAILS
            ALOGD("Unhandled key event: Dispatching fallback key.  "
                  "originalKeyCode=%d, fallbackKeyCode=%d, fallbackMetaState=%08x",
                  originalKeyCode, fallbackKeyCode, keyEntry->metaState);
#endif
            return true; // restart the event
        } else {
#if DEBUG_OUTBOUND_EVENT_DETAILS
            ALOGD("Unhandled key event: No fallback key.");
#endif

            // Report the key as unhandled, since there is no fallback key.
            mReporter->reportUnhandledKey(keyEntry->id);
        }
    }
    return false;
}

bool InputDispatcher::afterMotionEventLockedInterruptible(const sp<Connection>& connection,
                                                          DispatchEntry* dispatchEntry,
                                                          MotionEntry* motionEntry, bool handled) {
    return false;
}

void InputDispatcher::doPokeUserActivityLockedInterruptible(CommandEntry* commandEntry) {
    mLock.unlock();

    mPolicy->pokeUserActivity(commandEntry->eventTime, commandEntry->userActivityEventType);

    mLock.lock();
}

KeyEvent InputDispatcher::createKeyEvent(const KeyEntry& entry) {
    KeyEvent event;
    event.initialize(entry.id, entry.deviceId, entry.source, entry.displayId, INVALID_HMAC,
                     entry.action, entry.flags, entry.keyCode, entry.scanCode, entry.metaState,
                     entry.repeatCount, entry.downTime, entry.eventTime);
    return event;
}

void InputDispatcher::reportDispatchStatistics(std::chrono::nanoseconds eventDuration,
                                               const Connection& connection, bool handled) {
    // TODO Write some statistics about how long we spend waiting.
}

/**
 * Report the touch event latency to the statsd server.
 * Input events are reported for statistics if:
 * - This is a touchscreen event
 * - InputFilter is not enabled
 * - Event is not injected or synthesized
 *
 * Statistics should be reported before calling addValue, to prevent a fresh new sample
 * from getting aggregated with the "old" data.
 */
void InputDispatcher::reportTouchEventForStatistics(const MotionEntry& motionEntry)
        REQUIRES(mLock) {
    const bool reportForStatistics = (motionEntry.source == AINPUT_SOURCE_TOUCHSCREEN) &&
            !(motionEntry.isSynthesized()) && !mInputFilterEnabled;
    if (!reportForStatistics) {
        return;
    }

    if (mTouchStatistics.shouldReport()) {
        android::util::stats_write(android::util::TOUCH_EVENT_REPORTED, mTouchStatistics.getMin(),
                                   mTouchStatistics.getMax(), mTouchStatistics.getMean(),
                                   mTouchStatistics.getStDev(), mTouchStatistics.getCount());
        mTouchStatistics.reset();
    }
    const float latencyMicros = nanoseconds_to_microseconds(now() - motionEntry.eventTime);
    mTouchStatistics.addValue(latencyMicros);
}

void InputDispatcher::traceInboundQueueLengthLocked() {
    if (ATRACE_ENABLED()) {
        ATRACE_INT("iq", mInboundQueue.size());
    }
}

void InputDispatcher::traceOutboundQueueLength(const sp<Connection>& connection) {
    if (ATRACE_ENABLED()) {
        char counterName[40];
        snprintf(counterName, sizeof(counterName), "oq:%s", connection->getWindowName().c_str());
        ATRACE_INT(counterName, connection->outboundQueue.size());
    }
}

void InputDispatcher::traceWaitQueueLength(const sp<Connection>& connection) {
    if (ATRACE_ENABLED()) {
        char counterName[40];
        snprintf(counterName, sizeof(counterName), "wq:%s", connection->getWindowName().c_str());
        ATRACE_INT(counterName, connection->waitQueue.size());
    }
}

void InputDispatcher::dump(std::string& dump) {
    std::scoped_lock _l(mLock);

    dump += "Input Dispatcher State:\n";
    dumpDispatchStateLocked(dump);

    if (!mLastAnrState.empty()) {
        dump += "\nInput Dispatcher State at time of last ANR:\n";
        dump += mLastAnrState;
    }
}

void InputDispatcher::monitor() {
    // Acquire and release the lock to ensure that the dispatcher has not deadlocked.
    std::unique_lock _l(mLock);
    mLooper->wake();
    mDispatcherIsAlive.wait(_l);
}

/**
 * Wake up the dispatcher and wait until it processes all events and commands.
 * The notification of mDispatcherEnteredIdle is guaranteed to happen after wake(), so
 * this method can be safely called from any thread, as long as you've ensured that
 * the work you are interested in completing has already been queued.
 */
bool InputDispatcher::waitForIdle() {
    /**
     * Timeout should represent the longest possible time that a device might spend processing
     * events and commands.
     */
    constexpr std::chrono::duration TIMEOUT = 100ms;
    std::unique_lock lock(mLock);
    mLooper->wake();
    std::cv_status result = mDispatcherEnteredIdle.wait_for(lock, TIMEOUT);
    return result == std::cv_status::no_timeout;
}

} // namespace android::inputdispatcher
