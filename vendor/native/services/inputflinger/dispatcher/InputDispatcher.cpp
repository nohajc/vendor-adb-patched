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

#include <android-base/chrono_utils.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android/os/IInputConstants.h>
#include <binder/Binder.h>
#include <ftl/enum.h>
#include <gui/SurfaceComposerClient.h>
#include <input/InputDevice.h>
#include <openssl/mem.h>
#include <powermanager/PowerManager.h>
#include <unistd.h>
#include <utils/Trace.h>

#include <cerrno>
#include <cinttypes>
#include <climits>
#include <cstddef>
#include <ctime>
#include <queue>
#include <sstream>

#include "Connection.h"
#include "DebugConfig.h"
#include "InputDispatcher.h"

#define INDENT "  "
#define INDENT2 "    "
#define INDENT3 "      "
#define INDENT4 "        "

using android::base::HwTimeoutMultiplier;
using android::base::Result;
using android::base::StringPrintf;
using android::gui::DisplayInfo;
using android::gui::FocusRequest;
using android::gui::TouchOcclusionMode;
using android::gui::WindowInfo;
using android::gui::WindowInfoHandle;
using android::os::BlockUntrustedTouchesMode;
using android::os::IInputConstants;
using android::os::InputEventInjectionResult;
using android::os::InputEventInjectionSync;

namespace android::inputdispatcher {

namespace {
// Temporarily releases a held mutex for the lifetime of the instance.
// Named to match std::scoped_lock
class scoped_unlock {
public:
    explicit scoped_unlock(std::mutex& mutex) : mMutex(mutex) { mMutex.unlock(); }
    ~scoped_unlock() { mMutex.lock(); }

private:
    std::mutex& mMutex;
};

// Default input dispatching timeout if there is no focused application or paused window
// from which to determine an appropriate dispatching timeout.
const std::chrono::duration DEFAULT_INPUT_DISPATCHING_TIMEOUT = std::chrono::milliseconds(
        android::os::IInputConstants::UNMULTIPLIED_DEFAULT_DISPATCHING_TIMEOUT_MILLIS *
        HwTimeoutMultiplier());

// Amount of time to allow for all pending events to be processed when an app switch
// key is on the way.  This is used to preempt input dispatch and drop input events
// when an application takes too long to respond and the user has pressed an app switch key.
constexpr nsecs_t APP_SWITCH_TIMEOUT = 500 * 1000000LL; // 0.5sec

const std::chrono::duration STALE_EVENT_TIMEOUT = std::chrono::seconds(10) * HwTimeoutMultiplier();

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

// Event log tags. See EventLogTags.logtags for reference.
constexpr int LOGTAG_INPUT_INTERACTION = 62000;
constexpr int LOGTAG_INPUT_FOCUS = 62001;
constexpr int LOGTAG_INPUT_CANCEL = 62003;

const ui::Transform kIdentityTransform;

inline nsecs_t now() {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

inline const char* toString(bool value) {
    return value ? "true" : "false";
}

inline const std::string toString(const sp<IBinder>& binder) {
    if (binder == nullptr) {
        return "<null>";
    }
    return StringPrintf("%p", binder.get());
}

inline int32_t getMotionEventActionPointerIndex(int32_t action) {
    return (action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK) >>
            AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
}

bool isValidKeyAction(int32_t action) {
    switch (action) {
        case AKEY_EVENT_ACTION_DOWN:
        case AKEY_EVENT_ACTION_UP:
            return true;
        default:
            return false;
    }
}

bool validateKeyEvent(int32_t action) {
    if (!isValidKeyAction(action)) {
        ALOGE("Key event has invalid action code 0x%x", action);
        return false;
    }
    return true;
}

bool isValidMotionAction(int32_t action, int32_t actionButton, int32_t pointerCount) {
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

int64_t millis(std::chrono::nanoseconds t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t).count();
}

bool validateMotionEvent(int32_t action, int32_t actionButton, size_t pointerCount,
                         const PointerProperties* pointerProperties) {
    if (!isValidMotionAction(action, actionButton, pointerCount)) {
        ALOGE("Motion event has invalid action code 0x%x", action);
        return false;
    }
    if (pointerCount < 1 || pointerCount > MAX_POINTERS) {
        ALOGE("Motion event has invalid pointer count %zu; value must be between 1 and %zu.",
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

std::string dumpRegion(const Region& region) {
    if (region.isEmpty()) {
        return "<empty>";
    }

    std::string dump;
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
    return dump;
}

std::string dumpQueue(const std::deque<DispatchEntry*>& queue, nsecs_t currentTime) {
    constexpr size_t maxEntries = 50; // max events to print
    constexpr size_t skipBegin = maxEntries / 2;
    const size_t skipEnd = queue.size() - maxEntries / 2;
    // skip from maxEntries / 2 ... size() - maxEntries/2
    // only print from 0 .. skipBegin and then from skipEnd .. size()

    std::string dump;
    for (size_t i = 0; i < queue.size(); i++) {
        const DispatchEntry& entry = *queue[i];
        if (i >= skipBegin && i < skipEnd) {
            dump += StringPrintf(INDENT4 "<skipped %zu entries>\n", skipEnd - skipBegin);
            i = skipEnd - 1; // it will be incremented to "skipEnd" by 'continue'
            continue;
        }
        dump.append(INDENT4);
        dump += entry.eventEntry->getDescription();
        dump += StringPrintf(", seq=%" PRIu32
                             ", targetFlags=0x%08x, resolvedAction=%d, age=%" PRId64 "ms",
                             entry.seq, entry.targetFlags, entry.resolvedAction,
                             ns2ms(currentTime - entry.eventEntry->eventTime));
        if (entry.deliveryTime != 0) {
            // This entry was delivered, so add information on how long we've been waiting
            dump += StringPrintf(", wait=%" PRId64 "ms", ns2ms(currentTime - entry.deliveryTime));
        }
        dump.append("\n");
    }
    return dump;
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
V getValueByKey(const std::unordered_map<K, V>& map, K key) {
    auto it = map.find(key);
    return it != map.end() ? it->second : V{};
}

bool haveSameToken(const sp<WindowInfoHandle>& first, const sp<WindowInfoHandle>& second) {
    if (first == second) {
        return true;
    }

    if (first == nullptr || second == nullptr) {
        return false;
    }

    return first->getToken() == second->getToken();
}

bool haveSameApplicationToken(const WindowInfo* first, const WindowInfo* second) {
    if (first == nullptr || second == nullptr) {
        return false;
    }
    return first->applicationInfo.token != nullptr &&
            first->applicationInfo.token == second->applicationInfo.token;
}

std::unique_ptr<DispatchEntry> createDispatchEntry(const InputTarget& inputTarget,
                                                   std::shared_ptr<EventEntry> eventEntry,
                                                   int32_t inputTargetFlags) {
    if (inputTarget.useDefaultPointerTransform()) {
        const ui::Transform& transform = inputTarget.getDefaultPointerTransform();
        return std::make_unique<DispatchEntry>(eventEntry, inputTargetFlags, transform,
                                               inputTarget.displayTransform,
                                               inputTarget.globalScaleFactor);
    }

    ALOG_ASSERT(eventEntry->type == EventEntry::Type::MOTION);
    const MotionEntry& motionEntry = static_cast<const MotionEntry&>(*eventEntry);

    std::vector<PointerCoords> pointerCoords;
    pointerCoords.resize(motionEntry.pointerCount);

    // Use the first pointer information to normalize all other pointers. This could be any pointer
    // as long as all other pointers are normalized to the same value and the final DispatchEntry
    // uses the transform for the normalized pointer.
    const ui::Transform& firstPointerTransform =
            inputTarget.pointerTransforms[inputTarget.pointerIds.firstMarkedBit()];
    ui::Transform inverseFirstTransform = firstPointerTransform.inverse();

    // Iterate through all pointers in the event to normalize against the first.
    for (uint32_t pointerIndex = 0; pointerIndex < motionEntry.pointerCount; pointerIndex++) {
        const PointerProperties& pointerProperties = motionEntry.pointerProperties[pointerIndex];
        uint32_t pointerId = uint32_t(pointerProperties.id);
        const ui::Transform& currTransform = inputTarget.pointerTransforms[pointerId];

        pointerCoords[pointerIndex].copyFrom(motionEntry.pointerCoords[pointerIndex]);
        // First, apply the current pointer's transform to update the coordinates into
        // window space.
        pointerCoords[pointerIndex].transform(currTransform);
        // Next, apply the inverse transform of the normalized coordinates so the
        // current coordinates are transformed into the normalized coordinate space.
        pointerCoords[pointerIndex].transform(inverseFirstTransform);
    }

    std::unique_ptr<MotionEntry> combinedMotionEntry =
            std::make_unique<MotionEntry>(motionEntry.id, motionEntry.eventTime,
                                          motionEntry.deviceId, motionEntry.source,
                                          motionEntry.displayId, motionEntry.policyFlags,
                                          motionEntry.action, motionEntry.actionButton,
                                          motionEntry.flags, motionEntry.metaState,
                                          motionEntry.buttonState, motionEntry.classification,
                                          motionEntry.edgeFlags, motionEntry.xPrecision,
                                          motionEntry.yPrecision, motionEntry.xCursorPosition,
                                          motionEntry.yCursorPosition, motionEntry.downTime,
                                          motionEntry.pointerCount, motionEntry.pointerProperties,
                                          pointerCoords.data());

    if (motionEntry.injectionState) {
        combinedMotionEntry->injectionState = motionEntry.injectionState;
        combinedMotionEntry->injectionState->refCount += 1;
    }

    std::unique_ptr<DispatchEntry> dispatchEntry =
            std::make_unique<DispatchEntry>(std::move(combinedMotionEntry), inputTargetFlags,
                                            firstPointerTransform, inputTarget.displayTransform,
                                            inputTarget.globalScaleFactor);
    return dispatchEntry;
}

status_t openInputChannelPair(const std::string& name, std::shared_ptr<InputChannel>& serverChannel,
                              std::unique_ptr<InputChannel>& clientChannel) {
    std::unique_ptr<InputChannel> uniqueServerChannel;
    status_t result = InputChannel::openInputChannelPair(name, uniqueServerChannel, clientChannel);

    serverChannel = std::move(uniqueServerChannel);
    return result;
}

template <typename T>
bool sharedPointersEqual(const std::shared_ptr<T>& lhs, const std::shared_ptr<T>& rhs) {
    if (lhs == nullptr && rhs == nullptr) {
        return true;
    }
    if (lhs == nullptr || rhs == nullptr) {
        return false;
    }
    return *lhs == *rhs;
}

KeyEvent createKeyEvent(const KeyEntry& entry) {
    KeyEvent event;
    event.initialize(entry.id, entry.deviceId, entry.source, entry.displayId, INVALID_HMAC,
                     entry.action, entry.flags, entry.keyCode, entry.scanCode, entry.metaState,
                     entry.repeatCount, entry.downTime, entry.eventTime);
    return event;
}

bool shouldReportMetricsForConnection(const Connection& connection) {
    // Do not keep track of gesture monitors. They receive every event and would disproportionately
    // affect the statistics.
    if (connection.monitor) {
        return false;
    }
    // If the connection is experiencing ANR, let's skip it. We have separate ANR metrics
    if (!connection.responsive) {
        return false;
    }
    return true;
}

bool shouldReportFinishedEvent(const DispatchEntry& dispatchEntry, const Connection& connection) {
    const EventEntry& eventEntry = *dispatchEntry.eventEntry;
    const int32_t& inputEventId = eventEntry.id;
    if (inputEventId != dispatchEntry.resolvedEventId) {
        // Event was transmuted
        return false;
    }
    if (inputEventId == android::os::IInputConstants::INVALID_INPUT_EVENT_ID) {
        return false;
    }
    // Only track latency for events that originated from hardware
    if (eventEntry.isSynthesized()) {
        return false;
    }
    const EventEntry::Type& inputEventEntryType = eventEntry.type;
    if (inputEventEntryType == EventEntry::Type::KEY) {
        const KeyEntry& keyEntry = static_cast<const KeyEntry&>(eventEntry);
        if (keyEntry.flags & AKEY_EVENT_FLAG_CANCELED) {
            return false;
        }
    } else if (inputEventEntryType == EventEntry::Type::MOTION) {
        const MotionEntry& motionEntry = static_cast<const MotionEntry&>(eventEntry);
        if (motionEntry.action == AMOTION_EVENT_ACTION_CANCEL ||
            motionEntry.action == AMOTION_EVENT_ACTION_HOVER_EXIT) {
            return false;
        }
    } else {
        // Not a key or a motion
        return false;
    }
    if (!shouldReportMetricsForConnection(connection)) {
        return false;
    }
    return true;
}

/**
 * Connection is responsive if it has no events in the waitQueue that are older than the
 * current time.
 */
bool isConnectionResponsive(const Connection& connection) {
    const nsecs_t currentTime = now();
    for (const DispatchEntry* entry : connection.waitQueue) {
        if (entry->timeoutTime < currentTime) {
            return false;
        }
    }
    return true;
}

// Returns true if the event type passed as argument represents a user activity.
bool isUserActivityEvent(const EventEntry& eventEntry) {
    switch (eventEntry.type) {
        case EventEntry::Type::FOCUS:
        case EventEntry::Type::POINTER_CAPTURE_CHANGED:
        case EventEntry::Type::DRAG:
        case EventEntry::Type::TOUCH_MODE_CHANGED:
        case EventEntry::Type::SENSOR:
        case EventEntry::Type::CONFIGURATION_CHANGED:
            return false;
        case EventEntry::Type::DEVICE_RESET:
        case EventEntry::Type::KEY:
        case EventEntry::Type::MOTION:
            return true;
    }
}

// Returns true if the given window can accept pointer events at the given display location.
bool windowAcceptsTouchAt(const WindowInfo& windowInfo, int32_t displayId, float x, float y,
                          bool isStylus, const ui::Transform& displayTransform) {
    const auto inputConfig = windowInfo.inputConfig;
    if (windowInfo.displayId != displayId ||
        inputConfig.test(WindowInfo::InputConfig::NOT_VISIBLE)) {
        return false;
    }
    const bool windowCanInterceptTouch = isStylus && windowInfo.interceptsStylus();
    if (inputConfig.test(WindowInfo::InputConfig::NOT_TOUCHABLE) && !windowCanInterceptTouch) {
        return false;
    }

    // Window Manager works in the logical display coordinate space. When it specifies bounds for a
    // window as (l, t, r, b), the range of x in [l, r) and y in [t, b) are considered to be inside
    // the window. Points on the right and bottom edges should not be inside the window, so we need
    // to be careful about performing a hit test when the display is rotated, since the "right" and
    // "bottom" of the window will be different in the display (un-rotated) space compared to in the
    // logical display in which WM determined the bounds. Perform the hit test in the logical
    // display space to ensure these edges are considered correctly in all orientations.
    const auto touchableRegion = displayTransform.transform(windowInfo.touchableRegion);
    const auto p = displayTransform.transform(x, y);
    if (!touchableRegion.contains(std::floor(p.x), std::floor(p.y))) {
        return false;
    }
    return true;
}

bool isPointerFromStylus(const MotionEntry& entry, int32_t pointerIndex) {
    return isFromSource(entry.source, AINPUT_SOURCE_STYLUS) &&
            (entry.pointerProperties[pointerIndex].toolType == AMOTION_EVENT_TOOL_TYPE_STYLUS ||
             entry.pointerProperties[pointerIndex].toolType == AMOTION_EVENT_TOOL_TYPE_ERASER);
}

// Determines if the given window can be targeted as InputTarget::FLAG_FOREGROUND.
// Foreground events are only sent to "foreground targetable" windows, but not all gestures sent to
// such window are necessarily targeted with the flag. For example, an event with ACTION_OUTSIDE can
// be sent to such a window, but it is not a foreground event and doesn't use
// InputTarget::FLAG_FOREGROUND.
bool canReceiveForegroundTouches(const WindowInfo& info) {
    // A non-touchable window can still receive touch events (e.g. in the case of
    // STYLUS_INTERCEPTOR), so prevent such windows from receiving foreground events for touches.
    return !info.inputConfig.test(gui::WindowInfo::InputConfig::NOT_TOUCHABLE) && !info.isSpy();
}

bool isWindowOwnedBy(const sp<WindowInfoHandle>& windowHandle, int32_t pid, int32_t uid) {
    if (windowHandle == nullptr) {
        return false;
    }
    const WindowInfo* windowInfo = windowHandle->getInfo();
    if (pid == windowInfo->ownerPid && uid == windowInfo->ownerUid) {
        return true;
    }
    return false;
}

// Checks targeted injection using the window's owner's uid.
// Returns an empty string if an entry can be sent to the given window, or an error message if the
// entry is a targeted injection whose uid target doesn't match the window owner.
std::optional<std::string> verifyTargetedInjection(const sp<WindowInfoHandle>& window,
                                                   const EventEntry& entry) {
    if (entry.injectionState == nullptr || !entry.injectionState->targetUid) {
        // The event was not injected, or the injected event does not target a window.
        return {};
    }
    const int32_t uid = *entry.injectionState->targetUid;
    if (window == nullptr) {
        return StringPrintf("No valid window target for injection into uid %d.", uid);
    }
    if (entry.injectionState->targetUid != window->getInfo()->ownerUid) {
        return StringPrintf("Injected event targeted at uid %d would be dispatched to window '%s' "
                            "owned by uid %d.",
                            uid, window->getName().c_str(), window->getInfo()->ownerUid);
    }
    return {};
}

} // namespace

// --- InputDispatcher ---

InputDispatcher::InputDispatcher(const sp<InputDispatcherPolicyInterface>& policy)
      : InputDispatcher(policy, STALE_EVENT_TIMEOUT) {}

InputDispatcher::InputDispatcher(const sp<InputDispatcherPolicyInterface>& policy,
                                 std::chrono::nanoseconds staleEventTimeout)
      : mPolicy(policy),
        mPendingEvent(nullptr),
        mLastDropReason(DropReason::NOT_DROPPED),
        mIdGenerator(IdGenerator::Source::INPUT_DISPATCHER),
        mAppSwitchSawKeyDown(false),
        mAppSwitchDueTime(LONG_LONG_MAX),
        mNextUnblockedEvent(nullptr),
        mMonitorDispatchingTimeout(DEFAULT_INPUT_DISPATCHING_TIMEOUT),
        mDispatchEnabled(false),
        mDispatchFrozen(false),
        mInputFilterEnabled(false),
        // mInTouchMode will be initialized by the WindowManager to the default device config.
        // To avoid leaking stack in case that call never comes, and for tests,
        // initialize it here anyways.
        mInTouchMode(kDefaultInTouchMode),
        mMaximumObscuringOpacityForTouch(1.0f),
        mFocusedDisplayId(ADISPLAY_ID_DEFAULT),
        mWindowTokenWithPointerCapture(nullptr),
        mStaleEventTimeout(staleEventTimeout),
        mLatencyAggregator(),
        mLatencyTracker(&mLatencyAggregator) {
    mLooper = new Looper(false);
    mReporter = createInputReporter();

    mWindowInfoListener = new DispatcherWindowListener(*this);
    SurfaceComposerClient::getDefault()->addWindowInfosListener(mWindowInfoListener);

    mKeyRepeatState.lastKeyEntry = nullptr;

    policy->getDispatcherConfiguration(&mConfig);
}

InputDispatcher::~InputDispatcher() {
    std::scoped_lock _l(mLock);

    resetKeyRepeatLocked();
    releasePendingEventLocked();
    drainInboundQueueLocked();
    mCommandQueue.clear();

    while (!mConnectionsByToken.empty()) {
        sp<Connection> connection = mConnectionsByToken.begin()->second;
        removeInputChannelLocked(connection->inputChannel->getConnectionToken(),
                                 false /* notify */);
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
        if (runCommandsLockedInterruptable()) {
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
    std::shared_ptr<InputApplicationHandle> focusedApplication =
            getValueByKey(mFocusedApplicationHandlesByDisplay, mAwaitedApplicationDisplayId);
    if (focusedApplication == nullptr ||
        focusedApplication->getApplicationToken() !=
                mAwaitedFocusedApplication->getApplicationToken()) {
        // Unexpected because we should have reset the ANR timer when focused application changed
        ALOGE("Waited for a focused window, but focused application has already changed to %s",
              focusedApplication->getName().c_str());
        return; // The focused application has changed.
    }

    const sp<WindowInfoHandle>& focusedWindowHandle =
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
            mAwaitedFocusedApplication.reset();
            mNoFocusedWindowTimeoutTime = std::nullopt;
            return LONG_LONG_MIN;
        } else {
            // Keep waiting. We will drop the event when mNoFocusedWindowTimeoutTime comes.
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
    onAnrLocked(connection);
    return LONG_LONG_MIN;
}

std::chrono::nanoseconds InputDispatcher::getDispatchingTimeoutLocked(
        const sp<Connection>& connection) {
    if (connection->monitor) {
        return mMonitorDispatchingTimeout;
    }
    const sp<WindowInfoHandle> window =
            getWindowHandleLocked(connection->inputChannel->getConnectionToken());
    if (window != nullptr) {
        return window->getDispatchingTimeout(DEFAULT_INPUT_DISPATCHING_TIMEOUT);
    }
    return DEFAULT_INPUT_DISPATCHING_TIMEOUT;
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
            const ConfigurationChangedEntry& typedEntry =
                    static_cast<const ConfigurationChangedEntry&>(*mPendingEvent);
            done = dispatchConfigurationChangedLocked(currentTime, typedEntry);
            dropReason = DropReason::NOT_DROPPED; // configuration changes are never dropped
            break;
        }

        case EventEntry::Type::DEVICE_RESET: {
            const DeviceResetEntry& typedEntry =
                    static_cast<const DeviceResetEntry&>(*mPendingEvent);
            done = dispatchDeviceResetLocked(currentTime, typedEntry);
            dropReason = DropReason::NOT_DROPPED; // device resets are never dropped
            break;
        }

        case EventEntry::Type::FOCUS: {
            std::shared_ptr<FocusEntry> typedEntry =
                    std::static_pointer_cast<FocusEntry>(mPendingEvent);
            dispatchFocusLocked(currentTime, typedEntry);
            done = true;
            dropReason = DropReason::NOT_DROPPED; // focus events are never dropped
            break;
        }

        case EventEntry::Type::TOUCH_MODE_CHANGED: {
            const auto typedEntry = std::static_pointer_cast<TouchModeEntry>(mPendingEvent);
            dispatchTouchModeChangeLocked(currentTime, typedEntry);
            done = true;
            dropReason = DropReason::NOT_DROPPED; // touch mode events are never dropped
            break;
        }

        case EventEntry::Type::POINTER_CAPTURE_CHANGED: {
            const auto typedEntry =
                    std::static_pointer_cast<PointerCaptureChangedEntry>(mPendingEvent);
            dispatchPointerCaptureChangedLocked(currentTime, typedEntry, dropReason);
            done = true;
            break;
        }

        case EventEntry::Type::DRAG: {
            std::shared_ptr<DragEntry> typedEntry =
                    std::static_pointer_cast<DragEntry>(mPendingEvent);
            dispatchDragLocked(currentTime, typedEntry);
            done = true;
            break;
        }

        case EventEntry::Type::KEY: {
            std::shared_ptr<KeyEntry> keyEntry = std::static_pointer_cast<KeyEntry>(mPendingEvent);
            if (isAppSwitchDue) {
                if (isAppSwitchKeyEvent(*keyEntry)) {
                    resetPendingAppSwitchLocked(true);
                    isAppSwitchDue = false;
                } else if (dropReason == DropReason::NOT_DROPPED) {
                    dropReason = DropReason::APP_SWITCH;
                }
            }
            if (dropReason == DropReason::NOT_DROPPED && isStaleEvent(currentTime, *keyEntry)) {
                dropReason = DropReason::STALE;
            }
            if (dropReason == DropReason::NOT_DROPPED && mNextUnblockedEvent) {
                dropReason = DropReason::BLOCKED;
            }
            done = dispatchKeyLocked(currentTime, keyEntry, &dropReason, nextWakeupTime);
            break;
        }

        case EventEntry::Type::MOTION: {
            std::shared_ptr<MotionEntry> motionEntry =
                    std::static_pointer_cast<MotionEntry>(mPendingEvent);
            if (dropReason == DropReason::NOT_DROPPED && isAppSwitchDue) {
                dropReason = DropReason::APP_SWITCH;
            }
            if (dropReason == DropReason::NOT_DROPPED && isStaleEvent(currentTime, *motionEntry)) {
                dropReason = DropReason::STALE;
            }
            if (dropReason == DropReason::NOT_DROPPED && mNextUnblockedEvent) {
                dropReason = DropReason::BLOCKED;
            }
            done = dispatchMotionLocked(currentTime, motionEntry, &dropReason, nextWakeupTime);
            break;
        }

        case EventEntry::Type::SENSOR: {
            std::shared_ptr<SensorEntry> sensorEntry =
                    std::static_pointer_cast<SensorEntry>(mPendingEvent);
            if (dropReason == DropReason::NOT_DROPPED && isAppSwitchDue) {
                dropReason = DropReason::APP_SWITCH;
            }
            //  Sensor timestamps use SYSTEM_TIME_BOOTTIME time base, so we can't use
            // 'currentTime' here, get SYSTEM_TIME_BOOTTIME instead.
            nsecs_t bootTime = systemTime(SYSTEM_TIME_BOOTTIME);
            if (dropReason == DropReason::NOT_DROPPED && isStaleEvent(bootTime, *sensorEntry)) {
                dropReason = DropReason::STALE;
            }
            dispatchSensorLocked(currentTime, sensorEntry, &dropReason, nextWakeupTime);
            done = true;
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

bool InputDispatcher::isStaleEvent(nsecs_t currentTime, const EventEntry& entry) {
    return std::chrono::nanoseconds(currentTime - entry.eventTime) >= mStaleEventTimeout;
}

/**
 * Return true if the events preceding this incoming motion event should be dropped
 * Return false otherwise (the default behaviour)
 */
bool InputDispatcher::shouldPruneInboundQueueLocked(const MotionEntry& motionEntry) {
    const bool isPointerDownEvent = motionEntry.action == AMOTION_EVENT_ACTION_DOWN &&
            isFromSource(motionEntry.source, AINPUT_SOURCE_CLASS_POINTER);

    // Optimize case where the current application is unresponsive and the user
    // decides to touch a window in a different application.
    // If the application takes too long to catch up then we drop all events preceding
    // the touch into the other window.
    if (isPointerDownEvent && mAwaitedFocusedApplication != nullptr) {
        int32_t displayId = motionEntry.displayId;
        const float x = motionEntry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X);
        const float y = motionEntry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y);

        const bool isStylus = isPointerFromStylus(motionEntry, 0 /*pointerIndex*/);
        sp<WindowInfoHandle> touchedWindowHandle =
                findTouchedWindowAtLocked(displayId, x, y, nullptr, isStylus);
        if (touchedWindowHandle != nullptr &&
            touchedWindowHandle->getApplicationToken() !=
                    mAwaitedFocusedApplication->getApplicationToken()) {
            // User touched a different application than the one we are waiting on.
            ALOGI("Pruning input queue because user touched a different application while waiting "
                  "for %s",
                  mAwaitedFocusedApplication->getName().c_str());
            return true;
        }

        // Alternatively, maybe there's a spy window that could handle this event.
        const std::vector<sp<WindowInfoHandle>> touchedSpies =
                findTouchedSpyWindowsAtLocked(displayId, x, y, isStylus);
        for (const auto& windowHandle : touchedSpies) {
            const sp<Connection> connection = getConnectionLocked(windowHandle->getToken());
            if (connection != nullptr && connection->responsive) {
                // This spy window could take more input. Drop all events preceding this
                // event, so that the spy window can get a chance to receive the stream.
                ALOGW("Pruning the input queue because %s is unresponsive, but we have a "
                      "responsive spy window that may handle the event.",
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

bool InputDispatcher::enqueueInboundEventLocked(std::unique_ptr<EventEntry> newEntry) {
    bool needWake = mInboundQueue.empty();
    mInboundQueue.push_back(std::move(newEntry));
    EventEntry& entry = *(mInboundQueue.back());
    traceInboundQueueLengthLocked();

    switch (entry.type) {
        case EventEntry::Type::KEY: {
            LOG_ALWAYS_FATAL_IF((entry.policyFlags & POLICY_FLAG_TRUSTED) == 0,
                                "Unexpected untrusted event.");
            // Optimize app switch latency.
            // If the application takes too long to catch up then we drop all events preceding
            // the app switch key.
            const KeyEntry& keyEntry = static_cast<const KeyEntry&>(entry);
            if (isAppSwitchKeyEvent(keyEntry)) {
                if (keyEntry.action == AKEY_EVENT_ACTION_DOWN) {
                    mAppSwitchSawKeyDown = true;
                } else if (keyEntry.action == AKEY_EVENT_ACTION_UP) {
                    if (mAppSwitchSawKeyDown) {
                        if (DEBUG_APP_SWITCH) {
                            ALOGD("App switch is pending!");
                        }
                        mAppSwitchDueTime = keyEntry.eventTime + APP_SWITCH_TIMEOUT;
                        mAppSwitchSawKeyDown = false;
                        needWake = true;
                    }
                }
            }

            // If a new up event comes in, and the pending event with same key code has been asked
            // to try again later because of the policy. We have to reset the intercept key wake up
            // time for it may have been handled in the policy and could be dropped.
            if (keyEntry.action == AKEY_EVENT_ACTION_UP && mPendingEvent &&
                mPendingEvent->type == EventEntry::Type::KEY) {
                KeyEntry& pendingKey = static_cast<KeyEntry&>(*mPendingEvent);
                if (pendingKey.keyCode == keyEntry.keyCode &&
                    pendingKey.interceptKeyResult ==
                            KeyEntry::INTERCEPT_KEY_RESULT_TRY_AGAIN_LATER) {
                    pendingKey.interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_UNKNOWN;
                    pendingKey.interceptKeyWakeupTime = 0;
                    needWake = true;
                }
            }
            break;
        }

        case EventEntry::Type::MOTION: {
            LOG_ALWAYS_FATAL_IF((entry.policyFlags & POLICY_FLAG_TRUSTED) == 0,
                                "Unexpected untrusted event.");
            if (shouldPruneInboundQueueLocked(static_cast<MotionEntry&>(entry))) {
                mNextUnblockedEvent = mInboundQueue.back();
                needWake = true;
            }
            break;
        }
        case EventEntry::Type::FOCUS: {
            LOG_ALWAYS_FATAL("Focus events should be inserted using enqueueFocusEventLocked");
            break;
        }
        case EventEntry::Type::TOUCH_MODE_CHANGED:
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET:
        case EventEntry::Type::SENSOR:
        case EventEntry::Type::POINTER_CAPTURE_CHANGED:
        case EventEntry::Type::DRAG: {
            // nothing to do
            break;
        }
    }

    return needWake;
}

void InputDispatcher::addRecentEventLocked(std::shared_ptr<EventEntry> entry) {
    // Do not store sensor event in recent queue to avoid flooding the queue.
    if (entry->type != EventEntry::Type::SENSOR) {
        mRecentQueue.push_back(entry);
    }
    if (mRecentQueue.size() > RECENT_QUEUE_MAX_SIZE) {
        mRecentQueue.pop_front();
    }
}

sp<WindowInfoHandle> InputDispatcher::findTouchedWindowAtLocked(int32_t displayId, float x, float y,
                                                                TouchState* touchState,
                                                                bool isStylus,
                                                                bool addOutsideTargets,
                                                                bool ignoreDragWindow) {
    if (addOutsideTargets && touchState == nullptr) {
        LOG_ALWAYS_FATAL("Must provide a valid touch state if adding outside targets");
    }
    // Traverse windows from front to back to find touched window.
    const auto& windowHandles = getWindowHandlesLocked(displayId);
    for (const sp<WindowInfoHandle>& windowHandle : windowHandles) {
        if (ignoreDragWindow && haveSameToken(windowHandle, mDragState->dragWindow)) {
            continue;
        }

        const WindowInfo& info = *windowHandle->getInfo();
        if (!info.isSpy() &&
            windowAcceptsTouchAt(info, displayId, x, y, isStylus, getTransformLocked(displayId))) {
            return windowHandle;
        }

        if (addOutsideTargets &&
            info.inputConfig.test(WindowInfo::InputConfig::WATCH_OUTSIDE_TOUCH)) {
            touchState->addOrUpdateWindow(windowHandle, InputTarget::FLAG_DISPATCH_AS_OUTSIDE,
                                          BitSet32(0));
        }
    }
    return nullptr;
}

std::vector<sp<WindowInfoHandle>> InputDispatcher::findTouchedSpyWindowsAtLocked(
        int32_t displayId, float x, float y, bool isStylus) const {
    // Traverse windows from front to back and gather the touched spy windows.
    std::vector<sp<WindowInfoHandle>> spyWindows;
    const auto& windowHandles = getWindowHandlesLocked(displayId);
    for (const sp<WindowInfoHandle>& windowHandle : windowHandles) {
        const WindowInfo& info = *windowHandle->getInfo();

        if (!windowAcceptsTouchAt(info, displayId, x, y, isStylus, getTransformLocked(displayId))) {
            continue;
        }
        if (!info.isSpy()) {
            // The first touched non-spy window was found, so return the spy windows touched so far.
            return spyWindows;
        }
        spyWindows.push_back(windowHandle);
    }
    return spyWindows;
}

void InputDispatcher::dropInboundEventLocked(const EventEntry& entry, DropReason dropReason) {
    const char* reason;
    switch (dropReason) {
        case DropReason::POLICY:
            if (DEBUG_INBOUND_EVENT_DETAILS) {
                ALOGD("Dropped event because policy consumed it.");
            }
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
        case DropReason::NO_POINTER_CAPTURE:
            ALOGI("Dropped event because there is no window with Pointer Capture.");
            reason = "inbound event was dropped because there is no window with Pointer Capture";
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
        case EventEntry::Type::SENSOR: {
            break;
        }
        case EventEntry::Type::POINTER_CAPTURE_CHANGED:
        case EventEntry::Type::DRAG: {
            break;
        }
        case EventEntry::Type::FOCUS:
        case EventEntry::Type::TOUCH_MODE_CHANGED:
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET: {
            LOG_ALWAYS_FATAL("Should not drop %s events", ftl::enum_string(entry.type).c_str());
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

    if (DEBUG_APP_SWITCH) {
        if (handled) {
            ALOGD("App switch has arrived.");
        } else {
            ALOGD("App switch was abandoned.");
        }
    }
}

bool InputDispatcher::haveCommandsLocked() const {
    return !mCommandQueue.empty();
}

bool InputDispatcher::runCommandsLockedInterruptable() {
    if (mCommandQueue.empty()) {
        return false;
    }

    do {
        auto command = std::move(mCommandQueue.front());
        mCommandQueue.pop_front();
        // Commands are run with the lock held, but may release and re-acquire the lock from within.
        command();
    } while (!mCommandQueue.empty());
    return true;
}

void InputDispatcher::postCommandLocked(Command&& command) {
    mCommandQueue.push_back(command);
}

void InputDispatcher::drainInboundQueueLocked() {
    while (!mInboundQueue.empty()) {
        std::shared_ptr<EventEntry> entry = mInboundQueue.front();
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

void InputDispatcher::releaseInboundEventLocked(std::shared_ptr<EventEntry> entry) {
    InjectionState* injectionState = entry->injectionState;
    if (injectionState && injectionState->injectionResult == InputEventInjectionResult::PENDING) {
        if (DEBUG_DISPATCH_CYCLE) {
            ALOGD("Injected inbound event was dropped.");
        }
        setInjectionResult(*entry, InputEventInjectionResult::FAILED);
    }
    if (entry == mNextUnblockedEvent) {
        mNextUnblockedEvent = nullptr;
    }
    addRecentEventLocked(entry);
}

void InputDispatcher::resetKeyRepeatLocked() {
    if (mKeyRepeatState.lastKeyEntry) {
        mKeyRepeatState.lastKeyEntry = nullptr;
    }
}

std::shared_ptr<KeyEntry> InputDispatcher::synthesizeKeyRepeatLocked(nsecs_t currentTime) {
    std::shared_ptr<KeyEntry> entry = mKeyRepeatState.lastKeyEntry;

    uint32_t policyFlags = entry->policyFlags &
            (POLICY_FLAG_RAW_MASK | POLICY_FLAG_PASS_TO_USER | POLICY_FLAG_TRUSTED);

    std::shared_ptr<KeyEntry> newEntry =
            std::make_unique<KeyEntry>(mIdGenerator.nextId(), currentTime, entry->deviceId,
                                       entry->source, entry->displayId, policyFlags, entry->action,
                                       entry->flags, entry->keyCode, entry->scanCode,
                                       entry->metaState, entry->repeatCount + 1, entry->downTime);

    newEntry->syntheticRepeat = true;
    mKeyRepeatState.lastKeyEntry = newEntry;
    mKeyRepeatState.nextRepeatTime = currentTime + mConfig.keyRepeatDelay;
    return newEntry;
}

bool InputDispatcher::dispatchConfigurationChangedLocked(nsecs_t currentTime,
                                                         const ConfigurationChangedEntry& entry) {
    if (DEBUG_OUTBOUND_EVENT_DETAILS) {
        ALOGD("dispatchConfigurationChanged - eventTime=%" PRId64, entry.eventTime);
    }

    // Reset key repeating in case a keyboard device was added or removed or something.
    resetKeyRepeatLocked();

    // Enqueue a command to run outside the lock to tell the policy that the configuration changed.
    auto command = [this, eventTime = entry.eventTime]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->notifyConfigurationChanged(eventTime);
    };
    postCommandLocked(std::move(command));
    return true;
}

bool InputDispatcher::dispatchDeviceResetLocked(nsecs_t currentTime,
                                                const DeviceResetEntry& entry) {
    if (DEBUG_OUTBOUND_EVENT_DETAILS) {
        ALOGD("dispatchDeviceReset - eventTime=%" PRId64 ", deviceId=%d", entry.eventTime,
              entry.deviceId);
    }

    // Reset key repeating in case a keyboard device was disabled or enabled.
    if (mKeyRepeatState.lastKeyEntry && mKeyRepeatState.lastKeyEntry->deviceId == entry.deviceId) {
        resetKeyRepeatLocked();
    }

    CancelationOptions options(CancelationOptions::CANCEL_ALL_EVENTS, "device was reset");
    options.deviceId = entry.deviceId;
    synthesizeCancelationEventsForAllConnectionsLocked(options);
    return true;
}

void InputDispatcher::enqueueFocusEventLocked(const sp<IBinder>& windowToken, bool hasFocus,
                                              const std::string& reason) {
    if (mPendingEvent != nullptr) {
        // Move the pending event to the front of the queue. This will give the chance
        // for the pending event to get dispatched to the newly focused window
        mInboundQueue.push_front(mPendingEvent);
        mPendingEvent = nullptr;
    }

    std::unique_ptr<FocusEntry> focusEntry =
            std::make_unique<FocusEntry>(mIdGenerator.nextId(), now(), windowToken, hasFocus,
                                         reason);

    // This event should go to the front of the queue, but behind all other focus events
    // Find the last focus event, and insert right after it
    std::deque<std::shared_ptr<EventEntry>>::reverse_iterator it =
            std::find_if(mInboundQueue.rbegin(), mInboundQueue.rend(),
                         [](const std::shared_ptr<EventEntry>& event) {
                             return event->type == EventEntry::Type::FOCUS;
                         });

    // Maintain the order of focus events. Insert the entry after all other focus events.
    mInboundQueue.insert(it.base(), std::move(focusEntry));
}

void InputDispatcher::dispatchFocusLocked(nsecs_t currentTime, std::shared_ptr<FocusEntry> entry) {
    std::shared_ptr<InputChannel> channel = getInputChannelLocked(entry->connectionToken);
    if (channel == nullptr) {
        return; // Window has gone away
    }
    InputTarget target;
    target.inputChannel = channel;
    target.flags = InputTarget::FLAG_DISPATCH_AS_IS;
    entry->dispatchInProgress = true;
    std::string message = std::string("Focus ") + (entry->hasFocus ? "entering " : "leaving ") +
            channel->getName();
    std::string reason = std::string("reason=").append(entry->reason);
    android_log_event_list(LOGTAG_INPUT_FOCUS) << message << reason << LOG_ID_EVENTS;
    dispatchEventLocked(currentTime, entry, {target});
}

void InputDispatcher::dispatchPointerCaptureChangedLocked(
        nsecs_t currentTime, const std::shared_ptr<PointerCaptureChangedEntry>& entry,
        DropReason& dropReason) {
    dropReason = DropReason::NOT_DROPPED;

    const bool haveWindowWithPointerCapture = mWindowTokenWithPointerCapture != nullptr;
    sp<IBinder> token;

    if (entry->pointerCaptureRequest.enable) {
        // Enable Pointer Capture.
        if (haveWindowWithPointerCapture &&
            (entry->pointerCaptureRequest == mCurrentPointerCaptureRequest)) {
            // This can happen if pointer capture is disabled and re-enabled before we notify the
            // app of the state change, so there is no need to notify the app.
            ALOGI("Skipping dispatch of Pointer Capture being enabled: no state change.");
            return;
        }
        if (!mCurrentPointerCaptureRequest.enable) {
            // This can happen if a window requests capture and immediately releases capture.
            ALOGW("No window requested Pointer Capture.");
            dropReason = DropReason::NO_POINTER_CAPTURE;
            return;
        }
        if (entry->pointerCaptureRequest.seq != mCurrentPointerCaptureRequest.seq) {
            ALOGI("Skipping dispatch of Pointer Capture being enabled: sequence number mismatch.");
            return;
        }

        token = mFocusResolver.getFocusedWindowToken(mFocusedDisplayId);
        LOG_ALWAYS_FATAL_IF(!token, "Cannot find focused window for Pointer Capture.");
        mWindowTokenWithPointerCapture = token;
    } else {
        // Disable Pointer Capture.
        // We do not check if the sequence number matches for requests to disable Pointer Capture
        // for two reasons:
        //  1. Pointer Capture can be disabled by a focus change, which means we can get two entries
        //     to disable capture with the same sequence number: one generated by
        //     disablePointerCaptureForcedLocked() and another as an acknowledgement of Pointer
        //     Capture being disabled in InputReader.
        //  2. We respect any request to disable Pointer Capture generated by InputReader, since the
        //     actual Pointer Capture state that affects events being generated by input devices is
        //     in InputReader.
        if (!haveWindowWithPointerCapture) {
            // Pointer capture was already forcefully disabled because of focus change.
            dropReason = DropReason::NOT_DROPPED;
            return;
        }
        token = mWindowTokenWithPointerCapture;
        mWindowTokenWithPointerCapture = nullptr;
        if (mCurrentPointerCaptureRequest.enable) {
            setPointerCaptureLocked(false);
        }
    }

    auto channel = getInputChannelLocked(token);
    if (channel == nullptr) {
        // Window has gone away, clean up Pointer Capture state.
        mWindowTokenWithPointerCapture = nullptr;
        if (mCurrentPointerCaptureRequest.enable) {
            setPointerCaptureLocked(false);
        }
        return;
    }
    InputTarget target;
    target.inputChannel = channel;
    target.flags = InputTarget::FLAG_DISPATCH_AS_IS;
    entry->dispatchInProgress = true;
    dispatchEventLocked(currentTime, entry, {target});

    dropReason = DropReason::NOT_DROPPED;
}

void InputDispatcher::dispatchTouchModeChangeLocked(nsecs_t currentTime,
                                                    const std::shared_ptr<TouchModeEntry>& entry) {
    const std::vector<sp<WindowInfoHandle>>& windowHandles =
            getWindowHandlesLocked(mFocusedDisplayId);
    if (windowHandles.empty()) {
        return;
    }
    const std::vector<InputTarget> inputTargets =
            getInputTargetsFromWindowHandlesLocked(windowHandles);
    if (inputTargets.empty()) {
        return;
    }
    entry->dispatchInProgress = true;
    dispatchEventLocked(currentTime, entry, inputTargets);
}

std::vector<InputTarget> InputDispatcher::getInputTargetsFromWindowHandlesLocked(
        const std::vector<sp<WindowInfoHandle>>& windowHandles) const {
    std::vector<InputTarget> inputTargets;
    for (const sp<WindowInfoHandle>& handle : windowHandles) {
        // TODO(b/193718270): Due to performance concerns, consider notifying visible windows only.
        const sp<IBinder>& token = handle->getToken();
        if (token == nullptr) {
            continue;
        }
        std::shared_ptr<InputChannel> channel = getInputChannelLocked(token);
        if (channel == nullptr) {
            continue; // Window has gone away
        }
        InputTarget target;
        target.inputChannel = channel;
        target.flags = InputTarget::FLAG_DISPATCH_AS_IS;
        inputTargets.push_back(target);
    }
    return inputTargets;
}

bool InputDispatcher::dispatchKeyLocked(nsecs_t currentTime, std::shared_ptr<KeyEntry> entry,
                                        DropReason* dropReason, nsecs_t* nextWakeupTime) {
    // Preprocessing.
    if (!entry->dispatchInProgress) {
        if (entry->repeatCount == 0 && entry->action == AKEY_EVENT_ACTION_DOWN &&
            (entry->policyFlags & POLICY_FLAG_TRUSTED) &&
            (!(entry->policyFlags & POLICY_FLAG_DISABLE_KEY_REPEAT))) {
            if (mKeyRepeatState.lastKeyEntry &&
                mKeyRepeatState.lastKeyEntry->keyCode == entry->keyCode &&
                // We have seen two identical key downs in a row which indicates that the device
                // driver is automatically generating key repeats itself.  We take note of the
                // repeat here, but we disable our own next key repeat timer since it is clear that
                // we will not need to synthesize key repeats ourselves.
                mKeyRepeatState.lastKeyEntry->deviceId == entry->deviceId) {
                // Make sure we don't get key down from a different device. If a different
                // device Id has same key pressed down, the new device Id will replace the
                // current one to hold the key repeat with repeat count reset.
                // In the future when got a KEY_UP on the device id, drop it and do not
                // stop the key repeat on current device.
                entry->repeatCount = mKeyRepeatState.lastKeyEntry->repeatCount + 1;
                resetKeyRepeatLocked();
                mKeyRepeatState.nextRepeatTime = LONG_LONG_MAX; // don't generate repeats ourselves
            } else {
                // Not a repeat.  Save key down state in case we do see a repeat later.
                resetKeyRepeatLocked();
                mKeyRepeatState.nextRepeatTime = entry->eventTime + mConfig.keyRepeatTimeout;
            }
            mKeyRepeatState.lastKeyEntry = entry;
        } else if (entry->action == AKEY_EVENT_ACTION_UP && mKeyRepeatState.lastKeyEntry &&
                   mKeyRepeatState.lastKeyEntry->deviceId != entry->deviceId) {
            // The key on device 'deviceId' is still down, do not stop key repeat
            if (DEBUG_INBOUND_EVENT_DETAILS) {
                ALOGD("deviceId=%d got KEY_UP as stale", entry->deviceId);
            }
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
            sp<IBinder> focusedWindowToken =
                    mFocusResolver.getFocusedWindowToken(getTargetDisplayId(*entry));

            auto command = [this, focusedWindowToken, entry]() REQUIRES(mLock) {
                doInterceptKeyBeforeDispatchingCommand(focusedWindowToken, *entry);
            };
            postCommandLocked(std::move(command));
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
        setInjectionResult(*entry,
                           *dropReason == DropReason::POLICY ? InputEventInjectionResult::SUCCEEDED
                                                             : InputEventInjectionResult::FAILED);
        mReporter->reportDroppedKey(entry->id);
        return true;
    }

    // Identify targets.
    std::vector<InputTarget> inputTargets;
    InputEventInjectionResult injectionResult =
            findFocusedWindowTargetsLocked(currentTime, *entry, inputTargets, nextWakeupTime);
    if (injectionResult == InputEventInjectionResult::PENDING) {
        return false;
    }

    setInjectionResult(*entry, injectionResult);
    if (injectionResult != InputEventInjectionResult::SUCCEEDED) {
        return true;
    }

    // Add monitor channels from event's or focused display.
    addGlobalMonitoringTargetsLocked(inputTargets, getTargetDisplayId(*entry));

    // Dispatch the key.
    dispatchEventLocked(currentTime, entry, inputTargets);
    return true;
}

void InputDispatcher::logOutboundKeyDetails(const char* prefix, const KeyEntry& entry) {
    if (DEBUG_OUTBOUND_EVENT_DETAILS) {
        ALOGD("%seventTime=%" PRId64 ", deviceId=%d, source=0x%x, displayId=%" PRId32 ", "
              "policyFlags=0x%x, action=0x%x, flags=0x%x, keyCode=0x%x, scanCode=0x%x, "
              "metaState=0x%x, repeatCount=%d, downTime=%" PRId64,
              prefix, entry.eventTime, entry.deviceId, entry.source, entry.displayId,
              entry.policyFlags, entry.action, entry.flags, entry.keyCode, entry.scanCode,
              entry.metaState, entry.repeatCount, entry.downTime);
    }
}

void InputDispatcher::dispatchSensorLocked(nsecs_t currentTime,
                                           const std::shared_ptr<SensorEntry>& entry,
                                           DropReason* dropReason, nsecs_t* nextWakeupTime) {
    if (DEBUG_OUTBOUND_EVENT_DETAILS) {
        ALOGD("notifySensorEvent eventTime=%" PRId64 ", hwTimestamp=%" PRId64 ", deviceId=%d, "
              "source=0x%x, sensorType=%s",
              entry->eventTime, entry->hwTimestamp, entry->deviceId, entry->source,
              ftl::enum_string(entry->sensorType).c_str());
    }
    auto command = [this, entry]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);

        if (entry->accuracyChanged) {
            mPolicy->notifySensorAccuracy(entry->deviceId, entry->sensorType, entry->accuracy);
        }
        mPolicy->notifySensorEvent(entry->deviceId, entry->sensorType, entry->accuracy,
                                   entry->hwTimestamp, entry->values);
    };
    postCommandLocked(std::move(command));
}

bool InputDispatcher::flushSensor(int deviceId, InputDeviceSensorType sensorType) {
    if (DEBUG_OUTBOUND_EVENT_DETAILS) {
        ALOGD("flushSensor deviceId=%d, sensorType=%s", deviceId,
              ftl::enum_string(sensorType).c_str());
    }
    { // acquire lock
        std::scoped_lock _l(mLock);

        for (auto it = mInboundQueue.begin(); it != mInboundQueue.end(); it++) {
            std::shared_ptr<EventEntry> entry = *it;
            if (entry->type == EventEntry::Type::SENSOR) {
                it = mInboundQueue.erase(it);
                releaseInboundEventLocked(entry);
            }
        }
    }
    return true;
}

bool InputDispatcher::dispatchMotionLocked(nsecs_t currentTime, std::shared_ptr<MotionEntry> entry,
                                           DropReason* dropReason, nsecs_t* nextWakeupTime) {
    ATRACE_CALL();
    // Preprocessing.
    if (!entry->dispatchInProgress) {
        entry->dispatchInProgress = true;

        logOutboundMotionDetails("dispatchMotion - ", *entry);
    }

    // Clean up if dropping the event.
    if (*dropReason != DropReason::NOT_DROPPED) {
        setInjectionResult(*entry,
                           *dropReason == DropReason::POLICY ? InputEventInjectionResult::SUCCEEDED
                                                             : InputEventInjectionResult::FAILED);
        return true;
    }

    const bool isPointerEvent = isFromSource(entry->source, AINPUT_SOURCE_CLASS_POINTER);

    // Identify targets.
    std::vector<InputTarget> inputTargets;

    bool conflictingPointerActions = false;
    InputEventInjectionResult injectionResult;
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
    if (injectionResult == InputEventInjectionResult::PENDING) {
        return false;
    }

    setInjectionResult(*entry, injectionResult);
    if (injectionResult == InputEventInjectionResult::TARGET_MISMATCH) {
        return true;
    }
    if (injectionResult != InputEventInjectionResult::SUCCEEDED) {
        CancelationOptions::Mode mode(isPointerEvent
                                              ? CancelationOptions::CANCEL_POINTER_EVENTS
                                              : CancelationOptions::CANCEL_NON_POINTER_EVENTS);
        CancelationOptions options(mode, "input event injection failed");
        synthesizeCancelationEventsForMonitorsLocked(options);
        return true;
    }

    // Add monitor channels from event's or focused display.
    addGlobalMonitoringTargetsLocked(inputTargets, getTargetDisplayId(*entry));

    // Dispatch the motion.
    if (conflictingPointerActions) {
        CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS,
                                   "conflicting pointer actions");
        synthesizeCancelationEventsForAllConnectionsLocked(options);
    }
    dispatchEventLocked(currentTime, entry, inputTargets);
    return true;
}

void InputDispatcher::enqueueDragEventLocked(const sp<WindowInfoHandle>& windowHandle,
                                             bool isExiting, const int32_t rawX,
                                             const int32_t rawY) {
    const vec2 xy = windowHandle->getInfo()->transform.transform(vec2(rawX, rawY));
    std::unique_ptr<DragEntry> dragEntry =
            std::make_unique<DragEntry>(mIdGenerator.nextId(), now(), windowHandle->getToken(),
                                        isExiting, xy.x, xy.y);

    enqueueInboundEventLocked(std::move(dragEntry));
}

void InputDispatcher::dispatchDragLocked(nsecs_t currentTime, std::shared_ptr<DragEntry> entry) {
    std::shared_ptr<InputChannel> channel = getInputChannelLocked(entry->connectionToken);
    if (channel == nullptr) {
        return; // Window has gone away
    }
    InputTarget target;
    target.inputChannel = channel;
    target.flags = InputTarget::FLAG_DISPATCH_AS_IS;
    entry->dispatchInProgress = true;
    dispatchEventLocked(currentTime, entry, {target});
}

void InputDispatcher::logOutboundMotionDetails(const char* prefix, const MotionEntry& entry) {
    if (DEBUG_OUTBOUND_EVENT_DETAILS) {
        ALOGD("%seventTime=%" PRId64 ", deviceId=%d, source=0x%x, displayId=%" PRId32
              ", policyFlags=0x%x, "
              "action=%s, actionButton=0x%x, flags=0x%x, "
              "metaState=0x%x, buttonState=0x%x,"
              "edgeFlags=0x%x, xPrecision=%f, yPrecision=%f, downTime=%" PRId64,
              prefix, entry.eventTime, entry.deviceId, entry.source, entry.displayId,
              entry.policyFlags, MotionEvent::actionToString(entry.action).c_str(),
              entry.actionButton, entry.flags, entry.metaState, entry.buttonState, entry.edgeFlags,
              entry.xPrecision, entry.yPrecision, entry.downTime);

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
    }
}

void InputDispatcher::dispatchEventLocked(nsecs_t currentTime,
                                          std::shared_ptr<EventEntry> eventEntry,
                                          const std::vector<InputTarget>& inputTargets) {
    ATRACE_CALL();
    if (DEBUG_DISPATCH_CYCLE) {
        ALOGD("dispatchEventToCurrentInputTargets");
    }

    updateInteractionTokensLocked(*eventEntry, inputTargets);

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
    if (connection->status == Connection::Status::NORMAL) {
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
    mAwaitedFocusedApplication.reset();
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
        case EventEntry::Type::TOUCH_MODE_CHANGED:
        case EventEntry::Type::POINTER_CAPTURE_CHANGED:
        case EventEntry::Type::FOCUS:
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET:
        case EventEntry::Type::SENSOR:
        case EventEntry::Type::DRAG: {
            ALOGE("%s events do not have a target display", ftl::enum_string(entry.type).c_str());
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
        // Wait to send key because there are unprocessed events that may cause focus to change
        mKeyIsWaitingForEventsTimeout = currentTime +
                std::chrono::duration_cast<std::chrono::nanoseconds>(KEY_WAITING_FOR_EVENTS_TIMEOUT)
                        .count();
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

InputEventInjectionResult InputDispatcher::findFocusedWindowTargetsLocked(
        nsecs_t currentTime, const EventEntry& entry, std::vector<InputTarget>& inputTargets,
        nsecs_t* nextWakeupTime) {
    std::string reason;

    int32_t displayId = getTargetDisplayId(entry);
    sp<WindowInfoHandle> focusedWindowHandle = getFocusedWindowHandleLocked(displayId);
    std::shared_ptr<InputApplicationHandle> focusedApplicationHandle =
            getValueByKey(mFocusedApplicationHandlesByDisplay, displayId);

    // If there is no currently focused window and no focused application
    // then drop the event.
    if (focusedWindowHandle == nullptr && focusedApplicationHandle == nullptr) {
        ALOGI("Dropping %s event because there is no focused window or focused application in "
              "display %" PRId32 ".",
              ftl::enum_string(entry.type).c_str(), displayId);
        return InputEventInjectionResult::FAILED;
    }

    // Drop key events if requested by input feature
    if (focusedWindowHandle != nullptr && shouldDropInput(entry, focusedWindowHandle)) {
        return InputEventInjectionResult::FAILED;
    }

    // Compatibility behavior: raise ANR if there is a focused application, but no focused window.
    // Only start counting when we have a focused event to dispatch. The ANR is canceled if we
    // start interacting with another application via touch (app switch). This code can be removed
    // if the "no focused window ANR" is moved to the policy. Input doesn't know whether
    // an app is expected to have a focused window.
    if (focusedWindowHandle == nullptr && focusedApplicationHandle != nullptr) {
        if (!mNoFocusedWindowTimeoutTime.has_value()) {
            // We just discovered that there's no focused window. Start the ANR timer
            std::chrono::nanoseconds timeout = focusedApplicationHandle->getDispatchingTimeout(
                    DEFAULT_INPUT_DISPATCHING_TIMEOUT);
            mNoFocusedWindowTimeoutTime = currentTime + timeout.count();
            mAwaitedFocusedApplication = focusedApplicationHandle;
            mAwaitedApplicationDisplayId = displayId;
            ALOGW("Waiting because no window has focus but %s may eventually add a "
                  "window when it finishes starting up. Will wait for %" PRId64 "ms",
                  mAwaitedFocusedApplication->getName().c_str(), millis(timeout));
            *nextWakeupTime = *mNoFocusedWindowTimeoutTime;
            return InputEventInjectionResult::PENDING;
        } else if (currentTime > *mNoFocusedWindowTimeoutTime) {
            // Already raised ANR. Drop the event
            ALOGE("Dropping %s event because there is no focused window",
                  ftl::enum_string(entry.type).c_str());
            return InputEventInjectionResult::FAILED;
        } else {
            // Still waiting for the focused window
            return InputEventInjectionResult::PENDING;
        }
    }

    // we have a valid, non-null focused window
    resetNoFocusedWindowTimeoutLocked();

    // Verify targeted injection.
    if (const auto err = verifyTargetedInjection(focusedWindowHandle, entry); err) {
        ALOGW("Dropping injected event: %s", (*err).c_str());
        return InputEventInjectionResult::TARGET_MISMATCH;
    }

    if (focusedWindowHandle->getInfo()->inputConfig.test(
                WindowInfo::InputConfig::PAUSE_DISPATCHING)) {
        ALOGI("Waiting because %s is paused", focusedWindowHandle->getName().c_str());
        return InputEventInjectionResult::PENDING;
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
            return InputEventInjectionResult::PENDING;
        }
    }

    // Success!  Output targets.
    addWindowTargetLocked(focusedWindowHandle,
                          InputTarget::FLAG_FOREGROUND | InputTarget::FLAG_DISPATCH_AS_IS,
                          BitSet32(0), inputTargets);

    // Done.
    return InputEventInjectionResult::SUCCEEDED;
}

/**
 * Given a list of monitors, remove the ones we cannot find a connection for, and the ones
 * that are currently unresponsive.
 */
std::vector<Monitor> InputDispatcher::selectResponsiveMonitorsLocked(
        const std::vector<Monitor>& monitors) const {
    std::vector<Monitor> responsiveMonitors;
    std::copy_if(monitors.begin(), monitors.end(), std::back_inserter(responsiveMonitors),
                 [this](const Monitor& monitor) REQUIRES(mLock) {
                     sp<Connection> connection =
                             getConnectionLocked(monitor.inputChannel->getConnectionToken());
                     if (connection == nullptr) {
                         ALOGE("Could not find connection for monitor %s",
                               monitor.inputChannel->getName().c_str());
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

InputEventInjectionResult InputDispatcher::findTouchedWindowTargetsLocked(
        nsecs_t currentTime, const MotionEntry& entry, std::vector<InputTarget>& inputTargets,
        nsecs_t* nextWakeupTime, bool* outConflictingPointerActions) {
    ATRACE_CALL();

    // For security reasons, we defer updating the touch state until we are sure that
    // event injection will be allowed.
    const int32_t displayId = entry.displayId;
    const int32_t action = entry.action;
    const int32_t maskedAction = action & AMOTION_EVENT_ACTION_MASK;

    // Update the touch state as needed based on the properties of the touch event.
    InputEventInjectionResult injectionResult = InputEventInjectionResult::PENDING;
    sp<WindowInfoHandle> newHoverWindowHandle(mLastHoverWindowHandle);
    sp<WindowInfoHandle> newTouchedWindowHandle;

    // Copy current touch state into tempTouchState.
    // This state will be used to update mTouchStatesByDisplay at the end of this function.
    // If no state for the specified display exists, then our initial state will be empty.
    const TouchState* oldState = nullptr;
    TouchState tempTouchState;
    if (const auto it = mTouchStatesByDisplay.find(displayId); it != mTouchStatesByDisplay.end()) {
        oldState = &(it->second);
        tempTouchState = *oldState;
    }

    bool isSplit = tempTouchState.split;
    bool switchedDevice = tempTouchState.deviceId >= 0 && tempTouchState.displayId >= 0 &&
            (tempTouchState.deviceId != entry.deviceId || tempTouchState.source != entry.source ||
             tempTouchState.displayId != displayId);

    const bool isHoverAction = (maskedAction == AMOTION_EVENT_ACTION_HOVER_MOVE ||
                                maskedAction == AMOTION_EVENT_ACTION_HOVER_ENTER ||
                                maskedAction == AMOTION_EVENT_ACTION_HOVER_EXIT);
    const bool newGesture = (maskedAction == AMOTION_EVENT_ACTION_DOWN ||
                             maskedAction == AMOTION_EVENT_ACTION_SCROLL || isHoverAction);
    const bool isFromMouse = isFromSource(entry.source, AINPUT_SOURCE_MOUSE);
    bool wrongDevice = false;
    if (newGesture) {
        bool down = maskedAction == AMOTION_EVENT_ACTION_DOWN;
        if (switchedDevice && tempTouchState.down && !down && !isHoverAction) {
            ALOGI("Dropping event because a pointer for a different device is already down "
                  "in display %" PRId32,
                  displayId);
            // TODO: test multiple simultaneous input streams.
            injectionResult = InputEventInjectionResult::FAILED;
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
        injectionResult = InputEventInjectionResult::FAILED;
        switchedDevice = false;
        wrongDevice = true;
        goto Failed;
    }

    if (newGesture || (isSplit && maskedAction == AMOTION_EVENT_ACTION_POINTER_DOWN)) {
        /* Case 1: New splittable pointer going down, or need target for hover or scroll. */

        float x;
        float y;
        const int32_t pointerIndex = getMotionEventActionPointerIndex(action);
        // Always dispatch mouse events to cursor position.
        if (isFromMouse) {
            x = entry.xCursorPosition;
            y = entry.yCursorPosition;
        } else {
            x = entry.pointerCoords[pointerIndex].getAxisValue(AMOTION_EVENT_AXIS_X);
            y = entry.pointerCoords[pointerIndex].getAxisValue(AMOTION_EVENT_AXIS_Y);
        }
        const bool isDown = maskedAction == AMOTION_EVENT_ACTION_DOWN;
        const bool isStylus = isPointerFromStylus(entry, pointerIndex);
        newTouchedWindowHandle = findTouchedWindowAtLocked(displayId, x, y, &tempTouchState,
                                                           isStylus, isDown /*addOutsideTargets*/);

        // Handle the case where we did not find a window.
        if (newTouchedWindowHandle == nullptr) {
            ALOGD("No new touched window at (%.1f, %.1f) in display %" PRId32, x, y, displayId);
            // Try to assign the pointer to the first foreground window we find, if there is one.
            newTouchedWindowHandle = tempTouchState.getFirstForegroundWindowHandle();
        }

        // Verify targeted injection.
        if (const auto err = verifyTargetedInjection(newTouchedWindowHandle, entry); err) {
            ALOGW("Dropping injected touch event: %s", (*err).c_str());
            injectionResult = os::InputEventInjectionResult::TARGET_MISMATCH;
            newTouchedWindowHandle = nullptr;
            goto Failed;
        }

        // Figure out whether splitting will be allowed for this window.
        if (newTouchedWindowHandle != nullptr) {
            if (newTouchedWindowHandle->getInfo()->supportsSplitTouch()) {
                // New window supports splitting, but we should never split mouse events.
                isSplit = !isFromMouse;
            } else if (isSplit) {
                // New window does not support splitting but we have already split events.
                // Ignore the new window.
                newTouchedWindowHandle = nullptr;
            }
        } else {
            // No window is touched, so set split to true. This will allow the next pointer down to
            // be delivered to a new window which supports split touch. Pointers from a mouse device
            // should never be split.
            tempTouchState.split = isSplit = !isFromMouse;
        }

        // Update hover state.
        if (newTouchedWindowHandle != nullptr) {
            if (maskedAction == AMOTION_EVENT_ACTION_HOVER_EXIT) {
                newHoverWindowHandle = nullptr;
            } else if (isHoverAction) {
                newHoverWindowHandle = newTouchedWindowHandle;
            }
        }

        std::vector<sp<WindowInfoHandle>> newTouchedWindows =
                findTouchedSpyWindowsAtLocked(displayId, x, y, isStylus);
        if (newTouchedWindowHandle != nullptr) {
            // Process the foreground window first so that it is the first to receive the event.
            newTouchedWindows.insert(newTouchedWindows.begin(), newTouchedWindowHandle);
        }

        if (newTouchedWindows.empty()) {
            ALOGI("Dropping event because there is no touchable window at (%.1f, %.1f) on display "
                  "%d.",
                  x, y, displayId);
            injectionResult = InputEventInjectionResult::FAILED;
            goto Failed;
        }

        for (const sp<WindowInfoHandle>& windowHandle : newTouchedWindows) {
            const WindowInfo& info = *windowHandle->getInfo();

            // Skip spy window targets that are not valid for targeted injection.
            if (const auto err = verifyTargetedInjection(windowHandle, entry); err) {
                continue;
            }

            if (info.inputConfig.test(WindowInfo::InputConfig::PAUSE_DISPATCHING)) {
                ALOGI("Not sending touch event to %s because it is paused",
                      windowHandle->getName().c_str());
                continue;
            }

            // Ensure the window has a connection and the connection is responsive
            const bool isResponsive = hasResponsiveConnectionLocked(*windowHandle);
            if (!isResponsive) {
                ALOGW("Not sending touch gesture to %s because it is not responsive",
                      windowHandle->getName().c_str());
                continue;
            }

            // Drop events that can't be trusted due to occlusion
            if (mBlockUntrustedTouchesMode != BlockUntrustedTouchesMode::DISABLED) {
                TouchOcclusionInfo occlusionInfo =
                        computeTouchOcclusionInfoLocked(windowHandle, x, y);
                if (!isTouchTrustedLocked(occlusionInfo)) {
                    if (DEBUG_TOUCH_OCCLUSION) {
                        ALOGD("Stack of obscuring windows during untrusted touch (%.1f, %.1f):", x,
                              y);
                        for (const auto& log : occlusionInfo.debugInfo) {
                            ALOGD("%s", log.c_str());
                        }
                    }
                    sendUntrustedTouchCommandLocked(occlusionInfo.obscuringPackage);
                    if (mBlockUntrustedTouchesMode == BlockUntrustedTouchesMode::BLOCK) {
                        ALOGW("Dropping untrusted touch event due to %s/%d",
                              occlusionInfo.obscuringPackage.c_str(), occlusionInfo.obscuringUid);
                        continue;
                    }
                }
            }

            // Drop touch events if requested by input feature
            if (shouldDropInput(entry, windowHandle)) {
                continue;
            }

            // Set target flags.
            int32_t targetFlags = InputTarget::FLAG_DISPATCH_AS_IS;

            if (canReceiveForegroundTouches(*windowHandle->getInfo())) {
                // There should only be one touched window that can be "foreground" for the pointer.
                targetFlags |= InputTarget::FLAG_FOREGROUND;
            }

            if (isSplit) {
                targetFlags |= InputTarget::FLAG_SPLIT;
            }
            if (isWindowObscuredAtPointLocked(windowHandle, x, y)) {
                targetFlags |= InputTarget::FLAG_WINDOW_IS_OBSCURED;
            } else if (isWindowObscuredLocked(windowHandle)) {
                targetFlags |= InputTarget::FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
            }

            // Update the temporary touch state.
            BitSet32 pointerIds;
            pointerIds.markBit(entry.pointerProperties[pointerIndex].id);
            tempTouchState.addOrUpdateWindow(windowHandle, targetFlags, pointerIds);

            // If this is the pointer going down and the touched window has a wallpaper
            // then also add the touched wallpaper windows so they are locked in for the duration
            // of the touch gesture.
            // We do not collect wallpapers during HOVER_MOVE or SCROLL because the wallpaper
            // engine only supports touch events.  We would need to add a mechanism similar
            // to View.onGenericMotionEvent to enable wallpapers to handle these events.
            if (maskedAction == AMOTION_EVENT_ACTION_DOWN ||
                maskedAction == AMOTION_EVENT_ACTION_POINTER_DOWN) {
                if ((targetFlags & InputTarget::FLAG_FOREGROUND) &&
                    windowHandle->getInfo()->inputConfig.test(
                            gui::WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER)) {
                    sp<WindowInfoHandle> wallpaper = findWallpaperWindowBelow(windowHandle);
                    if (wallpaper != nullptr) {
                        int32_t wallpaperFlags = InputTarget::FLAG_WINDOW_IS_OBSCURED |
                                InputTarget::FLAG_WINDOW_IS_PARTIALLY_OBSCURED |
                                InputTarget::FLAG_DISPATCH_AS_IS;
                        if (isSplit) {
                            wallpaperFlags |= InputTarget::FLAG_SPLIT;
                        }
                        tempTouchState.addOrUpdateWindow(wallpaper, wallpaperFlags, pointerIds);
                    }
                }
            }
        }
    } else {
        /* Case 2: Pointer move, up, cancel or non-splittable pointer down. */

        // If the pointer is not currently down, then ignore the event.
        if (!tempTouchState.down) {
            if (DEBUG_FOCUS) {
                ALOGD("Dropping event because the pointer is not down or we previously "
                      "dropped the pointer down event in display %" PRId32,
                      displayId);
            }
            injectionResult = InputEventInjectionResult::FAILED;
            goto Failed;
        }

        addDragEventLocked(entry);

        // Check whether touches should slip outside of the current foreground window.
        if (maskedAction == AMOTION_EVENT_ACTION_MOVE && entry.pointerCount == 1 &&
            tempTouchState.isSlippery()) {
            const float x = entry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_X);
            const float y = entry.pointerCoords[0].getAxisValue(AMOTION_EVENT_AXIS_Y);

            const bool isStylus = isPointerFromStylus(entry, 0 /*pointerIndex*/);
            sp<WindowInfoHandle> oldTouchedWindowHandle =
                    tempTouchState.getFirstForegroundWindowHandle();
            newTouchedWindowHandle =
                    findTouchedWindowAtLocked(displayId, x, y, &tempTouchState, isStylus);

            // Verify targeted injection.
            if (const auto err = verifyTargetedInjection(newTouchedWindowHandle, entry); err) {
                ALOGW("Dropping injected event: %s", (*err).c_str());
                injectionResult = os::InputEventInjectionResult::TARGET_MISMATCH;
                newTouchedWindowHandle = nullptr;
                goto Failed;
            }

            // Drop touch events if requested by input feature
            if (newTouchedWindowHandle != nullptr &&
                shouldDropInput(entry, newTouchedWindowHandle)) {
                newTouchedWindowHandle = nullptr;
            }

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
                    isSplit = !isFromMouse;
                }

                int32_t targetFlags = InputTarget::FLAG_DISPATCH_AS_SLIPPERY_ENTER;
                if (canReceiveForegroundTouches(*newTouchedWindowHandle->getInfo())) {
                    targetFlags |= InputTarget::FLAG_FOREGROUND;
                }
                if (isSplit) {
                    targetFlags |= InputTarget::FLAG_SPLIT;
                }
                if (isWindowObscuredAtPointLocked(newTouchedWindowHandle, x, y)) {
                    targetFlags |= InputTarget::FLAG_WINDOW_IS_OBSCURED;
                } else if (isWindowObscuredLocked(newTouchedWindowHandle)) {
                    targetFlags |= InputTarget::FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
                }

                BitSet32 pointerIds;
                pointerIds.markBit(entry.pointerProperties[0].id);
                tempTouchState.addOrUpdateWindow(newTouchedWindowHandle, targetFlags, pointerIds);

                // Check if the wallpaper window should deliver the corresponding event.
                slipWallpaperTouch(targetFlags, oldTouchedWindowHandle, newTouchedWindowHandle,
                                   tempTouchState, pointerIds);
            }
        }

        // Update the pointerIds for non-splittable when it received pointer down.
        if (!isSplit && maskedAction == AMOTION_EVENT_ACTION_POINTER_DOWN) {
            // If no split, we suppose all touched windows should receive pointer down.
            const int32_t pointerIndex = getMotionEventActionPointerIndex(action);
            for (size_t i = 0; i < tempTouchState.windows.size(); i++) {
                TouchedWindow& touchedWindow = tempTouchState.windows[i];
                // Ignore drag window for it should just track one pointer.
                if (mDragState && mDragState->dragWindow == touchedWindow.windowHandle) {
                    continue;
                }
                touchedWindow.pointerIds.markBit(entry.pointerProperties[pointerIndex].id);
            }
        }
    }

    // Update dispatching for hover enter and exit.
    if (newHoverWindowHandle != mLastHoverWindowHandle) {
        // Let the previous window know that the hover sequence is over, unless we already did
        // it when dispatching it as is to newTouchedWindowHandle.
        if (mLastHoverWindowHandle != nullptr &&
            (maskedAction != AMOTION_EVENT_ACTION_HOVER_EXIT ||
             mLastHoverWindowHandle != newTouchedWindowHandle)) {
            if (DEBUG_HOVER) {
                ALOGD("Sending hover exit event to window %s.",
                      mLastHoverWindowHandle->getName().c_str());
            }
            tempTouchState.addOrUpdateWindow(mLastHoverWindowHandle,
                                             InputTarget::FLAG_DISPATCH_AS_HOVER_EXIT, BitSet32(0));
        }

        // Let the new window know that the hover sequence is starting, unless we already did it
        // when dispatching it as is to newTouchedWindowHandle.
        if (newHoverWindowHandle != nullptr &&
            (maskedAction != AMOTION_EVENT_ACTION_HOVER_ENTER ||
             newHoverWindowHandle != newTouchedWindowHandle)) {
            if (DEBUG_HOVER) {
                ALOGD("Sending hover enter event to window %s.",
                      newHoverWindowHandle->getName().c_str());
            }
            tempTouchState.addOrUpdateWindow(newHoverWindowHandle,
                                             InputTarget::FLAG_DISPATCH_AS_HOVER_ENTER,
                                             BitSet32(0));
        }
    }

    // Ensure that we have at least one foreground window or at least one window that cannot be a
    // foreground target. If we only have windows that are not receiving foreground touches (e.g. we
    // only have windows getting ACTION_OUTSIDE), then drop the event, because there is no window
    // that is actually receiving the entire gesture.
    if (std::none_of(tempTouchState.windows.begin(), tempTouchState.windows.end(),
                     [](const TouchedWindow& touchedWindow) {
                         return !canReceiveForegroundTouches(
                                        *touchedWindow.windowHandle->getInfo()) ||
                                 (touchedWindow.targetFlags & InputTarget::FLAG_FOREGROUND) != 0;
                     })) {
        ALOGI("Dropping event because there is no touched window on display %d to receive it: %s",
              displayId, entry.getDescription().c_str());
        injectionResult = InputEventInjectionResult::FAILED;
        goto Failed;
    }

    // Ensure that all touched windows are valid for injection.
    if (entry.injectionState != nullptr) {
        std::string errs;
        for (const TouchedWindow& touchedWindow : tempTouchState.windows) {
            if (touchedWindow.targetFlags & InputTarget::FLAG_DISPATCH_AS_OUTSIDE) {
                // Allow ACTION_OUTSIDE events generated by targeted injection to be
                // dispatched to any uid, since the coords will be zeroed out later.
                continue;
            }
            const auto err = verifyTargetedInjection(touchedWindow.windowHandle, entry);
            if (err) errs += "\n  - " + *err;
        }
        if (!errs.empty()) {
            ALOGW("Dropping targeted injection: At least one touched window is not owned by uid "
                  "%d:%s",
                  *entry.injectionState->targetUid, errs.c_str());
            injectionResult = InputEventInjectionResult::TARGET_MISMATCH;
            goto Failed;
        }
    }

    // Check whether windows listening for outside touches are owned by the same UID. If it is
    // set the policy flag that we will not reveal coordinate information to this window.
    if (maskedAction == AMOTION_EVENT_ACTION_DOWN) {
        sp<WindowInfoHandle> foregroundWindowHandle =
                tempTouchState.getFirstForegroundWindowHandle();
        if (foregroundWindowHandle) {
            const int32_t foregroundWindowUid = foregroundWindowHandle->getInfo()->ownerUid;
            for (const TouchedWindow& touchedWindow : tempTouchState.windows) {
                if (touchedWindow.targetFlags & InputTarget::FLAG_DISPATCH_AS_OUTSIDE) {
                    sp<WindowInfoHandle> windowInfoHandle = touchedWindow.windowHandle;
                    if (windowInfoHandle->getInfo()->ownerUid != foregroundWindowUid) {
                        tempTouchState.addOrUpdateWindow(windowInfoHandle,
                                                         InputTarget::FLAG_ZERO_COORDS,
                                                         BitSet32(0));
                    }
                }
            }
        }
    }

    // Success!  Output targets.
    injectionResult = InputEventInjectionResult::SUCCEEDED;

    for (const TouchedWindow& touchedWindow : tempTouchState.windows) {
        addWindowTargetLocked(touchedWindow.windowHandle, touchedWindow.targetFlags,
                              touchedWindow.pointerIds, inputTargets);
    }

    // Drop the outside or hover touch windows since we will not care about them
    // in the next iteration.
    tempTouchState.filterNonAsIsTouchWindows();

Failed:
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
            int32_t pointerIndex = getMotionEventActionPointerIndex(action);
            uint32_t pointerId = entry.pointerProperties[pointerIndex].id;

            for (size_t i = 0; i < tempTouchState.windows.size();) {
                TouchedWindow& touchedWindow = tempTouchState.windows[i];
                touchedWindow.pointerIds.clearBit(pointerId);
                if (touchedWindow.pointerIds.isEmpty()) {
                    tempTouchState.windows.erase(tempTouchState.windows.begin() + i);
                    continue;
                }
                i += 1;
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

void InputDispatcher::finishDragAndDrop(int32_t displayId, float x, float y) {
    // Prevent stylus interceptor windows from affecting drag and drop behavior for now, until we
    // have an explicit reason to support it.
    constexpr bool isStylus = false;

    const sp<WindowInfoHandle> dropWindow =
            findTouchedWindowAtLocked(displayId, x, y, nullptr /*touchState*/, isStylus,
                                      false /*addOutsideTargets*/, true /*ignoreDragWindow*/);
    if (dropWindow) {
        vec2 local = dropWindow->getInfo()->transform.transform(x, y);
        sendDropWindowCommandLocked(dropWindow->getToken(), local.x, local.y);
    } else {
        ALOGW("No window found when drop.");
        sendDropWindowCommandLocked(nullptr, 0, 0);
    }
    mDragState.reset();
}

void InputDispatcher::addDragEventLocked(const MotionEntry& entry) {
    if (!mDragState || mDragState->dragWindow->getInfo()->displayId != entry.displayId) {
        return;
    }

    if (!mDragState->isStartDrag) {
        mDragState->isStartDrag = true;
        mDragState->isStylusButtonDownAtStart =
                (entry.buttonState & AMOTION_EVENT_BUTTON_STYLUS_PRIMARY) != 0;
    }

    // Find the pointer index by id.
    int32_t pointerIndex = 0;
    for (; static_cast<uint32_t>(pointerIndex) < entry.pointerCount; pointerIndex++) {
        const PointerProperties& pointerProperties = entry.pointerProperties[pointerIndex];
        if (pointerProperties.id == mDragState->pointerId) {
            break;
        }
    }

    if (uint32_t(pointerIndex) == entry.pointerCount) {
        LOG_ALWAYS_FATAL("Should find a valid pointer index by id %d", mDragState->pointerId);
        sendDropWindowCommandLocked(nullptr, 0, 0);
        mDragState.reset();
        return;
    }

    const int32_t maskedAction = entry.action & AMOTION_EVENT_ACTION_MASK;
    const float x = entry.pointerCoords[pointerIndex].getX();
    const float y = entry.pointerCoords[pointerIndex].getY();

    switch (maskedAction) {
        case AMOTION_EVENT_ACTION_MOVE: {
            // Handle the special case : stylus button no longer pressed.
            bool isStylusButtonDown =
                    (entry.buttonState & AMOTION_EVENT_BUTTON_STYLUS_PRIMARY) != 0;
            if (mDragState->isStylusButtonDownAtStart && !isStylusButtonDown) {
                finishDragAndDrop(entry.displayId, x, y);
                return;
            }

            // Prevent stylus interceptor windows from affecting drag and drop behavior for now,
            // until we have an explicit reason to support it.
            constexpr bool isStylus = false;

            const sp<WindowInfoHandle> hoverWindowHandle =
                    findTouchedWindowAtLocked(entry.displayId, x, y, nullptr /*touchState*/,
                                              isStylus, false /*addOutsideTargets*/,
                                              true /*ignoreDragWindow*/);
            // enqueue drag exit if needed.
            if (hoverWindowHandle != mDragState->dragHoverWindowHandle &&
                !haveSameToken(hoverWindowHandle, mDragState->dragHoverWindowHandle)) {
                if (mDragState->dragHoverWindowHandle != nullptr) {
                    enqueueDragEventLocked(mDragState->dragHoverWindowHandle, true /*isExiting*/, x,
                                           y);
                }
                mDragState->dragHoverWindowHandle = hoverWindowHandle;
            }
            // enqueue drag location if needed.
            if (hoverWindowHandle != nullptr) {
                enqueueDragEventLocked(hoverWindowHandle, false /*isExiting*/, x, y);
            }
            break;
        }

        case AMOTION_EVENT_ACTION_POINTER_UP:
            if (getMotionEventActionPointerIndex(entry.action) != pointerIndex) {
                break;
            }
            // The drag pointer is up.
            [[fallthrough]];
        case AMOTION_EVENT_ACTION_UP:
            finishDragAndDrop(entry.displayId, x, y);
            break;
        case AMOTION_EVENT_ACTION_CANCEL: {
            ALOGD("Receiving cancel when drag and drop.");
            sendDropWindowCommandLocked(nullptr, 0, 0);
            mDragState.reset();
            break;
        }
    }
}

void InputDispatcher::addWindowTargetLocked(const sp<WindowInfoHandle>& windowHandle,
                                            int32_t targetFlags, BitSet32 pointerIds,
                                            std::vector<InputTarget>& inputTargets) {
    std::vector<InputTarget>::iterator it =
            std::find_if(inputTargets.begin(), inputTargets.end(),
                         [&windowHandle](const InputTarget& inputTarget) {
                             return inputTarget.inputChannel->getConnectionToken() ==
                                     windowHandle->getToken();
                         });

    const WindowInfo* windowInfo = windowHandle->getInfo();

    if (it == inputTargets.end()) {
        InputTarget inputTarget;
        std::shared_ptr<InputChannel> inputChannel =
                getInputChannelLocked(windowHandle->getToken());
        if (inputChannel == nullptr) {
            ALOGW("Window %s already unregistered input channel", windowHandle->getName().c_str());
            return;
        }
        inputTarget.inputChannel = inputChannel;
        inputTarget.flags = targetFlags;
        inputTarget.globalScaleFactor = windowInfo->globalScaleFactor;
        const auto& displayInfoIt = mDisplayInfos.find(windowInfo->displayId);
        if (displayInfoIt != mDisplayInfos.end()) {
            inputTarget.displayTransform = displayInfoIt->second.transform;
        } else {
            ALOGE("DisplayInfo not found for window on display: %d", windowInfo->displayId);
        }
        inputTargets.push_back(inputTarget);
        it = inputTargets.end() - 1;
    }

    ALOG_ASSERT(it->flags == targetFlags);
    ALOG_ASSERT(it->globalScaleFactor == windowInfo->globalScaleFactor);

    it->addPointers(pointerIds, windowInfo->transform);
}

void InputDispatcher::addGlobalMonitoringTargetsLocked(std::vector<InputTarget>& inputTargets,
                                                       int32_t displayId) {
    auto monitorsIt = mGlobalMonitorsByDisplay.find(displayId);
    if (monitorsIt == mGlobalMonitorsByDisplay.end()) return;

    for (const Monitor& monitor : selectResponsiveMonitorsLocked(monitorsIt->second)) {
        InputTarget target;
        target.inputChannel = monitor.inputChannel;
        target.flags = InputTarget::FLAG_DISPATCH_AS_IS;
        if (const auto& it = mDisplayInfos.find(displayId); it != mDisplayInfos.end()) {
            target.displayTransform = it->second.transform;
        }
        target.setDefaultPointerTransform(target.displayTransform);
        inputTargets.push_back(target);
    }
}

/**
 * Indicate whether one window handle should be considered as obscuring
 * another window handle. We only check a few preconditions. Actually
 * checking the bounds is left to the caller.
 */
static bool canBeObscuredBy(const sp<WindowInfoHandle>& windowHandle,
                            const sp<WindowInfoHandle>& otherHandle) {
    // Compare by token so cloned layers aren't counted
    if (haveSameToken(windowHandle, otherHandle)) {
        return false;
    }
    auto info = windowHandle->getInfo();
    auto otherInfo = otherHandle->getInfo();
    if (otherInfo->inputConfig.test(WindowInfo::InputConfig::NOT_VISIBLE)) {
        return false;
    } else if (otherInfo->alpha == 0 &&
               otherInfo->inputConfig.test(WindowInfo::InputConfig::NOT_TOUCHABLE)) {
        // Those act as if they were invisible, so we don't need to flag them.
        // We do want to potentially flag touchable windows even if they have 0
        // opacity, since they can consume touches and alter the effects of the
        // user interaction (eg. apps that rely on
        // FLAG_WINDOW_IS_PARTIALLY_OBSCURED should still be told about those
        // windows), hence we also check for FLAG_NOT_TOUCHABLE.
        return false;
    } else if (info->ownerUid == otherInfo->ownerUid) {
        // If ownerUid is the same we don't generate occlusion events as there
        // is no security boundary within an uid.
        return false;
    } else if (otherInfo->inputConfig.test(gui::WindowInfo::InputConfig::TRUSTED_OVERLAY)) {
        return false;
    } else if (otherInfo->displayId != info->displayId) {
        return false;
    }
    return true;
}

/**
 * Returns touch occlusion information in the form of TouchOcclusionInfo. To check if the touch is
 * untrusted, one should check:
 *
 * 1. If result.hasBlockingOcclusion is true.
 *    If it's, it means the touch should be blocked due to a window with occlusion mode of
 *    BLOCK_UNTRUSTED.
 *
 * 2. If result.obscuringOpacity > mMaximumObscuringOpacityForTouch.
 *    If it is (and 1 is false), then the touch should be blocked because a stack of windows
 *    (possibly only one) with occlusion mode of USE_OPACITY from one UID resulted in a composed
 *    obscuring opacity above the threshold. Note that if there was no window of occlusion mode
 *    USE_OPACITY, result.obscuringOpacity would've been 0 and since
 *    mMaximumObscuringOpacityForTouch >= 0, the condition above would never be true.
 *
 * If neither of those is true, then it means the touch can be allowed.
 */
InputDispatcher::TouchOcclusionInfo InputDispatcher::computeTouchOcclusionInfoLocked(
        const sp<WindowInfoHandle>& windowHandle, int32_t x, int32_t y) const {
    const WindowInfo* windowInfo = windowHandle->getInfo();
    int32_t displayId = windowInfo->displayId;
    const std::vector<sp<WindowInfoHandle>>& windowHandles = getWindowHandlesLocked(displayId);
    TouchOcclusionInfo info;
    info.hasBlockingOcclusion = false;
    info.obscuringOpacity = 0;
    info.obscuringUid = -1;
    std::map<int32_t, float> opacityByUid;
    for (const sp<WindowInfoHandle>& otherHandle : windowHandles) {
        if (windowHandle == otherHandle) {
            break; // All future windows are below us. Exit early.
        }
        const WindowInfo* otherInfo = otherHandle->getInfo();
        if (canBeObscuredBy(windowHandle, otherHandle) && otherInfo->frameContainsPoint(x, y) &&
            !haveSameApplicationToken(windowInfo, otherInfo)) {
            if (DEBUG_TOUCH_OCCLUSION) {
                info.debugInfo.push_back(
                        dumpWindowForTouchOcclusion(otherInfo, /* isTouchedWindow */ false));
            }
            // canBeObscuredBy() has returned true above, which means this window is untrusted, so
            // we perform the checks below to see if the touch can be propagated or not based on the
            // window's touch occlusion mode
            if (otherInfo->touchOcclusionMode == TouchOcclusionMode::BLOCK_UNTRUSTED) {
                info.hasBlockingOcclusion = true;
                info.obscuringUid = otherInfo->ownerUid;
                info.obscuringPackage = otherInfo->packageName;
                break;
            }
            if (otherInfo->touchOcclusionMode == TouchOcclusionMode::USE_OPACITY) {
                uint32_t uid = otherInfo->ownerUid;
                float opacity =
                        (opacityByUid.find(uid) == opacityByUid.end()) ? 0 : opacityByUid[uid];
                // Given windows A and B:
                // opacity(A, B) = 1 - [1 - opacity(A)] * [1 - opacity(B)]
                opacity = 1 - (1 - opacity) * (1 - otherInfo->alpha);
                opacityByUid[uid] = opacity;
                if (opacity > info.obscuringOpacity) {
                    info.obscuringOpacity = opacity;
                    info.obscuringUid = uid;
                    info.obscuringPackage = otherInfo->packageName;
                }
            }
        }
    }
    if (DEBUG_TOUCH_OCCLUSION) {
        info.debugInfo.push_back(
                dumpWindowForTouchOcclusion(windowInfo, /* isTouchedWindow */ true));
    }
    return info;
}

std::string InputDispatcher::dumpWindowForTouchOcclusion(const WindowInfo* info,
                                                         bool isTouchedWindow) const {
    return StringPrintf(INDENT2 "* %spackage=%s/%" PRId32 ", id=%" PRId32 ", mode=%s, alpha=%.2f, "
                                "frame=[%" PRId32 ",%" PRId32 "][%" PRId32 ",%" PRId32
                                "], touchableRegion=%s, window={%s}, inputConfig={%s}, "
                                "hasToken=%s, applicationInfo.name=%s, applicationInfo.token=%s\n",
                        isTouchedWindow ? "[TOUCHED] " : "", info->packageName.c_str(),
                        info->ownerUid, info->id, toString(info->touchOcclusionMode).c_str(),
                        info->alpha, info->frameLeft, info->frameTop, info->frameRight,
                        info->frameBottom, dumpRegion(info->touchableRegion).c_str(),
                        info->name.c_str(), info->inputConfig.string().c_str(),
                        toString(info->token != nullptr), info->applicationInfo.name.c_str(),
                        toString(info->applicationInfo.token).c_str());
}

bool InputDispatcher::isTouchTrustedLocked(const TouchOcclusionInfo& occlusionInfo) const {
    if (occlusionInfo.hasBlockingOcclusion) {
        ALOGW("Untrusted touch due to occlusion by %s/%d", occlusionInfo.obscuringPackage.c_str(),
              occlusionInfo.obscuringUid);
        return false;
    }
    if (occlusionInfo.obscuringOpacity > mMaximumObscuringOpacityForTouch) {
        ALOGW("Untrusted touch due to occlusion by %s/%d (obscuring opacity = "
              "%.2f, maximum allowed = %.2f)",
              occlusionInfo.obscuringPackage.c_str(), occlusionInfo.obscuringUid,
              occlusionInfo.obscuringOpacity, mMaximumObscuringOpacityForTouch);
        return false;
    }
    return true;
}

bool InputDispatcher::isWindowObscuredAtPointLocked(const sp<WindowInfoHandle>& windowHandle,
                                                    int32_t x, int32_t y) const {
    int32_t displayId = windowHandle->getInfo()->displayId;
    const std::vector<sp<WindowInfoHandle>>& windowHandles = getWindowHandlesLocked(displayId);
    for (const sp<WindowInfoHandle>& otherHandle : windowHandles) {
        if (windowHandle == otherHandle) {
            break; // All future windows are below us. Exit early.
        }
        const WindowInfo* otherInfo = otherHandle->getInfo();
        if (canBeObscuredBy(windowHandle, otherHandle) &&
            otherInfo->frameContainsPoint(x, y)) {
            return true;
        }
    }
    return false;
}

bool InputDispatcher::isWindowObscuredLocked(const sp<WindowInfoHandle>& windowHandle) const {
    int32_t displayId = windowHandle->getInfo()->displayId;
    const std::vector<sp<WindowInfoHandle>>& windowHandles = getWindowHandlesLocked(displayId);
    const WindowInfo* windowInfo = windowHandle->getInfo();
    for (const sp<WindowInfoHandle>& otherHandle : windowHandles) {
        if (windowHandle == otherHandle) {
            break; // All future windows are below us. Exit early.
        }
        const WindowInfo* otherInfo = otherHandle->getInfo();
        if (canBeObscuredBy(windowHandle, otherHandle) &&
            otherInfo->overlaps(windowInfo)) {
            return true;
        }
    }
    return false;
}

std::string InputDispatcher::getApplicationWindowLabel(
        const InputApplicationHandle* applicationHandle, const sp<WindowInfoHandle>& windowHandle) {
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
    if (!isUserActivityEvent(eventEntry)) {
        // Not poking user activity if the event type does not represent a user activity
        return;
    }
    int32_t displayId = getTargetDisplayId(eventEntry);
    sp<WindowInfoHandle> focusedWindowHandle = getFocusedWindowHandleLocked(displayId);
    if (focusedWindowHandle != nullptr) {
        const WindowInfo* info = focusedWindowHandle->getInfo();
        if (info->inputConfig.test(WindowInfo::InputConfig::DISABLE_USER_ACTIVITY)) {
            if (DEBUG_DISPATCH_CYCLE) {
                ALOGD("Not poking user activity: disabled by window '%s'.", info->name.c_str());
            }
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
        default: {
            LOG_ALWAYS_FATAL("%s events are not user activity",
                             ftl::enum_string(eventEntry.type).c_str());
            break;
        }
    }

    auto command = [this, eventTime = eventEntry.eventTime, eventType, displayId]()
                           REQUIRES(mLock) {
                               scoped_unlock unlock(mLock);
                               mPolicy->pokeUserActivity(eventTime, eventType, displayId);
                           };
    postCommandLocked(std::move(command));
}

void InputDispatcher::prepareDispatchCycleLocked(nsecs_t currentTime,
                                                 const sp<Connection>& connection,
                                                 std::shared_ptr<EventEntry> eventEntry,
                                                 const InputTarget& inputTarget) {
    if (ATRACE_ENABLED()) {
        std::string message =
                StringPrintf("prepareDispatchCycleLocked(inputChannel=%s, id=0x%" PRIx32 ")",
                             connection->getInputChannelName().c_str(), eventEntry->id);
        ATRACE_NAME(message.c_str());
    }
    if (DEBUG_DISPATCH_CYCLE) {
        ALOGD("channel '%s' ~ prepareDispatchCycle - flags=0x%08x, "
              "globalScaleFactor=%f, pointerIds=0x%x %s",
              connection->getInputChannelName().c_str(), inputTarget.flags,
              inputTarget.globalScaleFactor, inputTarget.pointerIds.value,
              inputTarget.getPointerInfoString().c_str());
    }

    // Skip this event if the connection status is not normal.
    // We don't want to enqueue additional outbound events if the connection is broken.
    if (connection->status != Connection::Status::NORMAL) {
        if (DEBUG_DISPATCH_CYCLE) {
            ALOGD("channel '%s' ~ Dropping event because the channel status is %s",
                  connection->getInputChannelName().c_str(),
                  ftl::enum_string(connection->status).c_str());
        }
        return;
    }

    // Split a motion event if needed.
    if (inputTarget.flags & InputTarget::FLAG_SPLIT) {
        LOG_ALWAYS_FATAL_IF(eventEntry->type != EventEntry::Type::MOTION,
                            "Entry type %s should not have FLAG_SPLIT",
                            ftl::enum_string(eventEntry->type).c_str());

        const MotionEntry& originalMotionEntry = static_cast<const MotionEntry&>(*eventEntry);
        if (inputTarget.pointerIds.count() != originalMotionEntry.pointerCount) {
            std::unique_ptr<MotionEntry> splitMotionEntry =
                    splitMotionEvent(originalMotionEntry, inputTarget.pointerIds);
            if (!splitMotionEntry) {
                return; // split event was dropped
            }
            if (splitMotionEntry->action == AMOTION_EVENT_ACTION_CANCEL) {
                std::string reason = std::string("reason=pointer cancel on split window");
                android_log_event_list(LOGTAG_INPUT_CANCEL)
                        << connection->getInputChannelName().c_str() << reason << LOG_ID_EVENTS;
            }
            if (DEBUG_FOCUS) {
                ALOGD("channel '%s' ~ Split motion event.",
                      connection->getInputChannelName().c_str());
                logOutboundMotionDetails("  ", *splitMotionEntry);
            }
            enqueueDispatchEntriesLocked(currentTime, connection, std::move(splitMotionEntry),
                                         inputTarget);
            return;
        }
    }

    // Not splitting.  Enqueue dispatch entries for the event as is.
    enqueueDispatchEntriesLocked(currentTime, connection, eventEntry, inputTarget);
}

void InputDispatcher::enqueueDispatchEntriesLocked(nsecs_t currentTime,
                                                   const sp<Connection>& connection,
                                                   std::shared_ptr<EventEntry> eventEntry,
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
                                                 std::shared_ptr<EventEntry> eventEntry,
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
    EventEntry& newEntry = *(dispatchEntry->eventEntry);
    // Apply target flags and update the connection's input state.
    switch (newEntry.type) {
        case EventEntry::Type::KEY: {
            const KeyEntry& keyEntry = static_cast<const KeyEntry&>(newEntry);
            dispatchEntry->resolvedEventId = keyEntry.id;
            dispatchEntry->resolvedAction = keyEntry.action;
            dispatchEntry->resolvedFlags = keyEntry.flags;

            if (!connection->inputState.trackKey(keyEntry, dispatchEntry->resolvedAction,
                                                 dispatchEntry->resolvedFlags)) {
                if (DEBUG_DISPATCH_CYCLE) {
                    ALOGD("channel '%s' ~ enqueueDispatchEntryLocked: skipping inconsistent key "
                          "event",
                          connection->getInputChannelName().c_str());
                }
                return; // skip the inconsistent event
            }
            break;
        }

        case EventEntry::Type::MOTION: {
            const MotionEntry& motionEntry = static_cast<const MotionEntry&>(newEntry);
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
                if (DEBUG_DISPATCH_CYCLE) {
                    ALOGD("channel '%s' ~ enqueueDispatchEntryLocked: filling in missing hover "
                          "enter event",
                          connection->getInputChannelName().c_str());
                }
                // We keep the 'resolvedEventId' here equal to the original 'motionEntry.id' because
                // this is a one-to-one event conversion.
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
                if (DEBUG_DISPATCH_CYCLE) {
                    ALOGD("channel '%s' ~ enqueueDispatchEntryLocked: skipping inconsistent motion "
                          "event",
                          connection->getInputChannelName().c_str());
                }
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

            if ((motionEntry.flags & AMOTION_EVENT_FLAG_NO_FOCUS_CHANGE) &&
                (motionEntry.policyFlags & POLICY_FLAG_TRUSTED)) {
                // Skip reporting pointer down outside focus to the policy.
                break;
            }

            dispatchPointerDownOutsideFocus(motionEntry.source, dispatchEntry->resolvedAction,
                                            inputTarget.inputChannel->getConnectionToken());

            break;
        }
        case EventEntry::Type::FOCUS:
        case EventEntry::Type::TOUCH_MODE_CHANGED:
        case EventEntry::Type::POINTER_CAPTURE_CHANGED:
        case EventEntry::Type::DRAG: {
            break;
        }
        case EventEntry::Type::SENSOR: {
            LOG_ALWAYS_FATAL("SENSOR events should not go to apps via input channel");
            break;
        }
        case EventEntry::Type::CONFIGURATION_CHANGED:
        case EventEntry::Type::DEVICE_RESET: {
            LOG_ALWAYS_FATAL("%s events should not go to apps",
                             ftl::enum_string(newEntry.type).c_str());
            break;
        }
    }

    // Remember that we are waiting for this dispatch to complete.
    if (dispatchEntry->hasForegroundTarget()) {
        incrementPendingForegroundDispatches(newEntry);
    }

    // Enqueue the dispatch entry.
    connection->outboundQueue.push_back(dispatchEntry.release());
    traceOutboundQueueLength(*connection);
}

/**
 * This function is purely for debugging. It helps us understand where the user interaction
 * was taking place. For example, if user is touching launcher, we will see a log that user
 * started interacting with launcher. In that example, the event would go to the wallpaper as well.
 * We will see both launcher and wallpaper in that list.
 * Once the interaction with a particular set of connections starts, no new logs will be printed
 * until the set of interacted connections changes.
 *
 * The following items are skipped, to reduce the logspam:
 * ACTION_OUTSIDE: any windows that are receiving ACTION_OUTSIDE are not logged
 * ACTION_UP: any windows that receive ACTION_UP are not logged (for both keys and motions).
 * This includes situations like the soft BACK button key. When the user releases (lifts up the
 * finger) the back button, then navigation bar will inject KEYCODE_BACK with ACTION_UP.
 * Both of those ACTION_UP events would not be logged
 */
void InputDispatcher::updateInteractionTokensLocked(const EventEntry& entry,
                                                    const std::vector<InputTarget>& targets) {
    // Skip ACTION_UP events, and all events other than keys and motions
    if (entry.type == EventEntry::Type::KEY) {
        const KeyEntry& keyEntry = static_cast<const KeyEntry&>(entry);
        if (keyEntry.action == AKEY_EVENT_ACTION_UP) {
            return;
        }
    } else if (entry.type == EventEntry::Type::MOTION) {
        const MotionEntry& motionEntry = static_cast<const MotionEntry&>(entry);
        if (motionEntry.action == AMOTION_EVENT_ACTION_UP ||
            motionEntry.action == AMOTION_EVENT_ACTION_CANCEL) {
            return;
        }
    } else {
        return; // Not a key or a motion
    }

    std::unordered_set<sp<IBinder>, StrongPointerHash<IBinder>> newConnectionTokens;
    std::vector<sp<Connection>> newConnections;
    for (const InputTarget& target : targets) {
        if ((target.flags & InputTarget::FLAG_DISPATCH_AS_OUTSIDE) ==
            InputTarget::FLAG_DISPATCH_AS_OUTSIDE) {
            continue; // Skip windows that receive ACTION_OUTSIDE
        }

        sp<IBinder> token = target.inputChannel->getConnectionToken();
        sp<Connection> connection = getConnectionLocked(token);
        if (connection == nullptr) {
            continue;
        }
        newConnectionTokens.insert(std::move(token));
        newConnections.emplace_back(connection);
    }
    if (newConnectionTokens == mInteractionConnectionTokens) {
        return; // no change
    }
    mInteractionConnectionTokens = newConnectionTokens;

    std::string targetList;
    for (const sp<Connection>& connection : newConnections) {
        targetList += connection->getWindowName() + ", ";
    }
    std::string message = "Interaction with: " + targetList;
    if (targetList.empty()) {
        message += "<none>";
    }
    android_log_event_list(LOGTAG_INPUT_INTERACTION) << message << LOG_ID_EVENTS;
}

void InputDispatcher::dispatchPointerDownOutsideFocus(uint32_t source, int32_t action,
                                                      const sp<IBinder>& token) {
    int32_t maskedAction = action & AMOTION_EVENT_ACTION_MASK;
    uint32_t maskedSource = source & AINPUT_SOURCE_CLASS_MASK;
    if (maskedSource != AINPUT_SOURCE_CLASS_POINTER || maskedAction != AMOTION_EVENT_ACTION_DOWN) {
        return;
    }

    sp<IBinder> focusedToken = mFocusResolver.getFocusedWindowToken(mFocusedDisplayId);
    if (focusedToken == token) {
        // ignore since token is focused
        return;
    }

    auto command = [this, token]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->onPointerDownOutsideFocus(token);
    };
    postCommandLocked(std::move(command));
}

void InputDispatcher::startDispatchCycleLocked(nsecs_t currentTime,
                                               const sp<Connection>& connection) {
    if (ATRACE_ENABLED()) {
        std::string message = StringPrintf("startDispatchCycleLocked(inputChannel=%s)",
                                           connection->getInputChannelName().c_str());
        ATRACE_NAME(message.c_str());
    }
    if (DEBUG_DISPATCH_CYCLE) {
        ALOGD("channel '%s' ~ startDispatchCycle", connection->getInputChannelName().c_str());
    }

    while (connection->status == Connection::Status::NORMAL && !connection->outboundQueue.empty()) {
        DispatchEntry* dispatchEntry = connection->outboundQueue.front();
        dispatchEntry->deliveryTime = currentTime;
        const std::chrono::nanoseconds timeout = getDispatchingTimeoutLocked(connection);
        dispatchEntry->timeoutTime = currentTime + timeout.count();

        // Publish the event.
        status_t status;
        const EventEntry& eventEntry = *(dispatchEntry->eventEntry);
        switch (eventEntry.type) {
            case EventEntry::Type::KEY: {
                const KeyEntry& keyEntry = static_cast<const KeyEntry&>(eventEntry);
                std::array<uint8_t, 32> hmac = getSignature(keyEntry, *dispatchEntry);

                // Publish the key event.
                status = connection->inputPublisher
                                 .publishKeyEvent(dispatchEntry->seq,
                                                  dispatchEntry->resolvedEventId, keyEntry.deviceId,
                                                  keyEntry.source, keyEntry.displayId,
                                                  std::move(hmac), dispatchEntry->resolvedAction,
                                                  dispatchEntry->resolvedFlags, keyEntry.keyCode,
                                                  keyEntry.scanCode, keyEntry.metaState,
                                                  keyEntry.repeatCount, keyEntry.downTime,
                                                  keyEntry.eventTime);
                break;
            }

            case EventEntry::Type::MOTION: {
                const MotionEntry& motionEntry = static_cast<const MotionEntry&>(eventEntry);

                PointerCoords scaledCoords[MAX_POINTERS];
                const PointerCoords* usingCoords = motionEntry.pointerCoords;

                // Set the X and Y offset and X and Y scale depending on the input source.
                if ((motionEntry.source & AINPUT_SOURCE_CLASS_POINTER) &&
                    !(dispatchEntry->targetFlags & InputTarget::FLAG_ZERO_COORDS)) {
                    float globalScaleFactor = dispatchEntry->globalScaleFactor;
                    if (globalScaleFactor != 1.0f) {
                        for (uint32_t i = 0; i < motionEntry.pointerCount; i++) {
                            scaledCoords[i] = motionEntry.pointerCoords[i];
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
                        for (uint32_t i = 0; i < motionEntry.pointerCount; i++) {
                            scaledCoords[i].clear();
                        }
                        usingCoords = scaledCoords;
                    }
                }

                std::array<uint8_t, 32> hmac = getSignature(motionEntry, *dispatchEntry);

                // Publish the motion event.
                status = connection->inputPublisher
                                 .publishMotionEvent(dispatchEntry->seq,
                                                     dispatchEntry->resolvedEventId,
                                                     motionEntry.deviceId, motionEntry.source,
                                                     motionEntry.displayId, std::move(hmac),
                                                     dispatchEntry->resolvedAction,
                                                     motionEntry.actionButton,
                                                     dispatchEntry->resolvedFlags,
                                                     motionEntry.edgeFlags, motionEntry.metaState,
                                                     motionEntry.buttonState,
                                                     motionEntry.classification,
                                                     dispatchEntry->transform,
                                                     motionEntry.xPrecision, motionEntry.yPrecision,
                                                     motionEntry.xCursorPosition,
                                                     motionEntry.yCursorPosition,
                                                     dispatchEntry->rawTransform,
                                                     motionEntry.downTime, motionEntry.eventTime,
                                                     motionEntry.pointerCount,
                                                     motionEntry.pointerProperties, usingCoords);
                break;
            }

            case EventEntry::Type::FOCUS: {
                const FocusEntry& focusEntry = static_cast<const FocusEntry&>(eventEntry);
                status = connection->inputPublisher.publishFocusEvent(dispatchEntry->seq,
                                                                      focusEntry.id,
                                                                      focusEntry.hasFocus);
                break;
            }

            case EventEntry::Type::TOUCH_MODE_CHANGED: {
                const TouchModeEntry& touchModeEntry =
                        static_cast<const TouchModeEntry&>(eventEntry);
                status = connection->inputPublisher
                                 .publishTouchModeEvent(dispatchEntry->seq, touchModeEntry.id,
                                                        touchModeEntry.inTouchMode);

                break;
            }

            case EventEntry::Type::POINTER_CAPTURE_CHANGED: {
                const auto& captureEntry =
                        static_cast<const PointerCaptureChangedEntry&>(eventEntry);
                status = connection->inputPublisher
                                 .publishCaptureEvent(dispatchEntry->seq, captureEntry.id,
                                                      captureEntry.pointerCaptureRequest.enable);
                break;
            }

            case EventEntry::Type::DRAG: {
                const DragEntry& dragEntry = static_cast<const DragEntry&>(eventEntry);
                status = connection->inputPublisher.publishDragEvent(dispatchEntry->seq,
                                                                     dragEntry.id, dragEntry.x,
                                                                     dragEntry.y,
                                                                     dragEntry.isExiting);
                break;
            }

            case EventEntry::Type::CONFIGURATION_CHANGED:
            case EventEntry::Type::DEVICE_RESET:
            case EventEntry::Type::SENSOR: {
                LOG_ALWAYS_FATAL("Should never start dispatch cycles for %s events",
                                 ftl::enum_string(eventEntry.type).c_str());
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
                          "event to it, status=%s(%d)",
                          connection->getInputChannelName().c_str(), statusToString(status).c_str(),
                          status);
                    abortBrokenDispatchCycleLocked(currentTime, connection, true /*notify*/);
                } else {
                    // Pipe is full and we are waiting for the app to finish process some events
                    // before sending more events to it.
                    if (DEBUG_DISPATCH_CYCLE) {
                        ALOGD("channel '%s' ~ Could not publish event because the pipe is full, "
                              "waiting for the application to catch up",
                              connection->getInputChannelName().c_str());
                    }
                }
            } else {
                ALOGE("channel '%s' ~ Could not publish event due to an unexpected error, "
                      "status=%s(%d)",
                      connection->getInputChannelName().c_str(), statusToString(status).c_str(),
                      status);
                abortBrokenDispatchCycleLocked(currentTime, connection, true /*notify*/);
            }
            return;
        }

        // Re-enqueue the event on the wait queue.
        connection->outboundQueue.erase(std::remove(connection->outboundQueue.begin(),
                                                    connection->outboundQueue.end(),
                                                    dispatchEntry));
        traceOutboundQueueLength(*connection);
        connection->waitQueue.push_back(dispatchEntry);
        if (connection->responsive) {
            mAnrTracker.insert(dispatchEntry->timeoutTime,
                               connection->inputChannel->getConnectionToken());
        }
        traceWaitQueueLength(*connection);
    }
}

std::array<uint8_t, 32> InputDispatcher::sign(const VerifiedInputEvent& event) const {
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
    return mHmacKeyManager.sign(start, size);
}

const std::array<uint8_t, 32> InputDispatcher::getSignature(
        const MotionEntry& motionEntry, const DispatchEntry& dispatchEntry) const {
    const int32_t actionMasked = dispatchEntry.resolvedAction & AMOTION_EVENT_ACTION_MASK;
    if (actionMasked != AMOTION_EVENT_ACTION_UP && actionMasked != AMOTION_EVENT_ACTION_DOWN) {
        // Only sign events up and down events as the purely move events
        // are tied to their up/down counterparts so signing would be redundant.
        return INVALID_HMAC;
    }

    VerifiedMotionEvent verifiedEvent =
            verifiedMotionEventFromMotionEntry(motionEntry, dispatchEntry.rawTransform);
    verifiedEvent.actionMasked = actionMasked;
    verifiedEvent.flags = dispatchEntry.resolvedFlags & VERIFIED_MOTION_EVENT_FLAGS;
    return sign(verifiedEvent);
}

const std::array<uint8_t, 32> InputDispatcher::getSignature(
        const KeyEntry& keyEntry, const DispatchEntry& dispatchEntry) const {
    VerifiedKeyEvent verifiedEvent = verifiedKeyEventFromKeyEntry(keyEntry);
    verifiedEvent.flags = dispatchEntry.resolvedFlags & VERIFIED_KEY_EVENT_FLAGS;
    verifiedEvent.action = dispatchEntry.resolvedAction;
    return sign(verifiedEvent);
}

void InputDispatcher::finishDispatchCycleLocked(nsecs_t currentTime,
                                                const sp<Connection>& connection, uint32_t seq,
                                                bool handled, nsecs_t consumeTime) {
    if (DEBUG_DISPATCH_CYCLE) {
        ALOGD("channel '%s' ~ finishDispatchCycle - seq=%u, handled=%s",
              connection->getInputChannelName().c_str(), seq, toString(handled));
    }

    if (connection->status == Connection::Status::BROKEN ||
        connection->status == Connection::Status::ZOMBIE) {
        return;
    }

    // Notify other system components and prepare to start the next dispatch cycle.
    auto command = [this, currentTime, connection, seq, handled, consumeTime]() REQUIRES(mLock) {
        doDispatchCycleFinishedCommand(currentTime, connection, seq, handled, consumeTime);
    };
    postCommandLocked(std::move(command));
}

void InputDispatcher::abortBrokenDispatchCycleLocked(nsecs_t currentTime,
                                                     const sp<Connection>& connection,
                                                     bool notify) {
    if (DEBUG_DISPATCH_CYCLE) {
        ALOGD("channel '%s' ~ abortBrokenDispatchCycle - notify=%s",
              connection->getInputChannelName().c_str(), toString(notify));
    }

    // Clear the dispatch queues.
    drainDispatchQueue(connection->outboundQueue);
    traceOutboundQueueLength(*connection);
    drainDispatchQueue(connection->waitQueue);
    traceWaitQueueLength(*connection);

    // The connection appears to be unrecoverably broken.
    // Ignore already broken or zombie connections.
    if (connection->status == Connection::Status::NORMAL) {
        connection->status = Connection::Status::BROKEN;

        if (notify) {
            // Notify other system components.
            ALOGE("channel '%s' ~ Channel is unrecoverably broken and will be disposed!",
                  connection->getInputChannelName().c_str());

            auto command = [this, connection]() REQUIRES(mLock) {
                scoped_unlock unlock(mLock);
                mPolicy->notifyInputChannelBroken(connection->inputChannel->getConnectionToken());
            };
            postCommandLocked(std::move(command));
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
        decrementPendingForegroundDispatches(*(dispatchEntry->eventEntry));
    }
    delete dispatchEntry;
}

int InputDispatcher::handleReceiveCallback(int events, sp<IBinder> connectionToken) {
    std::scoped_lock _l(mLock);
    sp<Connection> connection = getConnectionLocked(connectionToken);
    if (connection == nullptr) {
        ALOGW("Received looper callback for unknown input channel token %p.  events=0x%x",
              connectionToken.get(), events);
        return 0; // remove the callback
    }

    bool notify;
    if (!(events & (ALOOPER_EVENT_ERROR | ALOOPER_EVENT_HANGUP))) {
        if (!(events & ALOOPER_EVENT_INPUT)) {
            ALOGW("channel '%s' ~ Received spurious callback for unhandled poll event.  "
                  "events=0x%x",
                  connection->getInputChannelName().c_str(), events);
            return 1;
        }

        nsecs_t currentTime = now();
        bool gotOne = false;
        status_t status = OK;
        for (;;) {
            Result<InputPublisher::ConsumerResponse> result =
                    connection->inputPublisher.receiveConsumerResponse();
            if (!result.ok()) {
                status = result.error().code();
                break;
            }

            if (std::holds_alternative<InputPublisher::Finished>(*result)) {
                const InputPublisher::Finished& finish =
                        std::get<InputPublisher::Finished>(*result);
                finishDispatchCycleLocked(currentTime, connection, finish.seq, finish.handled,
                                          finish.consumeTime);
            } else if (std::holds_alternative<InputPublisher::Timeline>(*result)) {
                if (shouldReportMetricsForConnection(*connection)) {
                    const InputPublisher::Timeline& timeline =
                            std::get<InputPublisher::Timeline>(*result);
                    mLatencyTracker
                            .trackGraphicsLatency(timeline.inputEventId,
                                                  connection->inputChannel->getConnectionToken(),
                                                  std::move(timeline.graphicsTimeline));
                }
            }
            gotOne = true;
        }
        if (gotOne) {
            runCommandsLockedInterruptable();
            if (status == WOULD_BLOCK) {
                return 1;
            }
        }

        notify = status != DEAD_OBJECT || !connection->monitor;
        if (notify) {
            ALOGE("channel '%s' ~ Failed to receive finished signal.  status=%s(%d)",
                  connection->getInputChannelName().c_str(), statusToString(status).c_str(),
                  status);
        }
    } else {
        // Monitor channels are never explicitly unregistered.
        // We do it automatically when the remote endpoint is closed so don't warn about them.
        const bool stillHaveWindowHandle =
                getWindowHandleLocked(connection->inputChannel->getConnectionToken()) != nullptr;
        notify = !connection->monitor && stillHaveWindowHandle;
        if (notify) {
            ALOGW("channel '%s' ~ Consumer closed input channel or an error occurred.  events=0x%x",
                  connection->getInputChannelName().c_str(), events);
        }
    }

    // Remove the channel.
    removeInputChannelLocked(connection->inputChannel->getConnectionToken(), notify);
    return 0; // remove the callback
}

void InputDispatcher::synthesizeCancelationEventsForAllConnectionsLocked(
        const CancelationOptions& options) {
    for (const auto& [token, connection] : mConnectionsByToken) {
        synthesizeCancelationEventsForConnectionLocked(connection, options);
    }
}

void InputDispatcher::synthesizeCancelationEventsForMonitorsLocked(
        const CancelationOptions& options) {
    for (const auto& [_, monitors] : mGlobalMonitorsByDisplay) {
        for (const Monitor& monitor : monitors) {
            synthesizeCancelationEventsForInputChannelLocked(monitor.inputChannel, options);
        }
    }
}

void InputDispatcher::synthesizeCancelationEventsForInputChannelLocked(
        const std::shared_ptr<InputChannel>& channel, const CancelationOptions& options) {
    sp<Connection> connection = getConnectionLocked(channel->getConnectionToken());
    if (connection == nullptr) {
        return;
    }

    synthesizeCancelationEventsForConnectionLocked(connection, options);
}

void InputDispatcher::synthesizeCancelationEventsForConnectionLocked(
        const sp<Connection>& connection, const CancelationOptions& options) {
    if (connection->status == Connection::Status::BROKEN) {
        return;
    }

    nsecs_t currentTime = now();

    std::vector<std::unique_ptr<EventEntry>> cancelationEvents =
            connection->inputState.synthesizeCancelationEvents(currentTime, options);

    if (cancelationEvents.empty()) {
        return;
    }
    if (DEBUG_OUTBOUND_EVENT_DETAILS) {
        ALOGD("channel '%s' ~ Synthesized %zu cancelation events to bring channel back in sync "
              "with reality: %s, mode=%d.",
              connection->getInputChannelName().c_str(), cancelationEvents.size(), options.reason,
              options.mode);
    }

    std::string reason = std::string("reason=").append(options.reason);
    android_log_event_list(LOGTAG_INPUT_CANCEL)
            << connection->getInputChannelName().c_str() << reason << LOG_ID_EVENTS;

    InputTarget target;
    sp<WindowInfoHandle> windowHandle =
            getWindowHandleLocked(connection->inputChannel->getConnectionToken());
    if (windowHandle != nullptr) {
        const WindowInfo* windowInfo = windowHandle->getInfo();
        target.setDefaultPointerTransform(windowInfo->transform);
        target.globalScaleFactor = windowInfo->globalScaleFactor;
    }
    target.inputChannel = connection->inputChannel;
    target.flags = InputTarget::FLAG_DISPATCH_AS_IS;

    const bool wasEmpty = connection->outboundQueue.empty();

    for (size_t i = 0; i < cancelationEvents.size(); i++) {
        std::unique_ptr<EventEntry> cancelationEventEntry = std::move(cancelationEvents[i]);
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
            case EventEntry::Type::FOCUS:
            case EventEntry::Type::TOUCH_MODE_CHANGED:
            case EventEntry::Type::POINTER_CAPTURE_CHANGED:
            case EventEntry::Type::DRAG: {
                LOG_ALWAYS_FATAL("Canceling %s events is not supported",
                                 ftl::enum_string(cancelationEventEntry->type).c_str());
                break;
            }
            case EventEntry::Type::CONFIGURATION_CHANGED:
            case EventEntry::Type::DEVICE_RESET:
            case EventEntry::Type::SENSOR: {
                LOG_ALWAYS_FATAL("%s event should not be found inside Connections's queue",
                                 ftl::enum_string(cancelationEventEntry->type).c_str());
                break;
            }
        }

        enqueueDispatchEntryLocked(connection, std::move(cancelationEventEntry), target,
                                   InputTarget::FLAG_DISPATCH_AS_IS);
    }

    // If the outbound queue was previously empty, start the dispatch cycle going.
    if (wasEmpty && !connection->outboundQueue.empty()) {
        startDispatchCycleLocked(currentTime, connection);
    }
}

void InputDispatcher::synthesizePointerDownEventsForConnectionLocked(
        const sp<Connection>& connection, int32_t targetFlags) {
    if (connection->status == Connection::Status::BROKEN) {
        return;
    }

    nsecs_t currentTime = now();

    std::vector<std::unique_ptr<EventEntry>> downEvents =
            connection->inputState.synthesizePointerDownEvents(currentTime);

    if (downEvents.empty()) {
        return;
    }

    if (DEBUG_OUTBOUND_EVENT_DETAILS) {
        ALOGD("channel '%s' ~ Synthesized %zu down events to ensure consistent event stream.",
              connection->getInputChannelName().c_str(), downEvents.size());
    }

    InputTarget target;
    sp<WindowInfoHandle> windowHandle =
            getWindowHandleLocked(connection->inputChannel->getConnectionToken());
    if (windowHandle != nullptr) {
        const WindowInfo* windowInfo = windowHandle->getInfo();
        target.setDefaultPointerTransform(windowInfo->transform);
        target.globalScaleFactor = windowInfo->globalScaleFactor;
    }
    target.inputChannel = connection->inputChannel;
    target.flags = targetFlags;

    const bool wasEmpty = connection->outboundQueue.empty();

    for (std::unique_ptr<EventEntry>& downEventEntry : downEvents) {
        switch (downEventEntry->type) {
            case EventEntry::Type::MOTION: {
                logOutboundMotionDetails("down - ",
                        static_cast<const MotionEntry&>(*downEventEntry));
                break;
            }

            case EventEntry::Type::KEY:
            case EventEntry::Type::FOCUS:
            case EventEntry::Type::TOUCH_MODE_CHANGED:
            case EventEntry::Type::CONFIGURATION_CHANGED:
            case EventEntry::Type::DEVICE_RESET:
            case EventEntry::Type::POINTER_CAPTURE_CHANGED:
            case EventEntry::Type::SENSOR:
            case EventEntry::Type::DRAG: {
                LOG_ALWAYS_FATAL("%s event should not be found inside Connections's queue",
                                 ftl::enum_string(downEventEntry->type).c_str());
                break;
            }
        }

        enqueueDispatchEntryLocked(connection, std::move(downEventEntry), target,
                                   InputTarget::FLAG_DISPATCH_AS_IS);
    }
    // If the outbound queue was previously empty, start the dispatch cycle going.
    if (wasEmpty && !connection->outboundQueue.empty()) {
        startDispatchCycleLocked(currentTime, connection);
    }
}

void InputDispatcher::synthesizeCancelationEventsForWindowLocked(
        const sp<WindowInfoHandle>& windowHandle, const CancelationOptions& options) {
    if (windowHandle != nullptr) {
        sp<Connection> wallpaperConnection = getConnectionLocked(windowHandle->getToken());
        if (wallpaperConnection != nullptr) {
            synthesizeCancelationEventsForConnectionLocked(wallpaperConnection, options);
        }
    }
}

std::unique_ptr<MotionEntry> InputDispatcher::splitMotionEvent(
        const MotionEntry& originalMotionEntry, BitSet32 pointerIds) {
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
                        : (originalMotionEntry.flags & AMOTION_EVENT_FLAG_CANCELED) != 0
                                ? AMOTION_EVENT_ACTION_CANCEL
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
    std::unique_ptr<MotionEntry> splitMotionEntry =
            std::make_unique<MotionEntry>(newId, originalMotionEntry.eventTime,
                                          originalMotionEntry.deviceId, originalMotionEntry.source,
                                          originalMotionEntry.displayId,
                                          originalMotionEntry.policyFlags, action,
                                          originalMotionEntry.actionButton,
                                          originalMotionEntry.flags, originalMotionEntry.metaState,
                                          originalMotionEntry.buttonState,
                                          originalMotionEntry.classification,
                                          originalMotionEntry.edgeFlags,
                                          originalMotionEntry.xPrecision,
                                          originalMotionEntry.yPrecision,
                                          originalMotionEntry.xCursorPosition,
                                          originalMotionEntry.yCursorPosition,
                                          originalMotionEntry.downTime, splitPointerCount,
                                          splitPointerProperties, splitPointerCoords);

    if (originalMotionEntry.injectionState) {
        splitMotionEntry->injectionState = originalMotionEntry.injectionState;
        splitMotionEntry->injectionState->refCount += 1;
    }

    return splitMotionEntry;
}

void InputDispatcher::notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) {
    if (DEBUG_INBOUND_EVENT_DETAILS) {
        ALOGD("notifyConfigurationChanged - eventTime=%" PRId64, args->eventTime);
    }

    bool needWake = false;
    { // acquire lock
        std::scoped_lock _l(mLock);

        std::unique_ptr<ConfigurationChangedEntry> newEntry =
                std::make_unique<ConfigurationChangedEntry>(args->id, args->eventTime);
        needWake = enqueueInboundEventLocked(std::move(newEntry));
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
    if (DEBUG_INBOUND_EVENT_DETAILS) {
        ALOGD("notifyKey - eventTime=%" PRId64 ", deviceId=%d, source=0x%x, displayId=%" PRId32
              "policyFlags=0x%x, action=0x%x, "
              "flags=0x%x, keyCode=0x%x, scanCode=0x%x, metaState=0x%x, downTime=%" PRId64,
              args->eventTime, args->deviceId, args->source, args->displayId, args->policyFlags,
              args->action, args->flags, args->keyCode, args->scanCode, args->metaState,
              args->downTime);
    }
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

    bool needWake = false;
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

        std::unique_ptr<KeyEntry> newEntry =
                std::make_unique<KeyEntry>(args->id, args->eventTime, args->deviceId, args->source,
                                           args->displayId, policyFlags, args->action, flags,
                                           keyCode, args->scanCode, metaState, repeatCount,
                                           args->downTime);

        needWake = enqueueInboundEventLocked(std::move(newEntry));
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
    if (DEBUG_INBOUND_EVENT_DETAILS) {
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
    }
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

    bool needWake = false;
    { // acquire lock
        mLock.lock();

        if (shouldSendMotionToInputFilterLocked(args)) {
            ui::Transform displayTransform;
            if (const auto it = mDisplayInfos.find(args->displayId); it != mDisplayInfos.end()) {
                displayTransform = it->second.transform;
            }

            mLock.unlock();

            MotionEvent event;
            event.initialize(args->id, args->deviceId, args->source, args->displayId, INVALID_HMAC,
                             args->action, args->actionButton, args->flags, args->edgeFlags,
                             args->metaState, args->buttonState, args->classification,
                             displayTransform, args->xPrecision, args->yPrecision,
                             args->xCursorPosition, args->yCursorPosition, displayTransform,
                             args->downTime, args->eventTime, args->pointerCount,
                             args->pointerProperties, args->pointerCoords);

            policyFlags |= POLICY_FLAG_FILTERED;
            if (!mPolicy->filterInputEvent(&event, policyFlags)) {
                return; // event was consumed by the filter
            }

            mLock.lock();
        }

        // Just enqueue a new motion event.
        std::unique_ptr<MotionEntry> newEntry =
                std::make_unique<MotionEntry>(args->id, args->eventTime, args->deviceId,
                                              args->source, args->displayId, policyFlags,
                                              args->action, args->actionButton, args->flags,
                                              args->metaState, args->buttonState,
                                              args->classification, args->edgeFlags,
                                              args->xPrecision, args->yPrecision,
                                              args->xCursorPosition, args->yCursorPosition,
                                              args->downTime, args->pointerCount,
                                              args->pointerProperties, args->pointerCoords);

        if (args->id != android::os::IInputConstants::INVALID_INPUT_EVENT_ID &&
            IdGenerator::getSource(args->id) == IdGenerator::Source::INPUT_READER &&
            !mInputFilterEnabled) {
            const bool isDown = args->action == AMOTION_EVENT_ACTION_DOWN;
            mLatencyTracker.trackListener(args->id, isDown, args->eventTime, args->readTime);
        }

        needWake = enqueueInboundEventLocked(std::move(newEntry));
        mLock.unlock();
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
}

void InputDispatcher::notifySensor(const NotifySensorArgs* args) {
    if (DEBUG_INBOUND_EVENT_DETAILS) {
        ALOGD("notifySensor - id=%" PRIx32 " eventTime=%" PRId64 ", deviceId=%d, source=0x%x, "
              " sensorType=%s",
              args->id, args->eventTime, args->deviceId, args->source,
              ftl::enum_string(args->sensorType).c_str());
    }

    bool needWake = false;
    { // acquire lock
        mLock.lock();

        // Just enqueue a new sensor event.
        std::unique_ptr<SensorEntry> newEntry =
                std::make_unique<SensorEntry>(args->id, args->eventTime, args->deviceId,
                                              args->source, 0 /* policyFlags*/, args->hwTimestamp,
                                              args->sensorType, args->accuracy,
                                              args->accuracyChanged, args->values);

        needWake = enqueueInboundEventLocked(std::move(newEntry));
        mLock.unlock();
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
}

void InputDispatcher::notifyVibratorState(const NotifyVibratorStateArgs* args) {
    if (DEBUG_INBOUND_EVENT_DETAILS) {
        ALOGD("notifyVibratorState - eventTime=%" PRId64 ", device=%d,  isOn=%d", args->eventTime,
              args->deviceId, args->isOn);
    }
    mPolicy->notifyVibratorState(args->deviceId, args->isOn);
}

bool InputDispatcher::shouldSendMotionToInputFilterLocked(const NotifyMotionArgs* args) {
    return mInputFilterEnabled;
}

void InputDispatcher::notifySwitch(const NotifySwitchArgs* args) {
    if (DEBUG_INBOUND_EVENT_DETAILS) {
        ALOGD("notifySwitch - eventTime=%" PRId64 ", policyFlags=0x%x, switchValues=0x%08x, "
              "switchMask=0x%08x",
              args->eventTime, args->policyFlags, args->switchValues, args->switchMask);
    }

    uint32_t policyFlags = args->policyFlags;
    policyFlags |= POLICY_FLAG_TRUSTED;
    mPolicy->notifySwitch(args->eventTime, args->switchValues, args->switchMask, policyFlags);
}

void InputDispatcher::notifyDeviceReset(const NotifyDeviceResetArgs* args) {
    if (DEBUG_INBOUND_EVENT_DETAILS) {
        ALOGD("notifyDeviceReset - eventTime=%" PRId64 ", deviceId=%d", args->eventTime,
              args->deviceId);
    }

    bool needWake = false;
    { // acquire lock
        std::scoped_lock _l(mLock);

        std::unique_ptr<DeviceResetEntry> newEntry =
                std::make_unique<DeviceResetEntry>(args->id, args->eventTime, args->deviceId);
        needWake = enqueueInboundEventLocked(std::move(newEntry));
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
}

void InputDispatcher::notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs* args) {
    if (DEBUG_INBOUND_EVENT_DETAILS) {
        ALOGD("notifyPointerCaptureChanged - eventTime=%" PRId64 ", enabled=%s", args->eventTime,
              args->request.enable ? "true" : "false");
    }

    bool needWake = false;
    { // acquire lock
        std::scoped_lock _l(mLock);
        auto entry = std::make_unique<PointerCaptureChangedEntry>(args->id, args->eventTime,
                                                                  args->request);
        needWake = enqueueInboundEventLocked(std::move(entry));
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
}

InputEventInjectionResult InputDispatcher::injectInputEvent(const InputEvent* event,
                                                            std::optional<int32_t> targetUid,
                                                            InputEventInjectionSync syncMode,
                                                            std::chrono::milliseconds timeout,
                                                            uint32_t policyFlags) {
    if (DEBUG_INBOUND_EVENT_DETAILS) {
        ALOGD("injectInputEvent - eventType=%d, targetUid=%s, syncMode=%d, timeout=%lld, "
              "policyFlags=0x%08x",
              event->getType(), targetUid ? std::to_string(*targetUid).c_str() : "none", syncMode,
              timeout.count(), policyFlags);
    }
    nsecs_t endTime = now() + std::chrono::duration_cast<std::chrono::nanoseconds>(timeout).count();

    policyFlags |= POLICY_FLAG_INJECTED | POLICY_FLAG_TRUSTED;

    // For all injected events, set device id = VIRTUAL_KEYBOARD_ID. The only exception is events
    // that have gone through the InputFilter. If the event passed through the InputFilter, assign
    // the provided device id. If the InputFilter is accessibility, and it modifies or synthesizes
    // the injected event, it is responsible for setting POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY.
    // For those events, we will set FLAG_IS_ACCESSIBILITY_EVENT to allow apps to distinguish them
    // from events that originate from actual hardware.
    int32_t resolvedDeviceId = VIRTUAL_KEYBOARD_ID;
    if (policyFlags & POLICY_FLAG_FILTERED) {
        resolvedDeviceId = event->getDeviceId();
    }

    std::queue<std::unique_ptr<EventEntry>> injectedEntries;
    switch (event->getType()) {
        case AINPUT_EVENT_TYPE_KEY: {
            const KeyEvent& incomingKey = static_cast<const KeyEvent&>(*event);
            int32_t action = incomingKey.getAction();
            if (!validateKeyEvent(action)) {
                return InputEventInjectionResult::FAILED;
            }

            int32_t flags = incomingKey.getFlags();
            if (policyFlags & POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY) {
                flags |= AKEY_EVENT_FLAG_IS_ACCESSIBILITY_EVENT;
            }
            int32_t keyCode = incomingKey.getKeyCode();
            int32_t metaState = incomingKey.getMetaState();
            accelerateMetaShortcuts(resolvedDeviceId, action,
                                    /*byref*/ keyCode, /*byref*/ metaState);
            KeyEvent keyEvent;
            keyEvent.initialize(incomingKey.getId(), resolvedDeviceId, incomingKey.getSource(),
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
            std::unique_ptr<KeyEntry> injectedEntry =
                    std::make_unique<KeyEntry>(incomingKey.getId(), incomingKey.getEventTime(),
                                               resolvedDeviceId, incomingKey.getSource(),
                                               incomingKey.getDisplayId(), policyFlags, action,
                                               flags, keyCode, incomingKey.getScanCode(), metaState,
                                               incomingKey.getRepeatCount(),
                                               incomingKey.getDownTime());
            injectedEntries.push(std::move(injectedEntry));
            break;
        }

        case AINPUT_EVENT_TYPE_MOTION: {
            const MotionEvent& motionEvent = static_cast<const MotionEvent&>(*event);
            const int32_t action = motionEvent.getAction();
            const bool isPointerEvent =
                    isFromSource(event->getSource(), AINPUT_SOURCE_CLASS_POINTER);
            // If a pointer event has no displayId specified, inject it to the default display.
            const uint32_t displayId = isPointerEvent && (event->getDisplayId() == ADISPLAY_ID_NONE)
                    ? ADISPLAY_ID_DEFAULT
                    : event->getDisplayId();
            const size_t pointerCount = motionEvent.getPointerCount();
            const PointerProperties* pointerProperties = motionEvent.getPointerProperties();
            const int32_t actionButton = motionEvent.getActionButton();
            int32_t flags = motionEvent.getFlags();
            if (!validateMotionEvent(action, actionButton, pointerCount, pointerProperties)) {
                return InputEventInjectionResult::FAILED;
            }

            if (!(policyFlags & POLICY_FLAG_FILTERED)) {
                nsecs_t eventTime = motionEvent.getEventTime();
                android::base::Timer t;
                mPolicy->interceptMotionBeforeQueueing(displayId, eventTime, /*byref*/ policyFlags);
                if (t.duration() > SLOW_INTERCEPTION_THRESHOLD) {
                    ALOGW("Excessive delay in interceptMotionBeforeQueueing; took %s ms",
                          std::to_string(t.duration().count()).c_str());
                }
            }

            if (policyFlags & POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY) {
                flags |= AMOTION_EVENT_FLAG_IS_ACCESSIBILITY_EVENT;
            }

            mLock.lock();
            const nsecs_t* sampleEventTimes = motionEvent.getSampleEventTimes();
            const PointerCoords* samplePointerCoords = motionEvent.getSamplePointerCoords();
            std::unique_ptr<MotionEntry> injectedEntry =
                    std::make_unique<MotionEntry>(motionEvent.getId(), *sampleEventTimes,
                                                  resolvedDeviceId, motionEvent.getSource(),
                                                  displayId, policyFlags, action, actionButton,
                                                  flags, motionEvent.getMetaState(),
                                                  motionEvent.getButtonState(),
                                                  motionEvent.getClassification(),
                                                  motionEvent.getEdgeFlags(),
                                                  motionEvent.getXPrecision(),
                                                  motionEvent.getYPrecision(),
                                                  motionEvent.getRawXCursorPosition(),
                                                  motionEvent.getRawYCursorPosition(),
                                                  motionEvent.getDownTime(), uint32_t(pointerCount),
                                                  pointerProperties, samplePointerCoords);
            transformMotionEntryForInjectionLocked(*injectedEntry, motionEvent.getTransform());
            injectedEntries.push(std::move(injectedEntry));
            for (size_t i = motionEvent.getHistorySize(); i > 0; i--) {
                sampleEventTimes += 1;
                samplePointerCoords += pointerCount;
                std::unique_ptr<MotionEntry> nextInjectedEntry =
                        std::make_unique<MotionEntry>(motionEvent.getId(), *sampleEventTimes,
                                                      resolvedDeviceId, motionEvent.getSource(),
                                                      displayId, policyFlags, action, actionButton,
                                                      flags, motionEvent.getMetaState(),
                                                      motionEvent.getButtonState(),
                                                      motionEvent.getClassification(),
                                                      motionEvent.getEdgeFlags(),
                                                      motionEvent.getXPrecision(),
                                                      motionEvent.getYPrecision(),
                                                      motionEvent.getRawXCursorPosition(),
                                                      motionEvent.getRawYCursorPosition(),
                                                      motionEvent.getDownTime(),
                                                      uint32_t(pointerCount), pointerProperties,
                                                      samplePointerCoords);
                transformMotionEntryForInjectionLocked(*nextInjectedEntry,
                                                       motionEvent.getTransform());
                injectedEntries.push(std::move(nextInjectedEntry));
            }
            break;
        }

        default:
            ALOGW("Cannot inject %s events", inputEventTypeToString(event->getType()));
            return InputEventInjectionResult::FAILED;
    }

    InjectionState* injectionState = new InjectionState(targetUid);
    if (syncMode == InputEventInjectionSync::NONE) {
        injectionState->injectionIsAsync = true;
    }

    injectionState->refCount += 1;
    injectedEntries.back()->injectionState = injectionState;

    bool needWake = false;
    while (!injectedEntries.empty()) {
        needWake |= enqueueInboundEventLocked(std::move(injectedEntries.front()));
        injectedEntries.pop();
    }

    mLock.unlock();

    if (needWake) {
        mLooper->wake();
    }

    InputEventInjectionResult injectionResult;
    { // acquire lock
        std::unique_lock _l(mLock);

        if (syncMode == InputEventInjectionSync::NONE) {
            injectionResult = InputEventInjectionResult::SUCCEEDED;
        } else {
            for (;;) {
                injectionResult = injectionState->injectionResult;
                if (injectionResult != InputEventInjectionResult::PENDING) {
                    break;
                }

                nsecs_t remainingTimeout = endTime - now();
                if (remainingTimeout <= 0) {
                    if (DEBUG_INJECTION) {
                        ALOGD("injectInputEvent - Timed out waiting for injection result "
                              "to become available.");
                    }
                    injectionResult = InputEventInjectionResult::TIMED_OUT;
                    break;
                }

                mInjectionResultAvailable.wait_for(_l, std::chrono::nanoseconds(remainingTimeout));
            }

            if (injectionResult == InputEventInjectionResult::SUCCEEDED &&
                syncMode == InputEventInjectionSync::WAIT_FOR_FINISHED) {
                while (injectionState->pendingForegroundDispatches != 0) {
                    if (DEBUG_INJECTION) {
                        ALOGD("injectInputEvent - Waiting for %d pending foreground dispatches.",
                              injectionState->pendingForegroundDispatches);
                    }
                    nsecs_t remainingTimeout = endTime - now();
                    if (remainingTimeout <= 0) {
                        if (DEBUG_INJECTION) {
                            ALOGD("injectInputEvent - Timed out waiting for pending foreground "
                                  "dispatches to finish.");
                        }
                        injectionResult = InputEventInjectionResult::TIMED_OUT;
                        break;
                    }

                    mInjectionSyncFinished.wait_for(_l, std::chrono::nanoseconds(remainingTimeout));
                }
            }
        }

        injectionState->release();
    } // release lock

    if (DEBUG_INJECTION) {
        ALOGD("injectInputEvent - Finished with result %d.", injectionResult);
    }

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
            calculatedHmac = sign(verifiedKeyEvent);
            break;
        }
        case AINPUT_EVENT_TYPE_MOTION: {
            const MotionEvent& motionEvent = static_cast<const MotionEvent&>(event);
            VerifiedMotionEvent verifiedMotionEvent =
                    verifiedMotionEventFromMotionEvent(motionEvent);
            result = std::make_unique<VerifiedMotionEvent>(verifiedMotionEvent);
            calculatedHmac = sign(verifiedMotionEvent);
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
    if (0 != CRYPTO_memcmp(calculatedHmac.data(), event.getHmac().data(), calculatedHmac.size())) {
        return nullptr;
    }
    return result;
}

void InputDispatcher::setInjectionResult(EventEntry& entry,
                                         InputEventInjectionResult injectionResult) {
    InjectionState* injectionState = entry.injectionState;
    if (injectionState) {
        if (DEBUG_INJECTION) {
            ALOGD("Setting input event injection result to %d.", injectionResult);
        }

        if (injectionState->injectionIsAsync && !(entry.policyFlags & POLICY_FLAG_FILTERED)) {
            // Log the outcome since the injector did not wait for the injection result.
            switch (injectionResult) {
                case InputEventInjectionResult::SUCCEEDED:
                    ALOGV("Asynchronous input event injection succeeded.");
                    break;
                case InputEventInjectionResult::TARGET_MISMATCH:
                    ALOGV("Asynchronous input event injection target mismatch.");
                    break;
                case InputEventInjectionResult::FAILED:
                    ALOGW("Asynchronous input event injection failed.");
                    break;
                case InputEventInjectionResult::TIMED_OUT:
                    ALOGW("Asynchronous input event injection timed out.");
                    break;
                case InputEventInjectionResult::PENDING:
                    ALOGE("Setting result to 'PENDING' for asynchronous injection");
                    break;
            }
        }

        injectionState->injectionResult = injectionResult;
        mInjectionResultAvailable.notify_all();
    }
}

void InputDispatcher::transformMotionEntryForInjectionLocked(
        MotionEntry& entry, const ui::Transform& injectedTransform) const {
    // Input injection works in the logical display coordinate space, but the input pipeline works
    // display space, so we need to transform the injected events accordingly.
    const auto it = mDisplayInfos.find(entry.displayId);
    if (it == mDisplayInfos.end()) return;
    const auto& transformToDisplay = it->second.transform.inverse() * injectedTransform;

    if (entry.xCursorPosition != AMOTION_EVENT_INVALID_CURSOR_POSITION &&
        entry.yCursorPosition != AMOTION_EVENT_INVALID_CURSOR_POSITION) {
        const vec2 cursor =
                MotionEvent::calculateTransformedXY(entry.source, transformToDisplay,
                                                    {entry.xCursorPosition, entry.yCursorPosition});
        entry.xCursorPosition = cursor.x;
        entry.yCursorPosition = cursor.y;
    }
    for (uint32_t i = 0; i < entry.pointerCount; i++) {
        entry.pointerCoords[i] =
                MotionEvent::calculateTransformedCoords(entry.source, transformToDisplay,
                                                        entry.pointerCoords[i]);
    }
}

void InputDispatcher::incrementPendingForegroundDispatches(EventEntry& entry) {
    InjectionState* injectionState = entry.injectionState;
    if (injectionState) {
        injectionState->pendingForegroundDispatches += 1;
    }
}

void InputDispatcher::decrementPendingForegroundDispatches(EventEntry& entry) {
    InjectionState* injectionState = entry.injectionState;
    if (injectionState) {
        injectionState->pendingForegroundDispatches -= 1;

        if (injectionState->pendingForegroundDispatches == 0) {
            mInjectionSyncFinished.notify_all();
        }
    }
}

const std::vector<sp<WindowInfoHandle>>& InputDispatcher::getWindowHandlesLocked(
        int32_t displayId) const {
    static const std::vector<sp<WindowInfoHandle>> EMPTY_WINDOW_HANDLES;
    auto it = mWindowHandlesByDisplay.find(displayId);
    return it != mWindowHandlesByDisplay.end() ? it->second : EMPTY_WINDOW_HANDLES;
}

sp<WindowInfoHandle> InputDispatcher::getWindowHandleLocked(
        const sp<IBinder>& windowHandleToken) const {
    if (windowHandleToken == nullptr) {
        return nullptr;
    }

    for (auto& it : mWindowHandlesByDisplay) {
        const std::vector<sp<WindowInfoHandle>>& windowHandles = it.second;
        for (const sp<WindowInfoHandle>& windowHandle : windowHandles) {
            if (windowHandle->getToken() == windowHandleToken) {
                return windowHandle;
            }
        }
    }
    return nullptr;
}

sp<WindowInfoHandle> InputDispatcher::getWindowHandleLocked(const sp<IBinder>& windowHandleToken,
                                                            int displayId) const {
    if (windowHandleToken == nullptr) {
        return nullptr;
    }

    for (const sp<WindowInfoHandle>& windowHandle : getWindowHandlesLocked(displayId)) {
        if (windowHandle->getToken() == windowHandleToken) {
            return windowHandle;
        }
    }
    return nullptr;
}

sp<WindowInfoHandle> InputDispatcher::getWindowHandleLocked(
        const sp<WindowInfoHandle>& windowHandle) const {
    for (auto& it : mWindowHandlesByDisplay) {
        const std::vector<sp<WindowInfoHandle>>& windowHandles = it.second;
        for (const sp<WindowInfoHandle>& handle : windowHandles) {
            if (handle->getId() == windowHandle->getId() &&
                handle->getToken() == windowHandle->getToken()) {
                if (windowHandle->getInfo()->displayId != it.first) {
                    ALOGE("Found window %s in display %" PRId32
                          ", but it should belong to display %" PRId32,
                          windowHandle->getName().c_str(), it.first,
                          windowHandle->getInfo()->displayId);
                }
                return handle;
            }
        }
    }
    return nullptr;
}

sp<WindowInfoHandle> InputDispatcher::getFocusedWindowHandleLocked(int displayId) const {
    sp<IBinder> focusedToken = mFocusResolver.getFocusedWindowToken(displayId);
    return getWindowHandleLocked(focusedToken, displayId);
}

ui::Transform InputDispatcher::getTransformLocked(int32_t displayId) const {
    auto displayInfoIt = mDisplayInfos.find(displayId);
    return displayInfoIt != mDisplayInfos.end() ? displayInfoIt->second.transform
                                                : kIdentityTransform;
}

bool InputDispatcher::hasResponsiveConnectionLocked(WindowInfoHandle& windowHandle) const {
    sp<Connection> connection = getConnectionLocked(windowHandle.getToken());
    const bool noInputChannel =
            windowHandle.getInfo()->inputConfig.test(WindowInfo::InputConfig::NO_INPUT_CHANNEL);
    if (connection != nullptr && noInputChannel) {
        ALOGW("%s has feature NO_INPUT_CHANNEL, but it matched to connection %s",
              windowHandle.getName().c_str(), connection->inputChannel->getName().c_str());
        return false;
    }

    if (connection == nullptr) {
        if (!noInputChannel) {
            ALOGI("Could not find connection for %s", windowHandle.getName().c_str());
        }
        return false;
    }
    if (!connection->responsive) {
        ALOGW("Window %s is not responsive", windowHandle.getName().c_str());
        return false;
    }
    return true;
}

std::shared_ptr<InputChannel> InputDispatcher::getInputChannelLocked(
        const sp<IBinder>& token) const {
    auto connectionIt = mConnectionsByToken.find(token);
    if (connectionIt == mConnectionsByToken.end()) {
        return nullptr;
    }
    return connectionIt->second->inputChannel;
}

void InputDispatcher::updateWindowHandlesForDisplayLocked(
        const std::vector<sp<WindowInfoHandle>>& windowInfoHandles, int32_t displayId) {
    if (windowInfoHandles.empty()) {
        // Remove all handles on a display if there are no windows left.
        mWindowHandlesByDisplay.erase(displayId);
        return;
    }

    // Since we compare the pointer of input window handles across window updates, we need
    // to make sure the handle object for the same window stays unchanged across updates.
    const std::vector<sp<WindowInfoHandle>>& oldHandles = getWindowHandlesLocked(displayId);
    std::unordered_map<int32_t /*id*/, sp<WindowInfoHandle>> oldHandlesById;
    for (const sp<WindowInfoHandle>& handle : oldHandles) {
        oldHandlesById[handle->getId()] = handle;
    }

    std::vector<sp<WindowInfoHandle>> newHandles;
    for (const sp<WindowInfoHandle>& handle : windowInfoHandles) {
        const WindowInfo* info = handle->getInfo();
        if (getInputChannelLocked(handle->getToken()) == nullptr) {
            const bool noInputChannel =
                    info->inputConfig.test(WindowInfo::InputConfig::NO_INPUT_CHANNEL);
            const bool canReceiveInput =
                    !info->inputConfig.test(WindowInfo::InputConfig::NOT_TOUCHABLE) ||
                    !info->inputConfig.test(WindowInfo::InputConfig::NOT_FOCUSABLE);
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
            const sp<WindowInfoHandle>& oldHandle = oldHandlesById.at(handle->getId());
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
        const std::unordered_map<int32_t, std::vector<sp<WindowInfoHandle>>>& handlesPerDisplay) {
    // TODO(b/198444055): Remove setInputWindows from InputDispatcher.
    { // acquire lock
        std::scoped_lock _l(mLock);
        for (const auto& [displayId, handles] : handlesPerDisplay) {
            setInputWindowsLocked(handles, displayId);
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
        const std::vector<sp<WindowInfoHandle>>& windowInfoHandles, int32_t displayId) {
    if (DEBUG_FOCUS) {
        std::string windowList;
        for (const sp<WindowInfoHandle>& iwh : windowInfoHandles) {
            windowList += iwh->getName() + " ";
        }
        ALOGD("setInputWindows displayId=%" PRId32 " %s", displayId, windowList.c_str());
    }

    // Check preconditions for new input windows
    for (const sp<WindowInfoHandle>& window : windowInfoHandles) {
        const WindowInfo& info = *window->getInfo();

        // Ensure all tokens are null if the window has feature NO_INPUT_CHANNEL
        const bool noInputWindow = info.inputConfig.test(WindowInfo::InputConfig::NO_INPUT_CHANNEL);
        if (noInputWindow && window->getToken() != nullptr) {
            ALOGE("%s has feature NO_INPUT_WINDOW, but a non-null token. Clearing",
                  window->getName().c_str());
            window->releaseChannel();
        }

        // Ensure all spy windows are trusted overlays
        LOG_ALWAYS_FATAL_IF(info.isSpy() &&
                                    !info.inputConfig.test(
                                            WindowInfo::InputConfig::TRUSTED_OVERLAY),
                            "%s has feature SPY, but is not a trusted overlay.",
                            window->getName().c_str());

        // Ensure all stylus interceptors are trusted overlays
        LOG_ALWAYS_FATAL_IF(info.interceptsStylus() &&
                                    !info.inputConfig.test(
                                            WindowInfo::InputConfig::TRUSTED_OVERLAY),
                            "%s has feature INTERCEPTS_STYLUS, but is not a trusted overlay.",
                            window->getName().c_str());
    }

    // Copy old handles for release if they are no longer present.
    const std::vector<sp<WindowInfoHandle>> oldWindowHandles = getWindowHandlesLocked(displayId);

    // Save the old windows' orientation by ID before it gets updated.
    std::unordered_map<int32_t, uint32_t> oldWindowOrientations;
    for (const sp<WindowInfoHandle>& handle : oldWindowHandles) {
        oldWindowOrientations.emplace(handle->getId(),
                                      handle->getInfo()->transform.getOrientation());
    }

    updateWindowHandlesForDisplayLocked(windowInfoHandles, displayId);

    const std::vector<sp<WindowInfoHandle>>& windowHandles = getWindowHandlesLocked(displayId);
    if (mLastHoverWindowHandle) {
        const WindowInfo* lastHoverWindowInfo = mLastHoverWindowHandle->getInfo();
        if (lastHoverWindowInfo->displayId == displayId &&
            std::find(windowHandles.begin(), windowHandles.end(), mLastHoverWindowHandle) ==
                    windowHandles.end()) {
            mLastHoverWindowHandle = nullptr;
        }
    }

    std::optional<FocusResolver::FocusChanges> changes =
            mFocusResolver.setInputWindows(displayId, windowHandles);
    if (changes) {
        onFocusChangedLocked(*changes);
    }

    std::unordered_map<int32_t, TouchState>::iterator stateIt =
            mTouchStatesByDisplay.find(displayId);
    if (stateIt != mTouchStatesByDisplay.end()) {
        TouchState& state = stateIt->second;
        for (size_t i = 0; i < state.windows.size();) {
            TouchedWindow& touchedWindow = state.windows[i];
            if (getWindowHandleLocked(touchedWindow.windowHandle) == nullptr) {
                if (DEBUG_FOCUS) {
                    ALOGD("Touched window was removed: %s in display %" PRId32,
                          touchedWindow.windowHandle->getName().c_str(), displayId);
                }
                std::shared_ptr<InputChannel> touchedInputChannel =
                        getInputChannelLocked(touchedWindow.windowHandle->getToken());
                if (touchedInputChannel != nullptr) {
                    CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS,
                                               "touched window was removed");
                    synthesizeCancelationEventsForInputChannelLocked(touchedInputChannel, options);
                    // Since we are about to drop the touch, cancel the events for the wallpaper as
                    // well.
                    if (touchedWindow.targetFlags & InputTarget::FLAG_FOREGROUND &&
                        touchedWindow.windowHandle->getInfo()->inputConfig.test(
                                gui::WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER)) {
                        sp<WindowInfoHandle> wallpaper = state.getWallpaperWindow();
                        synthesizeCancelationEventsForWindowLocked(wallpaper, options);
                    }
                }
                state.windows.erase(state.windows.begin() + i);
            } else {
                ++i;
            }
        }

        // If drag window is gone, it would receive a cancel event and broadcast the DRAG_END. We
        // could just clear the state here.
        if (mDragState && mDragState->dragWindow->getInfo()->displayId == displayId &&
            std::find(windowHandles.begin(), windowHandles.end(), mDragState->dragWindow) ==
                    windowHandles.end()) {
            ALOGI("Drag window went away: %s", mDragState->dragWindow->getName().c_str());
            sendDropWindowCommandLocked(nullptr, 0, 0);
            mDragState.reset();
        }
    }

    // Determine if the orientation of any of the input windows have changed, and cancel all
    // pointer events if necessary.
    for (const sp<WindowInfoHandle>& oldWindowHandle : oldWindowHandles) {
        const sp<WindowInfoHandle> newWindowHandle = getWindowHandleLocked(oldWindowHandle);
        if (newWindowHandle != nullptr &&
            newWindowHandle->getInfo()->transform.getOrientation() !=
                    oldWindowOrientations[oldWindowHandle->getId()]) {
            std::shared_ptr<InputChannel> inputChannel =
                    getInputChannelLocked(newWindowHandle->getToken());
            if (inputChannel != nullptr) {
                CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS,
                                           "touched window's orientation changed");
                synthesizeCancelationEventsForInputChannelLocked(inputChannel, options);
            }
        }
    }

    // Release information for windows that are no longer present.
    // This ensures that unused input channels are released promptly.
    // Otherwise, they might stick around until the window handle is destroyed
    // which might not happen until the next GC.
    for (const sp<WindowInfoHandle>& oldWindowHandle : oldWindowHandles) {
        if (getWindowHandleLocked(oldWindowHandle) == nullptr) {
            if (DEBUG_FOCUS) {
                ALOGD("Window went away: %s", oldWindowHandle->getName().c_str());
            }
            oldWindowHandle->releaseChannel();
        }
    }
}

void InputDispatcher::setFocusedApplication(
        int32_t displayId, const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle) {
    if (DEBUG_FOCUS) {
        ALOGD("setFocusedApplication displayId=%" PRId32 " %s", displayId,
              inputApplicationHandle ? inputApplicationHandle->getName().c_str() : "<nullptr>");
    }
    { // acquire lock
        std::scoped_lock _l(mLock);
        setFocusedApplicationLocked(displayId, inputApplicationHandle);
    } // release lock

    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
}

void InputDispatcher::setFocusedApplicationLocked(
        int32_t displayId, const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle) {
    std::shared_ptr<InputApplicationHandle> oldFocusedApplicationHandle =
            getValueByKey(mFocusedApplicationHandlesByDisplay, displayId);

    if (sharedPointersEqual(oldFocusedApplicationHandle, inputApplicationHandle)) {
        return; // This application is already focused. No need to wake up or change anything.
    }

    // Set the new application handle.
    if (inputApplicationHandle != nullptr) {
        mFocusedApplicationHandlesByDisplay[displayId] = inputApplicationHandle;
    } else {
        mFocusedApplicationHandlesByDisplay.erase(displayId);
    }

    // No matter what the old focused application was, stop waiting on it because it is
    // no longer focused.
    resetNoFocusedWindowTimeoutLocked();
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
            sp<IBinder> oldFocusedWindowToken =
                    mFocusResolver.getFocusedWindowToken(mFocusedDisplayId);
            if (oldFocusedWindowToken != nullptr) {
                std::shared_ptr<InputChannel> inputChannel =
                        getInputChannelLocked(oldFocusedWindowToken);
                if (inputChannel != nullptr) {
                    CancelationOptions
                            options(CancelationOptions::CANCEL_NON_POINTER_EVENTS,
                                    "The display which contains this window no longer has focus.");
                    options.displayId = ADISPLAY_ID_NONE;
                    synthesizeCancelationEventsForInputChannelLocked(inputChannel, options);
                }
            }
            mFocusedDisplayId = displayId;

            // Find new focused window and validate
            sp<IBinder> newFocusedWindowToken = mFocusResolver.getFocusedWindowToken(displayId);
            sendFocusChangedCommandLocked(oldFocusedWindowToken, newFocusedWindowToken);

            if (newFocusedWindowToken == nullptr) {
                ALOGW("Focused display #%" PRId32 " does not have a focused window.", displayId);
                if (mFocusResolver.hasFocusedWindowTokens()) {
                    ALOGE("But another display has a focused window\n%s",
                          mFocusResolver.dumpFocusedWindows().c_str());
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

bool InputDispatcher::setInTouchMode(bool inTouchMode, int32_t pid, int32_t uid,
                                     bool hasPermission) {
    bool needWake = false;
    {
        std::scoped_lock lock(mLock);
        if (mInTouchMode == inTouchMode) {
            return false;
        }
        if (DEBUG_TOUCH_MODE) {
            ALOGD("Request to change touch mode from %s to %s (calling pid=%d, uid=%d, "
                  "hasPermission=%s)",
                  toString(mInTouchMode), toString(inTouchMode), pid, uid, toString(hasPermission));
        }
        if (!hasPermission) {
            if (!focusedWindowIsOwnedByLocked(pid, uid) &&
                !recentWindowsAreOwnedByLocked(pid, uid)) {
                ALOGD("Touch mode switch rejected, caller (pid=%d, uid=%d) doesn't own the focused "
                      "window nor none of the previously interacted window",
                      pid, uid);
                return false;
            }
        }

        // TODO(b/198499018): Store touch mode per display.
        mInTouchMode = inTouchMode;

        auto entry = std::make_unique<TouchModeEntry>(mIdGenerator.nextId(), now(), inTouchMode);
        needWake = enqueueInboundEventLocked(std::move(entry));
    } // release lock

    if (needWake) {
        mLooper->wake();
    }
    return true;
}

bool InputDispatcher::focusedWindowIsOwnedByLocked(int32_t pid, int32_t uid) {
    const sp<IBinder> focusedToken = mFocusResolver.getFocusedWindowToken(mFocusedDisplayId);
    if (focusedToken == nullptr) {
        return false;
    }
    sp<WindowInfoHandle> windowHandle = getWindowHandleLocked(focusedToken);
    return isWindowOwnedBy(windowHandle, pid, uid);
}

bool InputDispatcher::recentWindowsAreOwnedByLocked(int32_t pid, int32_t uid) {
    return std::find_if(mInteractionConnectionTokens.begin(), mInteractionConnectionTokens.end(),
                        [&](const sp<IBinder>& connectionToken) REQUIRES(mLock) {
                            const sp<WindowInfoHandle> windowHandle =
                                    getWindowHandleLocked(connectionToken);
                            return isWindowOwnedBy(windowHandle, pid, uid);
                        }) != mInteractionConnectionTokens.end();
}

void InputDispatcher::setMaximumObscuringOpacityForTouch(float opacity) {
    if (opacity < 0 || opacity > 1) {
        LOG_ALWAYS_FATAL("Maximum obscuring opacity for touch should be >= 0 and <= 1");
        return;
    }

    std::scoped_lock lock(mLock);
    mMaximumObscuringOpacityForTouch = opacity;
}

void InputDispatcher::setBlockUntrustedTouchesMode(BlockUntrustedTouchesMode mode) {
    std::scoped_lock lock(mLock);
    mBlockUntrustedTouchesMode = mode;
}

std::pair<TouchState*, TouchedWindow*> InputDispatcher::findTouchStateAndWindowLocked(
        const sp<IBinder>& token) {
    for (auto& [displayId, state] : mTouchStatesByDisplay) {
        for (TouchedWindow& w : state.windows) {
            if (w.windowHandle->getToken() == token) {
                return std::make_pair(&state, &w);
            }
        }
    }
    return std::make_pair(nullptr, nullptr);
}

bool InputDispatcher::transferTouchFocus(const sp<IBinder>& fromToken, const sp<IBinder>& toToken,
                                         bool isDragDrop) {
    if (fromToken == toToken) {
        if (DEBUG_FOCUS) {
            ALOGD("Trivial transfer to same window.");
        }
        return true;
    }

    { // acquire lock
        std::scoped_lock _l(mLock);

        // Find the target touch state and touched window by fromToken.
        auto [state, touchedWindow] = findTouchStateAndWindowLocked(fromToken);
        if (state == nullptr || touchedWindow == nullptr) {
            ALOGD("Focus transfer failed because from window is not being touched.");
            return false;
        }

        const int32_t displayId = state->displayId;
        sp<WindowInfoHandle> toWindowHandle = getWindowHandleLocked(toToken, displayId);
        if (toWindowHandle == nullptr) {
            ALOGW("Cannot transfer focus because to window not found.");
            return false;
        }

        if (DEBUG_FOCUS) {
            ALOGD("transferTouchFocus: fromWindowHandle=%s, toWindowHandle=%s",
                  touchedWindow->windowHandle->getName().c_str(),
                  toWindowHandle->getName().c_str());
        }

        // Erase old window.
        int32_t oldTargetFlags = touchedWindow->targetFlags;
        BitSet32 pointerIds = touchedWindow->pointerIds;
        sp<WindowInfoHandle> fromWindowHandle = touchedWindow->windowHandle;
        state->removeWindowByToken(fromToken);

        // Add new window.
        int32_t newTargetFlags =
                oldTargetFlags & (InputTarget::FLAG_SPLIT | InputTarget::FLAG_DISPATCH_AS_IS);
        if (canReceiveForegroundTouches(*toWindowHandle->getInfo())) {
            newTargetFlags |= InputTarget::FLAG_FOREGROUND;
        }
        state->addOrUpdateWindow(toWindowHandle, newTargetFlags, pointerIds);

        // Store the dragging window.
        if (isDragDrop) {
            if (pointerIds.count() != 1) {
                ALOGW("The drag and drop cannot be started when there is no pointer or more than 1"
                      " pointer on the window.");
                return false;
            }
            // Track the pointer id for drag window and generate the drag state.
            const int32_t id = pointerIds.firstMarkedBit();
            mDragState = std::make_unique<DragState>(toWindowHandle, id);
        }

        // Synthesize cancel for old window and down for new window.
        sp<Connection> fromConnection = getConnectionLocked(fromToken);
        sp<Connection> toConnection = getConnectionLocked(toToken);
        if (fromConnection != nullptr && toConnection != nullptr) {
            fromConnection->inputState.mergePointerStateTo(toConnection->inputState);
            CancelationOptions
                    options(CancelationOptions::CANCEL_POINTER_EVENTS,
                            "transferring touch focus from this window to another window");
            synthesizeCancelationEventsForConnectionLocked(fromConnection, options);
            synthesizePointerDownEventsForConnectionLocked(toConnection, newTargetFlags);
            // Check if the wallpaper window should deliver the corresponding event.
            transferWallpaperTouch(oldTargetFlags, newTargetFlags, fromWindowHandle, toWindowHandle,
                                   *state, pointerIds);
        }

        if (DEBUG_FOCUS) {
            logDispatchStateLocked();
        }
    } // release lock

    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
    return true;
}

/**
 * Get the touched foreground window on the given display.
 * Return null if there are no windows touched on that display, or if more than one foreground
 * window is being touched.
 */
sp<WindowInfoHandle> InputDispatcher::findTouchedForegroundWindowLocked(int32_t displayId) const {
    auto stateIt = mTouchStatesByDisplay.find(displayId);
    if (stateIt == mTouchStatesByDisplay.end()) {
        ALOGI("No touch state on display %" PRId32, displayId);
        return nullptr;
    }

    const TouchState& state = stateIt->second;
    sp<WindowInfoHandle> touchedForegroundWindow;
    // If multiple foreground windows are touched, return nullptr
    for (const TouchedWindow& window : state.windows) {
        if (window.targetFlags & InputTarget::FLAG_FOREGROUND) {
            if (touchedForegroundWindow != nullptr) {
                ALOGI("Two or more foreground windows: %s and %s",
                      touchedForegroundWindow->getName().c_str(),
                      window.windowHandle->getName().c_str());
                return nullptr;
            }
            touchedForegroundWindow = window.windowHandle;
        }
    }
    return touchedForegroundWindow;
}

// Binder call
bool InputDispatcher::transferTouch(const sp<IBinder>& destChannelToken, int32_t displayId) {
    sp<IBinder> fromToken;
    { // acquire lock
        std::scoped_lock _l(mLock);
        sp<WindowInfoHandle> toWindowHandle = getWindowHandleLocked(destChannelToken, displayId);
        if (toWindowHandle == nullptr) {
            ALOGW("Could not find window associated with token=%p on display %" PRId32,
                  destChannelToken.get(), displayId);
            return false;
        }

        sp<WindowInfoHandle> from = findTouchedForegroundWindowLocked(displayId);
        if (from == nullptr) {
            ALOGE("Could not find a source window in %s for %p", __func__, destChannelToken.get());
            return false;
        }

        fromToken = from->getToken();
    } // release lock

    return transferTouchFocus(fromToken, destChannelToken);
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

std::string InputDispatcher::dumpPointerCaptureStateLocked() {
    std::string dump;

    dump += StringPrintf(INDENT "Pointer Capture Requested: %s\n",
                         toString(mCurrentPointerCaptureRequest.enable));

    std::string windowName = "None";
    if (mWindowTokenWithPointerCapture) {
        const sp<WindowInfoHandle> captureWindowHandle =
                getWindowHandleLocked(mWindowTokenWithPointerCapture);
        windowName = captureWindowHandle ? captureWindowHandle->getName().c_str()
                                         : "token has capture without window";
    }
    dump += StringPrintf(INDENT "Current Window with Pointer Capture: %s\n", windowName.c_str());

    return dump;
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
            const std::shared_ptr<InputApplicationHandle>& applicationHandle = it.second;
            const std::chrono::duration timeout =
                    applicationHandle->getDispatchingTimeout(DEFAULT_INPUT_DISPATCHING_TIMEOUT);
            dump += StringPrintf(INDENT2 "displayId=%" PRId32
                                         ", name='%s', dispatchingTimeout=%" PRId64 "ms\n",
                                 displayId, applicationHandle->getName().c_str(), millis(timeout));
        }
    } else {
        dump += StringPrintf(INDENT "FocusedApplications: <none>\n");
    }

    dump += mFocusResolver.dump();
    dump += dumpPointerCaptureStateLocked();

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
        }
    } else {
        dump += INDENT "TouchStates: <no displays touched>\n";
    }

    if (mDragState) {
        dump += StringPrintf(INDENT "DragState:\n");
        mDragState->dump(dump, INDENT2);
    }

    if (!mWindowHandlesByDisplay.empty()) {
        for (const auto& [displayId, windowHandles] : mWindowHandlesByDisplay) {
            dump += StringPrintf(INDENT "Display: %" PRId32 "\n", displayId);
            if (const auto& it = mDisplayInfos.find(displayId); it != mDisplayInfos.end()) {
                const auto& displayInfo = it->second;
                dump += StringPrintf(INDENT2 "logicalSize=%dx%d\n", displayInfo.logicalWidth,
                                     displayInfo.logicalHeight);
                displayInfo.transform.dump(dump, "transform", INDENT4);
            } else {
                dump += INDENT2 "No DisplayInfo found!\n";
            }

            if (!windowHandles.empty()) {
                dump += INDENT2 "Windows:\n";
                for (size_t i = 0; i < windowHandles.size(); i++) {
                    const sp<WindowInfoHandle>& windowHandle = windowHandles[i];
                    const WindowInfo* windowInfo = windowHandle->getInfo();

                    dump += StringPrintf(INDENT3 "%zu: name='%s', id=%" PRId32 ", displayId=%d, "
                                                 "inputConfig=%s, alpha=%.2f, "
                                                 "frame=[%d,%d][%d,%d], globalScale=%f, "
                                                 "applicationInfo.name=%s, "
                                                 "applicationInfo.token=%s, "
                                                 "touchableRegion=",
                                         i, windowInfo->name.c_str(), windowInfo->id,
                                         windowInfo->displayId,
                                         windowInfo->inputConfig.string().c_str(),
                                         windowInfo->alpha, windowInfo->frameLeft,
                                         windowInfo->frameTop, windowInfo->frameRight,
                                         windowInfo->frameBottom, windowInfo->globalScaleFactor,
                                         windowInfo->applicationInfo.name.c_str(),
                                         toString(windowInfo->applicationInfo.token).c_str());
                    dump += dumpRegion(windowInfo->touchableRegion);
                    dump += StringPrintf(", ownerPid=%d, ownerUid=%d, dispatchingTimeout=%" PRId64
                                         "ms, hasToken=%s, "
                                         "touchOcclusionMode=%s\n",
                                         windowInfo->ownerPid, windowInfo->ownerUid,
                                         millis(windowInfo->dispatchingTimeout),
                                         toString(windowInfo->token != nullptr),
                                         toString(windowInfo->touchOcclusionMode).c_str());
                    windowInfo->transform.dump(dump, "transform", INDENT4);
                }
            } else {
                dump += INDENT2 "Windows: <none>\n";
            }
        }
    } else {
        dump += INDENT "Displays: <none>\n";
    }

    if (!mGlobalMonitorsByDisplay.empty()) {
        for (const auto& [displayId, monitors] : mGlobalMonitorsByDisplay) {
            dump += StringPrintf(INDENT "Global monitors on display %d:\n", displayId);
            dumpMonitors(dump, monitors);
        }
    } else {
        dump += INDENT "Global Monitors: <none>\n";
    }

    const nsecs_t currentTime = now();

    // Dump recently dispatched or dropped events from oldest to newest.
    if (!mRecentQueue.empty()) {
        dump += StringPrintf(INDENT "RecentQueue: length=%zu\n", mRecentQueue.size());
        for (std::shared_ptr<EventEntry>& entry : mRecentQueue) {
            dump += INDENT2;
            dump += entry->getDescription();
            dump += StringPrintf(", age=%" PRId64 "ms\n", ns2ms(currentTime - entry->eventTime));
        }
    } else {
        dump += INDENT "RecentQueue: <empty>\n";
    }

    // Dump event currently being dispatched.
    if (mPendingEvent) {
        dump += INDENT "PendingEvent:\n";
        dump += INDENT2;
        dump += mPendingEvent->getDescription();
        dump += StringPrintf(", age=%" PRId64 "ms\n",
                             ns2ms(currentTime - mPendingEvent->eventTime));
    } else {
        dump += INDENT "PendingEvent: <none>\n";
    }

    // Dump inbound events from oldest to newest.
    if (!mInboundQueue.empty()) {
        dump += StringPrintf(INDENT "InboundQueue: length=%zu\n", mInboundQueue.size());
        for (std::shared_ptr<EventEntry>& entry : mInboundQueue) {
            dump += INDENT2;
            dump += entry->getDescription();
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

    if (!mCommandQueue.empty()) {
        dump += StringPrintf(INDENT "CommandQueue: size=%zu\n", mCommandQueue.size());
    } else {
        dump += INDENT "CommandQueue: <empty>\n";
    }

    if (!mConnectionsByToken.empty()) {
        dump += INDENT "Connections:\n";
        for (const auto& [token, connection] : mConnectionsByToken) {
            dump += StringPrintf(INDENT2 "%i: channelName='%s', windowName='%s', "
                                         "status=%s, monitor=%s, responsive=%s\n",
                                 connection->inputChannel->getFd().get(),
                                 connection->getInputChannelName().c_str(),
                                 connection->getWindowName().c_str(),
                                 ftl::enum_string(connection->status).c_str(),
                                 toString(connection->monitor), toString(connection->responsive));

            if (!connection->outboundQueue.empty()) {
                dump += StringPrintf(INDENT3 "OutboundQueue: length=%zu\n",
                                     connection->outboundQueue.size());
                dump += dumpQueue(connection->outboundQueue, currentTime);

            } else {
                dump += INDENT3 "OutboundQueue: <empty>\n";
            }

            if (!connection->waitQueue.empty()) {
                dump += StringPrintf(INDENT3 "WaitQueue: length=%zu\n",
                                     connection->waitQueue.size());
                dump += dumpQueue(connection->waitQueue, currentTime);
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
    dump += mLatencyTracker.dump(INDENT2);
    dump += mLatencyAggregator.dump(INDENT2);
}

void InputDispatcher::dumpMonitors(std::string& dump, const std::vector<Monitor>& monitors) {
    const size_t numMonitors = monitors.size();
    for (size_t i = 0; i < numMonitors; i++) {
        const Monitor& monitor = monitors[i];
        const std::shared_ptr<InputChannel>& channel = monitor.inputChannel;
        dump += StringPrintf(INDENT2 "%zu: '%s', ", i, channel->getName().c_str());
        dump += "\n";
    }
}

class LooperEventCallback : public LooperCallback {
public:
    LooperEventCallback(std::function<int(int events)> callback) : mCallback(callback) {}
    int handleEvent(int /*fd*/, int events, void* /*data*/) override { return mCallback(events); }

private:
    std::function<int(int events)> mCallback;
};

Result<std::unique_ptr<InputChannel>> InputDispatcher::createInputChannel(const std::string& name) {
    if (DEBUG_CHANNEL_CREATION) {
        ALOGD("channel '%s' ~ createInputChannel", name.c_str());
    }

    std::unique_ptr<InputChannel> serverChannel;
    std::unique_ptr<InputChannel> clientChannel;
    status_t result = InputChannel::openInputChannelPair(name, serverChannel, clientChannel);

    if (result) {
        return base::Error(result) << "Failed to open input channel pair with name " << name;
    }

    { // acquire lock
        std::scoped_lock _l(mLock);
        const sp<IBinder>& token = serverChannel->getConnectionToken();
        int fd = serverChannel->getFd();
        sp<Connection> connection =
                new Connection(std::move(serverChannel), false /*monitor*/, mIdGenerator);

        if (mConnectionsByToken.find(token) != mConnectionsByToken.end()) {
            ALOGE("Created a new connection, but the token %p is already known", token.get());
        }
        mConnectionsByToken.emplace(token, connection);

        std::function<int(int events)> callback = std::bind(&InputDispatcher::handleReceiveCallback,
                                                            this, std::placeholders::_1, token);

        mLooper->addFd(fd, 0, ALOOPER_EVENT_INPUT, new LooperEventCallback(callback), nullptr);
    } // release lock

    // Wake the looper because some connections have changed.
    mLooper->wake();
    return clientChannel;
}

Result<std::unique_ptr<InputChannel>> InputDispatcher::createInputMonitor(int32_t displayId,
                                                                          const std::string& name,
                                                                          int32_t pid) {
    std::shared_ptr<InputChannel> serverChannel;
    std::unique_ptr<InputChannel> clientChannel;
    status_t result = openInputChannelPair(name, serverChannel, clientChannel);
    if (result) {
        return base::Error(result) << "Failed to open input channel pair with name " << name;
    }

    { // acquire lock
        std::scoped_lock _l(mLock);

        if (displayId < 0) {
            return base::Error(BAD_VALUE) << "Attempted to create input monitor with name " << name
                                          << " without a specified display.";
        }

        sp<Connection> connection = new Connection(serverChannel, true /*monitor*/, mIdGenerator);
        const sp<IBinder>& token = serverChannel->getConnectionToken();
        const int fd = serverChannel->getFd();

        if (mConnectionsByToken.find(token) != mConnectionsByToken.end()) {
            ALOGE("Created a new connection, but the token %p is already known", token.get());
        }
        mConnectionsByToken.emplace(token, connection);
        std::function<int(int events)> callback = std::bind(&InputDispatcher::handleReceiveCallback,
                                                            this, std::placeholders::_1, token);

        mGlobalMonitorsByDisplay[displayId].emplace_back(serverChannel, pid);

        mLooper->addFd(fd, 0, ALOOPER_EVENT_INPUT, new LooperEventCallback(callback), nullptr);
    }

    // Wake the looper because some connections have changed.
    mLooper->wake();
    return clientChannel;
}

status_t InputDispatcher::removeInputChannel(const sp<IBinder>& connectionToken) {
    { // acquire lock
        std::scoped_lock _l(mLock);

        status_t status = removeInputChannelLocked(connectionToken, false /*notify*/);
        if (status) {
            return status;
        }
    } // release lock

    // Wake the poll loop because removing the connection may have changed the current
    // synchronization state.
    mLooper->wake();
    return OK;
}

status_t InputDispatcher::removeInputChannelLocked(const sp<IBinder>& connectionToken,
                                                   bool notify) {
    sp<Connection> connection = getConnectionLocked(connectionToken);
    if (connection == nullptr) {
        // Connection can be removed via socket hang up or an explicit call to 'removeInputChannel'
        return BAD_VALUE;
    }

    removeConnectionLocked(connection);

    if (connection->monitor) {
        removeMonitorChannelLocked(connectionToken);
    }

    mLooper->removeFd(connection->inputChannel->getFd());

    nsecs_t currentTime = now();
    abortBrokenDispatchCycleLocked(currentTime, connection, notify);

    connection->status = Connection::Status::ZOMBIE;
    return OK;
}

void InputDispatcher::removeMonitorChannelLocked(const sp<IBinder>& connectionToken) {
    for (auto it = mGlobalMonitorsByDisplay.begin(); it != mGlobalMonitorsByDisplay.end();) {
        auto& [displayId, monitors] = *it;
        std::erase_if(monitors, [connectionToken](const Monitor& monitor) {
            return monitor.inputChannel->getConnectionToken() == connectionToken;
        });

        if (monitors.empty()) {
            it = mGlobalMonitorsByDisplay.erase(it);
        } else {
            ++it;
        }
    }
}

status_t InputDispatcher::pilferPointers(const sp<IBinder>& token) {
    std::scoped_lock _l(mLock);

    const std::shared_ptr<InputChannel> requestingChannel = getInputChannelLocked(token);
    if (!requestingChannel) {
        ALOGW("Attempted to pilfer pointers from an un-registered channel or invalid token");
        return BAD_VALUE;
    }

    auto [statePtr, windowPtr] = findTouchStateAndWindowLocked(token);
    if (statePtr == nullptr || windowPtr == nullptr || !statePtr->down) {
        ALOGW("Attempted to pilfer points from a channel without any on-going pointer streams."
              " Ignoring.");
        return BAD_VALUE;
    }

    TouchState& state = *statePtr;

    // Send cancel events to all the input channels we're stealing from.
    CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS,
                               "input channel stole pointer stream");
    options.deviceId = state.deviceId;
    options.displayId = state.displayId;
    std::string canceledWindows;
    for (const TouchedWindow& window : state.windows) {
        const std::shared_ptr<InputChannel> channel =
                getInputChannelLocked(window.windowHandle->getToken());
        if (channel != nullptr && channel->getConnectionToken() != token) {
            synthesizeCancelationEventsForInputChannelLocked(channel, options);
            canceledWindows += canceledWindows.empty() ? "[" : ", ";
            canceledWindows += channel->getName();
        }
    }
    canceledWindows += canceledWindows.empty() ? "[]" : "]";
    ALOGI("Channel %s is stealing touch from %s", requestingChannel->getName().c_str(),
          canceledWindows.c_str());

    // Prevent the gesture from being sent to any other windows.
    state.filterWindowsExcept(token);
    state.preventNewTargets = true;
    return OK;
}

void InputDispatcher::requestPointerCapture(const sp<IBinder>& windowToken, bool enabled) {
    { // acquire lock
        std::scoped_lock _l(mLock);
        if (DEBUG_FOCUS) {
            const sp<WindowInfoHandle> windowHandle = getWindowHandleLocked(windowToken);
            ALOGI("Request to %s Pointer Capture from: %s.", enabled ? "enable" : "disable",
                  windowHandle != nullptr ? windowHandle->getName().c_str()
                                          : "token without window");
        }

        const sp<IBinder> focusedToken = mFocusResolver.getFocusedWindowToken(mFocusedDisplayId);
        if (focusedToken != windowToken) {
            ALOGW("Ignoring request to %s Pointer Capture: window does not have focus.",
                  enabled ? "enable" : "disable");
            return;
        }

        if (enabled == mCurrentPointerCaptureRequest.enable) {
            ALOGW("Ignoring request to %s Pointer Capture: "
                  "window has %s requested pointer capture.",
                  enabled ? "enable" : "disable", enabled ? "already" : "not");
            return;
        }

        if (enabled) {
            if (std::find(mIneligibleDisplaysForPointerCapture.begin(),
                          mIneligibleDisplaysForPointerCapture.end(),
                          mFocusedDisplayId) != mIneligibleDisplaysForPointerCapture.end()) {
                ALOGW("Ignoring request to enable Pointer Capture: display is not eligible");
                return;
            }
        }

        setPointerCaptureLocked(enabled);
    } // release lock

    // Wake the thread to process command entries.
    mLooper->wake();
}

void InputDispatcher::setDisplayEligibilityForPointerCapture(int32_t displayId, bool isEligible) {
    { // acquire lock
        std::scoped_lock _l(mLock);
        std::erase(mIneligibleDisplaysForPointerCapture, displayId);
        if (!isEligible) {
            mIneligibleDisplaysForPointerCapture.push_back(displayId);
        }
    } // release lock
}

std::optional<int32_t> InputDispatcher::findMonitorPidByTokenLocked(const sp<IBinder>& token) {
    for (const auto& [_, monitors] : mGlobalMonitorsByDisplay) {
        for (const Monitor& monitor : monitors) {
            if (monitor.inputChannel->getConnectionToken() == token) {
                return monitor.pid;
            }
        }
    }
    return std::nullopt;
}

sp<Connection> InputDispatcher::getConnectionLocked(const sp<IBinder>& inputConnectionToken) const {
    if (inputConnectionToken == nullptr) {
        return nullptr;
    }

    for (const auto& [token, connection] : mConnectionsByToken) {
        if (token == inputConnectionToken) {
            return connection;
        }
    }

    return nullptr;
}

std::string InputDispatcher::getConnectionNameLocked(const sp<IBinder>& connectionToken) const {
    sp<Connection> connection = getConnectionLocked(connectionToken);
    if (connection == nullptr) {
        return "<nullptr>";
    }
    return connection->getInputChannelName();
}

void InputDispatcher::removeConnectionLocked(const sp<Connection>& connection) {
    mAnrTracker.eraseToken(connection->inputChannel->getConnectionToken());
    mConnectionsByToken.erase(connection->inputChannel->getConnectionToken());
}

void InputDispatcher::doDispatchCycleFinishedCommand(nsecs_t finishTime,
                                                     const sp<Connection>& connection, uint32_t seq,
                                                     bool handled, nsecs_t consumeTime) {
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
    if (shouldReportFinishedEvent(*dispatchEntry, *connection)) {
        mLatencyTracker.trackFinishedEvent(dispatchEntry->eventEntry->id,
                                           connection->inputChannel->getConnectionToken(),
                                           dispatchEntry->deliveryTime, consumeTime, finishTime);
    }

    bool restartEvent;
    if (dispatchEntry->eventEntry->type == EventEntry::Type::KEY) {
        KeyEntry& keyEntry = static_cast<KeyEntry&>(*(dispatchEntry->eventEntry));
        restartEvent =
                afterKeyEventLockedInterruptable(connection, dispatchEntry, keyEntry, handled);
    } else if (dispatchEntry->eventEntry->type == EventEntry::Type::MOTION) {
        MotionEntry& motionEntry = static_cast<MotionEntry&>(*(dispatchEntry->eventEntry));
        restartEvent = afterMotionEventLockedInterruptable(connection, dispatchEntry, motionEntry,
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
        const sp<IBinder>& connectionToken = connection->inputChannel->getConnectionToken();
        mAnrTracker.erase(dispatchEntry->timeoutTime, connectionToken);
        if (!connection->responsive) {
            connection->responsive = isConnectionResponsive(*connection);
            if (connection->responsive) {
                // The connection was unresponsive, and now it's responsive.
                processConnectionResponsiveLocked(*connection);
            }
        }
        traceWaitQueueLength(*connection);
        if (restartEvent && connection->status == Connection::Status::NORMAL) {
            connection->outboundQueue.push_front(dispatchEntry);
            traceOutboundQueueLength(*connection);
        } else {
            releaseDispatchEntry(dispatchEntry);
        }
    }

    // Start the next dispatch cycle for this connection.
    startDispatchCycleLocked(now(), connection);
}

void InputDispatcher::sendFocusChangedCommandLocked(const sp<IBinder>& oldToken,
                                                    const sp<IBinder>& newToken) {
    auto command = [this, oldToken, newToken]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->notifyFocusChanged(oldToken, newToken);
    };
    postCommandLocked(std::move(command));
}

void InputDispatcher::sendDropWindowCommandLocked(const sp<IBinder>& token, float x, float y) {
    auto command = [this, token, x, y]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->notifyDropWindow(token, x, y);
    };
    postCommandLocked(std::move(command));
}

void InputDispatcher::sendUntrustedTouchCommandLocked(const std::string& obscuringPackage) {
    auto command = [this, obscuringPackage]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->notifyUntrustedTouch(obscuringPackage);
    };
    postCommandLocked(std::move(command));
}

void InputDispatcher::onAnrLocked(const sp<Connection>& connection) {
    if (connection == nullptr) {
        LOG_ALWAYS_FATAL("Caller must check for nullness");
    }
    // Since we are allowing the policy to extend the timeout, maybe the waitQueue
    // is already healthy again. Don't raise ANR in this situation
    if (connection->waitQueue.empty()) {
        ALOGI("Not raising ANR because the connection %s has recovered",
              connection->inputChannel->getName().c_str());
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
    DispatchEntry* oldestEntry = *connection->waitQueue.begin();
    const nsecs_t currentWait = now() - oldestEntry->deliveryTime;
    std::string reason =
            android::base::StringPrintf("%s is not responding. Waited %" PRId64 "ms for %s",
                                        connection->inputChannel->getName().c_str(),
                                        ns2ms(currentWait),
                                        oldestEntry->eventEntry->getDescription().c_str());
    sp<IBinder> connectionToken = connection->inputChannel->getConnectionToken();
    updateLastAnrStateLocked(getWindowHandleLocked(connectionToken), reason);

    processConnectionUnresponsiveLocked(*connection, std::move(reason));

    // Stop waking up for events on this connection, it is already unresponsive
    cancelEventsForAnrLocked(connection);
}

void InputDispatcher::onAnrLocked(std::shared_ptr<InputApplicationHandle> application) {
    std::string reason =
            StringPrintf("%s does not have a focused window", application->getName().c_str());
    updateLastAnrStateLocked(*application, reason);

    auto command = [this, app = std::move(application)]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->notifyNoFocusedWindowAnr(app);
    };
    postCommandLocked(std::move(command));
}

void InputDispatcher::updateLastAnrStateLocked(const sp<WindowInfoHandle>& window,
                                               const std::string& reason) {
    const std::string windowLabel = getApplicationWindowLabel(nullptr, window);
    updateLastAnrStateLocked(windowLabel, reason);
}

void InputDispatcher::updateLastAnrStateLocked(const InputApplicationHandle& application,
                                               const std::string& reason) {
    const std::string windowLabel = getApplicationWindowLabel(&application, nullptr);
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

void InputDispatcher::doInterceptKeyBeforeDispatchingCommand(const sp<IBinder>& focusedWindowToken,
                                                             KeyEntry& entry) {
    const KeyEvent event = createKeyEvent(entry);
    nsecs_t delay = 0;
    { // release lock
        scoped_unlock unlock(mLock);
        android::base::Timer t;
        delay = mPolicy->interceptKeyBeforeDispatching(focusedWindowToken, &event,
                                                       entry.policyFlags);
        if (t.duration() > SLOW_INTERCEPTION_THRESHOLD) {
            ALOGW("Excessive delay in interceptKeyBeforeDispatching; took %s ms",
                  std::to_string(t.duration().count()).c_str());
        }
    } // acquire lock

    if (delay < 0) {
        entry.interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_SKIP;
    } else if (delay == 0) {
        entry.interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_CONTINUE;
    } else {
        entry.interceptKeyResult = KeyEntry::INTERCEPT_KEY_RESULT_TRY_AGAIN_LATER;
        entry.interceptKeyWakeupTime = now() + delay;
    }
}

void InputDispatcher::sendWindowUnresponsiveCommandLocked(const sp<IBinder>& token,
                                                          std::optional<int32_t> pid,
                                                          std::string reason) {
    auto command = [this, token, pid, r = std::move(reason)]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->notifyWindowUnresponsive(token, pid, r);
    };
    postCommandLocked(std::move(command));
}

void InputDispatcher::sendWindowResponsiveCommandLocked(const sp<IBinder>& token,
                                                        std::optional<int32_t> pid) {
    auto command = [this, token, pid]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->notifyWindowResponsive(token, pid);
    };
    postCommandLocked(std::move(command));
}

/**
 * Tell the policy that a connection has become unresponsive so that it can start ANR.
 * Check whether the connection of interest is a monitor or a window, and add the corresponding
 * command entry to the command queue.
 */
void InputDispatcher::processConnectionUnresponsiveLocked(const Connection& connection,
                                                          std::string reason) {
    const sp<IBinder>& connectionToken = connection.inputChannel->getConnectionToken();
    std::optional<int32_t> pid;
    if (connection.monitor) {
        ALOGW("Monitor %s is unresponsive: %s", connection.inputChannel->getName().c_str(),
              reason.c_str());
        pid = findMonitorPidByTokenLocked(connectionToken);
    } else {
        // The connection is a window
        ALOGW("Window %s is unresponsive: %s", connection.inputChannel->getName().c_str(),
              reason.c_str());
        const sp<WindowInfoHandle> handle = getWindowHandleLocked(connectionToken);
        if (handle != nullptr) {
            pid = handle->getInfo()->ownerPid;
        }
    }
    sendWindowUnresponsiveCommandLocked(connectionToken, pid, std::move(reason));
}

/**
 * Tell the policy that a connection has become responsive so that it can stop ANR.
 */
void InputDispatcher::processConnectionResponsiveLocked(const Connection& connection) {
    const sp<IBinder>& connectionToken = connection.inputChannel->getConnectionToken();
    std::optional<int32_t> pid;
    if (connection.monitor) {
        pid = findMonitorPidByTokenLocked(connectionToken);
    } else {
        // The connection is a window
        const sp<WindowInfoHandle> handle = getWindowHandleLocked(connectionToken);
        if (handle != nullptr) {
            pid = handle->getInfo()->ownerPid;
        }
    }
    sendWindowResponsiveCommandLocked(connectionToken, pid);
}

bool InputDispatcher::afterKeyEventLockedInterruptable(const sp<Connection>& connection,
                                                       DispatchEntry* dispatchEntry,
                                                       KeyEntry& keyEntry, bool handled) {
    if (keyEntry.flags & AKEY_EVENT_FLAG_FALLBACK) {
        if (!handled) {
            // Report the key as unhandled, since the fallback was not handled.
            mReporter->reportUnhandledKey(keyEntry.id);
        }
        return false;
    }

    // Get the fallback key state.
    // Clear it out after dispatching the UP.
    int32_t originalKeyCode = keyEntry.keyCode;
    int32_t fallbackKeyCode = connection->inputState.getFallbackKey(originalKeyCode);
    if (keyEntry.action == AKEY_EVENT_ACTION_UP) {
        connection->inputState.removeFallbackKey(originalKeyCode);
    }

    if (handled || !dispatchEntry->hasForegroundTarget()) {
        // If the application handles the original key for which we previously
        // generated a fallback or if the window is not a foreground window,
        // then cancel the associated fallback key, if any.
        if (fallbackKeyCode != -1) {
            // Dispatch the unhandled key to the policy with the cancel flag.
            if (DEBUG_OUTBOUND_EVENT_DETAILS) {
                ALOGD("Unhandled key event: Asking policy to cancel fallback action.  "
                      "keyCode=%d, action=%d, repeatCount=%d, policyFlags=0x%08x",
                      keyEntry.keyCode, keyEntry.action, keyEntry.repeatCount,
                      keyEntry.policyFlags);
            }
            KeyEvent event = createKeyEvent(keyEntry);
            event.setFlags(event.getFlags() | AKEY_EVENT_FLAG_CANCELED);

            mLock.unlock();

            mPolicy->dispatchUnhandledKey(connection->inputChannel->getConnectionToken(), &event,
                                          keyEntry.policyFlags, &event);

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
        bool initialDown = keyEntry.action == AKEY_EVENT_ACTION_DOWN && keyEntry.repeatCount == 0;
        if (fallbackKeyCode == -1 && !initialDown) {
            if (DEBUG_OUTBOUND_EVENT_DETAILS) {
                ALOGD("Unhandled key event: Skipping unhandled key event processing "
                      "since this is not an initial down.  "
                      "keyCode=%d, action=%d, repeatCount=%d, policyFlags=0x%08x",
                      originalKeyCode, keyEntry.action, keyEntry.repeatCount, keyEntry.policyFlags);
            }
            return false;
        }

        // Dispatch the unhandled key to the policy.
        if (DEBUG_OUTBOUND_EVENT_DETAILS) {
            ALOGD("Unhandled key event: Asking policy to perform fallback action.  "
                  "keyCode=%d, action=%d, repeatCount=%d, policyFlags=0x%08x",
                  keyEntry.keyCode, keyEntry.action, keyEntry.repeatCount, keyEntry.policyFlags);
        }
        KeyEvent event = createKeyEvent(keyEntry);

        mLock.unlock();

        bool fallback =
                mPolicy->dispatchUnhandledKey(connection->inputChannel->getConnectionToken(),
                                              &event, keyEntry.policyFlags, &event);

        mLock.lock();

        if (connection->status != Connection::Status::NORMAL) {
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
            if (DEBUG_OUTBOUND_EVENT_DETAILS) {
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
            }

            CancelationOptions options(CancelationOptions::CANCEL_FALLBACK_EVENTS,
                                       "canceling fallback, policy no longer desires it");
            options.keyCode = fallbackKeyCode;
            synthesizeCancelationEventsForConnectionLocked(connection, options);

            fallback = false;
            fallbackKeyCode = AKEYCODE_UNKNOWN;
            if (keyEntry.action != AKEY_EVENT_ACTION_UP) {
                connection->inputState.setFallbackKey(originalKeyCode, fallbackKeyCode);
            }
        }

        if (DEBUG_OUTBOUND_EVENT_DETAILS) {
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
        }

        if (fallback) {
            // Restart the dispatch cycle using the fallback key.
            keyEntry.eventTime = event.getEventTime();
            keyEntry.deviceId = event.getDeviceId();
            keyEntry.source = event.getSource();
            keyEntry.displayId = event.getDisplayId();
            keyEntry.flags = event.getFlags() | AKEY_EVENT_FLAG_FALLBACK;
            keyEntry.keyCode = fallbackKeyCode;
            keyEntry.scanCode = event.getScanCode();
            keyEntry.metaState = event.getMetaState();
            keyEntry.repeatCount = event.getRepeatCount();
            keyEntry.downTime = event.getDownTime();
            keyEntry.syntheticRepeat = false;

            if (DEBUG_OUTBOUND_EVENT_DETAILS) {
                ALOGD("Unhandled key event: Dispatching fallback key.  "
                      "originalKeyCode=%d, fallbackKeyCode=%d, fallbackMetaState=%08x",
                      originalKeyCode, fallbackKeyCode, keyEntry.metaState);
            }
            return true; // restart the event
        } else {
            if (DEBUG_OUTBOUND_EVENT_DETAILS) {
                ALOGD("Unhandled key event: No fallback key.");
            }

            // Report the key as unhandled, since there is no fallback key.
            mReporter->reportUnhandledKey(keyEntry.id);
        }
    }
    return false;
}

bool InputDispatcher::afterMotionEventLockedInterruptable(const sp<Connection>& connection,
                                                          DispatchEntry* dispatchEntry,
                                                          MotionEntry& motionEntry, bool handled) {
    return false;
}

void InputDispatcher::traceInboundQueueLengthLocked() {
    if (ATRACE_ENABLED()) {
        ATRACE_INT("iq", mInboundQueue.size());
    }
}

void InputDispatcher::traceOutboundQueueLength(const Connection& connection) {
    if (ATRACE_ENABLED()) {
        char counterName[40];
        snprintf(counterName, sizeof(counterName), "oq:%s", connection.getWindowName().c_str());
        ATRACE_INT(counterName, connection.outboundQueue.size());
    }
}

void InputDispatcher::traceWaitQueueLength(const Connection& connection) {
    if (ATRACE_ENABLED()) {
        char counterName[40];
        snprintf(counterName, sizeof(counterName), "wq:%s", connection.getWindowName().c_str());
        ATRACE_INT(counterName, connection.waitQueue.size());
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

/**
 * Sets focus to the window identified by the token. This must be called
 * after updating any input window handles.
 *
 * Params:
 *  request.token - input channel token used to identify the window that should gain focus.
 *  request.focusedToken - the token that the caller expects currently to be focused. If the
 *  specified token does not match the currently focused window, this request will be dropped.
 *  If the specified focused token matches the currently focused window, the call will succeed.
 *  Set this to "null" if this call should succeed no matter what the currently focused token is.
 *  request.timestamp - SYSTEM_TIME_MONOTONIC timestamp in nanos set by the client (wm)
 *  when requesting the focus change. This determines which request gets
 *  precedence if there is a focus change request from another source such as pointer down.
 */
void InputDispatcher::setFocusedWindow(const FocusRequest& request) {
    { // acquire lock
        std::scoped_lock _l(mLock);
        std::optional<FocusResolver::FocusChanges> changes =
                mFocusResolver.setFocusedWindow(request, getWindowHandlesLocked(request.displayId));
        if (changes) {
            onFocusChangedLocked(*changes);
        }
    } // release lock
    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
}

void InputDispatcher::onFocusChangedLocked(const FocusResolver::FocusChanges& changes) {
    if (changes.oldFocus) {
        std::shared_ptr<InputChannel> focusedInputChannel = getInputChannelLocked(changes.oldFocus);
        if (focusedInputChannel) {
            CancelationOptions options(CancelationOptions::CANCEL_NON_POINTER_EVENTS,
                                       "focus left window");
            synthesizeCancelationEventsForInputChannelLocked(focusedInputChannel, options);
            enqueueFocusEventLocked(changes.oldFocus, false /*hasFocus*/, changes.reason);
        }
    }
    if (changes.newFocus) {
        enqueueFocusEventLocked(changes.newFocus, true /*hasFocus*/, changes.reason);
    }

    // If a window has pointer capture, then it must have focus. We need to ensure that this
    // contract is upheld when pointer capture is being disabled due to a loss of window focus.
    // If the window loses focus before it loses pointer capture, then the window can be in a state
    // where it has pointer capture but not focus, violating the contract. Therefore we must
    // dispatch the pointer capture event before the focus event. Since focus events are added to
    // the front of the queue (above), we add the pointer capture event to the front of the queue
    // after the focus events are added. This ensures the pointer capture event ends up at the
    // front.
    disablePointerCaptureForcedLocked();

    if (mFocusedDisplayId == changes.displayId) {
        sendFocusChangedCommandLocked(changes.oldFocus, changes.newFocus);
    }
}

void InputDispatcher::disablePointerCaptureForcedLocked() {
    if (!mCurrentPointerCaptureRequest.enable && !mWindowTokenWithPointerCapture) {
        return;
    }

    ALOGD_IF(DEBUG_FOCUS, "Disabling Pointer Capture because the window lost focus.");

    if (mCurrentPointerCaptureRequest.enable) {
        setPointerCaptureLocked(false);
    }

    if (!mWindowTokenWithPointerCapture) {
        // No need to send capture changes because no window has capture.
        return;
    }

    if (mPendingEvent != nullptr) {
        // Move the pending event to the front of the queue. This will give the chance
        // for the pending event to be dropped if it is a captured event.
        mInboundQueue.push_front(mPendingEvent);
        mPendingEvent = nullptr;
    }

    auto entry = std::make_unique<PointerCaptureChangedEntry>(mIdGenerator.nextId(), now(),
                                                              mCurrentPointerCaptureRequest);
    mInboundQueue.push_front(std::move(entry));
}

void InputDispatcher::setPointerCaptureLocked(bool enable) {
    mCurrentPointerCaptureRequest.enable = enable;
    mCurrentPointerCaptureRequest.seq++;
    auto command = [this, request = mCurrentPointerCaptureRequest]() REQUIRES(mLock) {
        scoped_unlock unlock(mLock);
        mPolicy->setPointerCapture(request);
    };
    postCommandLocked(std::move(command));
}

void InputDispatcher::displayRemoved(int32_t displayId) {
    { // acquire lock
        std::scoped_lock _l(mLock);
        // Set an empty list to remove all handles from the specific display.
        setInputWindowsLocked(/* window handles */ {}, displayId);
        setFocusedApplicationLocked(displayId, nullptr);
        // Call focus resolver to clean up stale requests. This must be called after input windows
        // have been removed for the removed display.
        mFocusResolver.displayRemoved(displayId);
        // Reset pointer capture eligibility, regardless of previous state.
        std::erase(mIneligibleDisplaysForPointerCapture, displayId);
    } // release lock

    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
}

void InputDispatcher::onWindowInfosChanged(const std::vector<WindowInfo>& windowInfos,
                                           const std::vector<DisplayInfo>& displayInfos) {
    // The listener sends the windows as a flattened array. Separate the windows by display for
    // more convenient parsing.
    std::unordered_map<int32_t, std::vector<sp<WindowInfoHandle>>> handlesPerDisplay;
    for (const auto& info : windowInfos) {
        handlesPerDisplay.emplace(info.displayId, std::vector<sp<WindowInfoHandle>>());
        handlesPerDisplay[info.displayId].push_back(new WindowInfoHandle(info));
    }

    { // acquire lock
        std::scoped_lock _l(mLock);

        // Ensure that we have an entry created for all existing displays so that if a displayId has
        // no windows, we can tell that the windows were removed from the display.
        for (const auto& [displayId, _] : mWindowHandlesByDisplay) {
            handlesPerDisplay[displayId];
        }

        mDisplayInfos.clear();
        for (const auto& displayInfo : displayInfos) {
            mDisplayInfos.emplace(displayInfo.displayId, displayInfo);
        }

        for (const auto& [displayId, handles] : handlesPerDisplay) {
            setInputWindowsLocked(handles, displayId);
        }
    }
    // Wake up poll loop since it may need to make new input dispatching choices.
    mLooper->wake();
}

bool InputDispatcher::shouldDropInput(
        const EventEntry& entry, const sp<android::gui::WindowInfoHandle>& windowHandle) const {
    if (windowHandle->getInfo()->inputConfig.test(WindowInfo::InputConfig::DROP_INPUT) ||
        (windowHandle->getInfo()->inputConfig.test(
                 WindowInfo::InputConfig::DROP_INPUT_IF_OBSCURED) &&
         isWindowObscuredLocked(windowHandle))) {
        ALOGW("Dropping %s event targeting %s as requested by the input configuration {%s} on "
              "display %" PRId32 ".",
              ftl::enum_string(entry.type).c_str(), windowHandle->getName().c_str(),
              windowHandle->getInfo()->inputConfig.string().c_str(),
              windowHandle->getInfo()->displayId);
        return true;
    }
    return false;
}

void InputDispatcher::DispatcherWindowListener::onWindowInfosChanged(
        const std::vector<gui::WindowInfo>& windowInfos,
        const std::vector<DisplayInfo>& displayInfos) {
    mDispatcher.onWindowInfosChanged(windowInfos, displayInfos);
}

void InputDispatcher::cancelCurrentTouch() {
    {
        std::scoped_lock _l(mLock);
        ALOGD("Canceling all ongoing pointer gestures on all displays.");
        CancelationOptions options(CancelationOptions::CANCEL_POINTER_EVENTS,
                                   "cancel current touch");
        synthesizeCancelationEventsForAllConnectionsLocked(options);

        mTouchStatesByDisplay.clear();
        mLastHoverWindowHandle.clear();
    }
    // Wake up poll loop since there might be work to do.
    mLooper->wake();
}

void InputDispatcher::setMonitorDispatchingTimeoutForTest(std::chrono::nanoseconds timeout) {
    std::scoped_lock _l(mLock);
    mMonitorDispatchingTimeout = timeout;
}

void InputDispatcher::slipWallpaperTouch(int32_t targetFlags,
                                         const sp<WindowInfoHandle>& oldWindowHandle,
                                         const sp<WindowInfoHandle>& newWindowHandle,
                                         TouchState& state, const BitSet32& pointerIds) {
    const bool oldHasWallpaper = oldWindowHandle->getInfo()->inputConfig.test(
            gui::WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER);
    const bool newHasWallpaper = (targetFlags & InputTarget::FLAG_FOREGROUND) &&
            newWindowHandle->getInfo()->inputConfig.test(
                    gui::WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER);
    const sp<WindowInfoHandle> oldWallpaper =
            oldHasWallpaper ? state.getWallpaperWindow() : nullptr;
    const sp<WindowInfoHandle> newWallpaper =
            newHasWallpaper ? findWallpaperWindowBelow(newWindowHandle) : nullptr;
    if (oldWallpaper == newWallpaper) {
        return;
    }

    if (oldWallpaper != nullptr) {
        state.addOrUpdateWindow(oldWallpaper, InputTarget::FLAG_DISPATCH_AS_SLIPPERY_EXIT,
                                BitSet32(0));
    }

    if (newWallpaper != nullptr) {
        state.addOrUpdateWindow(newWallpaper,
                                InputTarget::FLAG_DISPATCH_AS_SLIPPERY_ENTER |
                                        InputTarget::FLAG_WINDOW_IS_OBSCURED |
                                        InputTarget::FLAG_WINDOW_IS_PARTIALLY_OBSCURED,
                                pointerIds);
    }
}

void InputDispatcher::transferWallpaperTouch(int32_t oldTargetFlags, int32_t newTargetFlags,
                                             const sp<WindowInfoHandle> fromWindowHandle,
                                             const sp<WindowInfoHandle> toWindowHandle,
                                             TouchState& state, const BitSet32& pointerIds) {
    const bool oldHasWallpaper = (oldTargetFlags & InputTarget::FLAG_FOREGROUND) &&
            fromWindowHandle->getInfo()->inputConfig.test(
                    gui::WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER);
    const bool newHasWallpaper = (newTargetFlags & InputTarget::FLAG_FOREGROUND) &&
            toWindowHandle->getInfo()->inputConfig.test(
                    gui::WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER);

    const sp<WindowInfoHandle> oldWallpaper =
            oldHasWallpaper ? state.getWallpaperWindow() : nullptr;
    const sp<WindowInfoHandle> newWallpaper =
            newHasWallpaper ? findWallpaperWindowBelow(toWindowHandle) : nullptr;
    if (oldWallpaper == newWallpaper) {
        return;
    }

    if (oldWallpaper != nullptr) {
        CancelationOptions options(CancelationOptions::Mode::CANCEL_POINTER_EVENTS,
                                   "transferring touch focus to another window");
        state.removeWindowByToken(oldWallpaper->getToken());
        synthesizeCancelationEventsForWindowLocked(oldWallpaper, options);
    }

    if (newWallpaper != nullptr) {
        int32_t wallpaperFlags =
                oldTargetFlags & (InputTarget::FLAG_SPLIT | InputTarget::FLAG_DISPATCH_AS_IS);
        wallpaperFlags |= InputTarget::FLAG_WINDOW_IS_OBSCURED |
                InputTarget::FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
        state.addOrUpdateWindow(newWallpaper, wallpaperFlags, pointerIds);
        sp<Connection> wallpaperConnection = getConnectionLocked(newWallpaper->getToken());
        if (wallpaperConnection != nullptr) {
            sp<Connection> toConnection = getConnectionLocked(toWindowHandle->getToken());
            toConnection->inputState.mergePointerStateTo(wallpaperConnection->inputState);
            synthesizePointerDownEventsForConnectionLocked(wallpaperConnection, wallpaperFlags);
        }
    }
}

sp<WindowInfoHandle> InputDispatcher::findWallpaperWindowBelow(
        const sp<WindowInfoHandle>& windowHandle) const {
    const std::vector<sp<WindowInfoHandle>>& windowHandles =
            getWindowHandlesLocked(windowHandle->getInfo()->displayId);
    bool foundWindow = false;
    for (const sp<WindowInfoHandle>& otherHandle : windowHandles) {
        if (!foundWindow && otherHandle != windowHandle) {
            continue;
        }
        if (windowHandle == otherHandle) {
            foundWindow = true;
            continue;
        }

        if (otherHandle->getInfo()->inputConfig.test(WindowInfo::InputConfig::IS_WALLPAPER)) {
            return otherHandle;
        }
    }
    return nullptr;
}

} // namespace android::inputdispatcher
