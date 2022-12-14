/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "UnwantedInteractionBlocker"
#include "UnwantedInteractionBlocker.h"

#include <android-base/stringprintf.h>
#include <input/PrintTools.h>
#include <inttypes.h>
#include <linux/input-event-codes.h>
#include <linux/input.h>
#include <server_configurable_flags/get_flags.h>

#include "ui/events/ozone/evdev/touch_filter/neural_stylus_palm_detection_filter.h"
#include "ui/events/ozone/evdev/touch_filter/palm_model/onedevice_train_palm_detection_filter_model.h"

using android::base::StringPrintf;

/**
 * This type is declared here to ensure consistency between the instantiated type (used in the
 * constructor via std::make_unique) and the cast-to type (used in PalmRejector::dump() with
 * static_cast). Due to the lack of rtti support, dynamic_cast is not available, so this can't be
 * checked at runtime to avoid undefined behaviour.
 */
using PalmFilterImplementation = ::ui::NeuralStylusPalmDetectionFilter;

namespace android {

/**
 * Log detailed debug messages about each inbound motion event notification to the blocker.
 * Enable this via "adb shell setprop log.tag.UnwantedInteractionBlockerInboundMotion DEBUG"
 * (requires restart)
 */
const bool DEBUG_INBOUND_MOTION =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "InboundMotion", ANDROID_LOG_INFO);

/**
 * Log detailed debug messages about each outbound motion event processed by the blocker.
 * Enable this via "adb shell setprop log.tag.UnwantedInteractionBlockerOutboundMotion DEBUG"
 * (requires restart)
 */
const bool DEBUG_OUTBOUND_MOTION =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "OutboundMotion", ANDROID_LOG_INFO);

/**
 * Log the data sent to the model and received back from the model.
 * Enable this via "adb shell setprop log.tag.UnwantedInteractionBlockerModel DEBUG"
 * (requires restart)
 */
const bool DEBUG_MODEL =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Model", ANDROID_LOG_INFO);

// Category (=namespace) name for the input settings that are applied at boot time
static const char* INPUT_NATIVE_BOOT = "input_native_boot";
/**
 * Feature flag name. This flag determines whether palm rejection is enabled. To enable, specify
 * 'true' (not case sensitive) or '1'. To disable, specify any other value.
 */
static const char* PALM_REJECTION_ENABLED = "palm_rejection_enabled";

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static bool isFromTouchscreen(int32_t source) {
    return isFromSource(source, AINPUT_SOURCE_TOUCHSCREEN);
}

static ::base::TimeTicks toChromeTimestamp(nsecs_t eventTime) {
    return ::base::TimeTicks::UnixEpoch() + ::base::TimeDelta::FromNanosecondsD(eventTime);
}

/**
 * Return true if palm rejection is enabled via the server configurable flags. Return false
 * otherwise.
 */
static bool isPalmRejectionEnabled() {
    std::string value = toLower(
            server_configurable_flags::GetServerConfigurableFlag(INPUT_NATIVE_BOOT,
                                                                 PALM_REJECTION_ENABLED, "0"));
    if (value == "1") {
        return true;
    }
    return false;
}

static int getLinuxToolCode(int toolType) {
    if (toolType == AMOTION_EVENT_TOOL_TYPE_STYLUS) {
        return BTN_TOOL_PEN;
    }
    if (toolType == AMOTION_EVENT_TOOL_TYPE_FINGER) {
        return BTN_TOOL_FINGER;
    }
    ALOGW("Got tool type %" PRId32 ", converting to BTN_TOOL_FINGER", toolType);
    return BTN_TOOL_FINGER;
}

static int32_t getActionUpForPointerId(const NotifyMotionArgs& args, int32_t pointerId) {
    for (size_t i = 0; i < args.pointerCount; i++) {
        if (pointerId == args.pointerProperties[i].id) {
            return AMOTION_EVENT_ACTION_POINTER_UP |
                    (i << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        }
    }
    LOG_ALWAYS_FATAL("Can't find pointerId %" PRId32 " in %s", pointerId, args.dump().c_str());
}

/**
 * Find the action for individual pointer at the given pointer index.
 * This is always equal to MotionEvent::getActionMasked, except for
 * POINTER_UP or POINTER_DOWN events. For example, in a POINTER_UP event, the action for
 * the active pointer is ACTION_POINTER_UP, while the action for the other pointers is ACTION_MOVE.
 */
static int32_t resolveActionForPointer(uint8_t pointerIndex, int32_t action) {
    const int32_t actionMasked = MotionEvent::getActionMasked(action);
    if (actionMasked != AMOTION_EVENT_ACTION_POINTER_DOWN &&
        actionMasked != AMOTION_EVENT_ACTION_POINTER_UP) {
        return actionMasked;
    }
    // This is a POINTER_DOWN or POINTER_UP event
    const uint8_t actionIndex = MotionEvent::getActionIndex(action);
    if (pointerIndex == actionIndex) {
        return actionMasked;
    }
    // When POINTER_DOWN or POINTER_UP happens, it's actually a MOVE for all of the other
    // pointers
    return AMOTION_EVENT_ACTION_MOVE;
}

NotifyMotionArgs removePointerIds(const NotifyMotionArgs& args,
                                  const std::set<int32_t>& pointerIds) {
    const uint8_t actionIndex = MotionEvent::getActionIndex(args.action);
    const int32_t actionMasked = MotionEvent::getActionMasked(args.action);
    const bool isPointerUpOrDownAction = actionMasked == AMOTION_EVENT_ACTION_POINTER_DOWN ||
            actionMasked == AMOTION_EVENT_ACTION_POINTER_UP;

    NotifyMotionArgs newArgs{args};
    newArgs.pointerCount = 0;
    int32_t newActionIndex = 0;
    for (uint32_t i = 0; i < args.pointerCount; i++) {
        const int32_t pointerId = args.pointerProperties[i].id;
        if (pointerIds.find(pointerId) != pointerIds.end()) {
            // skip this pointer
            if (isPointerUpOrDownAction && i == actionIndex) {
                // The active pointer is being removed, so the action is no longer valid.
                // Set the action to 'UNKNOWN' here. The caller is responsible for updating this
                // action later to a proper value.
                newArgs.action = ACTION_UNKNOWN;
            }
            continue;
        }
        newArgs.pointerProperties[newArgs.pointerCount].copyFrom(args.pointerProperties[i]);
        newArgs.pointerCoords[newArgs.pointerCount].copyFrom(args.pointerCoords[i]);
        if (i == actionIndex) {
            newActionIndex = newArgs.pointerCount;
        }
        newArgs.pointerCount++;
    }
    // Update POINTER_DOWN or POINTER_UP actions
    if (isPointerUpOrDownAction && newArgs.action != ACTION_UNKNOWN) {
        newArgs.action =
                actionMasked | (newActionIndex << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
        // Convert POINTER_DOWN and POINTER_UP to DOWN and UP if there's only 1 pointer remaining
        if (newArgs.pointerCount == 1) {
            if (actionMasked == AMOTION_EVENT_ACTION_POINTER_DOWN) {
                newArgs.action = AMOTION_EVENT_ACTION_DOWN;
            } else if (actionMasked == AMOTION_EVENT_ACTION_POINTER_UP) {
                newArgs.action = AMOTION_EVENT_ACTION_UP;
            }
        }
    }
    return newArgs;
}

/**
 * Remove stylus pointers from the provided NotifyMotionArgs.
 *
 * Return NotifyMotionArgs where the stylus pointers have been removed.
 * If this results in removal of the active pointer, then return nullopt.
 */
static std::optional<NotifyMotionArgs> removeStylusPointerIds(const NotifyMotionArgs& args) {
    std::set<int32_t> stylusPointerIds;
    for (uint32_t i = 0; i < args.pointerCount; i++) {
        if (args.pointerProperties[i].toolType == AMOTION_EVENT_TOOL_TYPE_STYLUS) {
            stylusPointerIds.insert(args.pointerProperties[i].id);
        }
    }
    NotifyMotionArgs withoutStylusPointers = removePointerIds(args, stylusPointerIds);
    if (withoutStylusPointers.pointerCount == 0 || withoutStylusPointers.action == ACTION_UNKNOWN) {
        return std::nullopt;
    }
    return withoutStylusPointers;
}

std::optional<AndroidPalmFilterDeviceInfo> createPalmFilterDeviceInfo(
        const InputDeviceInfo& deviceInfo) {
    if (!isFromTouchscreen(deviceInfo.getSources())) {
        return std::nullopt;
    }
    AndroidPalmFilterDeviceInfo out;
    const InputDeviceInfo::MotionRange* axisX =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_X, AINPUT_SOURCE_TOUCHSCREEN);
    if (axisX != nullptr) {
        out.max_x = axisX->max;
        out.x_res = axisX->resolution;
    } else {
        ALOGW("Palm rejection is disabled for %s because AXIS_X is not supported",
              deviceInfo.getDisplayName().c_str());
        return std::nullopt;
    }
    const InputDeviceInfo::MotionRange* axisY =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_Y, AINPUT_SOURCE_TOUCHSCREEN);
    if (axisY != nullptr) {
        out.max_y = axisY->max;
        out.y_res = axisY->resolution;
    } else {
        ALOGW("Palm rejection is disabled for %s because AXIS_Y is not supported",
              deviceInfo.getDisplayName().c_str());
        return std::nullopt;
    }
    const InputDeviceInfo::MotionRange* axisMajor =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_TOUCH_MAJOR, AINPUT_SOURCE_TOUCHSCREEN);
    if (axisMajor != nullptr) {
        out.major_radius_res = axisMajor->resolution;
        out.touch_major_res = axisMajor->resolution;
    } else {
        return std::nullopt;
    }
    const InputDeviceInfo::MotionRange* axisMinor =
            deviceInfo.getMotionRange(AMOTION_EVENT_AXIS_TOUCH_MINOR, AINPUT_SOURCE_TOUCHSCREEN);
    if (axisMinor != nullptr) {
        out.minor_radius_res = axisMinor->resolution;
        out.touch_minor_res = axisMinor->resolution;
        out.minor_radius_supported = true;
    } else {
        out.minor_radius_supported = false;
    }

    return out;
}

/**
 * Synthesize CANCEL events for any new pointers that should be canceled, while removing pointers
 * that have already been canceled.
 * The flow of the function is as follows:
 * 1. Remove all already canceled pointers
 * 2. Cancel all newly suppressed pointers
 * 3. Decide what to do with the current event : keep it, or drop it
 * The pointers can never be "unsuppressed": once a pointer is canceled, it will never become valid.
 */
std::vector<NotifyMotionArgs> cancelSuppressedPointers(
        const NotifyMotionArgs& args, const std::set<int32_t>& oldSuppressedPointerIds,
        const std::set<int32_t>& newSuppressedPointerIds) {
    LOG_ALWAYS_FATAL_IF(args.pointerCount == 0, "0 pointers in %s", args.dump().c_str());

    // First, let's remove the old suppressed pointers. They've already been canceled previously.
    NotifyMotionArgs oldArgs = removePointerIds(args, oldSuppressedPointerIds);

    // Cancel any newly suppressed pointers.
    std::vector<NotifyMotionArgs> out;
    const int32_t activePointerId =
            args.pointerProperties[MotionEvent::getActionIndex(args.action)].id;
    const int32_t actionMasked = MotionEvent::getActionMasked(args.action);
    // We will iteratively remove pointers from 'removedArgs'.
    NotifyMotionArgs removedArgs{oldArgs};
    for (uint32_t i = 0; i < oldArgs.pointerCount; i++) {
        const int32_t pointerId = oldArgs.pointerProperties[i].id;
        if (newSuppressedPointerIds.find(pointerId) == newSuppressedPointerIds.end()) {
            // This is a pointer that should not be canceled. Move on.
            continue;
        }
        if (pointerId == activePointerId && actionMasked == AMOTION_EVENT_ACTION_POINTER_DOWN) {
            // Remove this pointer, but don't cancel it. We'll just not send the POINTER_DOWN event
            removedArgs = removePointerIds(removedArgs, {pointerId});
            continue;
        }

        if (removedArgs.pointerCount == 1) {
            // We are about to remove the last pointer, which means there will be no more gesture
            // remaining. This is identical to canceling all pointers, so just send a single CANCEL
            // event, without any of the preceding POINTER_UP with FLAG_CANCELED events.
            oldArgs.flags |= AMOTION_EVENT_FLAG_CANCELED;
            oldArgs.action = AMOTION_EVENT_ACTION_CANCEL;
            return {oldArgs};
        }
        // Cancel the current pointer
        out.push_back(removedArgs);
        out.back().flags |= AMOTION_EVENT_FLAG_CANCELED;
        out.back().action = getActionUpForPointerId(out.back(), pointerId);

        // Remove the newly canceled pointer from the args
        removedArgs = removePointerIds(removedArgs, {pointerId});
    }

    // Now 'removedArgs' contains only pointers that are valid.
    if (removedArgs.pointerCount <= 0 || removedArgs.action == ACTION_UNKNOWN) {
        return out;
    }
    out.push_back(removedArgs);
    return out;
}

UnwantedInteractionBlocker::UnwantedInteractionBlocker(InputListenerInterface& listener)
      : UnwantedInteractionBlocker(listener, isPalmRejectionEnabled()){};

UnwantedInteractionBlocker::UnwantedInteractionBlocker(InputListenerInterface& listener,
                                                       bool enablePalmRejection)
      : mQueuedListener(listener), mEnablePalmRejection(enablePalmRejection) {}

void UnwantedInteractionBlocker::notifyConfigurationChanged(
        const NotifyConfigurationChangedArgs* args) {
    mQueuedListener.notifyConfigurationChanged(args);
    mQueuedListener.flush();
}

void UnwantedInteractionBlocker::notifyKey(const NotifyKeyArgs* args) {
    mQueuedListener.notifyKey(args);
    mQueuedListener.flush();
}

void UnwantedInteractionBlocker::notifyMotion(const NotifyMotionArgs* args) {
    ALOGD_IF(DEBUG_INBOUND_MOTION, "%s: %s", __func__, args->dump().c_str());
    { // acquire lock
        std::scoped_lock lock(mLock);
        const std::vector<NotifyMotionArgs> processedArgs =
                mPreferStylusOverTouchBlocker.processMotion(*args);
        for (const NotifyMotionArgs& loopArgs : processedArgs) {
            notifyMotionLocked(&loopArgs);
        }
    } // release lock

    // Call out to the next stage without holding the lock
    mQueuedListener.flush();
}

void UnwantedInteractionBlocker::enqueueOutboundMotionLocked(const NotifyMotionArgs& args) {
    ALOGD_IF(DEBUG_OUTBOUND_MOTION, "%s: %s", __func__, args.dump().c_str());
    mQueuedListener.notifyMotion(&args);
}

void UnwantedInteractionBlocker::notifyMotionLocked(const NotifyMotionArgs* args) {
    auto it = mPalmRejectors.find(args->deviceId);
    const bool sendToPalmRejector = it != mPalmRejectors.end() && isFromTouchscreen(args->source);
    if (!sendToPalmRejector) {
        enqueueOutboundMotionLocked(*args);
        return;
    }

    std::vector<NotifyMotionArgs> processedArgs = it->second.processMotion(*args);
    for (const NotifyMotionArgs& loopArgs : processedArgs) {
        enqueueOutboundMotionLocked(loopArgs);
    }
}

void UnwantedInteractionBlocker::notifySwitch(const NotifySwitchArgs* args) {
    mQueuedListener.notifySwitch(args);
    mQueuedListener.flush();
}

void UnwantedInteractionBlocker::notifySensor(const NotifySensorArgs* args) {
    mQueuedListener.notifySensor(args);
    mQueuedListener.flush();
}

void UnwantedInteractionBlocker::notifyVibratorState(const NotifyVibratorStateArgs* args) {
    mQueuedListener.notifyVibratorState(args);
    mQueuedListener.flush();
}
void UnwantedInteractionBlocker::notifyDeviceReset(const NotifyDeviceResetArgs* args) {
    { // acquire lock
        std::scoped_lock lock(mLock);
        auto it = mPalmRejectors.find(args->deviceId);
        if (it != mPalmRejectors.end()) {
            AndroidPalmFilterDeviceInfo info = it->second.getPalmFilterDeviceInfo();
            // Re-create the object instead of resetting it
            mPalmRejectors.erase(it);
            mPalmRejectors.emplace(args->deviceId, info);
        }
        mQueuedListener.notifyDeviceReset(args);
        mPreferStylusOverTouchBlocker.notifyDeviceReset(*args);
    } // release lock
    // Send events to the next stage without holding the lock
    mQueuedListener.flush();
}

void UnwantedInteractionBlocker::notifyPointerCaptureChanged(
        const NotifyPointerCaptureChangedArgs* args) {
    mQueuedListener.notifyPointerCaptureChanged(args);
    mQueuedListener.flush();
}

void UnwantedInteractionBlocker::notifyInputDevicesChanged(
        const std::vector<InputDeviceInfo>& inputDevices) {
    std::scoped_lock lock(mLock);
    if (!mEnablePalmRejection) {
        // Palm rejection is disabled. Don't create any palm rejector objects.
        return;
    }

    // Let's see which of the existing devices didn't change, so that we can keep them
    // and prevent event stream disruption
    std::set<int32_t /*deviceId*/> devicesToKeep;
    for (const InputDeviceInfo& device : inputDevices) {
        std::optional<AndroidPalmFilterDeviceInfo> info = createPalmFilterDeviceInfo(device);
        if (!info) {
            continue;
        }

        auto [it, emplaced] = mPalmRejectors.try_emplace(device.getId(), *info);
        if (!emplaced && *info != it->second.getPalmFilterDeviceInfo()) {
            // Re-create the PalmRejector because the device info has changed.
            mPalmRejectors.erase(it);
            mPalmRejectors.emplace(device.getId(), *info);
        }
        devicesToKeep.insert(device.getId());
    }
    // Delete all devices that we don't need to keep
    std::erase_if(mPalmRejectors, [&devicesToKeep](const auto& item) {
        auto const& [deviceId, _] = item;
        return devicesToKeep.find(deviceId) == devicesToKeep.end();
    });
    mPreferStylusOverTouchBlocker.notifyInputDevicesChanged(inputDevices);
}

void UnwantedInteractionBlocker::dump(std::string& dump) {
    std::scoped_lock lock(mLock);
    dump += "UnwantedInteractionBlocker:\n";
    dump += "  mPreferStylusOverTouchBlocker:\n";
    dump += addLinePrefix(mPreferStylusOverTouchBlocker.dump(), "    ");
    dump += StringPrintf("  mEnablePalmRejection: %s\n",
                         std::to_string(mEnablePalmRejection).c_str());
    dump += StringPrintf("  isPalmRejectionEnabled (flag value): %s\n",
                         std::to_string(isPalmRejectionEnabled()).c_str());
    dump += mPalmRejectors.empty() ? "  mPalmRejectors: None\n" : "  mPalmRejectors:\n";
    for (const auto& [deviceId, palmRejector] : mPalmRejectors) {
        dump += StringPrintf("    deviceId = %" PRId32 ":\n", deviceId);
        dump += addLinePrefix(palmRejector.dump(), "      ");
    }
}

void UnwantedInteractionBlocker::monitor() {
    std::scoped_lock lock(mLock);
}

UnwantedInteractionBlocker::~UnwantedInteractionBlocker() {}

void SlotState::update(const NotifyMotionArgs& args) {
    for (size_t i = 0; i < args.pointerCount; i++) {
        const int32_t pointerId = args.pointerProperties[i].id;
        const int32_t resolvedAction = resolveActionForPointer(i, args.action);
        processPointerId(pointerId, resolvedAction);
    }
}

size_t SlotState::findUnusedSlot() const {
    size_t unusedSlot = 0;
    // Since the collection is ordered, we can rely on the in-order traversal
    for (const auto& [slot, trackingId] : mPointerIdsBySlot) {
        if (unusedSlot != slot) {
            break;
        }
        unusedSlot++;
    }
    return unusedSlot;
}

void SlotState::processPointerId(int pointerId, int32_t actionMasked) {
    switch (MotionEvent::getActionMasked(actionMasked)) {
        case AMOTION_EVENT_ACTION_DOWN:
        case AMOTION_EVENT_ACTION_POINTER_DOWN:
        case AMOTION_EVENT_ACTION_HOVER_ENTER: {
            // New pointer going down
            size_t newSlot = findUnusedSlot();
            mPointerIdsBySlot[newSlot] = pointerId;
            mSlotsByPointerId[pointerId] = newSlot;
            return;
        }
        case AMOTION_EVENT_ACTION_MOVE:
        case AMOTION_EVENT_ACTION_HOVER_MOVE: {
            return;
        }
        case AMOTION_EVENT_ACTION_CANCEL:
        case AMOTION_EVENT_ACTION_POINTER_UP:
        case AMOTION_EVENT_ACTION_UP:
        case AMOTION_EVENT_ACTION_HOVER_EXIT: {
            auto it = mSlotsByPointerId.find(pointerId);
            LOG_ALWAYS_FATAL_IF(it == mSlotsByPointerId.end());
            size_t slot = it->second;
            // Erase this pointer from both collections
            mPointerIdsBySlot.erase(slot);
            mSlotsByPointerId.erase(pointerId);
            return;
        }
    }
    LOG_ALWAYS_FATAL("Unhandled action : %s", MotionEvent::actionToString(actionMasked).c_str());
    return;
}

std::optional<size_t> SlotState::getSlotForPointerId(int32_t pointerId) const {
    auto it = mSlotsByPointerId.find(pointerId);
    if (it == mSlotsByPointerId.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::string SlotState::dump() const {
    std::string out = "mSlotsByPointerId:\n";
    out += addLinePrefix(dumpMap(mSlotsByPointerId), "  ") + "\n";
    out += "mPointerIdsBySlot:\n";
    out += addLinePrefix(dumpMap(mPointerIdsBySlot), "  ") + "\n";
    return out;
}

class AndroidPalmRejectionModel : public ::ui::OneDeviceTrainNeuralStylusPalmDetectionFilterModel {
public:
    AndroidPalmRejectionModel()
          : ::ui::OneDeviceTrainNeuralStylusPalmDetectionFilterModel(/*default version*/ "",
                                                                     std::vector<float>()) {
        config_.resample_period = ::ui::kResamplePeriod;
    }
};

PalmRejector::PalmRejector(const AndroidPalmFilterDeviceInfo& info,
                           std::unique_ptr<::ui::PalmDetectionFilter> filter)
      : mSharedPalmState(std::make_unique<::ui::SharedPalmDetectionFilterState>()),
        mDeviceInfo(info),
        mPalmDetectionFilter(std::move(filter)) {
    if (mPalmDetectionFilter != nullptr) {
        // This path is used for testing. Non-testing invocations should let this constructor
        // create a real PalmDetectionFilter
        return;
    }
    std::unique_ptr<::ui::NeuralStylusPalmDetectionFilterModel> model =
            std::make_unique<AndroidPalmRejectionModel>();
    mPalmDetectionFilter = std::make_unique<PalmFilterImplementation>(mDeviceInfo, std::move(model),
                                                                      mSharedPalmState.get());
}

std::vector<::ui::InProgressTouchEvdev> getTouches(const NotifyMotionArgs& args,
                                                   const AndroidPalmFilterDeviceInfo& deviceInfo,
                                                   const SlotState& oldSlotState,
                                                   const SlotState& newSlotState) {
    std::vector<::ui::InProgressTouchEvdev> touches;

    for (size_t i = 0; i < args.pointerCount; i++) {
        const int32_t pointerId = args.pointerProperties[i].id;
        touches.emplace_back(::ui::InProgressTouchEvdev());
        touches.back().major = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MAJOR);
        touches.back().minor = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_TOUCH_MINOR);
        // The field 'tool_type' is not used for palm rejection

        // Whether there is new information for the touch.
        touches.back().altered = true;

        // Whether the touch was cancelled. Touch events should be ignored till a
        // new touch is initiated.
        touches.back().was_cancelled = false;

        // Whether the touch is going to be canceled.
        touches.back().cancelled = false;

        // Whether the touch is delayed at first appearance. Will not be reported yet.
        touches.back().delayed = false;

        // Whether the touch was delayed before.
        touches.back().was_delayed = false;

        // Whether the touch is held until end or no longer held.
        touches.back().held = false;

        // Whether this touch was held before being sent.
        touches.back().was_held = false;

        const int32_t resolvedAction = resolveActionForPointer(i, args.action);
        const bool isDown = resolvedAction == AMOTION_EVENT_ACTION_POINTER_DOWN ||
                resolvedAction == AMOTION_EVENT_ACTION_DOWN;
        touches.back().was_touching = !isDown;

        const bool isUpOrCancel = resolvedAction == AMOTION_EVENT_ACTION_CANCEL ||
                resolvedAction == AMOTION_EVENT_ACTION_UP ||
                resolvedAction == AMOTION_EVENT_ACTION_POINTER_UP;

        touches.back().x = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_X);
        touches.back().y = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_Y);

        std::optional<size_t> slot = newSlotState.getSlotForPointerId(pointerId);
        if (!slot) {
            slot = oldSlotState.getSlotForPointerId(pointerId);
        }
        LOG_ALWAYS_FATAL_IF(!slot, "Could not find slot for pointer %d", pointerId);
        touches.back().slot = *slot;
        touches.back().tracking_id = (!isUpOrCancel) ? pointerId : -1;
        touches.back().touching = !isUpOrCancel;

        // The fields 'radius_x' and 'radius_x' are not used for palm rejection
        touches.back().pressure = args.pointerCoords[i].getAxisValue(AMOTION_EVENT_AXIS_PRESSURE);
        touches.back().tool_code = getLinuxToolCode(args.pointerProperties[i].toolType);
        // The field 'orientation' is not used for palm rejection
        // The fields 'tilt_x' and 'tilt_y' are not used for palm rejection
        // The field 'reported_tool_type' is not used for palm rejection
        touches.back().stylus_button = false;
    }
    return touches;
}

std::set<int32_t> PalmRejector::detectPalmPointers(const NotifyMotionArgs& args) {
    std::bitset<::ui::kNumTouchEvdevSlots> slotsToHold;
    std::bitset<::ui::kNumTouchEvdevSlots> slotsToSuppress;

    // Store the slot state before we call getTouches and update it. This way, we can find
    // the slots that have been removed due to the incoming event.
    SlotState oldSlotState = mSlotState;
    mSlotState.update(args);

    std::vector<::ui::InProgressTouchEvdev> touches =
            getTouches(args, mDeviceInfo, oldSlotState, mSlotState);
    ::base::TimeTicks chromeTimestamp = toChromeTimestamp(args.eventTime);

    if (DEBUG_MODEL) {
        std::stringstream touchesStream;
        for (const ::ui::InProgressTouchEvdev& touch : touches) {
            touchesStream << touch.tracking_id << " : " << touch << "\n";
        }
        ALOGD("Filter: touches = %s", touchesStream.str().c_str());
    }

    mPalmDetectionFilter->Filter(touches, chromeTimestamp, &slotsToHold, &slotsToSuppress);

    ALOGD_IF(DEBUG_MODEL, "Response: slotsToHold = %s, slotsToSuppress = %s",
             slotsToHold.to_string().c_str(), slotsToSuppress.to_string().c_str());

    // Now that we know which slots should be suppressed, let's convert those to pointer id's.
    std::set<int32_t> newSuppressedIds;
    for (size_t i = 0; i < args.pointerCount; i++) {
        const int32_t pointerId = args.pointerProperties[i].id;
        std::optional<size_t> slot = oldSlotState.getSlotForPointerId(pointerId);
        if (!slot) {
            slot = mSlotState.getSlotForPointerId(pointerId);
            LOG_ALWAYS_FATAL_IF(!slot, "Could not find slot for pointer id %" PRId32, pointerId);
        }
        if (slotsToSuppress.test(*slot)) {
            newSuppressedIds.insert(pointerId);
        }
    }
    return newSuppressedIds;
}

std::vector<NotifyMotionArgs> PalmRejector::processMotion(const NotifyMotionArgs& args) {
    if (mPalmDetectionFilter == nullptr) {
        return {args};
    }
    const bool skipThisEvent = args.action == AMOTION_EVENT_ACTION_HOVER_ENTER ||
            args.action == AMOTION_EVENT_ACTION_HOVER_MOVE ||
            args.action == AMOTION_EVENT_ACTION_HOVER_EXIT ||
            args.action == AMOTION_EVENT_ACTION_BUTTON_PRESS ||
            args.action == AMOTION_EVENT_ACTION_BUTTON_RELEASE ||
            args.action == AMOTION_EVENT_ACTION_SCROLL;
    if (skipThisEvent) {
        // Lets not process hover events, button events, or scroll for now.
        return {args};
    }
    if (args.action == AMOTION_EVENT_ACTION_DOWN) {
        mSuppressedPointerIds.clear();
    }

    std::set<int32_t> oldSuppressedIds;
    std::swap(oldSuppressedIds, mSuppressedPointerIds);

    std::optional<NotifyMotionArgs> touchOnlyArgs = removeStylusPointerIds(args);
    if (touchOnlyArgs) {
        mSuppressedPointerIds = detectPalmPointers(*touchOnlyArgs);
    } else {
        // This is a stylus-only event.
        // We can skip this event and just keep the suppressed pointer ids the same as before.
        mSuppressedPointerIds = oldSuppressedIds;
    }

    std::vector<NotifyMotionArgs> argsWithoutUnwantedPointers =
            cancelSuppressedPointers(args, oldSuppressedIds, mSuppressedPointerIds);
    for (const NotifyMotionArgs& checkArgs : argsWithoutUnwantedPointers) {
        LOG_ALWAYS_FATAL_IF(checkArgs.action == ACTION_UNKNOWN, "%s", checkArgs.dump().c_str());
    }

    // Only log if new pointers are getting rejected. That means mSuppressedPointerIds is not a
    // subset of oldSuppressedIds.
    if (!std::includes(oldSuppressedIds.begin(), oldSuppressedIds.end(),
                       mSuppressedPointerIds.begin(), mSuppressedPointerIds.end())) {
        ALOGI("Palm detected, removing pointer ids %s after %" PRId64 "ms from %s",
              dumpSet(mSuppressedPointerIds).c_str(), ns2ms(args.eventTime - args.downTime),
              args.dump().c_str());
    }

    return argsWithoutUnwantedPointers;
}

const AndroidPalmFilterDeviceInfo& PalmRejector::getPalmFilterDeviceInfo() const {
    return mDeviceInfo;
}

std::string PalmRejector::dump() const {
    std::string out;
    out += "mDeviceInfo:\n";
    std::stringstream deviceInfo;
    deviceInfo << mDeviceInfo << ", touch_major_res=" << mDeviceInfo.touch_major_res
               << ", touch_minor_res=" << mDeviceInfo.touch_minor_res << "\n";
    out += addLinePrefix(deviceInfo.str(), "  ");
    out += "mSlotState:\n";
    out += addLinePrefix(mSlotState.dump(), "  ");
    out += "mSuppressedPointerIds: ";
    out += dumpSet(mSuppressedPointerIds) + "\n";
    std::stringstream state;
    state << *mSharedPalmState;
    out += "mSharedPalmState: " + state.str() + "\n";
    std::stringstream filter;
    filter << static_cast<const PalmFilterImplementation&>(*mPalmDetectionFilter);
    out += "mPalmDetectionFilter:\n";
    out += addLinePrefix(filter.str(), "  ") + "\n";
    return out;
}

} // namespace android
