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

#pragma once

#include <map>
#include <set>

#include <android-base/thread_annotations.h>
#include "include/UnwantedInteractionBlockerInterface.h"
#include "ui/events/ozone/evdev/touch_filter/neural_stylus_palm_detection_filter_util.h"
#include "ui/events/ozone/evdev/touch_filter/palm_detection_filter.h"

#include "PreferStylusOverTouchBlocker.h"

namespace android {

// --- Functions for manipulation of event streams

struct AndroidPalmFilterDeviceInfo : ::ui::PalmFilterDeviceInfo {
    // Additional fields from 'TouchEventConverterEvdev', added here for convenience
    int32_t touch_major_res = 1; // info.GetAbsInfoByCode(ABS_MT_TOUCH_MAJOR).resolution;
    int32_t touch_minor_res = 1; // info.GetAbsInfoByCode(ABS_MT_TOUCH_MINOR).resolution;

    auto operator<=>(const AndroidPalmFilterDeviceInfo&) const = default;
};

std::optional<AndroidPalmFilterDeviceInfo> createPalmFilterDeviceInfo(
        const InputDeviceInfo& deviceInfo);

static constexpr int32_t ACTION_UNKNOWN = -1;

/**
 * Remove the data for the provided pointers from the args. The pointers are identified by their
 * pointerId, not by the index inside the array.
 * Return the new NotifyMotionArgs struct that has the remaining pointers.
 * The only fields that may be different in the returned args from the provided args are:
 *     - action
 *     - pointerCount
 *     - pointerProperties
 *     - pointerCoords
 * Action might change because it contains a pointer index. If another pointer is removed, the
 * active pointer index would be shifted.
 *
 * If the active pointer id is removed (for example, for events like
 * POINTER_UP or POINTER_DOWN), then the action is set to ACTION_UNKNOWN. It is up to the caller
 * to set the action appropriately after the call.
 *
 * @param args the args from which the pointers should be removed
 * @param pointerIds the pointer ids of the pointers that should be removed
 */
NotifyMotionArgs removePointerIds(const NotifyMotionArgs& args,
                                  const std::set<int32_t>& pointerIds);

std::vector<NotifyMotionArgs> cancelSuppressedPointers(
        const NotifyMotionArgs& args, const std::set<int32_t>& oldSuppressedPointerIds,
        const std::set<int32_t>& newSuppressedPointerIds);

std::string toString(const ::ui::InProgressTouchEvdev& touch);

// --- Main classes and interfaces ---

class PalmRejector;

// --- Implementations ---

/**
 * Implementation of the UnwantedInteractionBlockerInterface.
 * Represents a separate stage of input processing. All of the input events go through this stage.
 * Acts as a passthrough for all input events except for motion events.
 *
 * The events of motion type are sent to PalmRejectors. PalmRejectors detect unwanted touches,
 * and emit input streams with the bad pointers removed.
 */
class UnwantedInteractionBlocker : public UnwantedInteractionBlockerInterface {
public:
    explicit UnwantedInteractionBlocker(InputListenerInterface& listener);
    explicit UnwantedInteractionBlocker(InputListenerInterface& listener, bool enablePalmRejection);

    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) override;
    void notifyKey(const NotifyKeyArgs* args) override;
    void notifyMotion(const NotifyMotionArgs* args) override;
    void notifySwitch(const NotifySwitchArgs* args) override;
    void notifySensor(const NotifySensorArgs* args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs* args) override;
    void notifyDeviceReset(const NotifyDeviceResetArgs* args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs* args) override;

    void notifyInputDevicesChanged(const std::vector<InputDeviceInfo>& inputDevices) override;
    void dump(std::string& dump) override;
    void monitor() override;

    ~UnwantedInteractionBlocker();

private:
    std::mutex mLock;
    // The next stage to pass input events to

    QueuedInputListener mQueuedListener;
    const bool mEnablePalmRejection;

    // When stylus is down, ignore touch
    PreferStylusOverTouchBlocker mPreferStylusOverTouchBlocker GUARDED_BY(mLock);

    // Detect and reject unwanted palms on screen
    // Use a separate palm rejector for every touch device.
    std::map<int32_t /*deviceId*/, PalmRejector> mPalmRejectors GUARDED_BY(mLock);
    // TODO(b/210159205): delete this when simultaneous stylus and touch is supported
    void notifyMotionLocked(const NotifyMotionArgs* args) REQUIRES(mLock);

    // Call this function for outbound events so that they can be logged when logging is enabled.
    void enqueueOutboundMotionLocked(const NotifyMotionArgs& args) REQUIRES(mLock);
};

class SlotState {
public:
    /**
     * Update the state using the new information provided in the NotifyMotionArgs
     */
    void update(const NotifyMotionArgs& args);
    std::optional<size_t> getSlotForPointerId(int32_t pointerId) const;
    std::string dump() const;

private:
    // Process a pointer with the provided action, and return the slot associated with it
    void processPointerId(int32_t pointerId, int32_t action);
    // The map from tracking id to slot state. Since the PalmRejectionFilter works close to the
    // evdev level, the only way to tell it about UP or CANCEL events is by sending tracking id = -1
    // to the appropriate touch slot. So we need to reconstruct the original slot.
    // The two collections below must always be in-sync.
    // Use std::map instead of std::unordered_map because we rely on these collections being
    // ordered. It also has better space efficiency than unordered_map because we only have a few
    // pointers most of the time.
    std::map<int32_t /*pointerId*/, size_t /*slot*/> mSlotsByPointerId;
    std::map<size_t /*slot*/, int32_t /*pointerId */> mPointerIdsBySlot;

    size_t findUnusedSlot() const;
};

/**
 * Convert an Android event to a linux-like 'InProgressTouchEvdev'. The provided SlotState's
 * are used to figure out which slot does each pointer belong to.
 */
std::vector<::ui::InProgressTouchEvdev> getTouches(const NotifyMotionArgs& args,
                                                   const AndroidPalmFilterDeviceInfo& deviceInfo,
                                                   const SlotState& oldSlotState,
                                                   const SlotState& newSlotState);

class PalmRejector {
public:
    explicit PalmRejector(const AndroidPalmFilterDeviceInfo& info,
                          std::unique_ptr<::ui::PalmDetectionFilter> filter = nullptr);
    std::vector<NotifyMotionArgs> processMotion(const NotifyMotionArgs& args);

    // Get the device info of this device, for comparison purposes
    const AndroidPalmFilterDeviceInfo& getPalmFilterDeviceInfo() const;
    std::string dump() const;

private:
    PalmRejector(const PalmRejector&) = delete;
    PalmRejector& operator=(const PalmRejector&) = delete;

    /**
     * Update the slot state and send this event to the palm rejection model for palm detection.
     * Return the pointer ids that should be suppressed.
     *
     * This function is not const because it has side-effects. It will update the slot state using
     * the incoming args! Also, it will call Filter(..), which has side-effects.
     */
    std::set<int32_t> detectPalmPointers(const NotifyMotionArgs& args);
    std::unique_ptr<::ui::SharedPalmDetectionFilterState> mSharedPalmState;
    AndroidPalmFilterDeviceInfo mDeviceInfo;
    std::unique_ptr<::ui::PalmDetectionFilter> mPalmDetectionFilter;
    std::set<int32_t> mSuppressedPointerIds;

    // Used to help convert an Android touch stream to Linux input stream.
    SlotState mSlotState;
};

} // namespace android
