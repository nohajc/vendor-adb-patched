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

#include "PreferStylusOverTouchBlocker.h"
#include <input/PrintTools.h>

namespace android {

static std::pair<bool, bool> checkToolType(const NotifyMotionArgs& args) {
    bool hasStylus = false;
    bool hasTouch = false;
    for (size_t i = 0; i < args.pointerCount; i++) {
        // Make sure we are canceling stylus pointers
        const int32_t toolType = args.pointerProperties[i].toolType;
        if (toolType == AMOTION_EVENT_TOOL_TYPE_STYLUS ||
            toolType == AMOTION_EVENT_TOOL_TYPE_ERASER) {
            hasStylus = true;
        }
        if (toolType == AMOTION_EVENT_TOOL_TYPE_FINGER) {
            hasTouch = true;
        }
    }
    return std::make_pair(hasTouch, hasStylus);
}

/**
 * Intersect two sets in-place, storing the result in 'set1'.
 * Find elements in set1 that are not present in set2 and delete them,
 * relying on the fact that the two sets are ordered.
 */
template <typename T>
static void intersectInPlace(std::set<T>& set1, const std::set<T>& set2) {
    typename std::set<T>::iterator it1 = set1.begin();
    typename std::set<T>::const_iterator it2 = set2.begin();
    while (it1 != set1.end() && it2 != set2.end()) {
        const T& element1 = *it1;
        const T& element2 = *it2;
        if (element1 < element2) {
            // This element is not present in set2. Remove it from set1.
            it1 = set1.erase(it1);
            continue;
        }
        if (element2 < element1) {
            it2++;
        }
        if (element1 == element2) {
            it1++;
            it2++;
        }
    }
    // Remove the rest of the elements in set1 because set2 is already exhausted.
    set1.erase(it1, set1.end());
}

/**
 * Same as above, but prune a map
 */
template <typename K, class V>
static void intersectInPlace(std::map<K, V>& map, const std::set<K>& set2) {
    typename std::map<K, V>::iterator it1 = map.begin();
    typename std::set<K>::const_iterator it2 = set2.begin();
    while (it1 != map.end() && it2 != set2.end()) {
        const auto& [key, _] = *it1;
        const K& element2 = *it2;
        if (key < element2) {
            // This element is not present in set2. Remove it from map.
            it1 = map.erase(it1);
            continue;
        }
        if (element2 < key) {
            it2++;
        }
        if (key == element2) {
            it1++;
            it2++;
        }
    }
    // Remove the rest of the elements in map because set2 is already exhausted.
    map.erase(it1, map.end());
}

// -------------------------------- PreferStylusOverTouchBlocker -----------------------------------

std::vector<NotifyMotionArgs> PreferStylusOverTouchBlocker::processMotion(
        const NotifyMotionArgs& args) {
    const auto [hasTouch, hasStylus] = checkToolType(args);
    const bool isUpOrCancel =
            args.action == AMOTION_EVENT_ACTION_UP || args.action == AMOTION_EVENT_ACTION_CANCEL;

    if (hasTouch && hasStylus) {
        mDevicesWithMixedToolType.insert(args.deviceId);
    }
    // Handle the case where mixed touch and stylus pointers are reported. Add this device to the
    // ignore list, since it clearly supports simultaneous touch and stylus.
    if (mDevicesWithMixedToolType.find(args.deviceId) != mDevicesWithMixedToolType.end()) {
        // This event comes from device with mixed stylus and touch event. Ignore this device.
        if (mCanceledDevices.find(args.deviceId) != mCanceledDevices.end()) {
            // If we started to cancel events from this device, continue to do so to keep
            // the stream consistent. It should happen at most once per "mixed" device.
            if (isUpOrCancel) {
                mCanceledDevices.erase(args.deviceId);
                mLastTouchEvents.erase(args.deviceId);
            }
            return {};
        }
        return {args};
    }

    const bool isStylusEvent = hasStylus;
    const bool isDown = args.action == AMOTION_EVENT_ACTION_DOWN;

    if (isStylusEvent) {
        if (isDown) {
            // Reject all touch while stylus is down
            mActiveStyli.insert(args.deviceId);

            // Cancel all current touch!
            std::vector<NotifyMotionArgs> result;
            for (auto& [deviceId, lastTouchEvent] : mLastTouchEvents) {
                if (mCanceledDevices.find(deviceId) != mCanceledDevices.end()) {
                    // Already canceled, go to next one.
                    continue;
                }
                // Not yet canceled. Cancel it.
                lastTouchEvent.action = AMOTION_EVENT_ACTION_CANCEL;
                lastTouchEvent.flags |= AMOTION_EVENT_FLAG_CANCELED;
                lastTouchEvent.eventTime = systemTime(SYSTEM_TIME_MONOTONIC);
                result.push_back(lastTouchEvent);
                mCanceledDevices.insert(deviceId);
            }
            result.push_back(args);
            return result;
        }
        if (isUpOrCancel) {
            mActiveStyli.erase(args.deviceId);
        }
        // Never drop stylus events
        return {args};
    }

    const bool isTouchEvent = hasTouch;
    if (isTouchEvent) {
        // Suppress the current gesture if any stylus is still down
        if (!mActiveStyli.empty()) {
            mCanceledDevices.insert(args.deviceId);
        }

        const bool shouldDrop = mCanceledDevices.find(args.deviceId) != mCanceledDevices.end();
        if (isUpOrCancel) {
            mCanceledDevices.erase(args.deviceId);
            mLastTouchEvents.erase(args.deviceId);
        }

        // If we already canceled the current gesture, then continue to drop events from it, even if
        // the stylus has been lifted.
        if (shouldDrop) {
            return {};
        }

        if (!isUpOrCancel) {
            mLastTouchEvents[args.deviceId] = args;
        }
        return {args};
    }

    // Not a touch or stylus event
    return {args};
}

void PreferStylusOverTouchBlocker::notifyInputDevicesChanged(
        const std::vector<InputDeviceInfo>& inputDevices) {
    std::set<int32_t> presentDevices;
    for (const InputDeviceInfo& device : inputDevices) {
        presentDevices.insert(device.getId());
    }
    // Only keep the devices that are still present.
    intersectInPlace(mDevicesWithMixedToolType, presentDevices);
    intersectInPlace(mLastTouchEvents, presentDevices);
    intersectInPlace(mCanceledDevices, presentDevices);
    intersectInPlace(mActiveStyli, presentDevices);
}

void PreferStylusOverTouchBlocker::notifyDeviceReset(const NotifyDeviceResetArgs& args) {
    mDevicesWithMixedToolType.erase(args.deviceId);
    mLastTouchEvents.erase(args.deviceId);
    mCanceledDevices.erase(args.deviceId);
    mActiveStyli.erase(args.deviceId);
}

static std::string dumpArgs(const NotifyMotionArgs& args) {
    return args.dump();
}

std::string PreferStylusOverTouchBlocker::dump() const {
    std::string out;
    out += "mActiveStyli: " + dumpSet(mActiveStyli) + "\n";
    out += "mLastTouchEvents: " + dumpMap(mLastTouchEvents, constToString, dumpArgs) + "\n";
    out += "mDevicesWithMixedToolType: " + dumpSet(mDevicesWithMixedToolType) + "\n";
    out += "mCanceledDevices: " + dumpSet(mCanceledDevices) + "\n";
    return out;
}

} // namespace android
