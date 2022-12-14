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

#ifndef _UI_INPUT_INPUTDISPATCHER_INPUTDISPATCHERPOLICYINTERFACE_H
#define _UI_INPUT_INPUTDISPATCHER_INPUTDISPATCHERPOLICYINTERFACE_H

#include "InputDispatcherConfiguration.h"

#include <binder/IBinder.h>
#include <input/Input.h>
#include <utils/RefBase.h>

namespace android {

class InputApplicationHandle;

/*
 * Input dispatcher policy interface.
 *
 * The input reader policy is used by the input reader to interact with the Window Manager
 * and other system components.
 *
 * The actual implementation is partially supported by callbacks into the DVM
 * via JNI.  This interface is also mocked in the unit tests.
 */
class InputDispatcherPolicyInterface : public virtual RefBase {
protected:
    InputDispatcherPolicyInterface() {}
    virtual ~InputDispatcherPolicyInterface() {}

public:
    /* Notifies the system that a configuration change has occurred. */
    virtual void notifyConfigurationChanged(nsecs_t when) = 0;

    /* Notifies the system that an application is not responding.
     * Returns a new timeout to continue waiting, or 0 to abort dispatch. */
    virtual nsecs_t notifyAnr(const sp<InputApplicationHandle>& inputApplicationHandle,
                              const sp<IBinder>& token, const std::string& reason) = 0;

    /* Notifies the system that an input channel is unrecoverably broken. */
    virtual void notifyInputChannelBroken(const sp<IBinder>& token) = 0;
    virtual void notifyFocusChanged(const sp<IBinder>& oldToken, const sp<IBinder>& newToken) = 0;

    /* Gets the input dispatcher configuration. */
    virtual void getDispatcherConfiguration(InputDispatcherConfiguration* outConfig) = 0;

    /* Filters an input event.
     * Return true to dispatch the event unmodified, false to consume the event.
     * A filter can also transform and inject events later by passing POLICY_FLAG_FILTERED
     * to injectInputEvent.
     */
    virtual bool filterInputEvent(const InputEvent* inputEvent, uint32_t policyFlags) = 0;

    /* Intercepts a key event immediately before queueing it.
     * The policy can use this method as an opportunity to perform power management functions
     * and early event preprocessing such as updating policy flags.
     *
     * This method is expected to set the POLICY_FLAG_PASS_TO_USER policy flag if the event
     * should be dispatched to applications.
     */
    virtual void interceptKeyBeforeQueueing(const KeyEvent* keyEvent, uint32_t& policyFlags) = 0;

    /* Intercepts a touch, trackball or other motion event before queueing it.
     * The policy can use this method as an opportunity to perform power management functions
     * and early event preprocessing such as updating policy flags.
     *
     * This method is expected to set the POLICY_FLAG_PASS_TO_USER policy flag if the event
     * should be dispatched to applications.
     */
    virtual void interceptMotionBeforeQueueing(const int32_t displayId, nsecs_t when,
                                               uint32_t& policyFlags) = 0;

    /* Allows the policy a chance to intercept a key before dispatching. */
    virtual nsecs_t interceptKeyBeforeDispatching(const sp<IBinder>& token,
                                                  const KeyEvent* keyEvent,
                                                  uint32_t policyFlags) = 0;

    /* Allows the policy a chance to perform default processing for an unhandled key.
     * Returns an alternate keycode to redispatch as a fallback, or 0 to give up. */
    virtual bool dispatchUnhandledKey(const sp<IBinder>& token, const KeyEvent* keyEvent,
                                      uint32_t policyFlags, KeyEvent* outFallbackKeyEvent) = 0;

    /* Notifies the policy about switch events.
     */
    virtual void notifySwitch(nsecs_t when, uint32_t switchValues, uint32_t switchMask,
                              uint32_t policyFlags) = 0;

    /* Poke user activity for an event dispatched to a window. */
    virtual void pokeUserActivity(nsecs_t eventTime, int32_t eventType) = 0;

    /* Checks whether a given application pid/uid has permission to inject input events
     * into other applications.
     *
     * This method is special in that its implementation promises to be non-reentrant and
     * is safe to call while holding other locks.  (Most other methods make no such guarantees!)
     */
    virtual bool checkInjectEventsPermissionNonReentrant(int32_t injectorPid,
                                                         int32_t injectorUid) = 0;

    /* Notifies the policy that a pointer down event has occurred outside the current focused
     * window.
     *
     * The touchedToken passed as an argument is the window that received the input event.
     */
    virtual void onPointerDownOutsideFocus(const sp<IBinder>& touchedToken) = 0;
};

} // namespace android

#endif // _UI_INPUT_INPUTDISPATCHER_INPUTDISPATCHERPOLICYINTERFACE_H
