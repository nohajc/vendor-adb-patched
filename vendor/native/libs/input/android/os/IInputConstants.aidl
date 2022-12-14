/**
 * Copyright (c) 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.os;


/** @hide */
interface IInputConstants
{
    // This should be multiplied by the value of the system property ro.hw_timeout_multiplier before
    // use. A pre-multiplied constant is available in Java in
    // android.os.InputConstants.DEFAULT_DISPATCHING_TIMEOUT_MILLIS.
    const int UNMULTIPLIED_DEFAULT_DISPATCHING_TIMEOUT_MILLIS = 5000; // 5 seconds

    // Indicate invalid battery capacity
    const int INVALID_BATTERY_CAPACITY = -1;

    /**
     * Every input event has an id. This constant value is used when a valid input event id is not
     * available.
     */
    const int INVALID_INPUT_EVENT_ID = 0;

    /**
     * The input event was injected from accessibility. Used in policyFlags for input event
     * injection.
     */
    const int POLICY_FLAG_INJECTED_FROM_ACCESSIBILITY = 0x20000;

    /**
     * The input event was generated or modified by accessibility service.
     * Shared by both KeyEvent and MotionEvent flags, so this value should not overlap with either
     * set of flags, including in input/Input.h and in android/input.h.
     */
    const int INPUT_EVENT_FLAG_IS_ACCESSIBILITY_EVENT = 0x800;

    /* The default pointer acceleration value. */
    const int DEFAULT_POINTER_ACCELERATION = 3;
}
