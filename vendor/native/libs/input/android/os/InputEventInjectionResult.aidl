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

/**
 * Constants used to report the outcome of input event injection.
 *
 * @hide
 */
@Backing(type="int")
enum InputEventInjectionResult {
    /* (INTERNAL USE ONLY) Specifies that injection is pending and its outcome is unknown. */
    PENDING = -1,

    /* Injection succeeded. */
    SUCCEEDED = 0,

    /* Injection failed because the injected event did not target the appropriate window. */
    TARGET_MISMATCH = 1,

    /* Injection failed because there were no available input targets. */
    FAILED = 2,

    /* Injection failed due to a timeout. */
    TIMED_OUT = 3,
}
