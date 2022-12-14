/*
 * Copyright 2021 The Android Open Source Project
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

package android.hardware.display;

/** @hide */
interface IDeviceProductInfoConstants {
    /** The device connection to the display sink is unknown. */
    const int CONNECTION_TO_SINK_UNKNOWN = 0;

    /** The device is built-in in the display sink. */
    const int CONNECTION_TO_SINK_BUILT_IN = 1;

    /** The device is directly connected to the display sink. */
    const int CONNECTION_TO_SINK_DIRECT = 2;

    /** The device is transitively connected to the display sink. */
    const int CONNECTION_TO_SINK_TRANSITIVE = 3;
}