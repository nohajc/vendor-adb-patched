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

package android.gui;

/** @hide */
parcelable DisplayBrightness {
    // Range 0-1f, the desired sdr white point brightness
    float sdrWhitePoint = 0f;

    // The SDR white point in nits. -1 if unknown
    float sdrWhitePointNits = -1f;

    // Range 0-1f, the desired brightness of the display itself. -1f to turn the backlight off
    float displayBrightness = 0f;

    // The desired brightness of the display in nits. -1 if unknown
    float displayBrightnessNits = -1f;
}