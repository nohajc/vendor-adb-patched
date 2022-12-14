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

package android.gui;

/** @hide */
parcelable FocusRequest {
    /**
     * Input channel token used to identify the window that should gain focus.
     */
    @nullable IBinder token;
    @utf8InCpp String windowName;
    /**
     * The token that the caller expects currently to be focused. If the
     * specified token does not match the currently focused window, this request will be dropped.
     * If the specified focused token matches the currently focused window, the call will succeed.
     * Set this to "null" if this call should succeed no matter what the currently focused token
     * is.
     */
    @nullable IBinder focusedToken;
    @utf8InCpp String focusedWindowName;
    /**
     * SYSTEM_TIME_MONOTONIC timestamp in nanos set by the client (wm) when requesting the focus
     * change. This determines which request gets precedence if there is a focus change request
     * from another source such as pointer down.
     */
    long timestamp;
    /**
     * Display id associated with this request.
     */
     int displayId;
}
