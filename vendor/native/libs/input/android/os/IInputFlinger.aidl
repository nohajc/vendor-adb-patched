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

import android.InputChannel;
import android.gui.FocusRequest;
import android.gui.WindowInfo;

/** @hide */
interface IInputFlinger
{
    InputChannel createInputChannel(in @utf8InCpp String name);
    void removeInputChannel(in IBinder connectionToken);
    /**
     * Sets focus to the window identified by the token. This must be called
     * after updating any input window handles.
     */
    oneway void setFocusedWindow(in FocusRequest request);
}
