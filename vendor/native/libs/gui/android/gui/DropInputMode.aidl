/**
 * Copyright (c) 2021, The Android Open Source Project
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


/**
  * Input event drop modes: Input event drop options for windows and its children.
  *
  * @hide
  */
@Backing(type="int")
enum DropInputMode {
    /**
      * Default mode, input events are sent to the target as usual.
      */
    NONE,

    /**
      * Window and its children will not receive any input even if it has a valid input channel.
      * Touches and keys will be dropped. If a window is focused, it will remain focused but will
      * not receive any keys. If the window has a touchable region and is the target of an input
      * event, the event will be dropped and will not go to the window behind. ref: b/197296414
      */
    ALL,

    /**
      * Similar to DROP but input events are only dropped if the window is considered to be
      * obscured. ref: b/197364677
      */
    OBSCURED
}
