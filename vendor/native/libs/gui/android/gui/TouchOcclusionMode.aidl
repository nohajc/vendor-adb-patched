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


/**
  * Touch occlusion modes: These modes represent how windows are taken into
  * consideration in order to decide whether to block obscured touches or
  * not.
  *
  * @hide
  */
@Backing(type="int")
enum TouchOcclusionMode {
    /**
      * Touches that pass through this window will be blocked if they are
      * consumed by a different UID and this window is not trusted.
      */
    BLOCK_UNTRUSTED,

    /**
      * The window's opacity will be taken into consideration for touch
      * occlusion rules if the touch passes through it and the window is not
      * trusted.
      */
    USE_OPACITY,

    /**
      * The window won't count for touch occlusion rules if the touch passes
      * through it.
      */
    ALLOW
}
