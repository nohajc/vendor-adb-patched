/**
 * Copyright (c) 2016, The Android Open Source Project
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
  * Listener for dumpstate events.
  *
  * <p>When bugreport creation is complete one of {@code onError} or {@code onFinished} is called.
  *
  *
  * {@hide}
  */
interface IDumpstateListener {
    /**
     * Called when there is a progress update.
     *
     * @param progress the progress in [0, 100]
     */
    oneway void onProgress(int progress);

    // NOTE: If you add to or change these error codes, please also change the corresponding enums
    // in system server, in BugreportManager.java.

    /* Options specified are invalid or incompatible */
    const int BUGREPORT_ERROR_INVALID_INPUT = 1;

    /* Bugreport encountered a runtime error */
    const int BUGREPORT_ERROR_RUNTIME_ERROR = 2;

    /* User denied consent to share the bugreport with the specified app */
    const int BUGREPORT_ERROR_USER_DENIED_CONSENT = 3;

    /* The request to get user consent timed out */
    const int BUGREPORT_ERROR_USER_CONSENT_TIMED_OUT = 4;

    /* There is currently a bugreport running. The caller should try again later. */
    const int BUGREPORT_ERROR_ANOTHER_REPORT_IN_PROGRESS = 5;

    /**
     * Called on an error condition with one of the error codes listed above.
     */
    oneway void onError(int errorCode);

    /**
     * Called when taking bugreport finishes successfully.
     */
    oneway void onFinished();

    /**
     * Called when screenshot is taken.
     */
    oneway void onScreenshotTaken(boolean success);

    /**
     * Called when ui intensive bugreport dumps are finished.
     */
    oneway void onUiIntensiveBugreportDumpsFinished();
}
