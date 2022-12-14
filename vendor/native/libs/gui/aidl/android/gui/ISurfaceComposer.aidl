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

import android.gui.DisplayCaptureArgs;
import android.gui.DisplayBrightness;
import android.gui.DisplayState;
import android.gui.DisplayStatInfo;
import android.gui.IHdrLayerInfoListener;
import android.gui.LayerCaptureArgs;
import android.gui.IScreenCaptureListener;

/** @hide */
interface ISurfaceComposer {

    /* create a virtual display
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    @nullable IBinder createDisplay(@utf8InCpp String displayName, boolean secure);

    /* destroy a virtual display
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    void destroyDisplay(IBinder display);

    /* get stable IDs for connected physical displays.
     */
    long[] getPhysicalDisplayIds();

    long getPrimaryPhysicalDisplayId();

    /* get token for a physical display given its stable ID obtained via getPhysicalDisplayIds or a
     * DisplayEventReceiver hotplug event.
     */
    @nullable IBinder getPhysicalDisplayToken(long displayId);

    /* set display power mode. depending on the mode, it can either trigger
     * screen on, off or low power mode and wait for it to complete.
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    void setPowerMode(IBinder display, int mode);

    /**
     * Returns display statistics for a given display
     * intended to be used by the media framework to properly schedule
     * video frames */
    DisplayStatInfo getDisplayStats(@nullable IBinder display);

     /**
     * Get transactional state of given display.
     */
    DisplayState getDisplayState(IBinder display);

    /**
     * Clears the user-preferred display mode. The device should now boot in system preferred
     * display mode.
     */
    void clearBootDisplayMode(IBinder display);

    /**
     * Gets whether boot time display mode operations are supported on the device.
     *
     * outSupport
     *      An output parameter for whether boot time display mode operations are supported.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND if the display is invalid, or
     *      BAD_VALUE      if the output parameter is invalid.
     */
    // TODO(b/213909104) : Add unit tests to verify surface flinger boot time APIs
    boolean getBootDisplayModeSupport();

    /**
     * Switches Auto Low Latency Mode on/off on the connected display, if it is
     * available. This should only be called if the display supports Auto Low
     * Latency Mode as reported in #getDynamicDisplayInfo.
     * For more information, see the HDMI 2.1 specification.
     */
    void setAutoLowLatencyMode(IBinder display, boolean on);

    /**
     * This will start sending infoframes to the connected display with
     * ContentType=Game (if on=true). This should only be called if the display
     * Game Content Type as reported in #getDynamicDisplayInfo.
     * For more information, see the HDMI 1.4 specification.
     */
    void setGameContentType(IBinder display, boolean on);

    /**
     * Capture the specified screen. This requires READ_FRAME_BUFFER
     * permission.  This function will fail if there is a secure window on
     * screen and DisplayCaptureArgs.captureSecureLayers is false.
     *
     * This function can capture a subregion (the source crop) of the screen.
     * The subregion can be optionally rotated.  It will also be scaled to
     * match the size of the output buffer.
     */
    void captureDisplay(in DisplayCaptureArgs args, IScreenCaptureListener listener);
    void captureDisplayById(long displayId, IScreenCaptureListener listener);
    /**
     * Capture a subtree of the layer hierarchy, potentially ignoring the root node.
     * This requires READ_FRAME_BUFFER permission. This function will fail if there
     * is a secure window on screen
     */
    void captureLayers(in LayerCaptureArgs args, IScreenCaptureListener listener);

    /*
     * Queries whether the given display is a wide color display.
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    boolean isWideColorDisplay(IBinder token);

    /*
     * Gets whether brightness operations are supported on a display.
     *
     * displayToken
     *      The token of the display.
     * outSupport
     *      An output parameter for whether brightness operations are supported.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND if the display is invalid, or
     *      BAD_VALUE      if the output parameter is invalid.
     */
    boolean getDisplayBrightnessSupport(IBinder displayToken);

    /*
     * Sets the brightness of a display.
     *
     * displayToken
     *      The token of the display whose brightness is set.
     * brightness
     *      The DisplayBrightness info to set on the desired display.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND    if the display is invalid, or
     *      BAD_VALUE         if the brightness is invalid, or
     *      INVALID_OPERATION if brightness operations are not supported.
     */
    void setDisplayBrightness(IBinder displayToken, in DisplayBrightness brightness);

    /*
     * Adds a listener that receives HDR layer information. This is used in combination
     * with setDisplayBrightness to adjust the display brightness depending on factors such
     * as whether or not HDR is in use.
     *
     * Returns NO_ERROR upon success or NAME_NOT_FOUND if the display is invalid.
     */
    void addHdrLayerInfoListener(IBinder displayToken, IHdrLayerInfoListener listener);

    /*
     * Removes a listener that was added with addHdrLayerInfoListener.
     *
     * Returns NO_ERROR upon success, NAME_NOT_FOUND if the display is invalid, and BAD_VALUE if
     *     the listener wasn't registered.
     *
     */
    void removeHdrLayerInfoListener(IBinder displayToken, IHdrLayerInfoListener listener);

    /*
     * Sends a power boost to the composer. This function is asynchronous.
     *
     * boostId
     *      boost id according to android::hardware::power::Boost
     *
     * Returns NO_ERROR upon success.
     */
    void notifyPowerBoost(int boostId);
}
