/*
 * Copyright 2019 The Android Open Source Project
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

#pragma once

#include <android/data_space.h>
#include <android/hardware_buffer.h>
#include <inttypes.h>

// TODO: the intention of these apis is to be stable - hence they are defined in
// an apex directory. But because they don't yet need to be stable, hold off on
// making them stable until a Mainline module needs them.
// #ifdef __cplusplus
extern "C" {
#endif

namespace android {

/**
 * Opaque handle for a native display
 */
typedef struct ADisplay ADisplay;

/**
 * Enum describing the possible types of a display
 */
enum ADisplayType {
    /**
     * A display that is the internal, or "primary" display for a device.
     */
    DISPLAY_TYPE_INTERNAL = 0,

    /**
     * A display that is externally connected for a device.
     */
    DISPLAY_TYPE_EXTERNAL = 1,
};

/**
 * Opaque handle for display metadata
 */
typedef struct ADisplayConfig ADisplayConfig;

/**
 * Acquires a list of display handles. Memory is allocated for the list and is
 * owned by the caller. The caller is responsible for freeing this memory by
 * calling ADisplayList_release.
 *
 * Returns the size of the returned list on success.
 * Returns -errno on error.
 */
int ADisplay_acquirePhysicalDisplays(ADisplay*** outDisplays);

/**
 * Releases a list of display handles created by
 * ADisplayList_acquirePhysicalDisplays.
 */
void ADisplay_release(ADisplay** displays);

/**
 * Queries the maximum supported fps for the given display.
 */
float ADisplay_getMaxSupportedFps(ADisplay* display);

/**
 * Queries the display's type.
 */
ADisplayType ADisplay_getDisplayType(ADisplay* display);

/**
 * Queries the display's preferred WCG format
 */
void ADisplay_getPreferredWideColorFormat(ADisplay* display, ADataSpace* outDataspace,
                                          AHardwareBuffer_Format* outPixelFormat);

/**
 * Gets the current display configuration for the given display.
 *
 * Memory is *not* allocated for the caller. As such, the returned output
 * configuration's lifetime will not be longer than the ADisplay* passed to this
 * function - if ADisplay_release is called destroying the ADisplay object then
 * it is invalid to access the ADisplayConfig returned here.
 *
 * Note that the current display configuration can change. Listening to updates
 * to the current display configuration should be done via Choreographer. If
 * such an update is observed, then this method should be recalled to get the
 * new current configuration.
 *
 * After a subsequent hotplug "connected" event the supported display configs
 * may change. Then the preloaded display configs will be stale and the
 * call for current config may return NAME_NOT_FOUND. In this case the client
 * should release and re-acquire the display handle.
 *
 * Returns OK on success, -errno on failure.
 */
int ADisplay_getCurrentConfig(ADisplay* display, ADisplayConfig** outConfig);

/**
 * Queries the width in pixels for a given display configuration.
 */
int32_t ADisplayConfig_getWidth(ADisplayConfig* config);

/**
 * Queries the height in pixels for a given display configuration.
 */
int32_t ADisplayConfig_getHeight(ADisplayConfig* config);

/**
 * Queries the display refresh rate for a given display configuration.
 */
float ADisplayConfig_getFps(ADisplayConfig* config);

/**
 * Queries the vsync offset from which the system compositor is scheduled to
 * run. If a vsync occurs at time T, and the compositor runs at time T + S, then
 * this returns S in nanoseconds.
 */
int64_t ADisplayConfig_getCompositorOffsetNanos(ADisplayConfig* config);

/**
 * Queries the vsync offset from which applications are scheduled to run. If a
 * vsync occurs at time T, and applications run at time T + S, then this returns
 * S in nanoseconds.
 */
int64_t ADisplayConfig_getAppVsyncOffsetNanos(ADisplayConfig* config);

} // namespace android
// #ifdef __cplusplus
}
#endif
