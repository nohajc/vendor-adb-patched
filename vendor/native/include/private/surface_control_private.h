/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_PRIVATE_NATIVE_SURFACE_CONTROL_H
#define ANDROID_PRIVATE_NATIVE_SURFACE_CONTROL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ASurfaceControl;
struct ASurfaceControlStats;

typedef struct ASurfaceControlStats ASurfaceControlStats;

/**
 * Callback to be notified when surface stats for a specific surface control are available.
 */
typedef void (*ASurfaceControl_SurfaceStatsListener)(void* context, int32_t id,
        ASurfaceControlStats* stats);

/**
 * Registers a callback to be invoked when surface stats from a specific surface are available.
 *
 * \param context Optional context provided by the client that is passed into
 * the callback.
 *
 * \param control The surface to retrieve callbacks for.
 *
 * \param func The callback to be invoked when surface stats are available.
 */
void ASurfaceControl_registerSurfaceStatsListener(ASurfaceControl* control, int32_t id, void* context,
        ASurfaceControl_SurfaceStatsListener func);

/**
 * Unregisters a callback to be invoked when surface stats from a specific surface are available.
 *
 * \param context The context passed into ASurfaceControl_registerSurfaceStatsListener
 *
 * \param func The callback passed into ASurfaceControl_registerSurfaceStatsListener
 */
void ASurfaceControl_unregisterSurfaceStatsListener(void* context,
                                       ASurfaceControl_SurfaceStatsListener func);

/**
 * Returns the timestamp of when the buffer was acquired for a specific frame with frame number
 * obtained from ASurfaceControlStats_getFrameNumber.
 */
int64_t ASurfaceControlStats_getAcquireTime(ASurfaceControlStats* stats);

/**
 * Returns the frame number of the surface stats object passed into the callback.
 */
uint64_t ASurfaceControlStats_getFrameNumber(ASurfaceControlStats* stats);

#ifdef __cplusplus
}
#endif

#endif //ANDROID_PRIVATE_NATIVE_SURFACE_CONTROL_H
