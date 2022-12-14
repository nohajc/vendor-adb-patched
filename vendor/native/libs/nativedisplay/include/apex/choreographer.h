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

#include <android/choreographer.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates an instance of AChoreographer.
 *
 * The key differences between this method and AChoreographer_getInstance are:
 * 1. The returned AChoreographer instance is not a thread-local, and
 * 2. This method does not require an existing ALooper attached to the thread.
 */
AChoreographer* AChoreographer_create();

/**
 * Destroys a choreographer instance created from AChoreographer_create.
 */
void AChoreographer_destroy(AChoreographer* choreographer);

/**
 * Returns the underlying file descriptor associated with this choreographer
 * instance.
 *
 * The caller can listen to the file descriptor to respond to any AChoreographer
 * events. One such way is registering the file descriptor to a Looper instance,
 * although this is not a requirement.
 */
int AChoreographer_getFd(const AChoreographer* choreographer);

/**
 * Provides a callback to handle all pending events emitted by this
 * choreographer instance. Specifically, this delegates to the callbacks
 * previously registered to choreographer.
 *
 * If the associated file descriptor is attached to a Looper instance, then the
 * callback attached to that Looper is expected to handle exceptional Looper
 * events.
 */
void AChoreographer_handlePendingEvents(AChoreographer* choreographer, void* data);

#ifdef __cplusplus
}
#endif
