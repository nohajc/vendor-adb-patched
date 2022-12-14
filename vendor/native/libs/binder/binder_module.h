/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _BINDER_MODULE_H_
#define _BINDER_MODULE_H_

/* obtain structures and constants from the kernel header */

// TODO(b/31559095): bionic on host
#ifndef __ANDROID__
#define __packed __attribute__((__packed__))
#endif

// TODO(b/31559095): bionic on host
#if defined(B_PACK_CHARS) && !defined(_UAPI_LINUX_BINDER_H)
#undef B_PACK_CHARS
#endif

#include <linux/android/binder.h>
#include <sys/ioctl.h>

#ifndef BR_FROZEN_REPLY
// Temporary definition of BR_FROZEN_REPLY. For production
// this will come from UAPI binder.h
#define BR_FROZEN_REPLY _IO('r', 18)
#endif // BR_FROZEN_REPLY

#ifndef BINDER_FREEZE
/*
 * Temporary definitions for freeze support. For the final version
 * these will be defined in the UAPI binder.h file from upstream kernel.
 */
#define BINDER_FREEZE _IOW('b', 14, struct binder_freeze_info)

struct binder_freeze_info {
    //
    // Group-leader PID of process to be frozen
    //
    uint32_t pid;
    //
    // Enable(1) / Disable(0) freeze for given PID
    //
    uint32_t enable;
    //
    // Timeout to wait for transactions to drain.
    // 0: don't wait (ioctl will return EAGAIN if not drained)
    // N: number of ms to wait
    uint32_t timeout_ms;
};
#endif // BINDER_FREEZE

#ifndef BINDER_GET_FROZEN_INFO

#define BINDER_GET_FROZEN_INFO _IOWR('b', 15, struct binder_frozen_status_info)

struct binder_frozen_status_info {
    //
    // Group-leader PID of process to be queried
    //
    __u32 pid;
    //
    // Indicates whether the process has received any sync calls since last
    // freeze (cleared at freeze/unfreeze)
    //
    __u32 sync_recv;
    //
    // Indicates whether the process has received any async calls since last
    // freeze (cleared at freeze/unfreeze)
    //
    __u32 async_recv;
};
#endif // BINDER_GET_FROZEN_INFO

#ifndef BR_ONEWAY_SPAM_SUSPECT
// Temporary definition of BR_ONEWAY_SPAM_SUSPECT. For production
// this will come from UAPI binder.h
#define BR_ONEWAY_SPAM_SUSPECT _IO('r', 19)
#endif // BR_ONEWAY_SPAM_SUSPECT

#ifndef BINDER_ENABLE_ONEWAY_SPAM_DETECTION
/*
 * Temporary definitions for oneway spam detection support. For the final version
 * these will be defined in the UAPI binder.h file from upstream kernel.
 */
#define BINDER_ENABLE_ONEWAY_SPAM_DETECTION _IOW('b', 16, __u32)
#endif // BINDER_ENABLE_ONEWAY_SPAM_DETECTION

#endif // _BINDER_MODULE_H_
