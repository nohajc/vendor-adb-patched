/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <uapi/trusty_uuid.h>

#define INFINITE_TIME 1
#define IPC_MAX_MSG_HANDLES 8

#define IPC_PORT_ALLOW_TA_CONNECT 0x1
#define IPC_PORT_ALLOW_NS_CONNECT 0x2

#define IPC_CONNECT_WAIT_FOR_PORT 0x1

#define IPC_HANDLE_POLL_HUP 0x1
#define IPC_HANDLE_POLL_MSG 0x2
#define IPC_HANDLE_POLL_SEND_UNBLOCKED 0x4

typedef int handle_t;

typedef struct ipc_msg {
    uint32_t num_iov;
    iovec* iov;
    uint32_t num_handles;
    handle_t* handles;
} ipc_msg_t;

typedef struct ipc_msg_info {
    size_t len;
    uint32_t id;
    uint32_t num_handles;
} ipc_msg_info_t;

typedef struct uevent {
    uint32_t event;
} uevent_t;

static inline handle_t port_create(const char*, uint32_t, uint32_t, uint32_t) {
    return 0;
}
static inline handle_t connect(const char*, uint32_t) {
    return 0;
}
static inline handle_t accept(handle_t, uuid_t*) {
    return 0;
}
static inline int set_cookie(handle_t, void*) {
    return 0;
}
static inline handle_t handle_set_create(void) {
    return 0;
}
static inline int handle_set_ctrl(handle_t, uint32_t, struct uevent*) {
    return 0;
}
static inline int wait(handle_t, uevent_t*, uint32_t) {
    return 0;
}
static inline int wait_any(uevent_t*, uint32_t) {
    return 0;
}
static inline int get_msg(handle_t, ipc_msg_info_t*) {
    return 0;
}
static inline ssize_t read_msg(handle_t, uint32_t, uint32_t, ipc_msg_t*) {
    return 0;
}
static inline int put_msg(handle_t, uint32_t) {
    return 0;
}
static inline ssize_t send_msg(handle_t, ipc_msg_t*) {
    return 0;
}
