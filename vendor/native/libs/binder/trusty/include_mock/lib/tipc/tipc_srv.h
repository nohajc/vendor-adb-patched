/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <trusty_ipc.h>
#include <uapi/trusty_uuid.h>

struct tipc_port_acl {
    uint32_t flags;
    uint32_t uuid_num;
    const struct uuid** uuids;
    const void* extra_data;
};

struct tipc_port {
    const char* name;
    uint32_t msg_max_size;
    uint32_t msg_queue_len;
    const struct tipc_port_acl* acl;
    const void* priv;
};

struct tipc_srv_ops {
    int (*on_connect)(const struct tipc_port* port, handle_t chan, const struct uuid* peer,
                      void** ctx_p);

    int (*on_message)(const struct tipc_port* port, handle_t chan, void* ctx);

    void (*on_disconnect)(const struct tipc_port* port, handle_t chan, void* ctx);

    void (*on_channel_cleanup)(void* ctx);
};

static inline int tipc_add_service(struct tipc_hset*, const struct tipc_port*, uint32_t, uint32_t,
                                   const struct tipc_srv_ops*) {
    return 0;
}
