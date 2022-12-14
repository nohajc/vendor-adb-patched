/*
 * Copyright 2020 The Android Open Source Project
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

#include <bpf_helpers.h>

/*
 * On Android the number of active processes using gpu is limited.
 * So this is assumed to be true: SUM(num_procs_using_gpu[i]) <= 1024
 */
#define GPU_MEM_TOTAL_MAP_SIZE 1024

/*
 * This map maintains the global and per process gpu memory total counters.
 *
 * The KEY is ((gpu_id << 32) | pid) while VAL is the size in bytes.
 * Use HASH type here since key is not int.
 * Pass AID_GRAPHICS as gid since gpuservice is in the graphics group.
 */
DEFINE_BPF_MAP_GRO(gpu_mem_total_map, HASH, uint64_t, uint64_t, GPU_MEM_TOTAL_MAP_SIZE,
                   AID_GRAPHICS);

/* This struct aligns with the fields offsets of the raw tracepoint format */
struct gpu_mem_total_args {
    uint64_t ignore;
    /* Actual fields start at offset 8 */
    uint32_t gpu_id;
    uint32_t pid;
    uint64_t size;
};

/*
 * This program parses the gpu_mem/gpu_mem_total tracepoint's data into
 * {KEY, VAL} pair used to update the corresponding bpf map.
 *
 * Pass AID_GRAPHICS as gid since gpuservice is in the graphics group.
 * Upon seeing size 0, the corresponding KEY needs to be cleaned up.
 */
DEFINE_BPF_PROG("tracepoint/gpu_mem/gpu_mem_total", AID_ROOT, AID_GRAPHICS, tp_gpu_mem_total)
(struct gpu_mem_total_args* args) {
    uint64_t key = 0;
    uint64_t cur_val = 0;
    uint64_t* prev_val = NULL;

    /* The upper 32 bits are for gpu_id while the lower is the pid */
    key = ((uint64_t)args->gpu_id << 32) | args->pid;
    cur_val = args->size;

    if (!cur_val) {
        bpf_gpu_mem_total_map_delete_elem(&key);
        return 0;
    }

    prev_val = bpf_gpu_mem_total_map_lookup_elem(&key);
    if (prev_val) {
        *prev_val = cur_val;
    } else {
        bpf_gpu_mem_total_map_update_elem(&key, &cur_val, BPF_NOEXIST);
    }
    return 0;
}

LICENSE("Apache 2.0");
