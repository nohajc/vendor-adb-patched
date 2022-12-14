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

#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <iostream>

[[noreturn]] static void usage(int exit_status) {
    std::cerr << "Usage: " << getprogname() << " <tid> <uclamp_min> <uclamp_max>" << std::endl
              << "    tid      Thread ID to apply the uclamp setting." << std::endl
              << "    uclamp_min  uclamp.min value range from [0, 1024]." << std::endl
              << "    uclamp_max  uclamp.max value range from [0, 1024]." << std::endl;
    exit(exit_status);
}

struct sched_attr {
    __u32 size;
    __u32 sched_policy;
    __u64 sched_flags;
    __s32 sched_nice;
    __u32 sched_priority;
    __u64 sched_runtime;
    __u64 sched_deadline;
    __u64 sched_period;
    __u32 sched_util_min;
    __u32 sched_util_max;
};

static int sched_setattr(int pid, struct sched_attr* attr, unsigned int flags) {
    return syscall(__NR_sched_setattr, pid, attr, flags);
}

static int set_uclamp(int32_t min, int32_t max, int tid) {
    sched_attr attr = {};
    attr.size = sizeof(attr);

    attr.sched_flags = (SCHED_FLAG_KEEP_ALL | SCHED_FLAG_UTIL_CLAMP);
    attr.sched_util_min = min;
    attr.sched_util_max = max;

    int ret = sched_setattr(tid, &attr, 0);
    if (ret) {
        int err = errno;
        std::cerr << "sched_setattr failed for thread " << tid << " err=" << err << std::endl;
    }

    return ret;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage(EXIT_FAILURE);
    }

    int tid = atoi(argv[1]);
    int uclamp_min = atoi(argv[2]);
    int uclamp_max = atoi(argv[3]);

    return set_uclamp(uclamp_min, uclamp_max, tid);
}
