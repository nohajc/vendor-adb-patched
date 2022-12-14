/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/logging.h>
#include <binder/BpBinder.h>
#include <binder/IServiceManager.h>
#include <binderdebug/BinderDebug.h>
#include <utils/Errors.h>

#include <inttypes.h>

namespace android {

extern "C" int main() {
    // ignore args - we only print csv

    // we should use a csv library here for escaping, because
    // the name is coming from another process
    printf("name,binder_threads_in_use,binder_threads_started,client_count\n");

    for (const String16& name : defaultServiceManager()->listServices()) {
        sp<IBinder> binder = defaultServiceManager()->checkService(name);
        if (binder == nullptr) {
            fprintf(stderr, "%s is null", String8(name).c_str());
            continue;
        }

        BpBinder* remote = binder->remoteBinder();
        const auto handle = remote->getDebugBinderHandle();
        CHECK(handle != std::nullopt);

        pid_t pid;
        CHECK_EQ(OK, binder->getDebugPid(&pid));

        BinderPidInfo info;
        CHECK_EQ(OK, getBinderPidInfo(BinderDebugContext::BINDER, pid, &info));

        std::vector<pid_t> clientPids;
        CHECK_EQ(OK,
                 getBinderClientPids(BinderDebugContext::BINDER, getpid(), pid, *handle,
                                     &clientPids));

        printf("%s,%" PRIu32 ",%" PRIu32 ",%zu\n", String8(name).c_str(), info.threadUsage,
               info.threadCount, clientPids.size());
    }
    return 0;
}

} // namespace android
