/*
 * Copyright (C) 2010 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <sys/resource.h>

#include <sched.h>

#include <android/frameworks/displayservice/1.0/IDisplayService.h>
#include <android/hardware/configstore/1.0/ISurfaceFlingerConfigs.h>
#include <android/hardware/graphics/allocator/2.0/IAllocator.h>
#include <android/hardware/graphics/allocator/3.0/IAllocator.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <configstore/Utils.h>
#include <displayservice/DisplayService.h>
#include <errno.h>
#include <hidl/LegacySupport.h>
#include <processgroup/sched_policy.h>
#include "SurfaceFlinger.h"
#include "SurfaceFlingerFactory.h"
#include "SurfaceFlingerProperties.h"

using namespace android;

static status_t startGraphicsAllocatorService() {
    using android::hardware::configstore::getBool;
    using android::hardware::configstore::V1_0::ISurfaceFlingerConfigs;
    if (!android::sysprop::start_graphics_allocator_service(false)) {
        return OK;
    }

    status_t result = hardware::registerPassthroughServiceImplementation<
            android::hardware::graphics::allocator::V3_0::IAllocator>();
    if (result == OK) {
        return OK;
    }

    result = hardware::registerPassthroughServiceImplementation<
            android::hardware::graphics::allocator::V2_0::IAllocator>();
    if (result != OK) {
        ALOGE("could not start graphics allocator service");
        return result;
    }

    return OK;
}

static void startDisplayService() {
    using android::frameworks::displayservice::V1_0::implementation::DisplayService;
    using android::frameworks::displayservice::V1_0::IDisplayService;

    sp<IDisplayService> displayservice = new DisplayService();
    status_t err = displayservice->registerAsService();

    // b/141930622
    if (err != OK) {
        ALOGE("Did not register (deprecated) IDisplayService service.");
    }
}

int main(int, char**) {
    signal(SIGPIPE, SIG_IGN);

    hardware::configureRpcThreadpool(1 /* maxThreads */,
            false /* callerWillJoin */);

    startGraphicsAllocatorService();

    // When SF is launched in its own process, limit the number of
    // binder threads to 4.
    ProcessState::self()->setThreadPoolMaxThreadCount(4);

    // Set uclamp.min setting on all threads, maybe an overkill but we want
    // to cover important threads like RenderEngine.
    if (SurfaceFlinger::setSchedAttr(true) != NO_ERROR) {
        ALOGW("Couldn't set uclamp.min: %s\n", strerror(errno));
    }

    // The binder threadpool we start will inherit sched policy and priority
    // of (this) creating thread. We want the binder thread pool to have
    // SCHED_FIFO policy and priority 1 (lowest RT priority)
    // Once the pool is created we reset this thread's priority back to
    // original.
    int newPriority = 0;
    int origPolicy = sched_getscheduler(0);
    struct sched_param origSchedParam;

    int errorInPriorityModification = sched_getparam(0, &origSchedParam);
    if (errorInPriorityModification == 0) {
        int policy = SCHED_FIFO;
        newPriority = sched_get_priority_min(policy);

        struct sched_param param;
        param.sched_priority = newPriority;

        errorInPriorityModification = sched_setscheduler(0, policy, &param);
    }

    // start the thread pool
    sp<ProcessState> ps(ProcessState::self());
    ps->startThreadPool();

    // Reset current thread's policy and priority
    if (errorInPriorityModification == 0) {
        errorInPriorityModification = sched_setscheduler(0, origPolicy, &origSchedParam);
    } else {
        ALOGE("Failed to set SurfaceFlinger binder threadpool priority to SCHED_FIFO");
    }

    // instantiate surfaceflinger
    sp<SurfaceFlinger> flinger = surfaceflinger::createSurfaceFlinger();

    // Set the minimum policy of surfaceflinger node to be SCHED_FIFO.
    // So any thread with policy/priority lower than {SCHED_FIFO, 1}, will run
    // at least with SCHED_FIFO policy and priority 1.
    if (errorInPriorityModification == 0) {
        flinger->setMinSchedulerPolicy(SCHED_FIFO, newPriority);
    }

    setpriority(PRIO_PROCESS, 0, PRIORITY_URGENT_DISPLAY);

    set_sched_policy(0, SP_FOREGROUND);

    // initialize before clients can connect
    flinger->init();

    // publish surface flinger
    sp<IServiceManager> sm(defaultServiceManager());
    sm->addService(String16(SurfaceFlinger::getServiceName()), flinger, false,
                   IServiceManager::DUMP_FLAG_PRIORITY_CRITICAL | IServiceManager::DUMP_FLAG_PROTO);

    // publish gui::ISurfaceComposer, the new AIDL interface
    sp<SurfaceComposerAIDL> composerAIDL = new SurfaceComposerAIDL(flinger);
    sm->addService(String16("SurfaceFlingerAIDL"), composerAIDL, false,
                   IServiceManager::DUMP_FLAG_PRIORITY_CRITICAL | IServiceManager::DUMP_FLAG_PROTO);

    startDisplayService(); // dependency on SF getting registered above

    if (SurfaceFlinger::setSchedFifo(true) != NO_ERROR) {
        ALOGW("Couldn't set to SCHED_FIFO: %s", strerror(errno));
    }

    // run surface flinger in this thread
    flinger->run();

    return 0;
}

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
