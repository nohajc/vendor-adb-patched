/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <stdint.h>

#include <android/binder_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This creates a threadpool for incoming binder transactions if it has not already been created.
 *
 * When using this, it is expected that ABinderProcess_setupPolling and
 * ABinderProcess_handlePolledCommands are not used.
 */
void ABinderProcess_startThreadPool();
/**
 * This sets the maximum number of threads that can be started in the threadpool. By default, after
 * startThreadPool is called, this is 15. If it is called additional times, it will only prevent
 * the kernel from starting new threads and will not delete already existing threads.
 */
bool ABinderProcess_setThreadPoolMaxThreadCount(uint32_t numThreads);
/**
 * This adds the current thread to the threadpool. This may cause the threadpool to exceed the
 * maximum size.
 */
void ABinderProcess_joinThreadPool();

/**
 * This gives you an fd to wait on. Whenever data is available on the fd,
 * ABinderProcess_handlePolledCommands can be called to handle binder queries.
 * This is expected to be used in a single threaded process which waits on
 * events from multiple different fds.
 *
 * When using this, it is expected ABinderProcess_startThreadPool and
 * ABinderProcess_joinThreadPool are not used.
 *
 * \param fd out param corresponding to the binder domain opened in this
 * process.
 * \return STATUS_OK on success
 */
__attribute__((weak)) binder_status_t ABinderProcess_setupPolling(int* fd) __INTRODUCED_IN(31);

/**
 * This will handle all queued binder commands in this process and then return.
 * It is expected to be called whenever there is data on the fd.
 *
 * \return STATUS_OK on success
 */
__attribute__((weak)) binder_status_t ABinderProcess_handlePolledCommands() __INTRODUCED_IN(31);

#ifdef __cplusplus
}
#endif
