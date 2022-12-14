/*
 * Copyright (C) 2005 The Android Open Source Project
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

#include <binder/IBinder.h>
#include <utils/KeyedVector.h>
#include <utils/String16.h>
#include <utils/String8.h>

#include <utils/threads.h>

#include <pthread.h>

// ---------------------------------------------------------------------------
namespace android {

class IPCThreadState;

class ProcessState : public virtual RefBase {
public:
    static sp<ProcessState> self();
    static sp<ProcessState> selfOrNull();

    /* initWithDriver() can be used to configure libbinder to use
     * a different binder driver dev node. It must be called *before*
     * any call to ProcessState::self(). The default is /dev/vndbinder
     * for processes built with the VNDK and /dev/binder for those
     * which are not.
     *
     * If this is called with nullptr, the behavior is the same as selfOrNull.
     */
    static sp<ProcessState> initWithDriver(const char* driver);

    sp<IBinder> getContextObject(const sp<IBinder>& caller);

    void startThreadPool();

    bool becomeContextManager();

    sp<IBinder> getStrongProxyForHandle(int32_t handle);
    void expungeHandle(int32_t handle, IBinder* binder);

    void spawnPooledThread(bool isMain);

    status_t setThreadPoolMaxThreadCount(size_t maxThreads);
    status_t enableOnewaySpamDetection(bool enable);
    void giveThreadPoolName();

    String8 getDriverName();

    ssize_t getKernelReferences(size_t count, uintptr_t* buf);

    // Only usable by the context manager.
    // This refcount includes:
    // 1. Strong references to the node by this and other processes
    // 2. Temporary strong references held by the kernel during a
    //    transaction on the node.
    // It does NOT include local strong references to the node
    ssize_t getStrongRefCountForNode(const sp<BpBinder>& binder);

    enum class CallRestriction {
        // all calls okay
        NONE,
        // log when calls are blocking
        ERROR_IF_NOT_ONEWAY,
        // abort process on blocking calls
        FATAL_IF_NOT_ONEWAY,
    };
    // Sets calling restrictions for all transactions in this process. This must be called
    // before any threads are spawned.
    void setCallRestriction(CallRestriction restriction);

    /**
     * Get the max number of threads that the kernel can start.
     *
     * Note: this is the lower bound. Additional threads may be started.
     */
    size_t getThreadPoolMaxThreadCount() const;

private:
    static sp<ProcessState> init(const char* defaultDriver, bool requireDefault);

    friend class IPCThreadState;
    friend class sp<ProcessState>;

    explicit ProcessState(const char* driver);
    ~ProcessState();

    ProcessState(const ProcessState& o);
    ProcessState& operator=(const ProcessState& o);
    String8 makeBinderThreadName();

    struct handle_entry {
        IBinder* binder;
        RefBase::weakref_type* refs;
    };

    handle_entry* lookupHandleLocked(int32_t handle);

    String8 mDriverName;
    int mDriverFD;
    void* mVMStart;

    // Protects thread count and wait variables below.
    pthread_mutex_t mThreadCountLock;
    // Broadcast whenever mWaitingForThreads > 0
    pthread_cond_t mThreadCountDecrement;
    // Number of binder threads current executing a command.
    size_t mExecutingThreadsCount;
    // Number of threads calling IPCThreadState::blockUntilThreadAvailable()
    size_t mWaitingForThreads;
    // Maximum number for binder threads allowed for this process.
    size_t mMaxThreads;
    // Time when thread pool was emptied
    int64_t mStarvationStartTimeMs;

    mutable Mutex mLock; // protects everything below.

    Vector<handle_entry> mHandleToObject;

    bool mThreadPoolStarted;
    volatile int32_t mThreadPoolSeq;

    CallRestriction mCallRestriction;
};

} // namespace android

// ---------------------------------------------------------------------------
