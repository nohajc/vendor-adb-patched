/*
 * Copyright 2022 The Android Open Source Project
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

#include <log/log.h>
#include <utils/Mutex.h>

namespace android {

struct SCOPED_CAPABILITY ConditionalLock {
    ConditionalLock(Mutex& mutex, bool lock) ACQUIRE(mutex) : mutex(mutex), lock(lock) {
        if (lock) mutex.lock();
    }

    ~ConditionalLock() RELEASE() {
        if (lock) mutex.unlock();
    }

    Mutex& mutex;
    const bool lock;
};

struct SCOPED_CAPABILITY TimedLock {
    TimedLock(Mutex& mutex, nsecs_t timeout, const char* whence) ACQUIRE(mutex)
          : mutex(mutex), status(mutex.timedLock(timeout)) {
        ALOGE_IF(!locked(), "%s timed out locking: %s (%d)", whence, strerror(-status), status);
    }

    ~TimedLock() RELEASE() {
        if (locked()) mutex.unlock();
    }

    bool locked() const { return status == NO_ERROR; }

    Mutex& mutex;
    const status_t status;
};

// Require, under penalty of compilation failure, that the compiler thinks that a mutex is held.
#define REQUIRE_MUTEX(expr) ([]() REQUIRES(expr) {})()

// Tell the compiler that we know that a mutex is held.
#define ASSERT_MUTEX(expr) ([]() ASSERT_CAPABILITY(expr) {})()

// Specify that one mutex is an alias for another.
// (e.g. SurfaceFlinger::mStateLock and Layer::mFlinger->mStateLock)
#define MUTEX_ALIAS(held, alias) (REQUIRE_MUTEX(held), ASSERT_MUTEX(alias))

} // namespace android
