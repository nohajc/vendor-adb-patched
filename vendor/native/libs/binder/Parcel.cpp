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

#define LOG_TAG "Parcel"
//#define LOG_NDEBUG 0

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/sched.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>

#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <binder/Stability.h>
#include <binder/Status.h>
#include <binder/TextOutput.h>

#include <cutils/ashmem.h>
#include <cutils/compiler.h>
#include <utils/Flattenable.h>
#include <utils/Log.h>
#include <utils/String16.h>
#include <utils/String8.h>
#include <utils/misc.h>

#include "RpcState.h"
#include "Static.h"
#include "Utils.h"
#include "binder_module.h"

#define LOG_REFS(...)
//#define LOG_REFS(...) ALOG(LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOG_ALLOC(...)
//#define LOG_ALLOC(...) ALOG(LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------

// This macro should never be used at runtime, as a too large value
// of s could cause an integer overflow. Instead, you should always
// use the wrapper function pad_size()
#define PAD_SIZE_UNSAFE(s) (((s)+3)&~3)

static size_t pad_size(size_t s) {
    if (s > (std::numeric_limits<size_t>::max() - 3)) {
        LOG_ALWAYS_FATAL("pad size too big %zu", s);
    }
    return PAD_SIZE_UNSAFE(s);
}

// Note: must be kept in sync with android/os/StrictMode.java's PENALTY_GATHER
#define STRICT_MODE_PENALTY_GATHER (1 << 31)

namespace android {

// many things compile this into prebuilts on the stack
#ifdef __LP64__
static_assert(sizeof(Parcel) == 120);
#else
static_assert(sizeof(Parcel) == 60);
#endif

static std::atomic<size_t> gParcelGlobalAllocCount;
static std::atomic<size_t> gParcelGlobalAllocSize;

static size_t gMaxFds = 0;

// Maximum size of a blob to transfer in-place.
static const size_t BLOB_INPLACE_LIMIT = 16 * 1024;

enum {
    BLOB_INPLACE = 0,
    BLOB_ASHMEM_IMMUTABLE = 1,
    BLOB_ASHMEM_MUTABLE = 2,
};

static void acquire_object(const sp<ProcessState>& proc,
    const flat_binder_object& obj, const void* who, size_t* outAshmemSize)
{
    switch (obj.hdr.type) {
        case BINDER_TYPE_BINDER:
            if (obj.binder) {
                LOG_REFS("Parcel %p acquiring reference on local %p", who, obj.cookie);
                reinterpret_cast<IBinder*>(obj.cookie)->incStrong(who);
            }
            return;
        case BINDER_TYPE_HANDLE: {
            const sp<IBinder> b = proc->getStrongProxyForHandle(obj.handle);
            if (b != nullptr) {
                LOG_REFS("Parcel %p acquiring reference on remote %p", who, b.get());
                b->incStrong(who);
            }
            return;
        }
        case BINDER_TYPE_FD: {
            if ((obj.cookie != 0) && (outAshmemSize != nullptr) && ashmem_valid(obj.handle)) {
                // If we own an ashmem fd, keep track of how much memory it refers to.
                int size = ashmem_get_size_region(obj.handle);
                if (size > 0) {
                    *outAshmemSize += size;
                }
            }
            return;
        }
    }

    ALOGD("Invalid object type 0x%08x", obj.hdr.type);
}

static void release_object(const sp<ProcessState>& proc,
    const flat_binder_object& obj, const void* who, size_t* outAshmemSize)
{
    switch (obj.hdr.type) {
        case BINDER_TYPE_BINDER:
            if (obj.binder) {
                LOG_REFS("Parcel %p releasing reference on local %p", who, obj.cookie);
                reinterpret_cast<IBinder*>(obj.cookie)->decStrong(who);
            }
            return;
        case BINDER_TYPE_HANDLE: {
            const sp<IBinder> b = proc->getStrongProxyForHandle(obj.handle);
            if (b != nullptr) {
                LOG_REFS("Parcel %p releasing reference on remote %p", who, b.get());
                b->decStrong(who);
            }
            return;
        }
        case BINDER_TYPE_FD: {
            if (obj.cookie != 0) { // owned
                if ((outAshmemSize != nullptr) && ashmem_valid(obj.handle)) {
                    int size = ashmem_get_size_region(obj.handle);
                    if (size > 0) {
                        // ashmem size might have changed since last time it was accounted for, e.g.
                        // in acquire_object(). Value of *outAshmemSize is not critical since we are
                        // releasing the object anyway. Check for integer overflow condition.
                        *outAshmemSize -= std::min(*outAshmemSize, static_cast<size_t>(size));
                    }
                }

                close(obj.handle);
            }
            return;
        }
    }

    ALOGE("Invalid object type 0x%08x", obj.hdr.type);
}

status_t Parcel::finishFlattenBinder(const sp<IBinder>& binder)
{
    internal::Stability::tryMarkCompilationUnit(binder.get());
    int16_t rep = internal::Stability::getCategory(binder.get()).repr();
    return writeInt32(rep);
}

status_t Parcel::finishUnflattenBinder(
    const sp<IBinder>& binder, sp<IBinder>* out) const
{
    int32_t stability;
    status_t status = readInt32(&stability);
    if (status != OK) return status;

    status = internal::Stability::setRepr(binder.get(), static_cast<int16_t>(stability),
                                          true /*log*/);
    if (status != OK) return status;

    *out = binder;
    return OK;
}

static constexpr inline int schedPolicyMask(int policy, int priority) {
    return (priority & FLAT_BINDER_FLAG_PRIORITY_MASK) | ((policy & 3) << FLAT_BINDER_FLAG_SCHED_POLICY_SHIFT);
}

status_t Parcel::flattenBinder(const sp<IBinder>& binder) {
    BBinder* local = nullptr;
    if (binder) local = binder->localBinder();
    if (local) local->setParceled();

    if (isForRpc()) {
        if (binder) {
            status_t status = writeInt32(1); // non-null
            if (status != OK) return status;
            RpcAddress address = RpcAddress::zero();
            // TODO(b/167966510): need to undo this if the Parcel is not sent
            status = mSession->state()->onBinderLeaving(mSession, binder, &address);
            if (status != OK) return status;
            status = address.writeToParcel(this);
            if (status != OK) return status;
        } else {
            status_t status = writeInt32(0); // null
            if (status != OK) return status;
        }
        return finishFlattenBinder(binder);
    }

    flat_binder_object obj;
    obj.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;

    int schedBits = 0;
    if (!IPCThreadState::self()->backgroundSchedulingDisabled()) {
        schedBits = schedPolicyMask(SCHED_NORMAL, 19);
    }

    if (binder != nullptr) {
        if (!local) {
            BpBinder *proxy = binder->remoteBinder();
            if (proxy == nullptr) {
                ALOGE("null proxy");
            } else {
                if (proxy->isRpcBinder()) {
                    ALOGE("Sending a socket binder over RPC is prohibited");
                    return INVALID_OPERATION;
                }
            }
            const int32_t handle = proxy ? proxy->getPrivateAccessorForId().binderHandle() : 0;
            obj.hdr.type = BINDER_TYPE_HANDLE;
            obj.binder = 0; /* Don't pass uninitialized stack data to a remote process */
            obj.handle = handle;
            obj.cookie = 0;
        } else {
            int policy = local->getMinSchedulerPolicy();
            int priority = local->getMinSchedulerPriority();

            if (policy != 0 || priority != 0) {
                // override value, since it is set explicitly
                schedBits = schedPolicyMask(policy, priority);
            }
            if (local->isRequestingSid()) {
                obj.flags |= FLAT_BINDER_FLAG_TXN_SECURITY_CTX;
            }
            if (local->isInheritRt()) {
                obj.flags |= FLAT_BINDER_FLAG_INHERIT_RT;
            }
            obj.hdr.type = BINDER_TYPE_BINDER;
            obj.binder = reinterpret_cast<uintptr_t>(local->getWeakRefs());
            obj.cookie = reinterpret_cast<uintptr_t>(local);
        }
    } else {
        obj.hdr.type = BINDER_TYPE_BINDER;
        obj.binder = 0;
        obj.cookie = 0;
    }

    obj.flags |= schedBits;

    status_t status = writeObject(obj, false);
    if (status != OK) return status;

    return finishFlattenBinder(binder);
}

status_t Parcel::unflattenBinder(sp<IBinder>* out) const
{
    if (isForRpc()) {
        LOG_ALWAYS_FATAL_IF(mSession == nullptr, "RpcSession required to read from remote parcel");

        int32_t isNull;
        status_t status = readInt32(&isNull);
        if (status != OK) return status;

        sp<IBinder> binder;

        if (isNull & 1) {
            auto addr = RpcAddress::zero();
            if (status_t status = addr.readFromParcel(*this); status != OK) return status;
            if (status_t status = mSession->state()->onBinderEntering(mSession, addr, &binder);
                status != OK)
                return status;
        }

        return finishUnflattenBinder(binder, out);
    }

    const flat_binder_object* flat = readObject(false);

    if (flat) {
        switch (flat->hdr.type) {
            case BINDER_TYPE_BINDER: {
                sp<IBinder> binder =
                        sp<IBinder>::fromExisting(reinterpret_cast<IBinder*>(flat->cookie));
                return finishUnflattenBinder(binder, out);
            }
            case BINDER_TYPE_HANDLE: {
                sp<IBinder> binder =
                    ProcessState::self()->getStrongProxyForHandle(flat->handle);
                return finishUnflattenBinder(binder, out);
            }
        }
    }
    return BAD_TYPE;
}

// ---------------------------------------------------------------------------

Parcel::Parcel()
{
    LOG_ALLOC("Parcel %p: constructing", this);
    initState();
}

Parcel::~Parcel()
{
    freeDataNoInit();
    LOG_ALLOC("Parcel %p: destroyed", this);
}

size_t Parcel::getGlobalAllocSize() {
    return gParcelGlobalAllocSize.load();
}

size_t Parcel::getGlobalAllocCount() {
    return gParcelGlobalAllocCount.load();
}

const uint8_t* Parcel::data() const
{
    return mData;
}

size_t Parcel::dataSize() const
{
    return (mDataSize > mDataPos ? mDataSize : mDataPos);
}

size_t Parcel::dataAvail() const
{
    size_t result = dataSize() - dataPosition();
    if (result > INT32_MAX) {
        LOG_ALWAYS_FATAL("result too big: %zu", result);
    }
    return result;
}

size_t Parcel::dataPosition() const
{
    return mDataPos;
}

size_t Parcel::dataCapacity() const
{
    return mDataCapacity;
}

status_t Parcel::setDataSize(size_t size)
{
    if (size > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    status_t err;
    err = continueWrite(size);
    if (err == NO_ERROR) {
        mDataSize = size;
        ALOGV("setDataSize Setting data size of %p to %zu", this, mDataSize);
    }
    return err;
}

void Parcel::setDataPosition(size_t pos) const
{
    if (pos > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        LOG_ALWAYS_FATAL("pos too big: %zu", pos);
    }

    mDataPos = pos;
    mNextObjectHint = 0;
    mObjectsSorted = false;
}

status_t Parcel::setDataCapacity(size_t size)
{
    if (size > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    if (size > mDataCapacity) return continueWrite(size);
    return NO_ERROR;
}

status_t Parcel::setData(const uint8_t* buffer, size_t len)
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    status_t err = restartWrite(len);
    if (err == NO_ERROR) {
        memcpy(const_cast<uint8_t*>(data()), buffer, len);
        mDataSize = len;
        mFdsKnown = false;
    }
    return err;
}

status_t Parcel::appendFrom(const Parcel *parcel, size_t offset, size_t len)
{
    if (parcel->isForRpc() != isForRpc()) {
        ALOGE("Cannot append Parcel of one format to another.");
        return BAD_TYPE;
    }

    status_t err;
    const uint8_t *data = parcel->mData;
    const binder_size_t *objects = parcel->mObjects;
    size_t size = parcel->mObjectsSize;
    int startPos = mDataPos;
    int firstIndex = -1, lastIndex = -2;

    if (len == 0) {
        return NO_ERROR;
    }

    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    // range checks against the source parcel size
    if ((offset > parcel->mDataSize)
            || (len > parcel->mDataSize)
            || (offset + len > parcel->mDataSize)) {
        return BAD_VALUE;
    }

    // Count objects in range
    for (int i = 0; i < (int) size; i++) {
        size_t off = objects[i];
        if ((off >= offset) && (off + sizeof(flat_binder_object) <= offset + len)) {
            if (firstIndex == -1) {
                firstIndex = i;
            }
            lastIndex = i;
        }
    }
    int numObjects = lastIndex - firstIndex + 1;

    if ((mDataSize+len) > mDataCapacity) {
        // grow data
        err = growData(len);
        if (err != NO_ERROR) {
            return err;
        }
    }

    // append data
    memcpy(mData + mDataPos, data + offset, len);
    mDataPos += len;
    mDataSize += len;

    err = NO_ERROR;

    if (numObjects > 0) {
        const sp<ProcessState> proc(ProcessState::self());
        // grow objects
        if (mObjectsCapacity < mObjectsSize + numObjects) {
            if ((size_t) numObjects > SIZE_MAX - mObjectsSize) return NO_MEMORY; // overflow
            if (mObjectsSize + numObjects > SIZE_MAX / 3) return NO_MEMORY; // overflow
            size_t newSize = ((mObjectsSize + numObjects)*3)/2;
            if (newSize > SIZE_MAX / sizeof(binder_size_t)) return NO_MEMORY; // overflow
            binder_size_t *objects =
                (binder_size_t*)realloc(mObjects, newSize*sizeof(binder_size_t));
            if (objects == (binder_size_t*)nullptr) {
                return NO_MEMORY;
            }
            mObjects = objects;
            mObjectsCapacity = newSize;
        }

        // append and acquire objects
        int idx = mObjectsSize;
        for (int i = firstIndex; i <= lastIndex; i++) {
            size_t off = objects[i] - offset + startPos;
            mObjects[idx++] = off;
            mObjectsSize++;

            flat_binder_object* flat
                = reinterpret_cast<flat_binder_object*>(mData + off);
            acquire_object(proc, *flat, this, &mOpenAshmemSize);

            if (flat->hdr.type == BINDER_TYPE_FD) {
                // If this is a file descriptor, we need to dup it so the
                // new Parcel now owns its own fd, and can declare that we
                // officially know we have fds.
                flat->handle = fcntl(flat->handle, F_DUPFD_CLOEXEC, 0);
                flat->cookie = 1;
                mHasFds = mFdsKnown = true;
                if (!mAllowFds) {
                    err = FDS_NOT_ALLOWED;
                }
            }
        }
    }

    return err;
}

int Parcel::compareData(const Parcel& other) {
    size_t size = dataSize();
    if (size != other.dataSize()) {
        return size < other.dataSize() ? -1 : 1;
    }
    return memcmp(data(), other.data(), size);
}

bool Parcel::allowFds() const
{
    return mAllowFds;
}

bool Parcel::pushAllowFds(bool allowFds)
{
    const bool origValue = mAllowFds;
    if (!allowFds) {
        mAllowFds = false;
    }
    return origValue;
}

void Parcel::restoreAllowFds(bool lastValue)
{
    mAllowFds = lastValue;
}

bool Parcel::hasFileDescriptors() const
{
    if (!mFdsKnown) {
        scanForFds();
    }
    return mHasFds;
}

void Parcel::markSensitive() const
{
    mDeallocZero = true;
}

void Parcel::markForBinder(const sp<IBinder>& binder) {
    LOG_ALWAYS_FATAL_IF(mData != nullptr, "format must be set before data is written");

    if (binder && binder->remoteBinder() && binder->remoteBinder()->isRpcBinder()) {
        markForRpc(binder->remoteBinder()->getPrivateAccessorForId().rpcSession());
    }
}

void Parcel::markForRpc(const sp<RpcSession>& session) {
    LOG_ALWAYS_FATAL_IF(mData != nullptr && mOwner == nullptr,
                        "format must be set before data is written OR on IPC data");

    LOG_ALWAYS_FATAL_IF(session == nullptr, "markForRpc requires session");
    mSession = session;
}

bool Parcel::isForRpc() const {
    return mSession != nullptr;
}

void Parcel::updateWorkSourceRequestHeaderPosition() const {
    // Only update the request headers once. We only want to point
    // to the first headers read/written.
    if (!mRequestHeaderPresent) {
        mWorkSourceRequestHeaderPosition = dataPosition();
        mRequestHeaderPresent = true;
    }
}

#if defined(__ANDROID_VNDK__) && !defined(__ANDROID_APEX__)
constexpr int32_t kHeader = B_PACK_CHARS('V', 'N', 'D', 'R');
#else
constexpr int32_t kHeader = B_PACK_CHARS('S', 'Y', 'S', 'T');
#endif

// Write RPC headers.  (previously just the interface token)
status_t Parcel::writeInterfaceToken(const String16& interface)
{
    return writeInterfaceToken(interface.string(), interface.size());
}

status_t Parcel::writeInterfaceToken(const char16_t* str, size_t len) {
    if (CC_LIKELY(!isForRpc())) {
        const IPCThreadState* threadState = IPCThreadState::self();
        writeInt32(threadState->getStrictModePolicy() | STRICT_MODE_PENALTY_GATHER);
        updateWorkSourceRequestHeaderPosition();
        writeInt32(threadState->shouldPropagateWorkSource() ? threadState->getCallingWorkSourceUid()
                                                            : IPCThreadState::kUnsetWorkSource);
        writeInt32(kHeader);
    }

    // currently the interface identification token is just its name as a string
    return writeString16(str, len);
}

bool Parcel::replaceCallingWorkSourceUid(uid_t uid)
{
    if (!mRequestHeaderPresent) {
        return false;
    }

    const size_t initialPosition = dataPosition();
    setDataPosition(mWorkSourceRequestHeaderPosition);
    status_t err = writeInt32(uid);
    setDataPosition(initialPosition);
    return err == NO_ERROR;
}

uid_t Parcel::readCallingWorkSourceUid() const
{
    if (!mRequestHeaderPresent) {
        return IPCThreadState::kUnsetWorkSource;
    }

    const size_t initialPosition = dataPosition();
    setDataPosition(mWorkSourceRequestHeaderPosition);
    uid_t uid = readInt32();
    setDataPosition(initialPosition);
    return uid;
}

bool Parcel::checkInterface(IBinder* binder) const
{
    return enforceInterface(binder->getInterfaceDescriptor());
}

bool Parcel::enforceInterface(const String16& interface,
                              IPCThreadState* threadState) const
{
    return enforceInterface(interface.string(), interface.size(), threadState);
}

bool Parcel::enforceInterface(const char16_t* interface,
                              size_t len,
                              IPCThreadState* threadState) const
{
    if (CC_LIKELY(!isForRpc())) {
        // StrictModePolicy.
        int32_t strictPolicy = readInt32();
        if (threadState == nullptr) {
            threadState = IPCThreadState::self();
        }
        if ((threadState->getLastTransactionBinderFlags() & IBinder::FLAG_ONEWAY) != 0) {
            // For one-way calls, the callee is running entirely
            // disconnected from the caller, so disable StrictMode entirely.
            // Not only does disk/network usage not impact the caller, but
            // there's no way to communicate back violations anyway.
            threadState->setStrictModePolicy(0);
        } else {
            threadState->setStrictModePolicy(strictPolicy);
        }
        // WorkSource.
        updateWorkSourceRequestHeaderPosition();
        int32_t workSource = readInt32();
        threadState->setCallingWorkSourceUidWithoutPropagation(workSource);
        // vendor header
        int32_t header = readInt32();
        if (header != kHeader) {
            ALOGE("Expecting header 0x%x but found 0x%x. Mixing copies of libbinder?", kHeader,
                  header);
            return false;
        }
    }

    // Interface descriptor.
    size_t parcel_interface_len;
    const char16_t* parcel_interface = readString16Inplace(&parcel_interface_len);
    if (len == parcel_interface_len &&
            (!len || !memcmp(parcel_interface, interface, len * sizeof (char16_t)))) {
        return true;
    } else {
        ALOGW("**** enforceInterface() expected '%s' but read '%s'",
              String8(interface, len).string(),
              String8(parcel_interface, parcel_interface_len).string());
        return false;
    }
}

size_t Parcel::objectsCount() const
{
    return mObjectsSize;
}

status_t Parcel::errorCheck() const
{
    return mError;
}

void Parcel::setError(status_t err)
{
    mError = err;
}

status_t Parcel::finishWrite(size_t len)
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    //printf("Finish write of %d\n", len);
    mDataPos += len;
    ALOGV("finishWrite Setting data pos of %p to %zu", this, mDataPos);
    if (mDataPos > mDataSize) {
        mDataSize = mDataPos;
        ALOGV("finishWrite Setting data size of %p to %zu", this, mDataSize);
    }
    //printf("New pos=%d, size=%d\n", mDataPos, mDataSize);
    return NO_ERROR;
}

status_t Parcel::writeUnpadded(const void* data, size_t len)
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    size_t end = mDataPos + len;
    if (end < mDataPos) {
        // integer overflow
        return BAD_VALUE;
    }

    if (end <= mDataCapacity) {
restart_write:
        memcpy(mData+mDataPos, data, len);
        return finishWrite(len);
    }

    status_t err = growData(len);
    if (err == NO_ERROR) goto restart_write;
    return err;
}

status_t Parcel::write(const void* data, size_t len)
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    void* const d = writeInplace(len);
    if (d) {
        memcpy(d, data, len);
        return NO_ERROR;
    }
    return mError;
}

void* Parcel::writeInplace(size_t len)
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return nullptr;
    }

    const size_t padded = pad_size(len);

    // sanity check for integer overflow
    if (mDataPos+padded < mDataPos) {
        return nullptr;
    }

    if ((mDataPos+padded) <= mDataCapacity) {
restart_write:
        //printf("Writing %ld bytes, padded to %ld\n", len, padded);
        uint8_t* const data = mData+mDataPos;

        // Need to pad at end?
        if (padded != len) {
#if BYTE_ORDER == BIG_ENDIAN
            static const uint32_t mask[4] = {
                0x00000000, 0xffffff00, 0xffff0000, 0xff000000
            };
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
            static const uint32_t mask[4] = {
                0x00000000, 0x00ffffff, 0x0000ffff, 0x000000ff
            };
#endif
            //printf("Applying pad mask: %p to %p\n", (void*)mask[padded-len],
            //    *reinterpret_cast<void**>(data+padded-4));
            *reinterpret_cast<uint32_t*>(data+padded-4) &= mask[padded-len];
        }

        finishWrite(padded);
        return data;
    }

    status_t err = growData(padded);
    if (err == NO_ERROR) goto restart_write;
    return nullptr;
}

status_t Parcel::writeUtf8AsUtf16(const std::string& str) {
    const uint8_t* strData = (uint8_t*)str.data();
    const size_t strLen= str.length();
    const ssize_t utf16Len = utf8_to_utf16_length(strData, strLen);
    if (utf16Len < 0 || utf16Len > std::numeric_limits<int32_t>::max()) {
        return BAD_VALUE;
    }

    status_t err = writeInt32(utf16Len);
    if (err) {
        return err;
    }

    // Allocate enough bytes to hold our converted string and its terminating NULL.
    void* dst = writeInplace((utf16Len + 1) * sizeof(char16_t));
    if (!dst) {
        return NO_MEMORY;
    }

    utf8_to_utf16(strData, strLen, (char16_t*)dst, (size_t) utf16Len + 1);

    return NO_ERROR;
}


status_t Parcel::writeUtf8AsUtf16(const std::optional<std::string>& str) { return writeData(str); }
status_t Parcel::writeUtf8AsUtf16(const std::unique_ptr<std::string>& str) { return writeData(str); }

status_t Parcel::writeString16(const std::optional<String16>& str) { return writeData(str); }
status_t Parcel::writeString16(const std::unique_ptr<String16>& str) { return writeData(str); }

status_t Parcel::writeByteVector(const std::vector<int8_t>& val) { return writeData(val); }
status_t Parcel::writeByteVector(const std::optional<std::vector<int8_t>>& val) { return writeData(val); }
status_t Parcel::writeByteVector(const std::unique_ptr<std::vector<int8_t>>& val) { return writeData(val); }
status_t Parcel::writeByteVector(const std::vector<uint8_t>& val) { return writeData(val); }
status_t Parcel::writeByteVector(const std::optional<std::vector<uint8_t>>& val) { return writeData(val); }
status_t Parcel::writeByteVector(const std::unique_ptr<std::vector<uint8_t>>& val){ return writeData(val); }
status_t Parcel::writeInt32Vector(const std::vector<int32_t>& val) { return writeData(val); }
status_t Parcel::writeInt32Vector(const std::optional<std::vector<int32_t>>& val) { return writeData(val); }
status_t Parcel::writeInt32Vector(const std::unique_ptr<std::vector<int32_t>>& val) { return writeData(val); }
status_t Parcel::writeInt64Vector(const std::vector<int64_t>& val) { return writeData(val); }
status_t Parcel::writeInt64Vector(const std::optional<std::vector<int64_t>>& val) { return writeData(val); }
status_t Parcel::writeInt64Vector(const std::unique_ptr<std::vector<int64_t>>& val) { return writeData(val); }
status_t Parcel::writeUint64Vector(const std::vector<uint64_t>& val) { return writeData(val); }
status_t Parcel::writeUint64Vector(const std::optional<std::vector<uint64_t>>& val) { return writeData(val); }
status_t Parcel::writeUint64Vector(const std::unique_ptr<std::vector<uint64_t>>& val) { return writeData(val); }
status_t Parcel::writeFloatVector(const std::vector<float>& val) { return writeData(val); }
status_t Parcel::writeFloatVector(const std::optional<std::vector<float>>& val) { return writeData(val); }
status_t Parcel::writeFloatVector(const std::unique_ptr<std::vector<float>>& val) { return writeData(val); }
status_t Parcel::writeDoubleVector(const std::vector<double>& val) { return writeData(val); }
status_t Parcel::writeDoubleVector(const std::optional<std::vector<double>>& val) { return writeData(val); }
status_t Parcel::writeDoubleVector(const std::unique_ptr<std::vector<double>>& val) { return writeData(val); }
status_t Parcel::writeBoolVector(const std::vector<bool>& val) { return writeData(val); }
status_t Parcel::writeBoolVector(const std::optional<std::vector<bool>>& val) { return writeData(val); }
status_t Parcel::writeBoolVector(const std::unique_ptr<std::vector<bool>>& val) { return writeData(val); }
status_t Parcel::writeCharVector(const std::vector<char16_t>& val) { return writeData(val); }
status_t Parcel::writeCharVector(const std::optional<std::vector<char16_t>>& val) { return writeData(val); }
status_t Parcel::writeCharVector(const std::unique_ptr<std::vector<char16_t>>& val) { return writeData(val); }

status_t Parcel::writeString16Vector(const std::vector<String16>& val) { return writeData(val); }
status_t Parcel::writeString16Vector(
        const std::optional<std::vector<std::optional<String16>>>& val) { return writeData(val); }
status_t Parcel::writeString16Vector(
        const std::unique_ptr<std::vector<std::unique_ptr<String16>>>& val) { return writeData(val); }
status_t Parcel::writeUtf8VectorAsUtf16Vector(
                        const std::optional<std::vector<std::optional<std::string>>>& val) { return writeData(val); }
status_t Parcel::writeUtf8VectorAsUtf16Vector(
                        const std::unique_ptr<std::vector<std::unique_ptr<std::string>>>& val) { return writeData(val); }
status_t Parcel::writeUtf8VectorAsUtf16Vector(const std::vector<std::string>& val) { return writeData(val); }

status_t Parcel::writeUniqueFileDescriptorVector(const std::vector<base::unique_fd>& val) { return writeData(val); }
status_t Parcel::writeUniqueFileDescriptorVector(const std::optional<std::vector<base::unique_fd>>& val) { return writeData(val); }
status_t Parcel::writeUniqueFileDescriptorVector(const std::unique_ptr<std::vector<base::unique_fd>>& val) { return writeData(val); }

status_t Parcel::writeStrongBinderVector(const std::vector<sp<IBinder>>& val) { return writeData(val); }
status_t Parcel::writeStrongBinderVector(const std::optional<std::vector<sp<IBinder>>>& val) { return writeData(val); }
status_t Parcel::writeStrongBinderVector(const std::unique_ptr<std::vector<sp<IBinder>>>& val) { return writeData(val); }

status_t Parcel::writeParcelable(const Parcelable& parcelable) { return writeData(parcelable); }

status_t Parcel::readUtf8FromUtf16(std::optional<std::string>* str) const { return readData(str); }
status_t Parcel::readUtf8FromUtf16(std::unique_ptr<std::string>* str) const { return readData(str); }

status_t Parcel::readString16(std::optional<String16>* pArg) const { return readData(pArg); }
status_t Parcel::readString16(std::unique_ptr<String16>* pArg) const { return readData(pArg); }

status_t Parcel::readByteVector(std::vector<int8_t>* val) const { return readData(val); }
status_t Parcel::readByteVector(std::vector<uint8_t>* val) const { return readData(val); }
status_t Parcel::readByteVector(std::optional<std::vector<int8_t>>* val) const { return readData(val); }
status_t Parcel::readByteVector(std::unique_ptr<std::vector<int8_t>>* val) const { return readData(val); }
status_t Parcel::readByteVector(std::optional<std::vector<uint8_t>>* val) const { return readData(val); }
status_t Parcel::readByteVector(std::unique_ptr<std::vector<uint8_t>>* val) const { return readData(val); }
status_t Parcel::readInt32Vector(std::optional<std::vector<int32_t>>* val) const { return readData(val); }
status_t Parcel::readInt32Vector(std::unique_ptr<std::vector<int32_t>>* val) const { return readData(val); }
status_t Parcel::readInt32Vector(std::vector<int32_t>* val) const { return readData(val); }
status_t Parcel::readInt64Vector(std::optional<std::vector<int64_t>>* val) const { return readData(val); }
status_t Parcel::readInt64Vector(std::unique_ptr<std::vector<int64_t>>* val) const { return readData(val); }
status_t Parcel::readInt64Vector(std::vector<int64_t>* val) const { return readData(val); }
status_t Parcel::readUint64Vector(std::optional<std::vector<uint64_t>>* val) const { return readData(val); }
status_t Parcel::readUint64Vector(std::unique_ptr<std::vector<uint64_t>>* val) const { return readData(val); }
status_t Parcel::readUint64Vector(std::vector<uint64_t>* val) const { return readData(val); }
status_t Parcel::readFloatVector(std::optional<std::vector<float>>* val) const { return readData(val); }
status_t Parcel::readFloatVector(std::unique_ptr<std::vector<float>>* val) const { return readData(val); }
status_t Parcel::readFloatVector(std::vector<float>* val) const { return readData(val); }
status_t Parcel::readDoubleVector(std::optional<std::vector<double>>* val) const { return readData(val); }
status_t Parcel::readDoubleVector(std::unique_ptr<std::vector<double>>* val) const { return readData(val); }
status_t Parcel::readDoubleVector(std::vector<double>* val) const { return readData(val); }
status_t Parcel::readBoolVector(std::optional<std::vector<bool>>* val) const { return readData(val); }
status_t Parcel::readBoolVector(std::unique_ptr<std::vector<bool>>* val) const { return readData(val); }
status_t Parcel::readBoolVector(std::vector<bool>* val) const { return readData(val); }
status_t Parcel::readCharVector(std::optional<std::vector<char16_t>>* val) const { return readData(val); }
status_t Parcel::readCharVector(std::unique_ptr<std::vector<char16_t>>* val) const { return readData(val); }
status_t Parcel::readCharVector(std::vector<char16_t>* val) const { return readData(val); }

status_t Parcel::readString16Vector(
        std::optional<std::vector<std::optional<String16>>>* val) const { return readData(val); }
status_t Parcel::readString16Vector(
        std::unique_ptr<std::vector<std::unique_ptr<String16>>>* val) const { return readData(val); }
status_t Parcel::readString16Vector(std::vector<String16>* val) const { return readData(val); }
status_t Parcel::readUtf8VectorFromUtf16Vector(
        std::optional<std::vector<std::optional<std::string>>>* val) const { return readData(val); }
status_t Parcel::readUtf8VectorFromUtf16Vector(
        std::unique_ptr<std::vector<std::unique_ptr<std::string>>>* val) const { return readData(val); }
status_t Parcel::readUtf8VectorFromUtf16Vector(std::vector<std::string>* val) const { return readData(val); }

status_t Parcel::readUniqueFileDescriptorVector(std::optional<std::vector<base::unique_fd>>* val) const { return readData(val); }
status_t Parcel::readUniqueFileDescriptorVector(std::unique_ptr<std::vector<base::unique_fd>>* val) const { return readData(val); }
status_t Parcel::readUniqueFileDescriptorVector(std::vector<base::unique_fd>* val) const { return readData(val); }

status_t Parcel::readStrongBinderVector(std::optional<std::vector<sp<IBinder>>>* val) const { return readData(val); }
status_t Parcel::readStrongBinderVector(std::unique_ptr<std::vector<sp<IBinder>>>* val) const { return readData(val); }
status_t Parcel::readStrongBinderVector(std::vector<sp<IBinder>>* val) const { return readData(val); }

status_t Parcel::readParcelable(Parcelable* parcelable) const { return readData(parcelable); }

status_t Parcel::writeInt32(int32_t val)
{
    return writeAligned(val);
}

status_t Parcel::writeUint32(uint32_t val)
{
    return writeAligned(val);
}

status_t Parcel::writeInt32Array(size_t len, const int32_t *val) {
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    if (!val) {
        return writeInt32(-1);
    }
    status_t ret = writeInt32(static_cast<uint32_t>(len));
    if (ret == NO_ERROR) {
        ret = write(val, len * sizeof(*val));
    }
    return ret;
}
status_t Parcel::writeByteArray(size_t len, const uint8_t *val) {
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    if (!val) {
        return writeInt32(-1);
    }
    status_t ret = writeInt32(static_cast<uint32_t>(len));
    if (ret == NO_ERROR) {
        ret = write(val, len * sizeof(*val));
    }
    return ret;
}

status_t Parcel::writeBool(bool val)
{
    return writeInt32(int32_t(val));
}

status_t Parcel::writeChar(char16_t val)
{
    return writeInt32(int32_t(val));
}

status_t Parcel::writeByte(int8_t val)
{
    return writeInt32(int32_t(val));
}

status_t Parcel::writeInt64(int64_t val)
{
    return writeAligned(val);
}

status_t Parcel::writeUint64(uint64_t val)
{
    return writeAligned(val);
}

status_t Parcel::writePointer(uintptr_t val)
{
    return writeAligned<binder_uintptr_t>(val);
}

status_t Parcel::writeFloat(float val)
{
    return writeAligned(val);
}

#if defined(__mips__) && defined(__mips_hard_float)

status_t Parcel::writeDouble(double val)
{
    union {
        double d;
        unsigned long long ll;
    } u;
    u.d = val;
    return writeAligned(u.ll);
}

#else

status_t Parcel::writeDouble(double val)
{
    return writeAligned(val);
}

#endif

status_t Parcel::writeCString(const char* str)
{
    return write(str, strlen(str)+1);
}

status_t Parcel::writeString8(const String8& str)
{
    return writeString8(str.string(), str.size());
}

status_t Parcel::writeString8(const char* str, size_t len)
{
    if (str == nullptr) return writeInt32(-1);

    // NOTE: Keep this logic in sync with android_os_Parcel.cpp
    status_t err = writeInt32(len);
    if (err == NO_ERROR) {
        uint8_t* data = (uint8_t*)writeInplace(len+sizeof(char));
        if (data) {
            memcpy(data, str, len);
            *reinterpret_cast<char*>(data+len) = 0;
            return NO_ERROR;
        }
        err = mError;
    }
    return err;
}

status_t Parcel::writeString16(const String16& str)
{
    return writeString16(str.string(), str.size());
}

status_t Parcel::writeString16(const char16_t* str, size_t len)
{
    if (str == nullptr) return writeInt32(-1);

    // NOTE: Keep this logic in sync with android_os_Parcel.cpp
    status_t err = writeInt32(len);
    if (err == NO_ERROR) {
        len *= sizeof(char16_t);
        uint8_t* data = (uint8_t*)writeInplace(len+sizeof(char16_t));
        if (data) {
            memcpy(data, str, len);
            *reinterpret_cast<char16_t*>(data+len) = 0;
            return NO_ERROR;
        }
        err = mError;
    }
    return err;
}

status_t Parcel::writeStrongBinder(const sp<IBinder>& val)
{
    return flattenBinder(val);
}


status_t Parcel::writeRawNullableParcelable(const Parcelable* parcelable) {
    if (!parcelable) {
        return writeInt32(0);
    }

    return writeParcelable(*parcelable);
}

status_t Parcel::writeNativeHandle(const native_handle* handle)
{
    if (!handle || handle->version != sizeof(native_handle))
        return BAD_TYPE;

    status_t err;
    err = writeInt32(handle->numFds);
    if (err != NO_ERROR) return err;

    err = writeInt32(handle->numInts);
    if (err != NO_ERROR) return err;

    for (int i=0 ; err==NO_ERROR && i<handle->numFds ; i++)
        err = writeDupFileDescriptor(handle->data[i]);

    if (err != NO_ERROR) {
        ALOGD("write native handle, write dup fd failed");
        return err;
    }
    err = write(handle->data + handle->numFds, sizeof(int)*handle->numInts);
    return err;
}

status_t Parcel::writeFileDescriptor(int fd, bool takeOwnership)
{
    if (isForRpc()) {
        ALOGE("Cannot write file descriptor to remote binder.");
        return BAD_TYPE;
    }

    flat_binder_object obj;
    obj.hdr.type = BINDER_TYPE_FD;
    obj.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj.binder = 0; /* Don't pass uninitialized stack data to a remote process */
    obj.handle = fd;
    obj.cookie = takeOwnership ? 1 : 0;
    return writeObject(obj, true);
}

status_t Parcel::writeDupFileDescriptor(int fd)
{
    int dupFd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (dupFd < 0) {
        return -errno;
    }
    status_t err = writeFileDescriptor(dupFd, true /*takeOwnership*/);
    if (err != OK) {
        close(dupFd);
    }
    return err;
}

status_t Parcel::writeParcelFileDescriptor(int fd, bool takeOwnership)
{
    writeInt32(0);
    return writeFileDescriptor(fd, takeOwnership);
}

status_t Parcel::writeDupParcelFileDescriptor(int fd)
{
    int dupFd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (dupFd < 0) {
        return -errno;
    }
    status_t err = writeParcelFileDescriptor(dupFd, true /*takeOwnership*/);
    if (err != OK) {
        close(dupFd);
    }
    return err;
}

status_t Parcel::writeUniqueFileDescriptor(const base::unique_fd& fd) {
    return writeDupFileDescriptor(fd.get());
}

status_t Parcel::writeBlob(size_t len, bool mutableCopy, WritableBlob* outBlob)
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    status_t status;
    if (!mAllowFds || len <= BLOB_INPLACE_LIMIT) {
        ALOGV("writeBlob: write in place");
        status = writeInt32(BLOB_INPLACE);
        if (status) return status;

        void* ptr = writeInplace(len);
        if (!ptr) return NO_MEMORY;

        outBlob->init(-1, ptr, len, false);
        return NO_ERROR;
    }

    ALOGV("writeBlob: write to ashmem");
    int fd = ashmem_create_region("Parcel Blob", len);
    if (fd < 0) return NO_MEMORY;

    int result = ashmem_set_prot_region(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        status = result;
    } else {
        void* ptr = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
            status = -errno;
        } else {
            if (!mutableCopy) {
                result = ashmem_set_prot_region(fd, PROT_READ);
            }
            if (result < 0) {
                status = result;
            } else {
                status = writeInt32(mutableCopy ? BLOB_ASHMEM_MUTABLE : BLOB_ASHMEM_IMMUTABLE);
                if (!status) {
                    status = writeFileDescriptor(fd, true /*takeOwnership*/);
                    if (!status) {
                        outBlob->init(fd, ptr, len, mutableCopy);
                        return NO_ERROR;
                    }
                }
            }
        }
        ::munmap(ptr, len);
    }
    ::close(fd);
    return status;
}

status_t Parcel::writeDupImmutableBlobFileDescriptor(int fd)
{
    // Must match up with what's done in writeBlob.
    if (!mAllowFds) return FDS_NOT_ALLOWED;
    status_t status = writeInt32(BLOB_ASHMEM_IMMUTABLE);
    if (status) return status;
    return writeDupFileDescriptor(fd);
}

status_t Parcel::write(const FlattenableHelperInterface& val)
{
    status_t err;

    // size if needed
    const size_t len = val.getFlattenedSize();
    const size_t fd_count = val.getFdCount();

    if ((len > INT32_MAX) || (fd_count >= gMaxFds)) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    err = this->writeInt32(len);
    if (err) return err;

    err = this->writeInt32(fd_count);
    if (err) return err;

    // payload
    void* const buf = this->writeInplace(len);
    if (buf == nullptr)
        return BAD_VALUE;

    int* fds = nullptr;
    if (fd_count) {
        fds = new (std::nothrow) int[fd_count];
        if (fds == nullptr) {
            ALOGE("write: failed to allocate requested %zu fds", fd_count);
            return BAD_VALUE;
        }
    }

    err = val.flatten(buf, len, fds, fd_count);
    for (size_t i=0 ; i<fd_count && err==NO_ERROR ; i++) {
        err = this->writeDupFileDescriptor( fds[i] );
    }

    if (fd_count) {
        delete [] fds;
    }

    return err;
}

status_t Parcel::writeObject(const flat_binder_object& val, bool nullMetaData)
{
    const bool enoughData = (mDataPos+sizeof(val)) <= mDataCapacity;
    const bool enoughObjects = mObjectsSize < mObjectsCapacity;
    if (enoughData && enoughObjects) {
restart_write:
        *reinterpret_cast<flat_binder_object*>(mData+mDataPos) = val;

        // remember if it's a file descriptor
        if (val.hdr.type == BINDER_TYPE_FD) {
            if (!mAllowFds) {
                // fail before modifying our object index
                return FDS_NOT_ALLOWED;
            }
            mHasFds = mFdsKnown = true;
        }

        // Need to write meta-data?
        if (nullMetaData || val.binder != 0) {
            mObjects[mObjectsSize] = mDataPos;
            acquire_object(ProcessState::self(), val, this, &mOpenAshmemSize);
            mObjectsSize++;
        }

        return finishWrite(sizeof(flat_binder_object));
    }

    if (!enoughData) {
        const status_t err = growData(sizeof(val));
        if (err != NO_ERROR) return err;
    }
    if (!enoughObjects) {
        if (mObjectsSize > SIZE_MAX - 2) return NO_MEMORY; // overflow
        if ((mObjectsSize + 2) > SIZE_MAX / 3) return NO_MEMORY; // overflow
        size_t newSize = ((mObjectsSize+2)*3)/2;
        if (newSize > SIZE_MAX / sizeof(binder_size_t)) return NO_MEMORY; // overflow
        binder_size_t* objects = (binder_size_t*)realloc(mObjects, newSize*sizeof(binder_size_t));
        if (objects == nullptr) return NO_MEMORY;
        mObjects = objects;
        mObjectsCapacity = newSize;
    }

    goto restart_write;
}

status_t Parcel::writeNoException()
{
    binder::Status status;
    return status.writeToParcel(this);
}

status_t Parcel::validateReadData(size_t upperBound) const
{
    // Don't allow non-object reads on object data
    if (mObjectsSorted || mObjectsSize <= 1) {
data_sorted:
        // Expect to check only against the next object
        if (mNextObjectHint < mObjectsSize && upperBound > mObjects[mNextObjectHint]) {
            // For some reason the current read position is greater than the next object
            // hint. Iterate until we find the right object
            size_t nextObject = mNextObjectHint;
            do {
                if (mDataPos < mObjects[nextObject] + sizeof(flat_binder_object)) {
                    // Requested info overlaps with an object
                    ALOGE("Attempt to read from protected data in Parcel %p", this);
                    return PERMISSION_DENIED;
                }
                nextObject++;
            } while (nextObject < mObjectsSize && upperBound > mObjects[nextObject]);
            mNextObjectHint = nextObject;
        }
        return NO_ERROR;
    }
    // Quickly determine if mObjects is sorted.
    binder_size_t* currObj = mObjects + mObjectsSize - 1;
    binder_size_t* prevObj = currObj;
    while (currObj > mObjects) {
        prevObj--;
        if(*prevObj > *currObj) {
            goto data_unsorted;
        }
        currObj--;
    }
    mObjectsSorted = true;
    goto data_sorted;

data_unsorted:
    // Insertion Sort mObjects
    // Great for mostly sorted lists. If randomly sorted or reverse ordered mObjects become common,
    // switch to std::sort(mObjects, mObjects + mObjectsSize);
    for (binder_size_t* iter0 = mObjects + 1; iter0 < mObjects + mObjectsSize; iter0++) {
        binder_size_t temp = *iter0;
        binder_size_t* iter1 = iter0 - 1;
        while (iter1 >= mObjects && *iter1 > temp) {
            *(iter1 + 1) = *iter1;
            iter1--;
        }
        *(iter1 + 1) = temp;
    }
    mNextObjectHint = 0;
    mObjectsSorted = true;
    goto data_sorted;
}

status_t Parcel::read(void* outData, size_t len) const
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    if ((mDataPos+pad_size(len)) >= mDataPos && (mDataPos+pad_size(len)) <= mDataSize
            && len <= pad_size(len)) {
        if (mObjectsSize > 0) {
            status_t err = validateReadData(mDataPos + pad_size(len));
            if(err != NO_ERROR) {
                // Still increment the data position by the expected length
                mDataPos += pad_size(len);
                ALOGV("read Setting data pos of %p to %zu", this, mDataPos);
                return err;
            }
        }
        memcpy(outData, mData+mDataPos, len);
        mDataPos += pad_size(len);
        ALOGV("read Setting data pos of %p to %zu", this, mDataPos);
        return NO_ERROR;
    }
    return NOT_ENOUGH_DATA;
}

const void* Parcel::readInplace(size_t len) const
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return nullptr;
    }

    if ((mDataPos+pad_size(len)) >= mDataPos && (mDataPos+pad_size(len)) <= mDataSize
            && len <= pad_size(len)) {
        if (mObjectsSize > 0) {
            status_t err = validateReadData(mDataPos + pad_size(len));
            if(err != NO_ERROR) {
                // Still increment the data position by the expected length
                mDataPos += pad_size(len);
                ALOGV("readInplace Setting data pos of %p to %zu", this, mDataPos);
                return nullptr;
            }
        }

        const void* data = mData+mDataPos;
        mDataPos += pad_size(len);
        ALOGV("readInplace Setting data pos of %p to %zu", this, mDataPos);
        return data;
    }
    return nullptr;
}

status_t Parcel::readOutVectorSizeWithCheck(size_t elmSize, int32_t* size) const {
    if (status_t status = readInt32(size); status != OK) return status;
    if (*size < 0) return OK; // may be null, client to handle

    LOG_ALWAYS_FATAL_IF(elmSize > INT32_MAX, "Cannot have element as big as %zu", elmSize);

    // approximation, can't know max element size (e.g. if it makes heap
    // allocations)
    static_assert(sizeof(int) == sizeof(int32_t), "Android is LP64");
    int32_t allocationSize;
    if (__builtin_smul_overflow(elmSize, *size, &allocationSize)) return NO_MEMORY;

    // High limit of 1MB since something this big could never be returned. Could
    // probably scope this down, but might impact very specific usecases.
    constexpr int32_t kMaxAllocationSize = 1 * 1000 * 1000;

    if (allocationSize >= kMaxAllocationSize) {
        return NO_MEMORY;
    }

    return OK;
}

template<class T>
status_t Parcel::readAligned(T *pArg) const {
    static_assert(PAD_SIZE_UNSAFE(sizeof(T)) == sizeof(T));

    if ((mDataPos+sizeof(T)) <= mDataSize) {
        if (mObjectsSize > 0) {
            status_t err = validateReadData(mDataPos + sizeof(T));
            if(err != NO_ERROR) {
                // Still increment the data position by the expected length
                mDataPos += sizeof(T);
                return err;
            }
        }

        const void* data = mData+mDataPos;
        mDataPos += sizeof(T);
        *pArg =  *reinterpret_cast<const T*>(data);
        return NO_ERROR;
    } else {
        return NOT_ENOUGH_DATA;
    }
}

template<class T>
T Parcel::readAligned() const {
    T result;
    if (readAligned(&result) != NO_ERROR) {
        result = 0;
    }

    return result;
}

template<class T>
status_t Parcel::writeAligned(T val) {
    static_assert(PAD_SIZE_UNSAFE(sizeof(T)) == sizeof(T));

    if ((mDataPos+sizeof(val)) <= mDataCapacity) {
restart_write:
        *reinterpret_cast<T*>(mData+mDataPos) = val;
        return finishWrite(sizeof(val));
    }

    status_t err = growData(sizeof(val));
    if (err == NO_ERROR) goto restart_write;
    return err;
}

status_t Parcel::readInt32(int32_t *pArg) const
{
    return readAligned(pArg);
}

int32_t Parcel::readInt32() const
{
    return readAligned<int32_t>();
}

status_t Parcel::readUint32(uint32_t *pArg) const
{
    return readAligned(pArg);
}

uint32_t Parcel::readUint32() const
{
    return readAligned<uint32_t>();
}

status_t Parcel::readInt64(int64_t *pArg) const
{
    return readAligned(pArg);
}


int64_t Parcel::readInt64() const
{
    return readAligned<int64_t>();
}

status_t Parcel::readUint64(uint64_t *pArg) const
{
    return readAligned(pArg);
}

uint64_t Parcel::readUint64() const
{
    return readAligned<uint64_t>();
}

status_t Parcel::readPointer(uintptr_t *pArg) const
{
    status_t ret;
    binder_uintptr_t ptr;
    ret = readAligned(&ptr);
    if (!ret)
        *pArg = ptr;
    return ret;
}

uintptr_t Parcel::readPointer() const
{
    return readAligned<binder_uintptr_t>();
}


status_t Parcel::readFloat(float *pArg) const
{
    return readAligned(pArg);
}


float Parcel::readFloat() const
{
    return readAligned<float>();
}

#if defined(__mips__) && defined(__mips_hard_float)

status_t Parcel::readDouble(double *pArg) const
{
    union {
      double d;
      unsigned long long ll;
    } u;
    u.d = 0;
    status_t status;
    status = readAligned(&u.ll);
    *pArg = u.d;
    return status;
}

double Parcel::readDouble() const
{
    union {
      double d;
      unsigned long long ll;
    } u;
    u.ll = readAligned<unsigned long long>();
    return u.d;
}

#else

status_t Parcel::readDouble(double *pArg) const
{
    return readAligned(pArg);
}

double Parcel::readDouble() const
{
    return readAligned<double>();
}

#endif

status_t Parcel::readBool(bool *pArg) const
{
    int32_t tmp = 0;
    status_t ret = readInt32(&tmp);
    *pArg = (tmp != 0);
    return ret;
}

bool Parcel::readBool() const
{
    return readInt32() != 0;
}

status_t Parcel::readChar(char16_t *pArg) const
{
    int32_t tmp = 0;
    status_t ret = readInt32(&tmp);
    *pArg = char16_t(tmp);
    return ret;
}

char16_t Parcel::readChar() const
{
    return char16_t(readInt32());
}

status_t Parcel::readByte(int8_t *pArg) const
{
    int32_t tmp = 0;
    status_t ret = readInt32(&tmp);
    *pArg = int8_t(tmp);
    return ret;
}

int8_t Parcel::readByte() const
{
    return int8_t(readInt32());
}

status_t Parcel::readUtf8FromUtf16(std::string* str) const {
    size_t utf16Size = 0;
    const char16_t* src = readString16Inplace(&utf16Size);
    if (!src) {
        return UNEXPECTED_NULL;
    }

    // Save ourselves the trouble, we're done.
    if (utf16Size == 0u) {
        str->clear();
       return NO_ERROR;
    }

    // Allow for closing '\0'
    ssize_t utf8Size = utf16_to_utf8_length(src, utf16Size) + 1;
    if (utf8Size < 1) {
        return BAD_VALUE;
    }
    // Note that while it is probably safe to assume string::resize keeps a
    // spare byte around for the trailing null, we still pass the size including the trailing null
    str->resize(utf8Size);
    utf16_to_utf8(src, utf16Size, &((*str)[0]), utf8Size);
    str->resize(utf8Size - 1);
    return NO_ERROR;
}

const char* Parcel::readCString() const
{
    if (mDataPos < mDataSize) {
        const size_t avail = mDataSize-mDataPos;
        const char* str = reinterpret_cast<const char*>(mData+mDataPos);
        // is the string's trailing NUL within the parcel's valid bounds?
        const char* eos = reinterpret_cast<const char*>(memchr(str, 0, avail));
        if (eos) {
            const size_t len = eos - str;
            mDataPos += pad_size(len+1);
            ALOGV("readCString Setting data pos of %p to %zu", this, mDataPos);
            return str;
        }
    }
    return nullptr;
}

String8 Parcel::readString8() const
{
    size_t len;
    const char* str = readString8Inplace(&len);
    if (str) return String8(str, len);
    ALOGE("Reading a NULL string not supported here.");
    return String8();
}

status_t Parcel::readString8(String8* pArg) const
{
    size_t len;
    const char* str = readString8Inplace(&len);
    if (str) {
        pArg->setTo(str, len);
        return 0;
    } else {
        *pArg = String8();
        return UNEXPECTED_NULL;
    }
}

const char* Parcel::readString8Inplace(size_t* outLen) const
{
    int32_t size = readInt32();
    // watch for potential int overflow from size+1
    if (size >= 0 && size < INT32_MAX) {
        *outLen = size;
        const char* str = (const char*)readInplace(size+1);
        if (str != nullptr) {
            if (str[size] == '\0') {
                return str;
            }
            android_errorWriteLog(0x534e4554, "172655291");
        }
    }
    *outLen = 0;
    return nullptr;
}

String16 Parcel::readString16() const
{
    size_t len;
    const char16_t* str = readString16Inplace(&len);
    if (str) return String16(str, len);
    ALOGE("Reading a NULL string not supported here.");
    return String16();
}


status_t Parcel::readString16(String16* pArg) const
{
    size_t len;
    const char16_t* str = readString16Inplace(&len);
    if (str) {
        pArg->setTo(str, len);
        return 0;
    } else {
        *pArg = String16();
        return UNEXPECTED_NULL;
    }
}

const char16_t* Parcel::readString16Inplace(size_t* outLen) const
{
    int32_t size = readInt32();
    // watch for potential int overflow from size+1
    if (size >= 0 && size < INT32_MAX) {
        *outLen = size;
        const char16_t* str = (const char16_t*)readInplace((size+1)*sizeof(char16_t));
        if (str != nullptr) {
            if (str[size] == u'\0') {
                return str;
            }
            android_errorWriteLog(0x534e4554, "172655291");
        }
    }
    *outLen = 0;
    return nullptr;
}

status_t Parcel::readStrongBinder(sp<IBinder>* val) const
{
    status_t status = readNullableStrongBinder(val);
    if (status == OK && !val->get()) {
        status = UNEXPECTED_NULL;
    }
    return status;
}

status_t Parcel::readNullableStrongBinder(sp<IBinder>* val) const
{
    return unflattenBinder(val);
}

sp<IBinder> Parcel::readStrongBinder() const
{
    sp<IBinder> val;
    // Note that a lot of code in Android reads binders by hand with this
    // method, and that code has historically been ok with getting nullptr
    // back (while ignoring error codes).
    readNullableStrongBinder(&val);
    return val;
}

int32_t Parcel::readExceptionCode() const
{
    binder::Status status;
    status.readFromParcel(*this);
    return status.exceptionCode();
}

native_handle* Parcel::readNativeHandle() const
{
    int numFds, numInts;
    status_t err;
    err = readInt32(&numFds);
    if (err != NO_ERROR) return nullptr;
    err = readInt32(&numInts);
    if (err != NO_ERROR) return nullptr;

    native_handle* h = native_handle_create(numFds, numInts);
    if (!h) {
        return nullptr;
    }

    for (int i=0 ; err==NO_ERROR && i<numFds ; i++) {
        h->data[i] = fcntl(readFileDescriptor(), F_DUPFD_CLOEXEC, 0);
        if (h->data[i] < 0) {
            for (int j = 0; j < i; j++) {
                close(h->data[j]);
            }
            native_handle_delete(h);
            return nullptr;
        }
    }
    err = read(h->data + numFds, sizeof(int)*numInts);
    if (err != NO_ERROR) {
        native_handle_close(h);
        native_handle_delete(h);
        h = nullptr;
    }
    return h;
}

int Parcel::readFileDescriptor() const
{
    const flat_binder_object* flat = readObject(true);

    if (flat && flat->hdr.type == BINDER_TYPE_FD) {
        return flat->handle;
    }

    return BAD_TYPE;
}

int Parcel::readParcelFileDescriptor() const
{
    int32_t hasComm = readInt32();
    int fd = readFileDescriptor();
    if (hasComm != 0) {
        // detach (owned by the binder driver)
        int comm = readFileDescriptor();

        // warning: this must be kept in sync with:
        // frameworks/base/core/java/android/os/ParcelFileDescriptor.java
        enum ParcelFileDescriptorStatus {
            DETACHED = 2,
        };

#if BYTE_ORDER == BIG_ENDIAN
        const int32_t message = ParcelFileDescriptorStatus::DETACHED;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
        const int32_t message = __builtin_bswap32(ParcelFileDescriptorStatus::DETACHED);
#endif

        ssize_t written = TEMP_FAILURE_RETRY(
            ::write(comm, &message, sizeof(message)));

        if (written != sizeof(message)) {
            ALOGW("Failed to detach ParcelFileDescriptor written: %zd err: %s",
                written, strerror(errno));
            return BAD_TYPE;
        }
    }
    return fd;
}

status_t Parcel::readUniqueFileDescriptor(base::unique_fd* val) const
{
    int got = readFileDescriptor();

    if (got == BAD_TYPE) {
        return BAD_TYPE;
    }

    val->reset(fcntl(got, F_DUPFD_CLOEXEC, 0));

    if (val->get() < 0) {
        return BAD_VALUE;
    }

    return OK;
}

status_t Parcel::readUniqueParcelFileDescriptor(base::unique_fd* val) const
{
    int got = readParcelFileDescriptor();

    if (got == BAD_TYPE) {
        return BAD_TYPE;
    }

    val->reset(fcntl(got, F_DUPFD_CLOEXEC, 0));

    if (val->get() < 0) {
        return BAD_VALUE;
    }

    return OK;
}

status_t Parcel::readBlob(size_t len, ReadableBlob* outBlob) const
{
    int32_t blobType;
    status_t status = readInt32(&blobType);
    if (status) return status;

    if (blobType == BLOB_INPLACE) {
        ALOGV("readBlob: read in place");
        const void* ptr = readInplace(len);
        if (!ptr) return BAD_VALUE;

        outBlob->init(-1, const_cast<void*>(ptr), len, false);
        return NO_ERROR;
    }

    ALOGV("readBlob: read from ashmem");
    bool isMutable = (blobType == BLOB_ASHMEM_MUTABLE);
    int fd = readFileDescriptor();
    if (fd == int(BAD_TYPE)) return BAD_VALUE;

    if (!ashmem_valid(fd)) {
        ALOGE("invalid fd");
        return BAD_VALUE;
    }
    int size = ashmem_get_size_region(fd);
    if (size < 0 || size_t(size) < len) {
        ALOGE("request size %zu does not match fd size %d", len, size);
        return BAD_VALUE;
    }
    void* ptr = ::mmap(nullptr, len, isMutable ? PROT_READ | PROT_WRITE : PROT_READ,
            MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) return NO_MEMORY;

    outBlob->init(fd, ptr, len, isMutable);
    return NO_ERROR;
}

status_t Parcel::read(FlattenableHelperInterface& val) const
{
    // size
    const size_t len = this->readInt32();
    const size_t fd_count = this->readInt32();

    if ((len > INT32_MAX) || (fd_count >= gMaxFds)) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    // payload
    void const* const buf = this->readInplace(pad_size(len));
    if (buf == nullptr)
        return BAD_VALUE;

    int* fds = nullptr;
    if (fd_count) {
        fds = new (std::nothrow) int[fd_count];
        if (fds == nullptr) {
            ALOGE("read: failed to allocate requested %zu fds", fd_count);
            return BAD_VALUE;
        }
    }

    status_t err = NO_ERROR;
    for (size_t i=0 ; i<fd_count && err==NO_ERROR ; i++) {
        int fd = this->readFileDescriptor();
        if (fd < 0 || ((fds[i] = fcntl(fd, F_DUPFD_CLOEXEC, 0)) < 0)) {
            err = BAD_VALUE;
            ALOGE("fcntl(F_DUPFD_CLOEXEC) failed in Parcel::read, i is %zu, fds[i] is %d, fd_count is %zu, error: %s",
                  i, fds[i], fd_count, strerror(fd < 0 ? -fd : errno));
            // Close all the file descriptors that were dup-ed.
            for (size_t j=0; j<i ;j++) {
                close(fds[j]);
            }
        }
    }

    if (err == NO_ERROR) {
        err = val.unflatten(buf, len, fds, fd_count);
    }

    if (fd_count) {
        delete [] fds;
    }

    return err;
}
const flat_binder_object* Parcel::readObject(bool nullMetaData) const
{
    const size_t DPOS = mDataPos;
    if ((DPOS+sizeof(flat_binder_object)) <= mDataSize) {
        const flat_binder_object* obj
                = reinterpret_cast<const flat_binder_object*>(mData+DPOS);
        mDataPos = DPOS + sizeof(flat_binder_object);
        if (!nullMetaData && (obj->cookie == 0 && obj->binder == 0)) {
            // When transferring a NULL object, we don't write it into
            // the object list, so we don't want to check for it when
            // reading.
            ALOGV("readObject Setting data pos of %p to %zu", this, mDataPos);
            return obj;
        }

        // Ensure that this object is valid...
        binder_size_t* const OBJS = mObjects;
        const size_t N = mObjectsSize;
        size_t opos = mNextObjectHint;

        if (N > 0) {
            ALOGV("Parcel %p looking for obj at %zu, hint=%zu",
                 this, DPOS, opos);

            // Start at the current hint position, looking for an object at
            // the current data position.
            if (opos < N) {
                while (opos < (N-1) && OBJS[opos] < DPOS) {
                    opos++;
                }
            } else {
                opos = N-1;
            }
            if (OBJS[opos] == DPOS) {
                // Found it!
                ALOGV("Parcel %p found obj %zu at index %zu with forward search",
                     this, DPOS, opos);
                mNextObjectHint = opos+1;
                ALOGV("readObject Setting data pos of %p to %zu", this, mDataPos);
                return obj;
            }

            // Look backwards for it...
            while (opos > 0 && OBJS[opos] > DPOS) {
                opos--;
            }
            if (OBJS[opos] == DPOS) {
                // Found it!
                ALOGV("Parcel %p found obj %zu at index %zu with backward search",
                     this, DPOS, opos);
                mNextObjectHint = opos+1;
                ALOGV("readObject Setting data pos of %p to %zu", this, mDataPos);
                return obj;
            }
        }
        ALOGW("Attempt to read object from Parcel %p at offset %zu that is not in the object list",
             this, DPOS);
    }
    return nullptr;
}

void Parcel::closeFileDescriptors()
{
    size_t i = mObjectsSize;
    if (i > 0) {
        //ALOGI("Closing file descriptors for %zu objects...", i);
    }
    while (i > 0) {
        i--;
        const flat_binder_object* flat
            = reinterpret_cast<flat_binder_object*>(mData+mObjects[i]);
        if (flat->hdr.type == BINDER_TYPE_FD) {
            //ALOGI("Closing fd: %ld", flat->handle);
            close(flat->handle);
        }
    }
}

uintptr_t Parcel::ipcData() const
{
    return reinterpret_cast<uintptr_t>(mData);
}

size_t Parcel::ipcDataSize() const
{
    return (mDataSize > mDataPos ? mDataSize : mDataPos);
}

uintptr_t Parcel::ipcObjects() const
{
    return reinterpret_cast<uintptr_t>(mObjects);
}

size_t Parcel::ipcObjectsCount() const
{
    return mObjectsSize;
}

void Parcel::ipcSetDataReference(const uint8_t* data, size_t dataSize,
    const binder_size_t* objects, size_t objectsCount, release_func relFunc)
{
    // this code uses 'mOwner == nullptr' to understand whether it owns memory
    LOG_ALWAYS_FATAL_IF(relFunc == nullptr, "must provide cleanup function");

    freeData();

    mData = const_cast<uint8_t*>(data);
    mDataSize = mDataCapacity = dataSize;
    mObjects = const_cast<binder_size_t*>(objects);
    mObjectsSize = mObjectsCapacity = objectsCount;
    mOwner = relFunc;

    binder_size_t minOffset = 0;
    for (size_t i = 0; i < mObjectsSize; i++) {
        binder_size_t offset = mObjects[i];
        if (offset < minOffset) {
            ALOGE("%s: bad object offset %" PRIu64 " < %" PRIu64 "\n",
                  __func__, (uint64_t)offset, (uint64_t)minOffset);
            mObjectsSize = 0;
            break;
        }
        const flat_binder_object* flat
            = reinterpret_cast<const flat_binder_object*>(mData + offset);
        uint32_t type = flat->hdr.type;
        if (!(type == BINDER_TYPE_BINDER || type == BINDER_TYPE_HANDLE ||
              type == BINDER_TYPE_FD)) {
            // We should never receive other types (eg BINDER_TYPE_FDA) as long as we don't support
            // them in libbinder. If we do receive them, it probably means a kernel bug; try to
            // recover gracefully by clearing out the objects, and releasing the objects we do
            // know about.
            android_errorWriteLog(0x534e4554, "135930648");
            ALOGE("%s: unsupported type object (%" PRIu32 ") at offset %" PRIu64 "\n",
                  __func__, type, (uint64_t)offset);
            releaseObjects();
            mObjectsSize = 0;
            break;
        }
        minOffset = offset + sizeof(flat_binder_object);
    }
    scanForFds();
}

void Parcel::print(TextOutput& to, uint32_t /*flags*/) const
{
    to << "Parcel(";

    if (errorCheck() != NO_ERROR) {
        const status_t err = errorCheck();
        to << "Error: " << (void*)(intptr_t)err << " \"" << strerror(-err) << "\"";
    } else if (dataSize() > 0) {
        const uint8_t* DATA = data();
        to << indent << HexDump(DATA, dataSize()) << dedent;
        const binder_size_t* OBJS = mObjects;
        const size_t N = objectsCount();
        for (size_t i=0; i<N; i++) {
            const flat_binder_object* flat
                = reinterpret_cast<const flat_binder_object*>(DATA+OBJS[i]);
            to << endl << "Object #" << i << " @ " << (void*)OBJS[i] << ": "
                << TypeCode(flat->hdr.type & 0x7f7f7f00)
                << " = " << flat->binder;
        }
    } else {
        to << "NULL";
    }

    to << ")";
}

void Parcel::releaseObjects()
{
    size_t i = mObjectsSize;
    if (i == 0) {
        return;
    }
    sp<ProcessState> proc(ProcessState::self());
    uint8_t* const data = mData;
    binder_size_t* const objects = mObjects;
    while (i > 0) {
        i--;
        const flat_binder_object* flat
            = reinterpret_cast<flat_binder_object*>(data+objects[i]);
        release_object(proc, *flat, this, &mOpenAshmemSize);
    }
}

void Parcel::acquireObjects()
{
    size_t i = mObjectsSize;
    if (i == 0) {
        return;
    }
    const sp<ProcessState> proc(ProcessState::self());
    uint8_t* const data = mData;
    binder_size_t* const objects = mObjects;
    while (i > 0) {
        i--;
        const flat_binder_object* flat
            = reinterpret_cast<flat_binder_object*>(data+objects[i]);
        acquire_object(proc, *flat, this, &mOpenAshmemSize);
    }
}

void Parcel::freeData()
{
    freeDataNoInit();
    initState();
}

void Parcel::freeDataNoInit()
{
    if (mOwner) {
        LOG_ALLOC("Parcel %p: freeing other owner data", this);
        //ALOGI("Freeing data ref of %p (pid=%d)", this, getpid());
        mOwner(this, mData, mDataSize, mObjects, mObjectsSize);
    } else {
        LOG_ALLOC("Parcel %p: freeing allocated data", this);
        releaseObjects();
        if (mData) {
            LOG_ALLOC("Parcel %p: freeing with %zu capacity", this, mDataCapacity);
            gParcelGlobalAllocSize -= mDataCapacity;
            gParcelGlobalAllocCount--;
            if (mDeallocZero) {
                zeroMemory(mData, mDataSize);
            }
            free(mData);
        }
        if (mObjects) free(mObjects);
    }
}

status_t Parcel::growData(size_t len)
{
    if (len > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    if (len > SIZE_MAX - mDataSize) return NO_MEMORY; // overflow
    if (mDataSize + len > SIZE_MAX / 3) return NO_MEMORY; // overflow
    size_t newSize = ((mDataSize+len)*3)/2;
    return (newSize <= mDataSize)
            ? (status_t) NO_MEMORY
            : continueWrite(std::max(newSize, (size_t) 128));
}

static uint8_t* reallocZeroFree(uint8_t* data, size_t oldCapacity, size_t newCapacity, bool zero) {
    if (!zero) {
        return (uint8_t*)realloc(data, newCapacity);
    }
    uint8_t* newData = (uint8_t*)malloc(newCapacity);
    if (!newData) {
        return nullptr;
    }

    memcpy(newData, data, std::min(oldCapacity, newCapacity));
    zeroMemory(data, oldCapacity);
    free(data);
    return newData;
}

status_t Parcel::restartWrite(size_t desired)
{
    if (desired > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    if (mOwner) {
        freeData();
        return continueWrite(desired);
    }

    uint8_t* data = reallocZeroFree(mData, mDataCapacity, desired, mDeallocZero);
    if (!data && desired > mDataCapacity) {
        mError = NO_MEMORY;
        return NO_MEMORY;
    }

    releaseObjects();

    if (data || desired == 0) {
        LOG_ALLOC("Parcel %p: restart from %zu to %zu capacity", this, mDataCapacity, desired);
        if (mDataCapacity > desired) {
            gParcelGlobalAllocSize -= (mDataCapacity - desired);
        } else {
            gParcelGlobalAllocSize += (desired - mDataCapacity);
        }

        if (!mData) {
            gParcelGlobalAllocCount++;
        }
        mData = data;
        mDataCapacity = desired;
    }

    mDataSize = mDataPos = 0;
    ALOGV("restartWrite Setting data size of %p to %zu", this, mDataSize);
    ALOGV("restartWrite Setting data pos of %p to %zu", this, mDataPos);

    free(mObjects);
    mObjects = nullptr;
    mObjectsSize = mObjectsCapacity = 0;
    mNextObjectHint = 0;
    mObjectsSorted = false;
    mHasFds = false;
    mFdsKnown = true;
    mAllowFds = true;

    return NO_ERROR;
}

status_t Parcel::continueWrite(size_t desired)
{
    if (desired > INT32_MAX) {
        // don't accept size_t values which may have come from an
        // inadvertent conversion from a negative int.
        return BAD_VALUE;
    }

    // If shrinking, first adjust for any objects that appear
    // after the new data size.
    size_t objectsSize = mObjectsSize;
    if (desired < mDataSize) {
        if (desired == 0) {
            objectsSize = 0;
        } else {
            while (objectsSize > 0) {
                if (mObjects[objectsSize-1] < desired)
                    break;
                objectsSize--;
            }
        }
    }

    if (mOwner) {
        // If the size is going to zero, just release the owner's data.
        if (desired == 0) {
            freeData();
            return NO_ERROR;
        }

        // If there is a different owner, we need to take
        // posession.
        uint8_t* data = (uint8_t*)malloc(desired);
        if (!data) {
            mError = NO_MEMORY;
            return NO_MEMORY;
        }
        binder_size_t* objects = nullptr;

        if (objectsSize) {
            objects = (binder_size_t*)calloc(objectsSize, sizeof(binder_size_t));
            if (!objects) {
                free(data);

                mError = NO_MEMORY;
                return NO_MEMORY;
            }

            // Little hack to only acquire references on objects
            // we will be keeping.
            size_t oldObjectsSize = mObjectsSize;
            mObjectsSize = objectsSize;
            acquireObjects();
            mObjectsSize = oldObjectsSize;
        }

        if (mData) {
            memcpy(data, mData, mDataSize < desired ? mDataSize : desired);
        }
        if (objects && mObjects) {
            memcpy(objects, mObjects, objectsSize*sizeof(binder_size_t));
        }
        //ALOGI("Freeing data ref of %p (pid=%d)", this, getpid());
        mOwner(this, mData, mDataSize, mObjects, mObjectsSize);
        mOwner = nullptr;

        LOG_ALLOC("Parcel %p: taking ownership of %zu capacity", this, desired);
        gParcelGlobalAllocSize += desired;
        gParcelGlobalAllocCount++;

        mData = data;
        mObjects = objects;
        mDataSize = (mDataSize < desired) ? mDataSize : desired;
        ALOGV("continueWrite Setting data size of %p to %zu", this, mDataSize);
        mDataCapacity = desired;
        mObjectsSize = mObjectsCapacity = objectsSize;
        mNextObjectHint = 0;
        mObjectsSorted = false;

    } else if (mData) {
        if (objectsSize < mObjectsSize) {
            // Need to release refs on any objects we are dropping.
            const sp<ProcessState> proc(ProcessState::self());
            for (size_t i=objectsSize; i<mObjectsSize; i++) {
                const flat_binder_object* flat
                    = reinterpret_cast<flat_binder_object*>(mData+mObjects[i]);
                if (flat->hdr.type == BINDER_TYPE_FD) {
                    // will need to rescan because we may have lopped off the only FDs
                    mFdsKnown = false;
                }
                release_object(proc, *flat, this, &mOpenAshmemSize);
            }

            if (objectsSize == 0) {
                free(mObjects);
                mObjects = nullptr;
                mObjectsCapacity = 0;
            } else {
                binder_size_t* objects =
                    (binder_size_t*)realloc(mObjects, objectsSize*sizeof(binder_size_t));
                if (objects) {
                    mObjects = objects;
                    mObjectsCapacity = objectsSize;
                }
            }
            mObjectsSize = objectsSize;
            mNextObjectHint = 0;
            mObjectsSorted = false;
        }

        // We own the data, so we can just do a realloc().
        if (desired > mDataCapacity) {
            uint8_t* data = reallocZeroFree(mData, mDataCapacity, desired, mDeallocZero);
            if (data) {
                LOG_ALLOC("Parcel %p: continue from %zu to %zu capacity", this, mDataCapacity,
                        desired);
                gParcelGlobalAllocSize += desired;
                gParcelGlobalAllocSize -= mDataCapacity;
                mData = data;
                mDataCapacity = desired;
            } else {
                mError = NO_MEMORY;
                return NO_MEMORY;
            }
        } else {
            if (mDataSize > desired) {
                mDataSize = desired;
                ALOGV("continueWrite Setting data size of %p to %zu", this, mDataSize);
            }
            if (mDataPos > desired) {
                mDataPos = desired;
                ALOGV("continueWrite Setting data pos of %p to %zu", this, mDataPos);
            }
        }

    } else {
        // This is the first data.  Easy!
        uint8_t* data = (uint8_t*)malloc(desired);
        if (!data) {
            mError = NO_MEMORY;
            return NO_MEMORY;
        }

        if(!(mDataCapacity == 0 && mObjects == nullptr
             && mObjectsCapacity == 0)) {
            ALOGE("continueWrite: %zu/%p/%zu/%zu", mDataCapacity, mObjects, mObjectsCapacity, desired);
        }

        LOG_ALLOC("Parcel %p: allocating with %zu capacity", this, desired);
        gParcelGlobalAllocSize += desired;
        gParcelGlobalAllocCount++;

        mData = data;
        mDataSize = mDataPos = 0;
        ALOGV("continueWrite Setting data size of %p to %zu", this, mDataSize);
        ALOGV("continueWrite Setting data pos of %p to %zu", this, mDataPos);
        mDataCapacity = desired;
    }

    return NO_ERROR;
}

void Parcel::initState()
{
    LOG_ALLOC("Parcel %p: initState", this);
    mError = NO_ERROR;
    mData = nullptr;
    mDataSize = 0;
    mDataCapacity = 0;
    mDataPos = 0;
    ALOGV("initState Setting data size of %p to %zu", this, mDataSize);
    ALOGV("initState Setting data pos of %p to %zu", this, mDataPos);
    mSession = nullptr;
    mObjects = nullptr;
    mObjectsSize = 0;
    mObjectsCapacity = 0;
    mNextObjectHint = 0;
    mObjectsSorted = false;
    mHasFds = false;
    mFdsKnown = true;
    mAllowFds = true;
    mDeallocZero = false;
    mOwner = nullptr;
    mOpenAshmemSize = 0;
    mWorkSourceRequestHeaderPosition = 0;
    mRequestHeaderPresent = false;

    // racing multiple init leads only to multiple identical write
    if (gMaxFds == 0) {
        struct rlimit result;
        if (!getrlimit(RLIMIT_NOFILE, &result)) {
            gMaxFds = (size_t)result.rlim_cur;
            //ALOGI("parcel fd limit set to %zu", gMaxFds);
        } else {
            ALOGW("Unable to getrlimit: %s", strerror(errno));
            gMaxFds = 1024;
        }
    }
}

void Parcel::scanForFds() const
{
    bool hasFds = false;
    for (size_t i=0; i<mObjectsSize; i++) {
        const flat_binder_object* flat
            = reinterpret_cast<const flat_binder_object*>(mData + mObjects[i]);
        if (flat->hdr.type == BINDER_TYPE_FD) {
            hasFds = true;
            break;
        }
    }
    mHasFds = hasFds;
    mFdsKnown = true;
}

size_t Parcel::getBlobAshmemSize() const
{
    // This used to return the size of all blobs that were written to ashmem, now we're returning
    // the ashmem currently referenced by this Parcel, which should be equivalent.
    // TODO: Remove method once ABI can be changed.
    return mOpenAshmemSize;
}

size_t Parcel::getOpenAshmemSize() const
{
    return mOpenAshmemSize;
}

// --- Parcel::Blob ---

Parcel::Blob::Blob() :
        mFd(-1), mData(nullptr), mSize(0), mMutable(false) {
}

Parcel::Blob::~Blob() {
    release();
}

void Parcel::Blob::release() {
    if (mFd != -1 && mData) {
        ::munmap(mData, mSize);
    }
    clear();
}

void Parcel::Blob::init(int fd, void* data, size_t size, bool isMutable) {
    mFd = fd;
    mData = data;
    mSize = size;
    mMutable = isMutable;
}

void Parcel::Blob::clear() {
    mFd = -1;
    mData = nullptr;
    mSize = 0;
    mMutable = false;
}

} // namespace android
