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

#include <binder/Binder.h>

#include <atomic>
#include <set>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/BpBinder.h>
#include <binder/IInterface.h>
#include <binder/IPCThreadState.h>
#include <binder/IResultReceiver.h>
#include <binder/IShellCallback.h>
#include <binder/Parcel.h>
#include <binder/RecordedTransaction.h>
#include <binder/RpcServer.h>
#include <cutils/compiler.h>
#include <private/android_filesystem_config.h>
#include <pthread.h>
#include <utils/misc.h>

#include <inttypes.h>
#include <stdio.h>

#ifdef __linux__
#include <linux/sched.h>
#endif

#include "BuildFlags.h"
#include "RpcState.h"

namespace android {

// Service implementations inherit from BBinder and IBinder, and this is frozen
// in prebuilts.
#ifdef __LP64__
static_assert(sizeof(IBinder) == 24);
static_assert(sizeof(BBinder) == 40);
#else
static_assert(sizeof(IBinder) == 12);
static_assert(sizeof(BBinder) == 20);
#endif

// global b/c b/230079120 - consistent symbol table
#ifdef BINDER_RPC_DEV_SERVERS
constexpr bool kEnableRpcDevServers = true;
#else
constexpr bool kEnableRpcDevServers = false;
#endif

#ifdef BINDER_ENABLE_RECORDING
constexpr bool kEnableRecording = true;
#else
constexpr bool kEnableRecording = false;
#endif

// Log any reply transactions for which the data exceeds this size
#define LOG_REPLIES_OVER_SIZE (300 * 1024)
// ---------------------------------------------------------------------------

IBinder::IBinder()
    : RefBase()
{
}

IBinder::~IBinder()
{
}

// ---------------------------------------------------------------------------

sp<IInterface>  IBinder::queryLocalInterface(const String16& /*descriptor*/)
{
    return nullptr;
}

BBinder* IBinder::localBinder()
{
    return nullptr;
}

BpBinder* IBinder::remoteBinder()
{
    return nullptr;
}

bool IBinder::checkSubclass(const void* /*subclassID*/) const
{
    return false;
}


status_t IBinder::shellCommand(const sp<IBinder>& target, int in, int out, int err,
    Vector<String16>& args, const sp<IShellCallback>& callback,
    const sp<IResultReceiver>& resultReceiver)
{
    Parcel send;
    Parcel reply;
    send.writeFileDescriptor(in);
    send.writeFileDescriptor(out);
    send.writeFileDescriptor(err);
    const size_t numArgs = args.size();
    send.writeInt32(numArgs);
    for (size_t i = 0; i < numArgs; i++) {
        send.writeString16(args[i]);
    }
    send.writeStrongBinder(callback != nullptr ? IInterface::asBinder(callback) : nullptr);
    send.writeStrongBinder(resultReceiver != nullptr ? IInterface::asBinder(resultReceiver) : nullptr);
    return target->transact(SHELL_COMMAND_TRANSACTION, send, &reply);
}

status_t IBinder::getExtension(sp<IBinder>* out) {
    BBinder* local = this->localBinder();
    if (local != nullptr) {
        *out = local->getExtension();
        return OK;
    }

    BpBinder* proxy = this->remoteBinder();
    LOG_ALWAYS_FATAL_IF(proxy == nullptr);

    Parcel data;
    Parcel reply;
    status_t status = transact(EXTENSION_TRANSACTION, data, &reply);
    if (status != OK) return status;

    return reply.readNullableStrongBinder(out);
}

status_t IBinder::getDebugPid(pid_t* out) {
    BBinder* local = this->localBinder();
    if (local != nullptr) {
      *out = local->getDebugPid();
      return OK;
    }

    BpBinder* proxy = this->remoteBinder();
    LOG_ALWAYS_FATAL_IF(proxy == nullptr);

    Parcel data;
    Parcel reply;
    status_t status = transact(DEBUG_PID_TRANSACTION, data, &reply);
    if (status != OK) return status;

    int32_t pid;
    status = reply.readInt32(&pid);
    if (status != OK) return status;

    if (pid < 0 || pid > std::numeric_limits<pid_t>::max()) {
        return BAD_VALUE;
    }
    *out = pid;
    return OK;
}

status_t IBinder::setRpcClientDebug(android::base::unique_fd socketFd,
                                    const sp<IBinder>& keepAliveBinder) {
    if (!kEnableRpcDevServers) {
        ALOGW("setRpcClientDebug disallowed because RPC is not enabled");
        return INVALID_OPERATION;
    }
    if (!kEnableKernelIpc) {
        ALOGW("setRpcClientDebug disallowed because kernel binder is not enabled");
        return INVALID_OPERATION;
    }

    BBinder* local = this->localBinder();
    if (local != nullptr) {
        return local->BBinder::setRpcClientDebug(std::move(socketFd), keepAliveBinder);
    }

    BpBinder* proxy = this->remoteBinder();
    LOG_ALWAYS_FATAL_IF(proxy == nullptr, "binder object must be either local or remote");

    Parcel data;
    Parcel reply;
    status_t status;
    if (status = data.writeBool(socketFd.ok()); status != OK) return status;
    if (socketFd.ok()) {
        // writeUniqueFileDescriptor currently makes an unnecessary dup().
        status = data.writeFileDescriptor(socketFd.release(), true /* own */);
        if (status != OK) return status;
    }
    if (status = data.writeStrongBinder(keepAliveBinder); status != OK) return status;
    return transact(SET_RPC_CLIENT_TRANSACTION, data, &reply);
}

void IBinder::withLock(const std::function<void()>& doWithLock) {
    BBinder* local = localBinder();
    if (local) {
        local->withLock(doWithLock);
        return;
    }
    BpBinder* proxy = this->remoteBinder();
    LOG_ALWAYS_FATAL_IF(proxy == nullptr, "binder object must be either local or remote");
    proxy->withLock(doWithLock);
}

sp<IBinder> IBinder::lookupOrCreateWeak(const void* objectID, object_make_func make,
                                        const void* makeArgs) {
    BBinder* local = localBinder();
    if (local) {
        return local->lookupOrCreateWeak(objectID, make, makeArgs);
    }
    BpBinder* proxy = this->remoteBinder();
    LOG_ALWAYS_FATAL_IF(proxy == nullptr, "binder object must be either local or remote");
    return proxy->lookupOrCreateWeak(objectID, make, makeArgs);
}

// ---------------------------------------------------------------------------

class BBinder::RpcServerLink : public IBinder::DeathRecipient {
public:
    // On binder died, calls RpcServer::shutdown on @a rpcServer, and removes itself from @a binder.
    RpcServerLink(const sp<RpcServer>& rpcServer, const sp<IBinder>& keepAliveBinder,
                  const wp<BBinder>& binder)
          : mRpcServer(rpcServer), mKeepAliveBinder(keepAliveBinder), mBinder(binder) {}
    virtual ~RpcServerLink();
    void binderDied(const wp<IBinder>&) override {
        auto promoted = mBinder.promote();
        ALOGI("RpcBinder: binder died, shutting down RpcServer for %s",
              promoted ? String8(promoted->getInterfaceDescriptor()).c_str() : "<NULL>");

        if (mRpcServer == nullptr) {
            ALOGW("RpcServerLink: Unable to shut down RpcServer because it does not exist.");
        } else {
            ALOGW_IF(!mRpcServer->shutdown(),
                     "RpcServerLink: RpcServer did not shut down properly. Not started?");
        }
        mRpcServer.clear();

        if (promoted) {
            promoted->removeRpcServerLink(sp<RpcServerLink>::fromExisting(this));
        }
        mBinder.clear();
    }

private:
    sp<RpcServer> mRpcServer;
    sp<IBinder> mKeepAliveBinder; // hold to avoid automatically unlinking
    wp<BBinder> mBinder;
};
BBinder::RpcServerLink::~RpcServerLink() {}

class BBinder::Extras
{
public:
    // unlocked objects
    sp<IBinder> mExtension;
#ifdef __linux__
    int mPolicy = SCHED_NORMAL;
    int mPriority = 0;
#endif
    bool mRequestingSid = false;
    bool mInheritRt = false;

    // for below objects
    Mutex mLock;
    std::set<sp<RpcServerLink>> mRpcServerLinks;
    BpBinder::ObjectManager mObjects;

    android::base::unique_fd mRecordingFd;
};

// ---------------------------------------------------------------------------

BBinder::BBinder() : mExtras(nullptr), mStability(0), mParceled(false), mRecordingOn(false) {}

bool BBinder::isBinderAlive() const
{
    return true;
}

status_t BBinder::pingBinder()
{
    return NO_ERROR;
}

status_t BBinder::startRecordingTransactions(const Parcel& data) {
    if (!kEnableRecording) {
        ALOGW("Binder recording disallowed because recording is not enabled");
        return INVALID_OPERATION;
    }
    if (!kEnableKernelIpc) {
        ALOGW("Binder recording disallowed because kernel binder is not enabled");
        return INVALID_OPERATION;
    }
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid != AID_ROOT) {
        ALOGE("Binder recording not allowed because client %" PRIu32 " is not root", uid);
        return PERMISSION_DENIED;
    }
    Extras* e = getOrCreateExtras();
    AutoMutex lock(e->mLock);
    if (mRecordingOn) {
        LOG(INFO) << "Could not start Binder recording. Another is already in progress.";
        return INVALID_OPERATION;
    } else {
        status_t readStatus = data.readUniqueFileDescriptor(&(e->mRecordingFd));
        if (readStatus != OK) {
            return readStatus;
        }
        mRecordingOn = true;
        LOG(INFO) << "Started Binder recording.";
        return NO_ERROR;
    }
}

status_t BBinder::stopRecordingTransactions() {
    if (!kEnableRecording) {
        ALOGW("Binder recording disallowed because recording is not enabled");
        return INVALID_OPERATION;
    }
    if (!kEnableKernelIpc) {
        ALOGW("Binder recording disallowed because kernel binder is not enabled");
        return INVALID_OPERATION;
    }
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid != AID_ROOT) {
        ALOGE("Binder recording not allowed because client %" PRIu32 " is not root", uid);
        return PERMISSION_DENIED;
    }
    Extras* e = getOrCreateExtras();
    AutoMutex lock(e->mLock);
    if (mRecordingOn) {
        e->mRecordingFd.reset();
        mRecordingOn = false;
        LOG(INFO) << "Stopped Binder recording.";
        return NO_ERROR;
    } else {
        LOG(INFO) << "Could not stop Binder recording. One is not in progress.";
        return INVALID_OPERATION;
    }
}

const String16& BBinder::getInterfaceDescriptor() const
{
    static StaticString16 sBBinder(u"BBinder");
    ALOGW("Reached BBinder::getInterfaceDescriptor (this=%p). Override?", this);
    return sBBinder;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    data.setDataPosition(0);

    if (reply != nullptr && (flags & FLAG_CLEAR_BUF)) {
        reply->markSensitive();
    }

    status_t err = NO_ERROR;
    switch (code) {
        case PING_TRANSACTION:
            err = pingBinder();
            break;
        case START_RECORDING_TRANSACTION:
            err = startRecordingTransactions(data);
            break;
        case STOP_RECORDING_TRANSACTION:
            err = stopRecordingTransactions();
            break;
        case EXTENSION_TRANSACTION:
            CHECK(reply != nullptr);
            err = reply->writeStrongBinder(getExtension());
            break;
        case DEBUG_PID_TRANSACTION:
            CHECK(reply != nullptr);
            err = reply->writeInt32(getDebugPid());
            break;
        case SET_RPC_CLIENT_TRANSACTION: {
            err = setRpcClientDebug(data);
            break;
        }
        default:
            err = onTransact(code, data, reply, flags);
            break;
    }

    // In case this is being transacted on in the same process.
    if (reply != nullptr) {
        reply->setDataPosition(0);
        if (reply->dataSize() > LOG_REPLIES_OVER_SIZE) {
            ALOGW("Large reply transaction of %zu bytes, interface descriptor %s, code %d",
                  reply->dataSize(), String8(getInterfaceDescriptor()).c_str(), code);
        }
    }

    if (CC_UNLIKELY(kEnableKernelIpc && mRecordingOn && code != START_RECORDING_TRANSACTION)) {
        Extras* e = mExtras.load(std::memory_order_acquire);
        AutoMutex lock(e->mLock);
        if (mRecordingOn) {
            Parcel emptyReply;
            timespec ts;
            timespec_get(&ts, TIME_UTC);
            auto transaction = android::binder::debug::RecordedTransaction::
                    fromDetails(getInterfaceDescriptor(), code, flags, ts, data,
                                reply ? *reply : emptyReply, err);
            if (transaction) {
                if (status_t err = transaction->dumpToFile(e->mRecordingFd); err != NO_ERROR) {
                    LOG(INFO) << "Failed to dump RecordedTransaction to file with error " << err;
                }
            } else {
                LOG(INFO) << "Failed to create RecordedTransaction object.";
            }
        }
    }

    return err;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BBinder::linkToDeath(
    const sp<DeathRecipient>& /*recipient*/, void* /*cookie*/,
    uint32_t /*flags*/)
{
    return INVALID_OPERATION;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BBinder::unlinkToDeath(
    const wp<DeathRecipient>& /*recipient*/, void* /*cookie*/,
    uint32_t /*flags*/, wp<DeathRecipient>* /*outRecipient*/)
{
    return INVALID_OPERATION;
}

status_t BBinder::dump(int /*fd*/, const Vector<String16>& /*args*/)
{
    return NO_ERROR;
}

void* BBinder::attachObject(const void* objectID, void* object, void* cleanupCookie,
                            object_cleanup_func func) {
    Extras* e = getOrCreateExtras();
    LOG_ALWAYS_FATAL_IF(!e, "no memory");

    AutoMutex _l(e->mLock);
    return e->mObjects.attach(objectID, object, cleanupCookie, func);
}

void* BBinder::findObject(const void* objectID) const
{
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (!e) return nullptr;

    AutoMutex _l(e->mLock);
    return e->mObjects.find(objectID);
}

void* BBinder::detachObject(const void* objectID) {
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (!e) return nullptr;

    AutoMutex _l(e->mLock);
    return e->mObjects.detach(objectID);
}

void BBinder::withLock(const std::function<void()>& doWithLock) {
    Extras* e = getOrCreateExtras();
    LOG_ALWAYS_FATAL_IF(!e, "no memory");

    AutoMutex _l(e->mLock);
    doWithLock();
}

sp<IBinder> BBinder::lookupOrCreateWeak(const void* objectID, object_make_func make,
                                        const void* makeArgs) {
    Extras* e = getOrCreateExtras();
    LOG_ALWAYS_FATAL_IF(!e, "no memory");
    AutoMutex _l(e->mLock);
    return e->mObjects.lookupOrCreateWeak(objectID, make, makeArgs);
}

BBinder* BBinder::localBinder()
{
    return this;
}

bool BBinder::isRequestingSid()
{
    Extras* e = mExtras.load(std::memory_order_acquire);

    return e && e->mRequestingSid;
}

void BBinder::setRequestingSid(bool requestingSid)
{
    LOG_ALWAYS_FATAL_IF(mParceled,
                        "setRequestingSid() should not be called after a binder object "
                        "is parceled/sent to another process");

    Extras* e = mExtras.load(std::memory_order_acquire);

    if (!e) {
        // default is false. Most things don't need sids, so avoiding allocations when possible.
        if (!requestingSid) {
            return;
        }

        e = getOrCreateExtras();
        if (!e) return; // out of memory
    }

    e->mRequestingSid = requestingSid;
}

sp<IBinder> BBinder::getExtension() {
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (e == nullptr) return nullptr;
    return e->mExtension;
}

#ifdef __linux__
void BBinder::setMinSchedulerPolicy(int policy, int priority) {
    LOG_ALWAYS_FATAL_IF(mParceled,
                        "setMinSchedulerPolicy() should not be called after a binder object "
                        "is parceled/sent to another process");

    switch (policy) {
    case SCHED_NORMAL:
      LOG_ALWAYS_FATAL_IF(priority < -20 || priority > 19, "Invalid priority for SCHED_NORMAL: %d", priority);
      break;
    case SCHED_RR:
    case SCHED_FIFO:
      LOG_ALWAYS_FATAL_IF(priority < 1 || priority > 99, "Invalid priority for sched %d: %d", policy, priority);
      break;
    default:
      LOG_ALWAYS_FATAL("Unrecognized scheduling policy: %d", policy);
    }

    Extras* e = mExtras.load(std::memory_order_acquire);

    if (e == nullptr) {
        // Avoid allocations if called with default.
        if (policy == SCHED_NORMAL && priority == 0) {
            return;
        }

        e = getOrCreateExtras();
        if (!e) return; // out of memory
    }

    e->mPolicy = policy;
    e->mPriority = priority;
}

int BBinder::getMinSchedulerPolicy() {
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (e == nullptr) return SCHED_NORMAL;
    return e->mPolicy;
}

int BBinder::getMinSchedulerPriority() {
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (e == nullptr) return 0;
    return e->mPriority;
}
#endif // __linux__

bool BBinder::isInheritRt() {
    Extras* e = mExtras.load(std::memory_order_acquire);

    return e && e->mInheritRt;
}

void BBinder::setInheritRt(bool inheritRt) {
    LOG_ALWAYS_FATAL_IF(mParceled,
                        "setInheritRt() should not be called after a binder object "
                        "is parceled/sent to another process");

    Extras* e = mExtras.load(std::memory_order_acquire);

    if (!e) {
        if (!inheritRt) {
            return;
        }

        e = getOrCreateExtras();
        if (!e) return; // out of memory
    }

    e->mInheritRt = inheritRt;
}

pid_t BBinder::getDebugPid() {
#ifdef __linux__
    return getpid();
#else
    // TODO: handle other OSes
    return 0;
#endif // __linux__
}

void BBinder::setExtension(const sp<IBinder>& extension) {
    LOG_ALWAYS_FATAL_IF(mParceled,
                        "setExtension() should not be called after a binder object "
                        "is parceled/sent to another process");

    Extras* e = getOrCreateExtras();
    e->mExtension = extension;
}

bool BBinder::wasParceled() {
    return mParceled;
}

void BBinder::setParceled() {
    mParceled = true;
}

status_t BBinder::setRpcClientDebug(const Parcel& data) {
    if (!kEnableRpcDevServers) {
        ALOGW("%s: disallowed because RPC is not enabled", __PRETTY_FUNCTION__);
        return INVALID_OPERATION;
    }
    if (!kEnableKernelIpc) {
        ALOGW("setRpcClientDebug disallowed because kernel binder is not enabled");
        return INVALID_OPERATION;
    }
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid != AID_ROOT) {
        ALOGE("%s: not allowed because client %" PRIu32 " is not root", __PRETTY_FUNCTION__, uid);
        return PERMISSION_DENIED;
    }
    status_t status;
    bool hasSocketFd;
    android::base::unique_fd clientFd;

    if (status = data.readBool(&hasSocketFd); status != OK) return status;
    if (hasSocketFd) {
        if (status = data.readUniqueFileDescriptor(&clientFd); status != OK) return status;
    }
    sp<IBinder> keepAliveBinder;
    if (status = data.readNullableStrongBinder(&keepAliveBinder); status != OK) return status;

    return setRpcClientDebug(std::move(clientFd), keepAliveBinder);
}

status_t BBinder::setRpcClientDebug(android::base::unique_fd socketFd,
                                    const sp<IBinder>& keepAliveBinder) {
    if (!kEnableRpcDevServers) {
        ALOGW("%s: disallowed because RPC is not enabled", __PRETTY_FUNCTION__);
        return INVALID_OPERATION;
    }
    if (!kEnableKernelIpc) {
        ALOGW("setRpcClientDebug disallowed because kernel binder is not enabled");
        return INVALID_OPERATION;
    }

    const int socketFdForPrint = socketFd.get();
    LOG_RPC_DETAIL("%s(fd=%d)", __PRETTY_FUNCTION__, socketFdForPrint);

    if (!socketFd.ok()) {
        ALOGE("%s: No socket FD provided.", __PRETTY_FUNCTION__);
        return BAD_VALUE;
    }

    if (keepAliveBinder == nullptr) {
        ALOGE("%s: No keepAliveBinder provided.", __PRETTY_FUNCTION__);
        return UNEXPECTED_NULL;
    }

    size_t binderThreadPoolMaxCount = ProcessState::self()->getThreadPoolMaxTotalThreadCount();
    if (binderThreadPoolMaxCount <= 1) {
        ALOGE("%s: ProcessState thread pool max count is %zu. RPC is disabled for this service "
              "because RPC requires the service to support multithreading.",
              __PRETTY_FUNCTION__, binderThreadPoolMaxCount);
        return INVALID_OPERATION;
    }

    // Weak ref to avoid circular dependency:
    // BBinder -> RpcServerLink ----> RpcServer -X-> BBinder
    //                          `-X-> BBinder
    auto weakThis = wp<BBinder>::fromExisting(this);

    Extras* e = getOrCreateExtras();
    AutoMutex _l(e->mLock);
    auto rpcServer = RpcServer::make();
    LOG_ALWAYS_FATAL_IF(rpcServer == nullptr, "RpcServer::make returns null");
    auto link = sp<RpcServerLink>::make(rpcServer, keepAliveBinder, weakThis);
    if (auto status = keepAliveBinder->linkToDeath(link, nullptr, 0); status != OK) {
        ALOGE("%s: keepAliveBinder->linkToDeath returns %s", __PRETTY_FUNCTION__,
              statusToString(status).c_str());
        return status;
    }
    rpcServer->setRootObjectWeak(weakThis);
    if (auto status = rpcServer->setupExternalServer(std::move(socketFd)); status != OK) {
        return status;
    }
    rpcServer->setMaxThreads(binderThreadPoolMaxCount);
    LOG(INFO) << "RpcBinder: Started Binder debug on " << getInterfaceDescriptor();
    rpcServer->start();
    e->mRpcServerLinks.emplace(link);
    LOG_RPC_DETAIL("%s(fd=%d) successful", __PRETTY_FUNCTION__, socketFdForPrint);
    return OK;
}

void BBinder::removeRpcServerLink(const sp<RpcServerLink>& link) {
    Extras* e = mExtras.load(std::memory_order_acquire);
    if (!e) return;
    AutoMutex _l(e->mLock);
    (void)e->mRpcServerLinks.erase(link);
}

BBinder::~BBinder()
{
    if (!wasParceled()) {
        if (getExtension()) {
             ALOGW("Binder %p destroyed with extension attached before being parceled.", this);
        }
        if (isRequestingSid()) {
             ALOGW("Binder %p destroyed when requesting SID before being parceled.", this);
        }
        if (isInheritRt()) {
             ALOGW("Binder %p destroyed after setInheritRt before being parceled.", this);
        }
#ifdef __linux__
        if (getMinSchedulerPolicy() != SCHED_NORMAL) {
             ALOGW("Binder %p destroyed after setMinSchedulerPolicy before being parceled.", this);
        }
        if (getMinSchedulerPriority() != 0) {
             ALOGW("Binder %p destroyed after setMinSchedulerPolicy before being parceled.", this);
        }
#endif // __linux__
    }

    Extras* e = mExtras.load(std::memory_order_relaxed);
    if (e) delete e;
}


// NOLINTNEXTLINE(google-default-arguments)
status_t BBinder::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t /*flags*/)
{
    switch (code) {
        case INTERFACE_TRANSACTION:
            CHECK(reply != nullptr);
            reply->writeString16(getInterfaceDescriptor());
            return NO_ERROR;

        case DUMP_TRANSACTION: {
            int fd = data.readFileDescriptor();
            int argc = data.readInt32();
            Vector<String16> args;
            for (int i = 0; i < argc && data.dataAvail() > 0; i++) {
               args.add(data.readString16());
            }
            return dump(fd, args);
        }

        case SHELL_COMMAND_TRANSACTION: {
            int in = data.readFileDescriptor();
            int out = data.readFileDescriptor();
            int err = data.readFileDescriptor();
            int argc = data.readInt32();
            Vector<String16> args;
            for (int i = 0; i < argc && data.dataAvail() > 0; i++) {
               args.add(data.readString16());
            }
            sp<IBinder> shellCallbackBinder = data.readStrongBinder();
            sp<IResultReceiver> resultReceiver = IResultReceiver::asInterface(
                    data.readStrongBinder());

            // XXX can't add virtuals until binaries are updated.
            // sp<IShellCallback> shellCallback = IShellCallback::asInterface(
            //        shellCallbackBinder);
            // return shellCommand(in, out, err, args, resultReceiver);
            (void)in;
            (void)out;
            (void)err;

            if (resultReceiver != nullptr) {
                resultReceiver->send(INVALID_OPERATION);
            }

            return NO_ERROR;
        }

        case SYSPROPS_TRANSACTION: {
            report_sysprop_change();
            return NO_ERROR;
        }

        default:
            return UNKNOWN_TRANSACTION;
    }
}

BBinder::Extras* BBinder::getOrCreateExtras()
{
    Extras* e = mExtras.load(std::memory_order_acquire);

    if (!e) {
        e = new Extras;
        Extras* expected = nullptr;
        if (!mExtras.compare_exchange_strong(expected, e,
                                             std::memory_order_release,
                                             std::memory_order_acquire)) {
            delete e;
            e = expected;  // Filled in by CAS
        }
        if (e == nullptr) return nullptr; // out of memory
    }

    return e;
}

// ---------------------------------------------------------------------------

enum {
    // This is used to transfer ownership of the remote binder from
    // the BpRefBase object holding it (when it is constructed), to the
    // owner of the BpRefBase object when it first acquires that BpRefBase.
    kRemoteAcquired = 0x00000001
};

BpRefBase::BpRefBase(const sp<IBinder>& o)
    : mRemote(o.get()), mRefs(nullptr), mState(0)
{
    extendObjectLifetime(OBJECT_LIFETIME_WEAK);

    if (mRemote) {
        mRemote->incStrong(this);           // Removed on first IncStrong().
        mRefs = mRemote->createWeak(this);  // Held for our entire lifetime.
    }
}

BpRefBase::~BpRefBase()
{
    if (mRemote) {
        if (!(mState.load(std::memory_order_relaxed)&kRemoteAcquired)) {
            mRemote->decStrong(this);
        }
        mRefs->decWeak(this);
    }
}

void BpRefBase::onFirstRef()
{
    mState.fetch_or(kRemoteAcquired, std::memory_order_relaxed);
}

void BpRefBase::onLastStrongRef(const void* /*id*/)
{
    if (mRemote) {
        mRemote->decStrong(this);
    }
}

bool BpRefBase::onIncStrongAttempted(uint32_t /*flags*/, const void* /*id*/)
{
    return mRemote ? mRefs->attemptIncStrong(this) : false;
}

// ---------------------------------------------------------------------------

} // namespace android
