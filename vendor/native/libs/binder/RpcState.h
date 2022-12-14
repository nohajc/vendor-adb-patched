/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android-base/unique_fd.h>
#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <binder/RpcSession.h>

#include <map>
#include <optional>
#include <queue>

namespace android {

struct RpcWireHeader;

/**
 * Log a lot more information about RPC calls, when debugging issues. Usually,
 * you would want to enable this in only one process. If repeated issues require
 * a specific subset of logs to debug, this could be broken up like
 * IPCThreadState's.
 */
#define SHOULD_LOG_RPC_DETAIL false

#if SHOULD_LOG_RPC_DETAIL
#define LOG_RPC_DETAIL(...) ALOGI(__VA_ARGS__)
#else
#define LOG_RPC_DETAIL(...) ALOGV(__VA_ARGS__) // for type checking
#endif

#define RPC_FLAKE_PRONE false

#if RPC_FLAKE_PRONE
void rpcMaybeWaitToFlake();
#define MAYBE_WAIT_IN_FLAKE_MODE rpcMaybeWaitToFlake()
#else
#define MAYBE_WAIT_IN_FLAKE_MODE do {} while (false)
#endif

/**
 * Abstracts away management of ref counts and the wire format from
 * RpcSession
 */
class RpcState {
public:
    RpcState();
    ~RpcState();

    status_t sendConnectionInit(const sp<RpcSession::RpcConnection>& connection,
                                const sp<RpcSession>& session);
    status_t readConnectionInit(const sp<RpcSession::RpcConnection>& connection,
                                const sp<RpcSession>& session);

    // TODO(b/182940634): combine some special transactions into one "getServerInfo" call?
    sp<IBinder> getRootObject(const sp<RpcSession::RpcConnection>& connection,
                              const sp<RpcSession>& session);
    status_t getMaxThreads(const sp<RpcSession::RpcConnection>& connection,
                           const sp<RpcSession>& session, size_t* maxThreadsOut);
    status_t getSessionId(const sp<RpcSession::RpcConnection>& connection,
                          const sp<RpcSession>& session, RpcAddress* sessionIdOut);

    [[nodiscard]] status_t transact(const sp<RpcSession::RpcConnection>& connection,
                                    const sp<IBinder>& address, uint32_t code, const Parcel& data,
                                    const sp<RpcSession>& session, Parcel* reply, uint32_t flags);
    [[nodiscard]] status_t transactAddress(const sp<RpcSession::RpcConnection>& connection,
                                           const RpcAddress& address, uint32_t code,
                                           const Parcel& data, const sp<RpcSession>& session,
                                           Parcel* reply, uint32_t flags);
    [[nodiscard]] status_t sendDecStrong(const sp<RpcSession::RpcConnection>& connection,
                                         const sp<RpcSession>& session, const RpcAddress& address);

    enum class CommandType {
        ANY,
        CONTROL_ONLY,
    };
    [[nodiscard]] status_t getAndExecuteCommand(const sp<RpcSession::RpcConnection>& connection,
                                                const sp<RpcSession>& session, CommandType type);
    [[nodiscard]] status_t drainCommands(const sp<RpcSession::RpcConnection>& connection,
                                         const sp<RpcSession>& session, CommandType type);

    /**
     * Called by Parcel for outgoing binders. This implies one refcount of
     * ownership to the outgoing binder.
     */
    [[nodiscard]] status_t onBinderLeaving(const sp<RpcSession>& session, const sp<IBinder>& binder,
                                           RpcAddress* outAddress);

    /**
     * Called by Parcel for incoming binders. This either returns the refcount
     * to the process, if this process already has one, or it takes ownership of
     * that refcount
     */
    [[nodiscard]] status_t onBinderEntering(const sp<RpcSession>& session,
                                            const RpcAddress& address, sp<IBinder>* out);

    size_t countBinders();
    void dump();

    /**
     * Called when reading or writing data to a session fails to clean up
     * data associated with the session in order to cleanup binders.
     * Specifically, we have a strong dependency cycle, since BpBinder is
     * OBJECT_LIFETIME_WEAK (so that onAttemptIncStrong may return true).
     *
     *     BpBinder -> RpcSession -> RpcState
     *      ^-----------------------------/
     *
     * In the success case, eventually all refcounts should be propagated over
     * the session, though this could also be called to eagerly cleanup
     * the session.
     *
     * WARNING: RpcState is responsible for calling this when the session is
     * no longer recoverable.
     */
    void clear();

private:
    void dumpLocked();

    // Alternative to std::vector<uint8_t> that doesn't abort on allocation failure and caps
    // large allocations to avoid being requested from allocating too much data.
    struct CommandData {
        explicit CommandData(size_t size);
        bool valid() { return mSize == 0 || mData != nullptr; }
        size_t size() { return mSize; }
        uint8_t* data() { return mData.get(); }
        uint8_t* release() { return mData.release(); }

    private:
        std::unique_ptr<uint8_t[]> mData;
        size_t mSize;
    };

    [[nodiscard]] status_t rpcSend(const sp<RpcSession::RpcConnection>& connection,
                                   const sp<RpcSession>& session, const char* what,
                                   const void* data, size_t size);
    [[nodiscard]] status_t rpcRec(const sp<RpcSession::RpcConnection>& connection,
                                  const sp<RpcSession>& session, const char* what, void* data,
                                  size_t size);

    [[nodiscard]] status_t waitForReply(const sp<RpcSession::RpcConnection>& connection,
                                        const sp<RpcSession>& session, Parcel* reply);
    [[nodiscard]] status_t processCommand(const sp<RpcSession::RpcConnection>& connection,
                                          const sp<RpcSession>& session,
                                          const RpcWireHeader& command, CommandType type);
    [[nodiscard]] status_t processTransact(const sp<RpcSession::RpcConnection>& connection,
                                           const sp<RpcSession>& session,
                                           const RpcWireHeader& command);
    [[nodiscard]] status_t processTransactInternal(const sp<RpcSession::RpcConnection>& connection,
                                                   const sp<RpcSession>& session,
                                                   CommandData transactionData);
    [[nodiscard]] status_t processDecStrong(const sp<RpcSession::RpcConnection>& connection,
                                            const sp<RpcSession>& session,
                                            const RpcWireHeader& command);

    struct BinderNode {
        // Two cases:
        // A - local binder we are serving
        // B - remote binder, we are sending transactions to
        wp<IBinder> binder;

        // if timesSent > 0, this will be equal to binder.promote()
        sp<IBinder> sentRef;

        // Number of times we've sent this binder out of process, which
        // translates to an implicit strong count. A client must send RPC binder
        // socket's dec ref for each time it is sent out of process in order to
        // deallocate it. Note, a proxy binder we are holding onto might be
        // sent (this is important when the only remaining refcount of this
        // binder is the one associated with a transaction sending it back to
        // its server)
        size_t timesSent = 0;

        // Number of times we've received this binder, each time corresponds to
        // a reference we hold over the wire (not a local incStrong/decStrong)
        size_t timesRecd = 0;

        // transaction ID, for async transactions
        uint64_t asyncNumber = 0;

        //
        // CASE A - local binder we are serving
        //

        // async transaction queue, _only_ for local binder
        struct AsyncTodo {
            sp<IBinder> ref;
            CommandData data;
            uint64_t asyncNumber = 0;

            bool operator<(const AsyncTodo& o) const {
                return asyncNumber > /* !!! */ o.asyncNumber;
            }
        };
        std::priority_queue<AsyncTodo> asyncTodo;

        //
        // CASE B - remote binder, we are sending transactions to
        //

        // (no additional data specific to remote binders)
    };

    // checks if there is any reference left to a node and erases it. If erase
    // happens, and there is a strong reference to the binder kept by
    // binderNode, this returns that strong reference, so that it can be
    // dropped after any locks are removed.
    sp<IBinder> tryEraseNode(std::map<RpcAddress, BinderNode>::iterator& it);
    // true - success
    // false - session shutdown, halt
    [[nodiscard]] bool nodeProgressAsyncNumber(BinderNode* node);

    std::mutex mNodeMutex;
    bool mTerminated = false;
    // binders known by both sides of a session
    std::map<RpcAddress, BinderNode> mNodeForAddress;
};

} // namespace android
