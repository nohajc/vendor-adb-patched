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
#include <binder/RpcAddress.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <map>
#include <optional>
#include <thread>
#include <vector>

// WARNING: This is a feature which is still in development, and it is subject
// to radical change. Any production use of this may subject your code to any
// number of problems.

namespace android {

class Parcel;
class RpcServer;
class RpcSocketAddress;
class RpcState;

/**
 * This represents a session (group of connections) between a client
 * and a server. Multiple connections are needed for multiple parallel "binder"
 * calls which may also have nested calls.
 */
class RpcSession final : public virtual RefBase {
public:
    static sp<RpcSession> make();

    /**
     * Set the maximum number of threads allowed to be made (for things like callbacks).
     * By default, this is 0. This must be called before setting up this connection as a client.
     * Server sessions will inherits this value from RpcServer.
     *
     * If this is called, 'shutdown' on this session must also be called.
     * Otherwise, a threadpool will leak.
     *
     * TODO(b/189955605): start these dynamically
     */
    void setMaxThreads(size_t threads);
    size_t getMaxThreads();

    /**
     * This should be called once per thread, matching 'join' in the remote
     * process.
     */
    [[nodiscard]] bool setupUnixDomainClient(const char* path);

    /**
     * Connects to an RPC server at the CVD & port.
     */
    [[nodiscard]] bool setupVsockClient(unsigned int cvd, unsigned int port);

    /**
     * Connects to an RPC server at the given address and port.
     */
    [[nodiscard]] bool setupInetClient(const char* addr, unsigned int port);

    /**
     * For debugging!
     *
     * Sets up an empty connection. All queries to this connection which require a
     * response will never be satisfied. All data sent here will be
     * unceremoniously cast down the bottomless pit, /dev/null.
     */
    [[nodiscard]] bool addNullDebuggingClient();

    /**
     * Query the other side of the session for the root object hosted by that
     * process's RpcServer (if one exists)
     */
    sp<IBinder> getRootObject();

    /**
     * Query the other side of the session for the maximum number of threads
     * it supports (maximum number of concurrent non-nested synchronous transactions)
     */
    status_t getRemoteMaxThreads(size_t* maxThreads);

    /**
     * Shuts down the service.
     *
     * For client sessions, wait can be true or false. For server sessions,
     * waiting is not currently supported (will abort).
     *
     * Warning: this is currently not active/nice (the server isn't told we're
     * shutting down). Being nicer to the server could potentially make it
     * reclaim resources faster.
     *
     * If this is called w/ 'wait' true, then this will wait for shutdown to
     * complete before returning. This will hang if it is called from the
     * session threadpool (when processing received calls).
     */
    [[nodiscard]] bool shutdownAndWait(bool wait);

    [[nodiscard]] status_t transact(const sp<IBinder>& binder, uint32_t code, const Parcel& data,
                                    Parcel* reply, uint32_t flags);
    [[nodiscard]] status_t sendDecStrong(const RpcAddress& address);

    ~RpcSession();

    /**
     * Server if this session is created as part of a server (symmetrical to
     * client servers). Otherwise, nullptr.
     */
    sp<RpcServer> server();

    // internal only
    const std::unique_ptr<RpcState>& state() { return mState; }

private:
    friend sp<RpcSession>;
    friend RpcServer;
    friend RpcState;
    RpcSession();

    /** This is not a pipe. */
    struct FdTrigger {
        /** Returns nullptr for error case */
        static std::unique_ptr<FdTrigger> make();

        /**
         * Close the write end of the pipe so that the read end receives POLLHUP.
         * Not threadsafe.
         */
        void trigger();

        /**
         * Whether this has been triggered.
         */
        bool isTriggered();

        /**
         * Poll for a read event.
         *
         * event - for pollfd
         *
         * Return:
         *   true - time to read!
         *   false - trigger happened
         */
        status_t triggerablePoll(base::borrowed_fd fd, int16_t event);

        /**
         * Read (or write), but allow to be interrupted by this trigger.
         *
         * Return:
         *   true - succeeded in completely processing 'size'
         *   false - interrupted (failure or trigger)
         */
        status_t interruptableReadFully(base::borrowed_fd fd, void* data, size_t size);
        status_t interruptableWriteFully(base::borrowed_fd fd, const void* data, size_t size);

    private:
        base::unique_fd mWrite;
        base::unique_fd mRead;
    };

    class EventListener : public virtual RefBase {
    public:
        virtual void onSessionLockedAllIncomingThreadsEnded(const sp<RpcSession>& session) = 0;
        virtual void onSessionIncomingThreadEnded() = 0;
    };

    class WaitForShutdownListener : public EventListener {
    public:
        void onSessionLockedAllIncomingThreadsEnded(const sp<RpcSession>& session) override;
        void onSessionIncomingThreadEnded() override;
        void waitForShutdown(std::unique_lock<std::mutex>& lock);

    private:
        std::condition_variable mCv;
        bool mShutdown = false;
    };

    struct RpcConnection : public RefBase {
        base::unique_fd fd;

        // whether this or another thread is currently using this fd to make
        // or receive transactions.
        std::optional<pid_t> exclusiveTid;

        bool allowNested = false;
    };

    status_t readId();

    // A thread joining a server must always call these functions in order, and
    // cleanup is only programmed once into join. These are in separate
    // functions in order to allow for different locks to be taken during
    // different parts of setup.
    //
    // transfer ownership of thread (usually done while a lock is taken on the
    // structure which originally owns the thread)
    void preJoinThreadOwnership(std::thread thread);
    // pass FD to thread and read initial connection information
    struct PreJoinSetupResult {
        // Server connection object associated with this
        sp<RpcConnection> connection;
        // Status of setup
        status_t status;
    };
    PreJoinSetupResult preJoinSetup(base::unique_fd fd);
    // join on thread passed to preJoinThreadOwnership
    static void join(sp<RpcSession>&& session, PreJoinSetupResult&& result);

    [[nodiscard]] bool setupSocketClient(const RpcSocketAddress& address);
    [[nodiscard]] bool setupOneSocketConnection(const RpcSocketAddress& address,
                                                const RpcAddress& sessionId, bool server);
    [[nodiscard]] bool addIncomingConnection(base::unique_fd fd);
    [[nodiscard]] bool addOutgoingConnection(base::unique_fd fd, bool init);
    [[nodiscard]] bool setForServer(const wp<RpcServer>& server,
                                    const wp<RpcSession::EventListener>& eventListener,
                                    const RpcAddress& sessionId);
    sp<RpcConnection> assignIncomingConnectionToThisThread(base::unique_fd fd);
    [[nodiscard]] bool removeIncomingConnection(const sp<RpcConnection>& connection);

    enum class ConnectionUse {
        CLIENT,
        CLIENT_ASYNC,
        CLIENT_REFCOUNT,
    };

    // Object representing exclusive access to a connection.
    class ExclusiveConnection {
    public:
        static status_t find(const sp<RpcSession>& session, ConnectionUse use,
                             ExclusiveConnection* connection);

        ~ExclusiveConnection();
        const sp<RpcConnection>& get() { return mConnection; }

    private:
        static void findConnection(pid_t tid, sp<RpcConnection>* exclusive,
                                   sp<RpcConnection>* available,
                                   std::vector<sp<RpcConnection>>& sockets,
                                   size_t socketsIndexHint);

        sp<RpcSession> mSession; // avoid deallocation
        sp<RpcConnection> mConnection;

        // whether this is being used for a nested transaction (being on the same
        // thread guarantees we won't write in the middle of a message, the way
        // the wire protocol is constructed guarantees this is safe).
        bool mReentrant = false;
    };

    // On the other side of a session, for each of mOutgoingConnections here, there should
    // be one of mIncomingConnections on the other side (and vice versa).
    //
    // For the simplest session, a single server with one client, you would
    // have:
    //  - the server has a single 'mIncomingConnections' and a thread listening on this
    //  - the client has a single 'mOutgoingConnections' and makes calls to this
    //  - here, when the client makes a call, the server can call back into it
    //    (nested calls), but outside of this, the client will only ever read
    //    calls from the server when it makes a call itself.
    //
    // For a more complicated case, the client might itself open up a thread to
    // serve calls to the server at all times (e.g. if it hosts a callback)

    wp<RpcServer> mForServer; // maybe null, for client sessions
    sp<WaitForShutdownListener> mShutdownListener; // used for client sessions
    wp<EventListener> mEventListener; // mForServer if server, mShutdownListener if client

    std::optional<RpcAddress> mId;

    std::unique_ptr<FdTrigger> mShutdownTrigger;

    std::unique_ptr<RpcState> mState;

    std::mutex mMutex; // for all below

    size_t mMaxThreads = 0;

    std::condition_variable mAvailableConnectionCv; // for mWaitingThreads
    size_t mWaitingThreads = 0;
    // hint index into clients, ++ when sending an async transaction
    size_t mOutgoingConnectionsOffset = 0;
    std::vector<sp<RpcConnection>> mOutgoingConnections;
    std::vector<sp<RpcConnection>> mIncomingConnections;
    std::map<std::thread::id, std::thread> mThreads;
};

} // namespace android
