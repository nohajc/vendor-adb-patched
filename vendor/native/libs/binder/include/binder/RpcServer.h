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
#include <binder/RpcSession.h>
#include <binder/RpcThreads.h>
#include <binder/RpcTransport.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <mutex>
#include <thread>

namespace android {

class FdTrigger;
class RpcServerTrusty;
class RpcSocketAddress;

/**
 * This represents a server of an interface, which may be connected to by any
 * number of clients over sockets.
 *
 * Usage:
 *     auto server = RpcServer::make();
 *     // only supports one now
 *     if (!server->setup*Server(...)) {
 *         :(
 *     }
 *     server->join();
 */
class RpcServer final : public virtual RefBase, private RpcSession::EventListener {
public:
    static sp<RpcServer> make(
            std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory = nullptr);

    /**
     * This represents a session for responses, e.g.:
     *
     *     process A serves binder a
     *     process B opens a session to process A
     *     process B makes binder b and sends it to A
     *     A uses this 'back session' to send things back to B
     */
    [[nodiscard]] status_t setupUnixDomainServer(const char* path);

    /**
     * Creates an RPC server at the current port.
     */
    [[nodiscard]] status_t setupVsockServer(unsigned int port);

    /**
     * Creates an RPC server at the current port using IPv4.
     *
     * TODO(b/182914638): IPv6 support
     *
     * Set |port| to 0 to pick an ephemeral port; see discussion of
     * /proc/sys/net/ipv4/ip_local_port_range in ip(7). In this case, |assignedPort|
     * will be set to the picked port number, if it is not null.
     *
     * Set the IPv4 address for the socket to be listening on.
     * "127.0.0.1" allows for local connections from the same device.
     * "0.0.0.0" allows for connections on any IP address that the device may
     * have
     */
    [[nodiscard]] status_t setupInetServer(const char* address, unsigned int port,
                                           unsigned int* assignedPort = nullptr);

    /**
     * If setup*Server has been successful, return true. Otherwise return false.
     */
    [[nodiscard]] bool hasServer();

    /**
     * If hasServer(), return the server FD. Otherwise return invalid FD.
     */
    [[nodiscard]] base::unique_fd releaseServer();

    /**
     * Set up server using an external FD previously set up by releaseServer().
     * Return false if there's already a server.
     */
    [[nodiscard]] status_t setupExternalServer(base::unique_fd serverFd);

    /**
     * This must be called before adding a client session.
     *
     * If this is not specified, this will be a single-threaded server.
     *
     * TODO(b/167966510): these are currently created per client, but these
     * should be shared.
     */
    void setMaxThreads(size_t threads);
    size_t getMaxThreads();

    /**
     * By default, the latest protocol version which is supported by a client is
     * used. However, this can be used in order to prevent newer protocol
     * versions from ever being used. This is expected to be useful for testing.
     */
    void setProtocolVersion(uint32_t version);

    /**
     * Set the supported transports for sending and receiving file descriptors.
     *
     * Clients will propose a mode when connecting. If the mode is not in the
     * provided list, the connection will be rejected.
     */
    void setSupportedFileDescriptorTransportModes(
            const std::vector<RpcSession::FileDescriptorTransportMode>& modes);

    /**
     * The root object can be retrieved by any client, without any
     * authentication. TODO(b/183988761)
     *
     * Holds a strong reference to the root object.
     */
    void setRootObject(const sp<IBinder>& binder);
    /**
     * Holds a weak reference to the root object.
     */
    void setRootObjectWeak(const wp<IBinder>& binder);
    /**
     * Allows a root object to be created for each session.
     *
     * Takes one argument: a callable that is invoked once per new session.
     * The callable takes two arguments: a type-erased pointer to an OS- and
     * transport-specific address structure, e.g., sockaddr_vm for vsock, and
     * an integer representing the size in bytes of that structure. The
     * callable should validate the size, then cast the type-erased pointer
     * to a pointer to the actual type of the address, e.g., const void* to
     * const sockaddr_vm*.
     */
    void setPerSessionRootObject(std::function<sp<IBinder>(const void*, size_t)>&& object);
    sp<IBinder> getRootObject();

    /**
     * See RpcTransportCtx::getCertificate
     */
    std::vector<uint8_t> getCertificate(RpcCertificateFormat);

    /**
     * Runs join() in a background thread. Immediately returns.
     */
    void start();

    /**
     * You must have at least one client session before calling this.
     *
     * If a client needs to actively terminate join, call shutdown() in a separate thread.
     *
     * At any given point, there can only be one thread calling join().
     *
     * Warning: if shutdown is called, this will return while the shutdown is
     * still occurring. To ensure that the service is fully shutdown, you might
     * want to call shutdown after 'join' returns.
     */
    void join();

    /**
     * Shut down any existing join(). Return true if successfully shut down, false otherwise
     * (e.g. no join() is running). Will wait for the server to be fully
     * shutdown.
     *
     * Warning: this will hang if it is called from its own thread.
     */
    [[nodiscard]] bool shutdown();

    /**
     * For debugging!
     */
    std::vector<sp<RpcSession>> listSessions();
    size_t numUninitializedSessions();

    ~RpcServer();

private:
    friend RpcServerTrusty;
    friend sp<RpcServer>;
    explicit RpcServer(std::unique_ptr<RpcTransportCtx> ctx);

    void onSessionAllIncomingThreadsEnded(const sp<RpcSession>& session) override;
    void onSessionIncomingThreadEnded() override;

    static constexpr size_t kRpcAddressSize = 128;
    static void establishConnection(
            sp<RpcServer>&& server, base::unique_fd clientFd,
            std::array<uint8_t, kRpcAddressSize> addr, size_t addrLen,
            std::function<void(sp<RpcSession>&&, RpcSession::PreJoinSetupResult&&)>&& joinFn);
    [[nodiscard]] status_t setupSocketServer(const RpcSocketAddress& address);

    const std::unique_ptr<RpcTransportCtx> mCtx;
    size_t mMaxThreads = 1;
    std::optional<uint32_t> mProtocolVersion;
    // A mode is supported if the N'th bit is on, where N is the mode enum's value.
    std::bitset<8> mSupportedFileDescriptorTransportModes = std::bitset<8>().set(
            static_cast<size_t>(RpcSession::FileDescriptorTransportMode::NONE));
    base::unique_fd mServer; // socket we are accepting sessions on

    RpcMutex mLock; // for below
    std::unique_ptr<RpcMaybeThread> mJoinThread;
    bool mJoinThreadRunning = false;
    std::map<RpcMaybeThread::id, RpcMaybeThread> mConnectingThreads;

    sp<IBinder> mRootObject;
    wp<IBinder> mRootObjectWeak;
    std::function<sp<IBinder>(const void*, size_t)> mRootObjectFactory;
    std::map<std::vector<uint8_t>, sp<RpcSession>> mSessions;
    std::unique_ptr<FdTrigger> mShutdownTrigger;
    RpcConditionVariable mShutdownCv;
};

} // namespace android
