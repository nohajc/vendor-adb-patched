/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <binder_rpc_unstable.hpp>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android/binder_libbinder.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <cutils/sockets.h>
#include <linux/vm_sockets.h>

using android::OK;
using android::RpcServer;
using android::RpcSession;
using android::sp;
using android::status_t;
using android::statusToString;
using android::base::unique_fd;

// Opaque handle for RpcServer.
struct ARpcServer {};

// Opaque handle for RpcSession.
struct ARpcSession {};

template <typename A, typename T>
static A* createObjectHandle(sp<T>& server) {
    auto ref = server.get();
    ref->incStrong(ref);
    return reinterpret_cast<A*>(ref);
}

template <typename T, typename A>
static void freeObjectHandle(A* handle) {
    LOG_ALWAYS_FATAL_IF(handle == nullptr, "Handle cannot be null");
    auto ref = reinterpret_cast<T*>(handle);
    ref->decStrong(ref);
}

template <typename T, typename A>
static sp<T> handleToStrongPointer(A* handle) {
    LOG_ALWAYS_FATAL_IF(handle == nullptr, "Handle cannot be null");
    auto ref = reinterpret_cast<T*>(handle);
    return sp<T>::fromExisting(ref);
}

RpcSession::FileDescriptorTransportMode toTransportMode(
        ARpcSession_FileDescriptorTransportMode mode) {
    switch (mode) {
        case ARpcSession_FileDescriptorTransportMode::None:
            return RpcSession::FileDescriptorTransportMode::NONE;
        case ARpcSession_FileDescriptorTransportMode::Unix:
            return RpcSession::FileDescriptorTransportMode::UNIX;
        case ARpcSession_FileDescriptorTransportMode::Trusty:
            return RpcSession::FileDescriptorTransportMode::TRUSTY;
        default:
            return RpcSession::FileDescriptorTransportMode::NONE;
    }
}

extern "C" {

ARpcServer* ARpcServer_newVsock(AIBinder* service, unsigned int cid, unsigned int port) {
    auto server = RpcServer::make();

    unsigned int bindCid = VMADDR_CID_ANY; // bind to the remote interface
    if (cid == VMADDR_CID_LOCAL) {
        bindCid = VMADDR_CID_LOCAL; // bind to the local interface
        cid = VMADDR_CID_ANY;       // no need for a connection filter
    }

    if (status_t status = server->setupVsockServer(bindCid, port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock server with port " << port
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    if (cid != VMADDR_CID_ANY) {
        server->setConnectionFilter([=](const void* addr, size_t addrlen) {
            LOG_ALWAYS_FATAL_IF(addrlen < sizeof(sockaddr_vm), "sockaddr is truncated");
            const sockaddr_vm* vaddr = reinterpret_cast<const sockaddr_vm*>(addr);
            LOG_ALWAYS_FATAL_IF(vaddr->svm_family != AF_VSOCK, "address is not a vsock");
            if (cid != vaddr->svm_cid) {
                LOG(ERROR) << "Rejected vsock connection from CID " << vaddr->svm_cid;
                return false;
            }
            return true;
        });
    }
    server->setRootObject(AIBinder_toPlatformBinder(service));
    return createObjectHandle<ARpcServer>(server);
}

ARpcServer* ARpcServer_newBoundSocket(AIBinder* service, int socketFd) {
    auto server = RpcServer::make();
    auto fd = unique_fd(socketFd);
    if (!fd.ok()) {
        LOG(ERROR) << "Invalid socket fd " << socketFd;
        return nullptr;
    }
    if (status_t status = server->setupRawSocketServer(std::move(fd)); status != OK) {
        LOG(ERROR) << "Failed to set up RPC server with fd " << socketFd
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    server->setRootObject(AIBinder_toPlatformBinder(service));
    return createObjectHandle<ARpcServer>(server);
}

ARpcServer* ARpcServer_newUnixDomainBootstrap(AIBinder* service, int bootstrapFd) {
    auto server = RpcServer::make();
    auto fd = unique_fd(bootstrapFd);
    if (!fd.ok()) {
        LOG(ERROR) << "Invalid bootstrap fd " << bootstrapFd;
        return nullptr;
    }
    if (status_t status = server->setupUnixDomainSocketBootstrapServer(std::move(fd));
        status != OK) {
        LOG(ERROR) << "Failed to set up Unix Domain RPC server with bootstrap fd " << bootstrapFd
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    server->setRootObject(AIBinder_toPlatformBinder(service));
    return createObjectHandle<ARpcServer>(server);
}

ARpcServer* ARpcServer_newInet(AIBinder* service, const char* address, unsigned int port) {
    auto server = RpcServer::make();
    if (status_t status = server->setupInetServer(address, port, nullptr); status != OK) {
        LOG(ERROR) << "Failed to set up inet RPC server with address " << address << " and port "
                   << port << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    server->setRootObject(AIBinder_toPlatformBinder(service));
    return createObjectHandle<ARpcServer>(server);
}

void ARpcServer_setSupportedFileDescriptorTransportModes(
        ARpcServer* handle, const ARpcSession_FileDescriptorTransportMode modes[],
        size_t modes_len) {
    auto server = handleToStrongPointer<RpcServer>(handle);
    std::vector<RpcSession::FileDescriptorTransportMode> modevec;
    for (size_t i = 0; i < modes_len; i++) {
        modevec.push_back(toTransportMode(modes[i]));
    }
    server->setSupportedFileDescriptorTransportModes(modevec);
}

void ARpcServer_start(ARpcServer* handle) {
    handleToStrongPointer<RpcServer>(handle)->start();
}

void ARpcServer_join(ARpcServer* handle) {
    handleToStrongPointer<RpcServer>(handle)->join();
}

bool ARpcServer_shutdown(ARpcServer* handle) {
    return handleToStrongPointer<RpcServer>(handle)->shutdown();
}

void ARpcServer_free(ARpcServer* handle) {
    // Ignore the result of ARpcServer_shutdown - either it had been called
    // earlier, or the RpcServer destructor will panic.
    (void)ARpcServer_shutdown(handle);
    freeObjectHandle<RpcServer>(handle);
}

ARpcSession* ARpcSession_new() {
    auto session = RpcSession::make();
    return createObjectHandle<ARpcSession>(session);
}

void ARpcSession_free(ARpcSession* handle) {
    freeObjectHandle<RpcSession>(handle);
}

AIBinder* ARpcSession_setupVsockClient(ARpcSession* handle, unsigned int cid, unsigned int port) {
    auto session = handleToStrongPointer<RpcSession>(handle);
    if (status_t status = session->setupVsockClient(cid, port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client with CID " << cid << " and port " << port
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* ARpcSession_setupUnixDomainClient(ARpcSession* handle, const char* name) {
    std::string pathname(name);
    pathname = ANDROID_SOCKET_DIR "/" + pathname;
    auto session = handleToStrongPointer<RpcSession>(handle);
    if (status_t status = session->setupUnixDomainClient(pathname.c_str()); status != OK) {
        LOG(ERROR) << "Failed to set up Unix Domain RPC client with path: " << pathname
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* ARpcSession_setupUnixDomainBootstrapClient(ARpcSession* handle, int bootstrapFd) {
    auto session = handleToStrongPointer<RpcSession>(handle);
    auto fd = unique_fd(dup(bootstrapFd));
    if (!fd.ok()) {
        LOG(ERROR) << "Invalid bootstrap fd " << bootstrapFd;
        return nullptr;
    }
    if (status_t status = session->setupUnixDomainSocketBootstrapClient(std::move(fd));
        status != OK) {
        LOG(ERROR) << "Failed to set up Unix Domain RPC client with bootstrap fd: " << bootstrapFd
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* ARpcSession_setupInet(ARpcSession* handle, const char* address, unsigned int port) {
    auto session = handleToStrongPointer<RpcSession>(handle);
    if (status_t status = session->setupInetClient(address, port); status != OK) {
        LOG(ERROR) << "Failed to set up inet RPC client with address " << address << " and port "
                   << port << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* ARpcSession_setupPreconnectedClient(ARpcSession* handle, int (*requestFd)(void* param),
                                              void* param) {
    auto session = handleToStrongPointer<RpcSession>(handle);
    auto request = [=] { return unique_fd{requestFd(param)}; };
    if (status_t status = session->setupPreconnectedClient(unique_fd{}, request); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client. error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

void ARpcSession_setFileDescriptorTransportMode(ARpcSession* handle,
                                                ARpcSession_FileDescriptorTransportMode mode) {
    auto session = handleToStrongPointer<RpcSession>(handle);
    session->setFileDescriptorTransportMode(toTransportMode(mode));
}

void ARpcSession_setMaxIncomingThreads(ARpcSession* handle, size_t threads) {
    auto session = handleToStrongPointer<RpcSession>(handle);
    session->setMaxIncomingThreads(threads);
}

void ARpcSession_setMaxOutgoingConnections(ARpcSession* handle, size_t connections) {
    auto session = handleToStrongPointer<RpcSession>(handle);
    session->setMaxOutgoingConnections(connections);
}
}
