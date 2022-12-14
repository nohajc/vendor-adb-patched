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

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android/binder_libbinder.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <linux/vm_sockets.h>

using android::OK;
using android::RpcServer;
using android::RpcSession;
using android::status_t;
using android::statusToString;
using android::base::unique_fd;

extern "C" {

bool RunRpcServerWithFactory(AIBinder* (*factory)(unsigned int cid, void* context),
                             void* factoryContext, unsigned int port) {
    auto server = RpcServer::make();
    if (status_t status = server->setupVsockServer(port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock server with port " << port
                   << " error: " << statusToString(status).c_str();
        return false;
    }
    server->setPerSessionRootObject([=](const void* addr, size_t addrlen) {
        LOG_ALWAYS_FATAL_IF(addrlen < sizeof(sockaddr_vm), "sockaddr is truncated");
        const sockaddr_vm* vaddr = reinterpret_cast<const sockaddr_vm*>(addr);
        LOG_ALWAYS_FATAL_IF(vaddr->svm_family != AF_VSOCK, "address is not a vsock");
        return AIBinder_toPlatformBinder(factory(vaddr->svm_cid, factoryContext));
    });

    server->join();

    // Shutdown any open sessions since server failed.
    (void)server->shutdown();
    return true;
}

bool RunRpcServerCallback(AIBinder* service, unsigned int port, void (*readyCallback)(void* param),
                          void* param) {
    auto server = RpcServer::make();
    if (status_t status = server->setupVsockServer(port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock server with port " << port
                   << " error: " << statusToString(status).c_str();
        return false;
    }
    server->setRootObject(AIBinder_toPlatformBinder(service));

    if (readyCallback) readyCallback(param);
    server->join();

    // Shutdown any open sessions since server failed.
    (void)server->shutdown();
    return true;
}

bool RunRpcServer(AIBinder* service, unsigned int port) {
    return RunRpcServerCallback(service, port, nullptr, nullptr);
}

AIBinder* RpcClient(unsigned int cid, unsigned int port) {
    auto session = RpcSession::make();
    if (status_t status = session->setupVsockClient(cid, port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client with CID " << cid << " and port " << port
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* RpcPreconnectedClient(int (*requestFd)(void* param), void* param) {
    auto session = RpcSession::make();
    auto request = [=] { return unique_fd{requestFd(param)}; };
    if (status_t status = session->setupPreconnectedClient(unique_fd{}, request); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client. error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}
}
