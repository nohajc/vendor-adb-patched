/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "RpcServerTrusty"

#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcServerTrusty.h>
#include <binder/RpcThreads.h>
#include <binder/RpcTransportTipcTrusty.h>
#include <log/log.h>

#include "../FdTrigger.h"
#include "../RpcState.h"
#include "TrustyStatus.h"

using android::base::unexpected;

namespace android {

android::base::expected<sp<RpcServerTrusty>, int> RpcServerTrusty::make(
        tipc_hset* handleSet, std::string&& portName, std::shared_ptr<const PortAcl>&& portAcl,
        size_t msgMaxSize, std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory) {
    // Default is without TLS.
    if (rpcTransportCtxFactory == nullptr)
        rpcTransportCtxFactory = RpcTransportCtxFactoryTipcTrusty::make();
    auto ctx = rpcTransportCtxFactory->newServerCtx();
    if (ctx == nullptr) {
        return unexpected(ERR_NO_MEMORY);
    }

    auto srv = sp<RpcServerTrusty>::make(std::move(ctx), std::move(portName), std::move(portAcl),
                                         msgMaxSize);
    if (srv == nullptr) {
        return unexpected(ERR_NO_MEMORY);
    }

    int rc = tipc_add_service(handleSet, &srv->mTipcPort, 1, 0, &kTipcOps);
    if (rc != NO_ERROR) {
        return unexpected(rc);
    }
    return srv;
}

RpcServerTrusty::RpcServerTrusty(std::unique_ptr<RpcTransportCtx> ctx, std::string&& portName,
                                 std::shared_ptr<const PortAcl>&& portAcl, size_t msgMaxSize)
      : mRpcServer(sp<RpcServer>::make(std::move(ctx))),
        mPortName(std::move(portName)),
        mPortAcl(std::move(portAcl)) {
    mTipcPort.name = mPortName.c_str();
    mTipcPort.msg_max_size = msgMaxSize;
    mTipcPort.msg_queue_len = 6; // Three each way
    mTipcPort.priv = this;

    // TODO(b/266741352): follow-up to prevent needing this in the future
    // Trusty needs to be set to the latest stable version that is in prebuilts there.
    LOG_ALWAYS_FATAL_IF(!mRpcServer->setProtocolVersion(0));

    if (mPortAcl) {
        // Initialize the array of pointers to uuids.
        // The pointers in mUuidPtrs should stay valid across moves of
        // RpcServerTrusty (the addresses of a std::vector's elements
        // shouldn't change when the vector is moved), but would be invalidated
        // by a copy which is why we disable the copy constructor and assignment
        // operator for RpcServerTrusty.
        auto numUuids = mPortAcl->uuids.size();
        mUuidPtrs.resize(numUuids);
        for (size_t i = 0; i < numUuids; i++) {
            mUuidPtrs[i] = &mPortAcl->uuids[i];
        }

        // Copy the contents of portAcl into the tipc_port_acl structure that we
        // pass to tipc_add_service
        mTipcPortAcl.flags = mPortAcl->flags;
        mTipcPortAcl.uuid_num = numUuids;
        mTipcPortAcl.uuids = mUuidPtrs.data();
        mTipcPortAcl.extra_data = mPortAcl->extraData;

        mTipcPort.acl = &mTipcPortAcl;
    } else {
        mTipcPort.acl = nullptr;
    }
}

int RpcServerTrusty::handleConnect(const tipc_port* port, handle_t chan, const uuid* peer,
                                   void** ctx_p) {
    auto* server = reinterpret_cast<RpcServerTrusty*>(const_cast<void*>(port->priv));
    server->mRpcServer->mShutdownTrigger = FdTrigger::make();
    server->mRpcServer->mConnectingThreads[rpc_this_thread::get_id()] = RpcMaybeThread();

    int rc = NO_ERROR;
    auto joinFn = [&](sp<RpcSession>&& session, RpcSession::PreJoinSetupResult&& result) {
        if (result.status != OK) {
            rc = statusToTrusty(result.status);
            return;
        }

        /* Save the session and connection for the other callbacks */
        auto* channelContext = new (std::nothrow) ChannelContext;
        if (channelContext == nullptr) {
            rc = ERR_NO_MEMORY;
            return;
        }

        channelContext->session = std::move(session);
        channelContext->connection = std::move(result.connection);

        *ctx_p = channelContext;
    };

    // We need to duplicate the channel handle here because the tipc library
    // owns the original handle and closes is automatically on channel cleanup.
    // We use dup() because Trusty does not have fcntl().
    // NOLINTNEXTLINE(android-cloexec-dup)
    handle_t chanDup = dup(chan);
    if (chanDup < 0) {
        return chanDup;
    }
    base::unique_fd clientFd(chanDup);
    android::RpcTransportFd transportFd(std::move(clientFd));

    std::array<uint8_t, RpcServer::kRpcAddressSize> addr;
    constexpr size_t addrLen = sizeof(*peer);
    memcpy(addr.data(), peer, addrLen);
    RpcServer::establishConnection(sp(server->mRpcServer), std::move(transportFd), addr, addrLen,
                                   joinFn);

    return rc;
}

int RpcServerTrusty::handleMessage(const tipc_port* /*port*/, handle_t /*chan*/, void* ctx) {
    auto* channelContext = reinterpret_cast<ChannelContext*>(ctx);
    LOG_ALWAYS_FATAL_IF(channelContext == nullptr,
                        "bad state: message received on uninitialized channel");

    auto& session = channelContext->session;
    auto& connection = channelContext->connection;
    status_t status =
            session->state()->drainCommands(connection, session, RpcState::CommandType::ANY);
    if (status != OK) {
        LOG_RPC_DETAIL("Binder connection thread closing w/ status %s",
                       statusToString(status).c_str());
    }

    return NO_ERROR;
}

void RpcServerTrusty::handleDisconnect(const tipc_port* /*port*/, handle_t /*chan*/, void* ctx) {
    auto* channelContext = reinterpret_cast<ChannelContext*>(ctx);
    if (channelContext == nullptr) {
        // Connections marked "incoming" (outgoing from the server's side)
        // do not have a valid channel context because joinFn does not get
        // called for them. We ignore them here.
        return;
    }

    auto& session = channelContext->session;
    (void)session->shutdownAndWait(false);
}

void RpcServerTrusty::handleChannelCleanup(void* ctx) {
    auto* channelContext = reinterpret_cast<ChannelContext*>(ctx);
    if (channelContext == nullptr) {
        return;
    }

    auto& session = channelContext->session;
    auto& connection = channelContext->connection;
    LOG_ALWAYS_FATAL_IF(!session->removeIncomingConnection(connection),
                        "bad state: connection object guaranteed to be in list");

    delete channelContext;
}

} // namespace android
