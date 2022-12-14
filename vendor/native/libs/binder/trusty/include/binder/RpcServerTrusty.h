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

#pragma once

#include <android-base/expected.h>
#include <android-base/macros.h>
#include <android-base/unique_fd.h>
#include <binder/IBinder.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransport.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <map>
#include <vector>

#include <lib/tipc/tipc_srv.h>

namespace android {

/**
 * This is the Trusty-specific RPC server code.
 */
class RpcServerTrusty final : public virtual RefBase {
public:
    // C++ equivalent to tipc_port_acl that uses safe data structures instead of
    // raw pointers, except for |extraData| which doesn't have a good
    // equivalent.
    struct PortAcl {
        uint32_t flags;
        std::vector<const uuid> uuids;
        const void* extraData;
    };

    /**
     * Creates an RPC server listening on the given port and adds it to the
     * Trusty handle set at |handleSet|.
     *
     * The caller is responsible for calling tipc_run_event_loop() to start
     * the TIPC event loop after creating one or more services here.
     */
    static android::base::expected<sp<RpcServerTrusty>, int> make(
            tipc_hset* handleSet, std::string&& portName, std::shared_ptr<const PortAcl>&& portAcl,
            size_t msgMaxSize,
            std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory = nullptr);

    [[nodiscard]] bool setProtocolVersion(uint32_t version) {
        return mRpcServer->setProtocolVersion(version);
    }
    void setSupportedFileDescriptorTransportModes(
            const std::vector<RpcSession::FileDescriptorTransportMode>& modes) {
        mRpcServer->setSupportedFileDescriptorTransportModes(modes);
    }
    void setRootObject(const sp<IBinder>& binder) { mRpcServer->setRootObject(binder); }
    void setRootObjectWeak(const wp<IBinder>& binder) { mRpcServer->setRootObjectWeak(binder); }
    void setPerSessionRootObject(
            std::function<sp<IBinder>(wp<RpcSession> session, const void*, size_t)>&& object) {
        mRpcServer->setPerSessionRootObject(std::move(object));
    }
    sp<IBinder> getRootObject() { return mRpcServer->getRootObject(); }

    /**
     * For debugging!
     */
    std::vector<sp<RpcSession>> listSessions() { return mRpcServer->listSessions(); }

private:
    // Both this class and RpcServer have multiple non-copyable fields,
    // including mPortAcl below which can't be copied because mUuidPtrs
    // holds pointers into it
    DISALLOW_COPY_AND_ASSIGN(RpcServerTrusty);

    friend sp<RpcServerTrusty>;
    explicit RpcServerTrusty(std::unique_ptr<RpcTransportCtx> ctx, std::string&& portName,
                             std::shared_ptr<const PortAcl>&& portAcl, size_t msgMaxSize);

    // The Rpc-specific context maintained for every open TIPC channel.
    struct ChannelContext {
        sp<RpcSession> session;
        sp<RpcSession::RpcConnection> connection;
    };

    static int handleConnect(const tipc_port* port, handle_t chan, const uuid* peer, void** ctx_p);
    static int handleMessage(const tipc_port* port, handle_t chan, void* ctx);
    static void handleDisconnect(const tipc_port* port, handle_t chan, void* ctx);
    static void handleChannelCleanup(void* ctx);

    static constexpr tipc_srv_ops kTipcOps = {
            .on_connect = &handleConnect,
            .on_message = &handleMessage,
            .on_disconnect = &handleDisconnect,
            .on_channel_cleanup = &handleChannelCleanup,
    };

    sp<RpcServer> mRpcServer;
    std::string mPortName;
    std::shared_ptr<const PortAcl> mPortAcl;
    std::vector<const uuid*> mUuidPtrs;
    tipc_port_acl mTipcPortAcl;
    tipc_port mTipcPort;
};

} // namespace android
