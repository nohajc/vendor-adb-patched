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

// Wraps the transport layer of RPC. Implementation uses TLS.

#pragma once

#include <binder/RpcAuth.h>
#include <binder/RpcCertificateVerifier.h>
#include <binder/RpcTransport.h>

namespace android {

// RpcTransportCtxFactory with TLS enabled with self-signed certificate.
class RpcTransportCtxFactoryTls : public RpcTransportCtxFactory {
public:
    static std::unique_ptr<RpcTransportCtxFactory> make(std::shared_ptr<RpcCertificateVerifier>,
                                                        std::unique_ptr<RpcAuth>);

    std::unique_ptr<RpcTransportCtx> newServerCtx() const override;
    std::unique_ptr<RpcTransportCtx> newClientCtx() const override;
    const char* toCString() const override;

private:
    RpcTransportCtxFactoryTls(std::shared_ptr<RpcCertificateVerifier> verifier,
                              std::unique_ptr<RpcAuth> auth)
          : mCertVerifier(std::move(verifier)), mAuth(std::move(auth)){};

    std::shared_ptr<RpcCertificateVerifier> mCertVerifier;
    std::unique_ptr<RpcAuth> mAuth;
};

} // namespace android
