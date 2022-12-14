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

#pragma once

#include <openssl/ssl.h>
#include <utils/Errors.h>

namespace android {

// An interface with a function that configures the SSL_CTX object with authentication information,
// including certificates and private keys.
class RpcAuth {
public:
    virtual ~RpcAuth() = default;

    // The keys and certificates to provide is up to the implementation. Multiple calls to
    // |configure()| may configure |ctx| with the same keys / certificates, or generate a
    // different key / certificate every time |configure()| is called.
    //
    // It is guaranteed that, when a context object (RpcTransportCtx) is created,
    // libbinder_tls calls |configure()| on server RpcAuth exactly once.
    //
    // The implementation may use the following function to set the private
    // keys and certificates:
    // - SSL_CTX_use_PrivateKey
    // - SSL_CTX_use_certificate
    // - SSL_CTX_set*_chain
    // - SSL_CTX_add0_chain_cert
    [[nodiscard]] virtual status_t configure(SSL_CTX* ctx) = 0;
};

} // namespace android
