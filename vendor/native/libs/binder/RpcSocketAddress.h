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

#include <string>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "vm_sockets.h"

namespace android {

class RpcSocketAddress {
public:
    virtual ~RpcSocketAddress() {}
    virtual std::string toString() const = 0;
    virtual const sockaddr* addr() const = 0;
    virtual size_t addrSize() const = 0;
};

class UnixSocketAddress : public RpcSocketAddress {
public:
    explicit UnixSocketAddress(const char* path) : mAddr({.sun_family = AF_UNIX}) {
        unsigned int pathLen = strlen(path) + 1;
        LOG_ALWAYS_FATAL_IF(pathLen > sizeof(mAddr.sun_path), "Socket path is too long: %u %s",
                            pathLen, path);
        memcpy(mAddr.sun_path, path, pathLen);
    }
    virtual ~UnixSocketAddress() {}
    std::string toString() const override {
        return String8::format("path '%.*s'", static_cast<int>(sizeof(mAddr.sun_path)),
                               mAddr.sun_path)
                .c_str();
    }
    const sockaddr* addr() const override { return reinterpret_cast<const sockaddr*>(&mAddr); }
    size_t addrSize() const override { return sizeof(mAddr); }

private:
    sockaddr_un mAddr;
};

class VsockSocketAddress : public RpcSocketAddress {
public:
    VsockSocketAddress(unsigned int cid, unsigned int port)
          : mAddr({
                    .svm_family = AF_VSOCK,
                    .svm_port = port,
                    .svm_cid = cid,
            }) {}
    virtual ~VsockSocketAddress() {}
    std::string toString() const override {
        return String8::format("cid %u port %u", mAddr.svm_cid, mAddr.svm_port).c_str();
    }
    const sockaddr* addr() const override { return reinterpret_cast<const sockaddr*>(&mAddr); }
    size_t addrSize() const override { return sizeof(mAddr); }

private:
    sockaddr_vm mAddr;
};

class InetSocketAddress : public RpcSocketAddress {
public:
    InetSocketAddress(const sockaddr* sockAddr, size_t size, const char* addr, unsigned int port)
          : mSockAddr(sockAddr), mSize(size), mAddr(addr), mPort(port) {}
    [[nodiscard]] std::string toString() const override {
        return String8::format("%s:%u", mAddr, mPort).c_str();
    }
    [[nodiscard]] const sockaddr* addr() const override { return mSockAddr; }
    [[nodiscard]] size_t addrSize() const override { return mSize; }

    using AddrInfo = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>;
    static AddrInfo getAddrInfo(const char* addr, unsigned int port) {
        addrinfo hint{
                .ai_flags = 0,
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
                .ai_protocol = 0,
        };
        addrinfo* aiStart = nullptr;
        if (int rc = getaddrinfo(addr, std::to_string(port).data(), &hint, &aiStart); 0 != rc) {
            ALOGE("Unable to resolve %s:%u: %s", addr, port, gai_strerror(rc));
            return AddrInfo(nullptr, nullptr);
        }
        if (aiStart == nullptr) {
            ALOGE("Unable to resolve %s:%u: getaddrinfo returns null", addr, port);
            return AddrInfo(nullptr, nullptr);
        }
        return AddrInfo(aiStart, &freeaddrinfo);
    }

private:
    const sockaddr* mSockAddr;
    size_t mSize;
    const char* mAddr;
    unsigned int mPort;
};

} // namespace android
