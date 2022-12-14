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

namespace android {

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"

constexpr uint8_t RPC_CONNECTION_OPTION_INCOMING = 0x1; // default is outgoing

constexpr uint32_t RPC_WIRE_ADDRESS_OPTION_CREATED = 1 << 0; // distinguish from '0' address
constexpr uint32_t RPC_WIRE_ADDRESS_OPTION_FOR_SERVER = 1 << 1;

struct RpcWireAddress {
    uint32_t options;
    uint32_t address;

    static inline RpcWireAddress fromRaw(uint64_t raw) {
        return *reinterpret_cast<RpcWireAddress*>(&raw);
    }
    static inline uint64_t toRaw(RpcWireAddress addr) {
        return *reinterpret_cast<uint64_t*>(&addr);
    }
};
static_assert(sizeof(RpcWireAddress) == sizeof(uint64_t));

/**
 * This is sent to an RpcServer in order to request a new connection is created,
 * either as part of a new session or an existing session
 */
struct RpcConnectionHeader {
    uint32_t version; // maximum supported by caller
    uint8_t options;
    uint8_t fileDescriptorTransportMode;
    uint8_t reservered[8];
    // Follows is sessionIdSize bytes.
    // if size is 0, this is requesting a new session.
    uint16_t sessionIdSize;
};
static_assert(sizeof(RpcConnectionHeader) == 16);

/**
 * In response to an RpcConnectionHeader which corresponds to a new session,
 * this returns information to the server.
 */
struct RpcNewSessionResponse {
    uint32_t version; // maximum supported by callee <= maximum supported by caller
    uint8_t reserved[4];
};
static_assert(sizeof(RpcNewSessionResponse) == 8);

#define RPC_CONNECTION_INIT_OKAY "cci"

/**
 * Whenever a client connection is setup, this is sent as the initial
 * transaction. The main use of this is in order to control the timing for when
 * an incoming connection is setup.
 */
struct RpcOutgoingConnectionInit {
    char msg[4];
    uint8_t reserved[4];
};
static_assert(sizeof(RpcOutgoingConnectionInit) == 8);

enum : uint32_t {
    /**
     * follows is RpcWireTransaction, if flags != oneway, reply w/ RPC_COMMAND_REPLY expected
     */
    RPC_COMMAND_TRANSACT = 0,
    /**
     * follows is RpcWireReply
     */
    RPC_COMMAND_REPLY,
    /**
     * follows is RpcDecStrong
     *
     * note - this in the protocol directly instead of as a 'special
     * transaction' in order to keep it as lightweight as possible (we don't
     * want to create a 'Parcel' object for every decref)
     */
    RPC_COMMAND_DEC_STRONG,
};

/**
 * These commands are used when the address in an RpcWireTransaction is zero'd
 * out (no address). This allows the transact/reply flow to be used for
 * additional server commands, without making the protocol for
 * transactions/replies more complicated.
 */
enum : uint32_t {
    RPC_SPECIAL_TRANSACT_GET_ROOT = 0,
    RPC_SPECIAL_TRANSACT_GET_MAX_THREADS = 1,
    RPC_SPECIAL_TRANSACT_GET_SESSION_ID = 2,
};

// serialization is like:
// |RpcWireHeader|struct desginated by 'command'| (over and over again)
//
// When file descriptors are included in out-of-band data (e.g. in unix domain
// sockets), they are always paired with the RpcWireHeader bytes of the
// transaction or reply the file descriptors belong to.

struct RpcWireHeader {
    uint32_t command; // RPC_COMMAND_*
    uint32_t bodySize;

    uint32_t reserved[2];
};
static_assert(sizeof(RpcWireHeader) == 16);

struct RpcDecStrong {
    RpcWireAddress address;
    uint32_t amount;
    uint32_t reserved;
};
static_assert(sizeof(RpcDecStrong) == 16);

struct RpcWireTransaction {
    RpcWireAddress address;
    uint32_t code;
    uint32_t flags;

    uint64_t asyncNumber;

    // The size of the Parcel data directly following RpcWireTransaction.
    uint32_t parcelDataSize;

    uint32_t reserved[3];

    uint8_t data[];
};
static_assert(sizeof(RpcWireTransaction) == 40);

struct RpcWireReply {
    int32_t status; // transact return

    // -- Fields below only transmitted starting at protocol version 1 --

    // The size of the Parcel data directly following RpcWireReply.
    uint32_t parcelDataSize;

    uint32_t reserved[3];

    // Byte size of RpcWireReply in the wire protocol.
    static size_t wireSize(uint32_t protocolVersion) {
        if (protocolVersion == 0) {
            return sizeof(int32_t);
        }
        return sizeof(RpcWireReply);
    }
};
static_assert(sizeof(RpcWireReply) == 20);

#pragma clang diagnostic pop

} // namespace android
