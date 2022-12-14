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

enum : uint8_t {
    RPC_CONNECTION_OPTION_INCOMING = 0x1, // default is outgoing
};

constexpr uint64_t RPC_WIRE_ADDRESS_OPTION_CREATED = 1 << 0; // distinguish from '0' address
constexpr uint64_t RPC_WIRE_ADDRESS_OPTION_FOR_SERVER = 1 << 1;

struct RpcWireAddress {
    uint64_t options;
    uint8_t address[32];
};

/**
 * This is sent to an RpcServer in order to request a new connection is created,
 * either as part of a new session or an existing session
 */
struct RpcConnectionHeader {
    RpcWireAddress sessionId;
    uint8_t options;
    uint8_t reserved[7];
};

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
     * follows is RpcWireAddress
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

struct RpcWireHeader {
    uint32_t command; // RPC_COMMAND_*
    uint32_t bodySize;

    uint32_t reserved[2];
};

struct RpcWireTransaction {
    RpcWireAddress address;
    uint32_t code;
    uint32_t flags;

    uint64_t asyncNumber;

    uint32_t reserved[4];

    uint8_t data[0];
};

struct RpcWireReply {
    int32_t status; // transact return
    uint8_t data[0];
};

#pragma clang diagnostic pop

} // namespace android
