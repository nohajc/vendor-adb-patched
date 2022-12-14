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

#include <sys/socket.h>
#include <stdint.h>

extern "C" {

struct AIBinder;
struct ARpcServer;
struct ARpcSession;

enum class ARpcSession_FileDescriptorTransportMode {
    None,
    Unix,
    Trusty,
};

// Starts an RPC server on a given port and a given root IBinder object.
// The server will only accept connections from the given CID.
// Set `cid` to VMADDR_CID_ANY to accept connections from any client.
// Set `cid` to VMADDR_CID_LOCAL to only bind to the local vsock interface.
// Returns an opaque handle to the running server instance, or null if the server
// could not be started.
[[nodiscard]] ARpcServer* ARpcServer_newVsock(AIBinder* service, unsigned int cid,
                                              unsigned int port);

// Starts a Unix domain RPC server with an open raw socket file descriptor
// and a given root IBinder object.
// The socket should be created and bound to an address.
// Returns an opaque handle to the running server instance, or null if the server
// could not be started.
// The socket will be closed by the server once the server goes out of scope.
[[nodiscard]] ARpcServer* ARpcServer_newBoundSocket(AIBinder* service, int socketFd);

// Starts an RPC server that bootstraps sessions using an existing Unix domain
// socket pair, with a given root IBinder object.
// Callers should create a pair of SOCK_STREAM Unix domain sockets, pass one to
// this function and the other to UnixDomainBootstrapClient(). Multiple client
// session can be created from the client end of the pair.
// Does not take ownership of `service`.
// Returns an opaque handle to the running server instance, or null if the server
// could not be started.
[[nodiscard]] ARpcServer* ARpcServer_newUnixDomainBootstrap(AIBinder* service, int bootstrapFd);

// Starts an RPC server on a given IP address+port and a given IBinder object.
// Returns an opaque handle to the running server instance, or null if the server
// could not be started.
// Does not take ownership of `service`.
// Returns an opaque handle to the running service instance, or null if the server
// could not be started.
[[nodiscard]] ARpcServer* ARpcServer_newInet(AIBinder* service, const char* address,
                                             unsigned int port);

// Sets the list of supported file descriptor transport modes of this RPC server.
void ARpcServer_setSupportedFileDescriptorTransportModes(
        ARpcServer* handle,
        const ARpcSession_FileDescriptorTransportMode modes[],
        size_t modes_len);

// Runs ARpcServer_join() in a background thread. Immediately returns.
void ARpcServer_start(ARpcServer* server);

// Joins the thread of a running RpcServer instance. At any given point, there
// can only be one thread calling ARpcServer_join().
// If a client needs to actively terminate join, call ARpcServer_shutdown() in
// a separate thread.
void ARpcServer_join(ARpcServer* server);

// Shuts down any running ARpcServer_join().
[[nodiscard]] bool ARpcServer_shutdown(ARpcServer* server);

// Frees the ARpcServer handle and drops the reference count on the underlying
// RpcServer instance. The handle must not be reused afterwards.
// This automatically calls ARpcServer_shutdown().
void ARpcServer_free(ARpcServer* server);

// Allocates a new RpcSession object and returns an opaque handle to it.
[[nodiscard]] ARpcSession* ARpcSession_new();

// Connects to an RPC server over vsock at a given CID on a given port.
// Returns the root Binder object of the server.
AIBinder* ARpcSession_setupVsockClient(ARpcSession* session, unsigned int cid,
                                       unsigned int port);

// Connects to an RPC server over a Unix Domain Socket of the given name.
// The final Unix Domain Socket path name is /dev/socket/`name`.
// Returns the root Binder object of the server.
AIBinder* ARpcSession_setupUnixDomainClient(ARpcSession* session, const char* name);

// Connects to an RPC server over the given bootstrap Unix domain socket.
// Does NOT take ownership of `bootstrapFd`.
AIBinder* ARpcSession_setupUnixDomainBootstrapClient(ARpcSession* session,
                                                     int bootstrapFd);

// Connects to an RPC server over an INET socket at a given IP address on a given port.
// Returns the root Binder object of the server.
AIBinder* ARpcSession_setupInet(ARpcSession* session, const char* address, unsigned int port);

// Connects to an RPC server with preconnected file descriptors.
//
// requestFd should connect to the server and return a valid file descriptor, or
// -1 if connection fails.
//
// param will be passed to requestFd. Callers can use param to pass contexts to
// the requestFd function.
AIBinder* ARpcSession_setupPreconnectedClient(ARpcSession* session,
                                              int (*requestFd)(void* param),
                                              void* param);

// Sets the file descriptor transport mode for this session.
void ARpcSession_setFileDescriptorTransportMode(ARpcSession* session,
                                                ARpcSession_FileDescriptorTransportMode mode);

// Sets the maximum number of incoming threads, to service connections.
void ARpcSession_setMaxIncomingThreads(ARpcSession* session, size_t threads);

// Sets the maximum number of outgoing connections.
void ARpcSession_setMaxOutgoingConnections(ARpcSession* session, size_t connections);

// Decrements the refcount of the underlying RpcSession object.
void ARpcSession_free(ARpcSession* session);
}
