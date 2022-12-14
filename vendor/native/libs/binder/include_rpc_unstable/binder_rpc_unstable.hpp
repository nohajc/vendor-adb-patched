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

extern "C" {

struct AIBinder;

// Starts an RPC server on a given port and a given root IBinder object.
// This function sets up the server and joins before returning.
bool RunRpcServer(AIBinder* service, unsigned int port);

// Starts an RPC server on a given port and a given root IBinder object.
// This function sets up the server, calls readyCallback with a given param, and
// then joins before returning.
bool RunRpcServerCallback(AIBinder* service, unsigned int port, void (*readyCallback)(void* param),
                          void* param);

// Starts an RPC server on a given port and a given root IBinder factory.
// RunRpcServerWithFactory acts like RunRpcServerCallback, but instead of
// assigning single root IBinder object to all connections, factory is called
// whenever a client connects, making it possible to assign unique IBinder
// object to each client.
bool RunRpcServerWithFactory(AIBinder* (*factory)(unsigned int cid, void* context),
                          void* factoryContext, unsigned int port);

AIBinder* RpcClient(unsigned int cid, unsigned int port);

// Connect to an RPC server with preconnected file descriptors.
//
// requestFd should connect to the server and return a valid file descriptor, or
// -1 if connection fails.
//
// param will be passed to requestFd. Callers can use param to pass contexts to
// the requestFd function.
AIBinder* RpcPreconnectedClient(int (*requestFd)(void* param), void* param);

}
