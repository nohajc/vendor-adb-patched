#pragma once

/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#if !defined(__INTRODUCED_IN)
#define __INTRODUCED_IN(__api_level) /* nothing */
#endif

#ifdef __cplusplus
extern "C" {
#endif

// The transport type of the device connection.
enum AdbTransportType : int32_t {
    kAdbTransportTypeUsb = 0,
    kAdbTransportTypeWifi,
};
static_assert(sizeof(AdbTransportType) == sizeof(int32_t), "Unexpected AdbTransportType size");

struct AdbdAuthCallbacks {
    uint32_t version;
};

struct AdbdAuthCallbacksV1 : AdbdAuthCallbacks {
    // Callback for a successful user authorization.
    void (*key_authorized)(void* opaque, uint64_t id);
    // The framework removed the key from the keystore. This callback notifies
    // adbd so it can take the appropriate actions (e.g. disconnect all devices
    // using that key).
    void (*key_removed)(const char* public_key, size_t length);
};

struct AdbdAuthContext;
typedef struct AdbdAuthContext AdbdAuthContext;

/**
 * Creates a new AdbdAuthContext.
 *
 * @param callbacks a set of user-provided callbacks used internally (see
 * #AdbdAuthCallbacksV1
 * @return a new AdbdAuthContext instance. Caller is responsible for destroying
 * the context with #adbd_auth_delete.
 */
AdbdAuthContext* adbd_auth_new(AdbdAuthCallbacks* callbacks) __INTRODUCED_IN(30);

/**
 * Destroys the AdbdAuthContext.
 *
 * @param ctx the AdbdAuthContext to destroy.
 */
void adbd_auth_delete(AdbdAuthContext* ctx) __INTRODUCED_IN(30);

/**
 * Starts the AdbdAuthContext.
 *
 * The caller may want to run this on a different thread, as this
 * runs indefinitely.
 *
 * @param ctx the AdbdAuthContext
 */
void adbd_auth_run(AdbdAuthContext* ctx) __INTRODUCED_IN(30);

/**
 * Iterate through the list of authorized public keys.
 *
 * @param ctx the AdbdAuthContext
 * @param callback a callback which will get called for every known adb public
 * key in its keystore. To stop iteration of the keys, return false in the
 * callback. Otherwise, return true to continue the iteration.
 * @param opaque an opaque userdata argument
 */
void adbd_auth_get_public_keys(AdbdAuthContext* ctx,
                               bool (*callback)(void* opaque, const char* public_key, size_t len),
                               void* opaque) __INTRODUCED_IN(30);

/**
 * Let system_server know that a key has been successfully used for authentication.
 *
 * @param ctx the AdbdAuthContext
 * @param public_key the RSA key that was authorized using the AUTH protocol
 * @param len the length of the public_key argument
 * @return an id corresponding to the new connection
 */
uint64_t adbd_auth_notify_auth(AdbdAuthContext* ctx,
                               const char* public_key,
                               size_t len) __INTRODUCED_IN(30);

/**
 * Let system_server know that an AUTH connection has been closed.
 *
 * @param ctx the AdbdAuthContext
 * @param id the id of the disconnected device
 */
void adbd_auth_notify_disconnect(AdbdAuthContext* ctx,
                                 uint64_t id) __INTRODUCED_IN(30);

/**
 * Prompt the user to authorize a public key.
 *
 * When this happens, a callback will be run on the auth thread with the result.
 *
 * @param ctx the AdbdAuthContext
 * @param public_key the RSA public key to prompt user with
 * @param len the length of the public_key argument
 * @param arg an opaque userdata argument
 */
void adbd_auth_prompt_user(AdbdAuthContext* ctx, const char* public_key, size_t len, void* opaque)
        __INTRODUCED_IN(30);

/**
 * Prompt the user to authorize a public key.
 *
 * When this happens, a callback will be run on the auth thread with the result.
 *
 * @param ctx the AdbdAuthContext
 * @param public_key the RSA public key to prompt user with
 * @param len the length of the public_key argument
 * @param arg an opaque userdata argument
 * @return a unique id which will be returned via callback
 */
__attribute__((weak)) uint64_t adbd_auth_prompt_user_with_id(AdbdAuthContext* ctx,
                                                             const char* public_key, size_t len,
                                                             void* opaque) __INTRODUCED_IN(30);

/**
 * Let system_server know that a TLS device has connected.
 *
 * @param ctx the AdbdAuthContext
 * @param type the transport type of the connection (see #AdbTransportType)
 * @param public_key the RSA public key used to establish the connection
 * @param len the length of the public_key argument
 * @return an id corresponding to the new connection
 */
uint64_t adbd_auth_tls_device_connected(AdbdAuthContext* ctx,
                                        AdbTransportType type,
                                        const char* public_key,
                                        size_t len) __INTRODUCED_IN(30);

/**
 * Let system_server know that a TLS device has disconnected.
 *
 * @param ctx the AdbdAuthContext
 * @param type the transport type of the connection (see #AdbTransportType)
 * @param the id of the disconnected device (see #adbd_tls_device_connected)
 */
void adbd_auth_tls_device_disconnected(AdbdAuthContext* ctx,
                                       AdbTransportType type,
                                       uint64_t id) __INTRODUCED_IN(30);

/**
 * Returns the max #AdbdAuthCallbacks version.
 *
 * The version starts at 1, with version 1 corresponding to the
 * #AdbdAuthCallbacksV1 struct.
 *
 * @return the max #AdbdAuthCallbacks version.
 */
uint32_t adbd_auth_get_max_version(void) __INTRODUCED_IN(30);

enum AdbdAuthFeature : int32_t {
};

/**
 * Checks if a feature is supported by the framework. See #AdbdAuthFeature.
 *
 * @param feature the feature to check for support
 * @return true if the feature is supported
 */
bool adbd_auth_supports_feature(AdbdAuthFeature feature);

#ifdef __cplusplus
}
#endif
