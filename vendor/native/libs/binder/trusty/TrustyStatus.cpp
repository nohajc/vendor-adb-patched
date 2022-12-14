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

#include "TrustyStatus.h"
#include "../RpcState.h"

namespace android {

status_t statusFromTrusty(int rc) {
    LOG_RPC_DETAIL("Trusty error: %d", rc);
    switch (rc) {
        case NO_ERROR:
            return OK;
        case ERR_NOT_FOUND:
            return NAME_NOT_FOUND;
        case ERR_NOT_READY:
            // We get this error if we try to perform an IPC operation when the
            // channel is not ready
            return INVALID_OPERATION;
        case ERR_NO_MSG:
            return WOULD_BLOCK;
        case ERR_NO_MEMORY:
            return NO_MEMORY;
        case ERR_INVALID_ARGS:
            return BAD_VALUE;
        case ERR_NOT_ENOUGH_BUFFER:
            return WOULD_BLOCK;
        case ERR_TIMED_OUT:
            return TIMED_OUT;
        case ERR_ALREADY_EXISTS:
            return ALREADY_EXISTS;
        case ERR_CHANNEL_CLOSED:
            return DEAD_OBJECT;
        case ERR_NOT_ALLOWED:
            return INVALID_OPERATION;
        case ERR_NOT_SUPPORTED:
            return INVALID_OPERATION;
        case ERR_TOO_BIG:
            return BAD_INDEX;
        case ERR_CMD_UNKNOWN:
            return UNKNOWN_TRANSACTION;
        case ERR_BAD_STATE:
            return INVALID_OPERATION;
        case ERR_BAD_LEN:
            return NOT_ENOUGH_DATA;
        case ERR_BAD_HANDLE:
            return BAD_VALUE;
        case ERR_ACCESS_DENIED:
            return PERMISSION_DENIED;
        default:
            return UNKNOWN_ERROR;
    }
}

int statusToTrusty(status_t status) {
    switch (status) {
        case OK:
            return NO_ERROR;
        case NO_MEMORY:
            return ERR_NO_MEMORY;
        case INVALID_OPERATION:
        case BAD_VALUE:
        case BAD_TYPE:
            return ERR_NOT_VALID;
        case NAME_NOT_FOUND:
            return ERR_NOT_FOUND;
        case PERMISSION_DENIED:
            return ERR_ACCESS_DENIED;
        case NO_INIT:
            return ERR_NOT_CONFIGURED;
        case ALREADY_EXISTS:
            return ERR_ALREADY_EXISTS;
        case DEAD_OBJECT:
            return ERR_CHANNEL_CLOSED;
        case BAD_INDEX:
            return ERR_TOO_BIG;
        case NOT_ENOUGH_DATA:
            return ERR_BAD_LEN;
        case WOULD_BLOCK:
            return ERR_NO_MSG;
        case TIMED_OUT:
            return ERR_TIMED_OUT;
        case UNKNOWN_TRANSACTION:
            return ERR_CMD_UNKNOWN;
        case FDS_NOT_ALLOWED:
            return ERR_NOT_SUPPORTED;
        case UNEXPECTED_NULL:
            return ERR_NOT_VALID;
        default:
            return ERR_GENERIC;
    }
}

} // namespace android
