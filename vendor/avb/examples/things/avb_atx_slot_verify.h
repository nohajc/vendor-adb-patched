/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef AVB_ATX_SLOT_VERIFY_H_
#define AVB_ATX_SLOT_VERIFY_H_

#include <libavb_atx/libavb_atx.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  AVB_ATX_LOCKED,
  AVB_ATX_UNLOCKED,
} AvbAtxLockState;

typedef enum {
  AVB_ATX_SLOT_MARKED_SUCCESSFUL,
  AVB_ATX_SLOT_NOT_MARKED_SUCCESSFUL,
} AvbAtxSlotState;

typedef enum {
  AVB_ATX_OEM_DATA_USED,
  AVB_ATX_OEM_DATA_NOT_USED,
} AvbAtxOemDataState;

/* Performs a full verification of the slot identified by |ab_suffix|. If
 * |lock_state| indicates verified boot is unlocked then verification errors
 * will be allowed (see AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR for more
 * details.
 *
 * If |slot_state| indicates the slot identified by |ab_suffix| has been marked
 * successful then minimum rollback index values will be bumped to match the
 * values in the verified slot (on success).
 *
 * If |oem_data_state| indicates that OEM-specific data is not being used, then
 * verification of the 'oem_bootloader' partition will be skipped and it will
 * not be represented in |out_data|.
 *
 * The semantics of |out_data| are the same as for avb_slot_verify().
 *
 * On success, an Android Things |vbh_extension| is populated. This value must
 * be extended into the Verified Boot Hash value accumulated from earlier boot
 * stages.
 *
 * All of the function pointers in |ops| must be valid except for
 * set_key_version, which will be ignored and may be NULL.
 */
AvbSlotVerifyResult avb_atx_slot_verify(
    AvbAtxOps* ops,
    const char* ab_suffix,
    AvbAtxLockState lock_state,
    AvbAtxSlotState slot_state,
    AvbAtxOemDataState oem_data_state,
    AvbSlotVerifyData** verify_data,
    uint8_t vbh_extension[AVB_SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* AVB_SLOT_VERIFY_H_ */
