/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"

#ifndef DATATYPES_H_
#define DATATYPES_H_

#define DH_KEY_SIZE        20
#define NONCE_SIZE         16
#define MAC_SIZE           16
#define MAC_KEY_SIZE       16
#define PADDING_SIZE       16

#define TAG_SIZE        16
#define IV_SIZE            12

#define DERIVE_MAC_KEY      0x0
#define DERIVE_SESSION_KEY  0x1
#define DERIVE_VK1_KEY      0x3
#define DERIVE_VK2_KEY      0x4

#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

#define MESSAGE_EXCHANGE 0x0
#define ENCLAVE_TO_ENCLAVE_CALL 0x1

#define INVALID_ARGUMENT                   -2   ///< Invalid function argument
#define LOGIC_ERROR                        -3   ///< Functional logic error
#define FILE_NOT_FOUND                     -4   ///< File not found

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}

#define VMC_ATTRIBUTE_MASK  0xFFFFFFFFFFFFFFCB

typedef uint8_t dh_nonce[NONCE_SIZE];
typedef uint8_t cmac_128[MAC_SIZE];

#pragma pack(push, 1)

//Session Tracker to generate session ids
typedef struct _session_id_tracker_t
{
    uint32_t          session_id;
}session_id_tracker_t;

#pragma pack(pop)

#endif
