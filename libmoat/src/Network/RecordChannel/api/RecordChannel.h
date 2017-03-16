#ifndef _RECORD_CHANNEL_H
#define _RECORD_CHANNEL_H

#include "sgx_eid.h"
#include "sgx_trts.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_key.h"
#include "sgx_report.h"
#include "sgx_attributes.h"
#include <stdbool.h>

//Session information structure
typedef struct
{
    size_t                   session_id; //Identifies the current session
    sgx_measurement_t        measurement; //measurement of the remote enclave
    sgx_dh_session_role_t    role; //role of this enclave: initiator or responder?
    sgx_aes_gcm_128bit_key_t AEK; //Session master secret
    uint8_t                  iv_constant[SGX_AESGCM_IV_SIZE]; //Session master secret
    sgx_aes_gcm_128bit_key_t local_key; //Session local key
    sgx_aes_gcm_128bit_key_t remote_key; //Session remote key
    uint64_t                 local_seq_number; //Message Sequence Number, which we use as IV
    uint64_t                 remote_seq_number; //most recent remote IV, to prevent replay attacks
    uint8_t                  *recv_carryover_start;
    uint8_t                  *recv_carryover_ptr;
    size_t                   recv_carryover_bytes;
} dh_session_t;

/***************************************************
LOCAL ATTESTATION
 ***************************************************/

void local_attestation_module_init();
size_t establish_shared_secret(bool is_server, sgx_measurement_t *target_enclave, dh_session_t *session_info);

/***************************************************
 RECORD LAYER
 ***************************************************/

void record_channel_module_init();
dh_session_t *open_session();
size_t close_session(dh_session_t *session_info);
dh_session_t *find_session(size_t session_id);

#endif
