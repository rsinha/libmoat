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

#define MAX_SESSION_COUNT  16
#define MAX_SCC_NAME_LEN   64

//Session information structure
typedef struct
{
    int64_t                  session_id; //Identifies the current session
    char                     remote_name[MAX_SCC_NAME_LEN];
    bool                     role_is_server;
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
    size_t                   record_size;
} dh_session_t;

typedef struct
{
    size_t cleartext_length;
} scc_cleartext_header_t;

/***************************************************
LOCAL ATTESTATION
 ***************************************************/

void local_attestation_module_init();
size_t client_dh_exchange(sgx_measurement_t *target_enclave, dh_session_t *session_info);
size_t server_dh_exchange(sgx_measurement_t *target_enclave, dh_session_t *session_info);

/***************************************************
 RECORD LAYER
 ***************************************************/

void record_channel_module_init();
dh_session_t *find_session(int64_t session_id);
dh_session_t *session_open(char *name, sgx_measurement_t *target_enclave);
int64_t session_close(dh_session_t *session_info);
int64_t session_recv(dh_session_t *session_info, void *record, size_t record_size);
int64_t session_send(dh_session_t *session_info, void *record, size_t record_size);

#endif
