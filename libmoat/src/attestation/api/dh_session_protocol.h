#ifndef _DH_SESSION_PROROCOL_H
#define _DH_SESSION_PROROCOL_H

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
    sgx_aes_gcm_128bit_key_t AEK; //Session Key
    uint32_t                 local_counter; //Message Sequence Number, which we use as IV
    uint32_t                 remote_counter; //most recent remote IV, to prevent replay attacks
    uint8_t                  *recv_carryover_start;
    uint8_t                  *recv_carryover_ptr;
    size_t                   recv_carryover_bytes;
} dh_session_t;

void local_attestation_module_init();
size_t create_session(bool is_server, sgx_measurement_t *target_enclave);
dh_session_t* get_session_info(size_t session_id);
size_t close_session(size_t session_id);


#endif
