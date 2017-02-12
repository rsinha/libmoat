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

//session status
#define CLOSED 0x0
#define IN_PROGRESS 0x1
#define ACTIVE 0x2

//Session information structure
typedef struct
{
    uint32_t                 session_id; //Identifies the current session
    uint32_t                 status; //Indicates session is in progress, active or closed
    sgx_measurement_t        measurement; //measurement of the remote enclave
    sgx_dh_session_role_t    role; //role of this enclave: initiator or responder?
    sgx_aes_gcm_128bit_key_t AEK; //Session Key
    uint32_t                 local_counter; //Message Sequence Number, which we use as IV
    uint32_t                 remote_counter; //most recent remote IV, to prevent replay attacks
    uint8_t                  *recv_carryover_start;
    uint8_t                  *recv_carryover_ptr;
    size_t                   recv_carryover_bytes;
} dh_session_t;

uint32_t SGXAPI create_session(bool is_server, sgx_measurement_t *target_enclave);
dh_session_t* SGXAPI get_session_info(uint32_t session_id);
uint32_t SGXAPI close_session(uint32_t session_id);


#endif
