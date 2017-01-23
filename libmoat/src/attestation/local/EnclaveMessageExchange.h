#include "sgx_eid.h"
#include "sgx_trts.h"
#include "dh_session_protocol.h"

#include <stdbool.h>

#ifndef LOCALATTESTATION_H_
#define LOCALATTESTATION_H_

uint32_t SGXAPI create_session(bool is_server, sgx_measurement_t *target_enclave);
sgx_aes_gcm_128bit_key_t * SGXAPI get_session_key(uint32_t session_id);
uint32_t SGXAPI close_session(uint32_t session_id);


#endif
