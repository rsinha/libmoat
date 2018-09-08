#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "../../../api/libbarbican.h"
#include "api/RecordChannel.h"

/***************************************************
        DEFINITIONS FOR INTERNAL USE
 ***************************************************/

typedef size_t attestation_status_t;

#define SUCCESS                          0x00
#define INVALID_PARAMETER                0xE1
#define VALID_SESSION                    0xE2
#define INVALID_SESSION                  0xE3
#define ATTESTATION_ERROR                0xE4
#define ATTESTATION_SE_ERROR             0xE5
#define IPP_ERROR                        0xE6
#define NO_AVAILABLE_SESSION_ERROR       0xE7
#define MALLOC_ERROR                     0xE8
#define ERROR_TAG_MISMATCH               0xE9
#define OUT_BUFFER_LENGTH_ERROR          0xEA
#define INVALID_REQUEST_TYPE_ERROR       0xEB
#define INVALID_PARAMETER_ERROR          0xEC
#define ENCLAVE_TRUST_ERROR              0xED
#define ENCRYPT_DECRYPT_ERROR            0xEE
#define DUPLICATE_SESSION                0xEF

/***************************************************
 PRIVATE METHODS
 ***************************************************/

attestation_status_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity, sgx_measurement_t *target_enclave)
{
    if (peer_enclave_identity->isv_prod_id != 0) { 
        return ENCLAVE_TRUST_ERROR;
    }
    if (peer_enclave_identity->isv_svn != 0) {
        return ENCLAVE_TRUST_ERROR;
    }
    if (!(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED)) {
        return ENCLAVE_TRUST_ERROR;
    }
#ifdef RELEASE
    if (memcmp(target_enclave, &(peer_enclave_identity->mr_enclave), sizeof(sgx_measurement_t)) != 0) {
        return ENCLAVE_TRUST_ERROR;
    }
#endif
    return SUCCESS;
}

size_t server_dh_exchange(sgx_measurement_t *target_enclave, dh_session_t *session_info)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    sgx_key_128bit_t dh_aek;          // Session Key
    size_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    //everything allocated, now lets zero them out.
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));
    memset(&sgx_dh_session, 0, sizeof(sgx_dh_session_t));

    //Intialize the session as a session initiator
    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SGX_SUCCESS != status) { return -1; }

    //Ocall to request for a session with the destination enclave and obtain Message 1 if successful
    status = recv_dh_msg1_ocall(&retstatus, target_enclave, &dh_msg1, session_info->session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) { return -1; }

    //Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if(SGX_SUCCESS != status) { return -1; }

    //Send Message 2 to Destination Enclave and get Message 3 in return
    status = send_dh_msg2_recv_dh_msg3_ocall(&retstatus, &dh_msg2, &dh_msg3, session_info->session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) { return -1; }

    //Process Message 3 obtained from the destination enclave
    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SGX_SUCCESS != status) { return -1; }

    // Verify the identity of the destination enclave
    if(verify_peer_enclave_trust(&responder_identity, target_enclave) != SUCCESS) { return -1; }

    session_info->role = SGX_DH_SESSION_INITIATOR; //server is called initiator, idk why...
    memcpy(&(session_info->AEK), &dh_aek, sizeof(sgx_key_128bit_t));
    memcpy(&(session_info->measurement), target_enclave, sizeof(sgx_measurement_t));

    return 0;
}

size_t client_dh_exchange(sgx_measurement_t *target_enclave, dh_session_t *session_info)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    sgx_key_128bit_t dh_aek;          //Session Key
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t initiator_identity;
    sgx_status_t status;
    size_t retstatus;

    //everything allocated, now lets zero them out.
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));
    memset(&sgx_dh_session, 0, sizeof(sgx_dh_session_t));

    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status) { return -1; }

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1(&dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status) { return -1; }

    //ocall to send msg 1 and get msg 2
    status = send_dh_msg1_recv_dh_msg2_ocall(&retstatus, target_enclave, &dh_msg1, &dh_msg2, session_info->session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t) retstatus != SUCCESS)) { return -1; }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    dh_msg3.msg3_body.additional_prop_length = 0;

    //Process message 2 from source enclave and obtain message 3
    status = sgx_dh_responder_proc_msg2(&dh_msg2, &dh_msg3, &sgx_dh_session, &dh_aek, &initiator_identity);
    if(SGX_SUCCESS != status) { return -1; }

    //Verify source enclave's trust
    if(verify_peer_enclave_trust(&initiator_identity, target_enclave) != SUCCESS) { return -1; }

    //ocall to send msg3
    status = send_dh_msg3_ocall(&retstatus, &dh_msg3, session_info->session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) { return -1; }

    session_info->role = SGX_DH_SESSION_RESPONDER; //client
    memcpy(&(session_info->AEK), &dh_aek, sizeof(sgx_key_128bit_t));
    memcpy(&(session_info->measurement), target_enclave, sizeof(sgx_measurement_t));

    return 0;
}


/***************************************************
            PUBLIC API IMPLEMENTATION
***************************************************/

void local_attestation_module_init() { }

//Create a session with the destination enclave
size_t establish_shared_secret(char *name, bool is_server, sgx_measurement_t *target_enclave, dh_session_t *session_info)
{
    size_t retstatus;
    sgx_status_t status = start_session_ocall(&retstatus, name, target_enclave, session_info->session_id, (size_t) is_server);
    assert(status == SGX_SUCCESS);
    if (retstatus != 0) { return -1; }

    if (is_server) {
        return server_dh_exchange(target_enclave, session_info);
    } else {
        return client_dh_exchange(target_enclave, session_info);
    }
}

