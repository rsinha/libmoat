
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

#include "../../../api/libmoat_untrusted.h"
#include "../api/dh_session_protocol.h"
#include "../../utils/api/Utils.h"

/***************************************************
        DEFINITIONS FOR INTERNAL USE
 ***************************************************/

#define MAX_SESSION_COUNT  16

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
                INTERNAL STATE
 ***************************************************/

//Map between the source enclave id and the session information associated with that particular session
static ll_t *g_dest_session_info;

/***************************************************
                PRIVATE METHODS
 ***************************************************/

//finds session in the linked list
static dh_session_t *find_session(size_t session_id)
{
    ll_iterator_t *iter = list_create_iterator(g_dest_session_info);
    while (list_has_next(iter))
    {
        dh_session_t *tmp = (dh_session_t *) list_get_next(iter);
        if (tmp->session_id == session_id) {
            return tmp;
        }
    }
    list_destroy_iterator(iter);
    return NULL; //didn't find this session id
}

//Returns a new sessionID for the source destination session
attestation_status_t generate_unique_session_id(size_t *session_id)
{
    if(!session_id) { return INVALID_PARAMETER_ERROR; }

    bool occupied[MAX_SESSION_COUNT];
    for (int i = 0; i < MAX_SESSION_COUNT; i++) { 
        occupied[i] = false;
    }

    ll_iterator_t *iter = list_create_iterator(g_dest_session_info);
    while (list_has_next(iter))
    {
        dh_session_t *tmp = (dh_session_t *) list_get_next(iter);
        //session ids start at 1
        occupied[tmp->session_id - 1] = true;
    }
    list_destroy_iterator(iter);
    
    for (int i = 0; i < MAX_SESSION_COUNT; i++) { 
        if (occupied[i] == false) {
            *session_id = i + 1; //session ids start at 1
            return SUCCESS;
        }
    }

    return NO_AVAILABLE_SESSION_ERROR;
}

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
#else
    _moat_print_debug("peer identity: ");
    for (size_t i = 0; i < sizeof(sgx_measurement_t); i++)
    {
        _moat_print_debug("0x%02X,", ((uint8_t *) &(peer_enclave_identity->mr_enclave))[i]);
    }
    _moat_print_debug("\n");
#endif
    return SUCCESS;
}

size_t server_create_session(sgx_measurement_t *target_enclave)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    sgx_key_128bit_t dh_aek;          // Session Key
    size_t session_id;
    size_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    dh_session_t *session_info = (dh_session_t *) malloc(sizeof(dh_session_t));
    if (!session_info) { return 0; }

    //everything allocated, now lets zero them out.
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));
    memset(&sgx_dh_session, 0, sizeof(sgx_dh_session_t));

    status = (sgx_status_t) generate_unique_session_id(&session_id);
    if (status != SUCCESS) { free(session_info); return 0; } //no more sessions available

    //Intialize the session as a session initiator
    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }
    
    //Ocall to request for a session with the destination enclave and obtain Message 1 if successful
    status = recv_dh_msg1_ocall(&retstatus, target_enclave, &dh_msg1, session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        free(session_info); return 0;
    }

    //Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }

    //Send Message 2 to Destination Enclave and get Message 3 in return
    status = send_dh_msg2_recv_dh_msg3_ocall(&retstatus, &dh_msg2, &dh_msg3, session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        free(session_info); return 0;
    }

    //Process Message 3 obtained from the destination enclave
    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }

    // Verify the identity of the destination enclave
    if(verify_peer_enclave_trust(&responder_identity, target_enclave) != SUCCESS) { free(session_info); return 0; }

    session_info->session_id = session_id;
    session_info->role = SGX_DH_SESSION_INITIATOR; //server is called initiator, idk why...
    memcpy(&(session_info->AEK), &dh_aek, sizeof(sgx_key_128bit_t));
    memcpy(&(session_info->measurement), target_enclave, sizeof(sgx_measurement_t));

    //save the session until it gets destroyed via close_session
    list_insert_value(g_dest_session_info, session_info);

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    return session_id;
}

size_t client_create_session(sgx_measurement_t *target_enclave)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    sgx_key_128bit_t dh_aek;          //Session Key
    sgx_dh_session_t sgx_dh_session;
    size_t session_id;
    sgx_dh_session_enclave_identity_t initiator_identity;
    sgx_status_t status;
    size_t retstatus;

    dh_session_t *session_info = (dh_session_t *) malloc(sizeof(dh_session_t));
    if (session_info == NULL) { return 0; }

    //everything allocated, now lets zero them out.
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));
    memset(&sgx_dh_session, 0, sizeof(sgx_dh_session_t));

    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }
    
    //get a new SessionID
    status = (sgx_status_t) generate_unique_session_id(&session_id);
    if (status != SUCCESS) { free(session_info); return 0; } //no more sessions available

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1(&dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }

    //ocall to send msg 1 and get msg 2
    status = send_dh_msg1_recv_dh_msg2_ocall(&retstatus, target_enclave, &dh_msg1, &dh_msg2, session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        free(session_info); return 0;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    dh_msg3.msg3_body.additional_prop_length = 0;

    //Process message 2 from source enclave and obtain message 3
    status = sgx_dh_responder_proc_msg2(&dh_msg2, &dh_msg3, &sgx_dh_session, &dh_aek, &initiator_identity);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }

    //Verify source enclave's trust
    if(verify_peer_enclave_trust(&initiator_identity, target_enclave) != SUCCESS) {
        free(session_info); return 0;
    }

    //ocall to send msg3
    status = send_dh_msg3_ocall(&retstatus, &dh_msg3, session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        free(session_info); return 0;
    }

    //save the session ID, status and initialize the session nonce
    session_info->session_id = session_id;
    memcpy(&(session_info->measurement), target_enclave, sizeof(sgx_measurement_t));
    session_info->role = SGX_DH_SESSION_RESPONDER; //client
    memcpy(&(session_info->AEK), &dh_aek, sizeof(sgx_key_128bit_t));
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));

    //Store the session information under the correspoding source enlave id key
    list_insert_value(g_dest_session_info, session_info);

    return session_id;
}


/***************************************************
            PUBLIC API IMPLEMENTATION
***************************************************/

void local_attestation_module_init()
{
    g_dest_session_info = malloc(sizeof(ll_t));
    assert(g_dest_session_info != NULL);
    g_dest_session_info->head = NULL;
}

//Create a session with the destination enclave
size_t create_session(bool is_server, sgx_measurement_t *target_enclave)
{
    if (is_server) {
        return server_create_session(target_enclave);
    } else {
        return client_create_session(target_enclave);
    }
}

//Close a current session
size_t close_session(size_t session_id)
{
    sgx_status_t status;
    size_t retstatus;

    //Get the session information from the list corresponding to the session id
    dh_session_t *session_info = find_session(session_id);
    if (session_info == NULL) { return INVALID_SESSION; }

    //Erase the session information for the current session
    bool deleted_successfully = list_delete_value(g_dest_session_info, session_info);
    assert(deleted_successfully);

    free(session_info);

    //Ocall to ask the destination enclave to end the session
    status = end_session_ocall(&retstatus, session_id);

    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        return ATTESTATION_SE_ERROR;
    }

    return SUCCESS;
}

dh_session_t *get_session_info(size_t session_id)
{
    return find_session(session_id);
}

