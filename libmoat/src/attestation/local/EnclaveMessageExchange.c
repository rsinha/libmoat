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


#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "dh_session_protocol.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "../../libmoat_untrusted.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"

uint32_t message_exchange_response_generator(char* decrypted_data, char** resp_buffer, size_t* resp_length);
uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity);

uint32_t session_request(sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
uint32_t exchange_report(sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
uint32_t end_session(uint32_t session_id);

#define MAX_SESSION_COUNT  16

typedef struct _ll_node 
{
  dh_session_t *value;
  struct _ll_node *next;
} ll_node_t;

//Map between the source enclave id and the session information associated with that particular session
static ll_node_t *g_dest_session_info = NULL;

static uint32_t number_of_active_sessions()
{
    ll_node_t *iter = g_dest_session_info;
    uint32_t count = 0;
    while (iter != NULL)
    {
        iter = iter->next;
        count += 1;
    }
    return count;
}

static void insert_session(dh_session_t *session)
{
    ll_node_t *node = (ll_node_t *) malloc(sizeof(ll_node_t));
    node->value = session;
    node->next = NULL; //we are always going to insert at the tail

    if (g_dest_session_info == NULL) {
        g_dest_session_info = node; //empty list
    }

    //if we got here, then we have a list of size >= 1
    ll_node_t *iter = g_dest_session_info;
    ll_node_t *iter_next = g_dest_session_info->next;
    while (iter_next != NULL)
    {
        iter_next = iter_next->next;
        iter = iter->next;
    }
    
    //at this poimt. iter is at the tail and iter_next is NULL
    iter->next = node;
}

//removes session from the linked list
static bool delete_session(dh_session_t *session)
{
    if (g_dest_session_info == NULL) { return false; }

    //if we got here, then we have a list of size >= 1
    ll_node_t *iter = g_dest_session_info;
    ll_node_t *iter_next = g_dest_session_info->next;

    //is the head what we are looking for?
    if (iter->value == session) { g_dest_session_info = iter->next; return true; }

    while (iter_next != NULL)
    {
        if (iter_next->value == session) {
            iter->next = iter_next->next;
            free(iter_next); //session must be freed outside
            return true;
        }
        iter_next = iter_next->next;
        iter = iter->next;
    }

    return false;
}

//finds session in the linked list
static dh_session_t *find_session(uint32_t session_id)
{
    ll_node_t *iter = g_dest_session_info;
    while (iter != NULL)
    {
        if (iter->value->session_id == session_id) {
            return iter->value;
        }
        iter = iter->next;
    }
    return NULL; //didn't find this session id
}

//Returns a new sessionID for the source destination session
attestation_status_t generate_session_id(uint32_t *session_id)
{
    if(!session_id) { return INVALID_PARAMETER_ERROR; }

    bool occupied[MAX_SESSION_COUNT];
    for (int i = 0; i < MAX_SESSION_COUNT; i++) { 
        occupied[i] = false;
    }

    ll_node_t *iter = g_dest_session_info;
    while (iter != NULL) {
        //session ids start at 1
        occupied[iter->value->session_id - 1] = true;
    }

    for (int i = 0; i < MAX_SESSION_COUNT; i++) { 
        if (occupied[i] == false) {
            *session_id = i + 1; //session ids start at 1
            return SUCCESS;
        }
    }

    return NO_AVAILABLE_SESSION_ERROR;
}

uint32_t server_create_session(sgx_measurement_t *target_enclave)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    sgx_key_128bit_t dh_aek;          // Session Key
    uint32_t session_id;
    uint32_t retstatus;
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

    status = (sgx_status_t) generate_session_id(&session_id);
    if (status != SUCCESS) { free(session_info); return 0; } //no more sessions available

    //Intialize the session as a session initiator
    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }
    _moat_print_debug("got here 1\n");
    
    //Ocall to request for a session with the destination enclave and obtain Message 1 if successful
    status = recv_dh_msg1_ocall(&retstatus, target_enclave, &dh_msg1, session_id);
    _moat_print_debug("got here 2\n");
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        free(session_info); return 0;
    }
    _moat_print_debug("got here 3\n");

    //Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    _moat_print_debug("got here 4:%u\n", status);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }
    _moat_print_debug("got here 5\n");

    //Send Message 2 to Destination Enclave and get Message 3 in return
    status = send_dh_msg2_recv_dh_msg3_ocall(&retstatus, &dh_msg2, &dh_msg3, session_id);
    _moat_print_debug("got here 6\n");
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        free(session_info); return 0;
    }

    //Process Message 3 obtained from the destination enclave
    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SGX_SUCCESS != status) { free(session_info); return 0; }

    // Verify the identity of the destination enclave
    if(verify_peer_enclave_trust(&responder_identity) != SUCCESS) { free(session_info); return 0; }

    session_info->session_id = session_id;
    session_info->status = ACTIVE;
    session_info->active.counter = 0;
    session_info->role = SGX_DH_SESSION_INITIATOR; //server is called initiator, idk why...
    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    memcpy(&session_info->measurement, target_enclave, sizeof(sgx_measurement_t));

    //save the session until it gets destroyed via close_session
    insert_session(session_info);

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    return session_id;
}

uint32_t client_create_session(sgx_measurement_t *target_enclave)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    sgx_key_128bit_t dh_aek;          //Session Key
    sgx_dh_session_t sgx_dh_session;
    uint32_t session_id;
    sgx_dh_session_enclave_identity_t initiator_identity;
    sgx_status_t status;
    uint32_t retstatus;

    dh_session_t *session_info = (dh_session_t *) malloc(sizeof(dh_session_t));
    if (session_info == NULL) { return MALLOC_ERROR; }

    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status) { return status; }
    
    //get a new SessionID
    status = (sgx_status_t) generate_session_id(&session_id);
    if (status != SUCCESS) { return status; } //no more sessions available

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1(&dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status) { return status; }

    session_info->session_id = session_id;
    session_info->status = IN_PROGRESS;
    session_info->role = SGX_DH_SESSION_RESPONDER; //client
    memcpy(&session_info->in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));

    //ocall to send msg 1 and get msg 2
    status = send_dh_msg1_recv_dh_msg2_ocall(&retstatus, &dh_msg1, &dh_msg2, session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        free(session_info); return status;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    dh_msg3.msg3_body.additional_prop_length = 0;

    //Process message 2 from source enclave and obtain message 3
    status = sgx_dh_responder_proc_msg2(&dh_msg2, &dh_msg3, &sgx_dh_session, &dh_aek, &initiator_identity);
    if(SGX_SUCCESS != status) { return status; }

    //Verify source enclave's trust
    if(verify_peer_enclave_trust(&initiator_identity) != SUCCESS) { return INVALID_SESSION; }

    //ocall to send msg3
    status = send_dh_msg3_ocall(&retstatus, &dh_msg3, session_id);
    if ((status != SGX_SUCCESS) || ((attestation_status_t)retstatus != SUCCESS)) {
        free(session_info); return status;
    }

    //save the session ID, status and initialize the session nonce
    session_info->status = ACTIVE;
    session_info->active.counter = 0;
    memcpy(&session_info->measurement, target_enclave, sizeof(sgx_measurement_t));
    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));

    //Store the session information under the correspoding source enlave id key
    insert_session(session_info);

    return SUCCESS;
}

//Create a session with the destination enclave
uint32_t create_session(bool is_server, sgx_measurement_t *target_enclave)
{
    if (is_server) {
        return server_create_session(target_enclave);
    } else {
        return client_create_session(target_enclave);
    }
}

//ecall: Handle the request from Source Enclave for a session
attestation_status_t session_request(sgx_dh_msg1_t *dh_msg1, uint32_t *session_id )
{
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status;

    if(!session_id || !dh_msg1) { return INVALID_PARAMETER_ERROR; }

    dh_session_t *session_info = (dh_session_t *) malloc(sizeof(dh_session_t));
    if (session_info == NULL) { return MALLOC_ERROR; }

    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status) { return status; }
    
    //get a new SessionID
    status = (sgx_status_t) generate_session_id(session_id);
    if (status != SUCCESS) { return status; } //no more sessions available

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1(dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status) { return status; }

    session_info->session_id = *session_id;
    session_info->status = IN_PROGRESS;
    memcpy(&session_info->in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));

    //Store the session information under the correspoding source enlave id key
    insert_session(session_info);
    
    return SUCCESS;
}

//ecall: Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
attestation_status_t exchange_report(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{

    sgx_key_128bit_t dh_aek;   // Session key
    dh_session_t *session_info;
    attestation_status_t status;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t initiator_identity;

    if(!dh_msg2 || !dh_msg3) { return INVALID_PARAMETER_ERROR; }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));

    do
    {
        //Retreive the session information for the corresponding source enclave id
        session_info = find_session(session_id);
        if (session_info == NULL) { status = INVALID_SESSION; break; }
        if(session_info->status != IN_PROGRESS) { status = INVALID_SESSION; break; }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        dh_msg3->msg3_body.additional_prop_length = 0;

        //Process message 2 from source enclave and obtain message 3
        sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2, dh_msg3, &sgx_dh_session, &dh_aek, &initiator_identity);

        if(SGX_SUCCESS != se_ret) { status = se_ret; break; }

        //Verify source enclave's trust
        if(verify_peer_enclave_trust(&initiator_identity) != SUCCESS) { status = INVALID_SESSION; break; }

        //save the session ID, status and initialize the session nonce
        //session_info->session_id = session_id;
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
        status = SUCCESS;
    } while(0);

    if(status != SUCCESS)
    {
        end_session(session_id);
    }

    return status;
}

//Close a current session
attestation_status_t close_session(uint32_t session_id)
{
    sgx_status_t status;
    uint32_t retstatus;
    dh_session_t *session_info;

    //Get the session information from the list corresponding to the session id
    session_info = find_session(session_id);
    if (session_info == NULL) { return INVALID_SESSION; }

    //Erase the session information for the current session
    bool deleted_successfully = delete_session(session_info);
    assert(deleted_successfully);

    free(session_info);

    //Ocall to ask the destination enclave to end the session
    status = end_session_ocall(&retstatus, session_id);

    if (status == SGX_SUCCESS)
    {
        if ((attestation_status_t)retstatus != SUCCESS) {
            return ((attestation_status_t)retstatus);
        }
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    return SUCCESS;
}

sgx_aes_gcm_128bit_key_t *get_session_key(uint32_t session_id)
{
    dh_session_t *session_info = find_session(session_id);
    if (session_info == NULL) { return NULL; }

    return &(session_info->active.AEK);
}

//ecall: Respond to the request from the Source Enclave to close the session
attestation_status_t end_session(uint32_t session_id)
{
    dh_session_t *session_info;

    //Get the session information from the list corresponding to the session id
    session_info = find_session(session_id);
    if (session_info == NULL) { return INVALID_SESSION; }

    //Erase the session information for the current session
    bool deleted_successfully = delete_session(session_info);
    assert(deleted_successfully);

    free(session_info);
    return SUCCESS;

}

