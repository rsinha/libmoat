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
#include "EnclaveMessageExchange.h"
#include "sgx_eid.h"
#include "error_codes.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "dh_session_protocol.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"
#include "../../libmoat_untrusted.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t message_exchange_response_generator(char* decrypted_data, char** resp_buffer, size_t* resp_length);
uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity);

uint32_t session_request(sgx_enclave_id_t src_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
uint32_t exchange_report(sgx_enclave_id_t src_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
uint32_t end_session(sgx_enclave_id_t src_enclave_id);

#ifdef __cplusplus
}
#endif

#define MAX_SESSION_COUNT  16

//number of open sessions
uint32_t g_session_count = 0;

ATTESTATION_STATUS generate_session_id(uint32_t *session_id);
ATTESTATION_STATUS end_session(sgx_enclave_id_t src_enclave_id);

//Array of open session ids
session_id_tracker_t *g_session_id_tracker[MAX_SESSION_COUNT];

//Map between the source enclave id and the session information associated with that particular session
std::map<sgx_enclave_id_t, dh_session_t>g_dest_session_info_map;

//Create a session with the destination enclave
ATTESTATION_STATUS create_session(sgx_enclave_id_t src_enclave_id,
                         sgx_enclave_id_t dest_enclave_id,
                         dh_session_t *session_info)
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;        // Session Key
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    uint32_t session_id;
    uint32_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    if(!session_info)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));

    //Intialize the session as a session initiator
    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
            return status;
    }
    
    //Ocall to request for a session with the destination enclave and obtain session id and Message 1 if successful
    status = session_request_ocall(&retstatus, src_enclave_id, dest_enclave_id, &dh_msg1, &session_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    //Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
         return status;
    }

    //Send Message 2 to Destination Enclave and get Message 3 in return
    status = exchange_report_ocall(&retstatus, src_enclave_id, dest_enclave_id, &dh_msg2, &dh_msg3, session_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }

    //Process Message 3 obtained from the destination enclave
    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SGX_SUCCESS != status)
    {
        return status;
    }

    // Verify the identity of the destination enclave
    if(verify_peer_enclave_trust(&responder_identity) != SUCCESS)
    {
        return INVALID_SESSION;
    }

    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    session_info->session_id = session_id;
    session_info->active.counter = 0;
    session_info->status = ACTIVE;
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    return status;
}

//Handle the request from Source Enclave for a session
ATTESTATION_STATUS session_request(sgx_enclave_id_t src_enclave_id,
                          sgx_dh_msg1_t *dh_msg1,
                          uint32_t *session_id )
{
    dh_session_t session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;

    if(!session_id || !dh_msg1)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return status;
    }
    
    //get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(session_id)) != SUCCESS)
        return status; //no more sessions available

    //Allocate memory for the session id tracker
    g_session_id_tracker[*session_id] = (session_id_tracker_t *)malloc(sizeof(session_id_tracker_t));
    if(!g_session_id_tracker[*session_id])
    {
        return MALLOC_ERROR;
    }

    memset(g_session_id_tracker[*session_id], 0, sizeof(session_id_tracker_t));
    g_session_id_tracker[*session_id]->session_id = *session_id;
    session_info.status = IN_PROGRESS;

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(g_session_id_tracker[*session_id]);
        return status;
    }
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    //Store the session information under the correspoding source enlave id key
    g_dest_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(src_enclave_id, session_info));
    
    return status;
}

//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
ATTESTATION_STATUS exchange_report(sgx_enclave_id_t src_enclave_id,
                          sgx_dh_msg2_t *dh_msg2,
                          sgx_dh_msg3_t *dh_msg3,
                          uint32_t session_id)
{

    sgx_key_128bit_t dh_aek;   // Session key
    dh_session_t *session_info;
    ATTESTATION_STATUS status = SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t initiator_identity;

    if(!dh_msg2 || !dh_msg3)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    do
    {
        //Retreive the session information for the corresponding source enclave id
        std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_dest_session_info_map.find(src_enclave_id);
        if(it != g_dest_session_info_map.end())
        {
            session_info = &it->second;
        }
        else
        {
            status = INVALID_SESSION;
            break;
        }

        if(session_info->status != IN_PROGRESS)
        {
            status = INVALID_SESSION;
            break;
        }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        dh_msg3->msg3_body.additional_prop_length = 0;
        //Process message 2 from source enclave and obtain message 3
        sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2, 
                                                       dh_msg3, 
                                                       &sgx_dh_session, 
                                                       &dh_aek, 
                                                       &initiator_identity);
        if(SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }

        //Verify source enclave's trust
          if(verify_peer_enclave_trust(&initiator_identity) != SUCCESS)
        {
            return INVALID_SESSION;
        }

        //save the session ID, status and initialize the session nonce
        session_info->session_id = session_id;
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
        g_session_count++;
    }while(0);

    if(status != SUCCESS)
    {
        end_session(src_enclave_id);
    }

    return status;
}

//Close a current session
ATTESTATION_STATUS close_session(sgx_enclave_id_t src_enclave_id,
                        sgx_enclave_id_t dest_enclave_id)
{
    sgx_status_t status;

    uint32_t retstatus;

    //Ocall to ask the destination enclave to end the session
    status = end_session_ocall(&retstatus, src_enclave_id, dest_enclave_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    return SUCCESS;
}

//Respond to the request from the Source Enclave to close the session
ATTESTATION_STATUS end_session(sgx_enclave_id_t src_enclave_id)
{
    ATTESTATION_STATUS status = SUCCESS;
    int i;
    dh_session_t session_info;
    uint32_t session_id;

    //Get the session information from the map corresponding to the source enclave id
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_dest_session_info_map.find(src_enclave_id);
    if(it != g_dest_session_info_map.end())
    {
        session_info = it->second;
    }
    else
    {
        return INVALID_SESSION;
    }

    session_id = session_info.session_id;
    //Erase the session information for the current session
    g_dest_session_info_map.erase(src_enclave_id);

    //Update the session id tracker
    if (g_session_count > 0)
    {
        //check if session exists
        for (i=1; i <= MAX_SESSION_COUNT; i++)
        {
            if(g_session_id_tracker[i-1] != NULL && g_session_id_tracker[i-1]->session_id == session_id)
            {
                memset(g_session_id_tracker[i-1], 0, sizeof(session_id_tracker_t));
                SAFE_FREE(g_session_id_tracker[i-1]);
                g_session_count--;
                break;
            }
        }
    }

    return status;

}


//Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    if(!session_id)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //if the session structure is untintialized, set that as the next session ID
    for (int i = 0; i < MAX_SESSION_COUNT; i++)
    {
        if (g_session_id_tracker[i] == NULL)
        {
            *session_id = i;
            return status;
        }
    }

    status = NO_AVAILABLE_SESSION_ERROR;

    return status;

}
