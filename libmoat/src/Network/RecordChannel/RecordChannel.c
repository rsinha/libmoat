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

#include "api/RecordChannel.h"
#include "../../Utils/api/Utils.h"
#include "../../../api/libmoat_untrusted.h"

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

typedef enum {
    RESET = 0,
    TEARDOWN = 1,
    APPLICATION_DATA = 2
} scc_ciphertext_type_t;

typedef struct
{
    size_t type;
    size_t length;
} scc_ciphertext_header_t;

/***************************************************
 INTERNAL STATE
 ***************************************************/

//Map between the source enclave id and the session information associated with that particular session
static ll_t *g_dest_session_info;

/***************************************************
 PRIVATE METHODS
 ***************************************************/

//Returns a new sessionID for the source destination session
size_t generate_unique_session_id()
{
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
            return i + 1; //session ids start at 1
        }
    }
    
    return 0;
}


/***************************************************
 PUBLIC METHODS
 ***************************************************/

void record_channel_module_init()
{
    g_dest_session_info = malloc(sizeof(ll_t));
    assert(g_dest_session_info != NULL);
    g_dest_session_info->head = NULL;
}

//finds an open session by its id
dh_session_t *find_session(size_t session_id)
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

//creates a session struct with a unique id
dh_session_t *session_open()
{
    size_t session_id = generate_unique_session_id();
    if (session_id == 0) { return NULL; } //can't give you a session at this time. Try later.

    dh_session_t *session_info = (dh_session_t *) malloc(sizeof(dh_session_t));
    assert(session_info != NULL);

    list_insert_value(g_dest_session_info, session_info);
    session_info->session_id = session_id;

    return session_info;
}

//Close an open session, and free all associated resources (inverse of open_session)
size_t session_close(dh_session_t *session_info)
{
    sgx_status_t status;
    size_t retstatus;

    //Ocall to ask the destination enclave to end the session
    status = end_session_ocall(&retstatus, session_info->session_id);
    if ((status != SGX_SUCCESS) || (retstatus != 0)) { return -1; }

    //Erase the session information for the current session
    bool deleted_successfully = list_delete_value(g_dest_session_info, session_info);
    assert(deleted_successfully);

    if(session_info->recv_carryover_start != NULL) {
        free(session_info->recv_carryover_start);
    }
    free(session_info);

    return 0;
}

size_t session_send(dh_session_t *session_info, void *record, size_t record_size)
{
    sgx_status_t status;
    size_t retstatus;
    
    //a full size record cannot exceed 2^14 bytes in TLS 1.3
    if (record_size > (1<<14)) { return -1; }
    assert(record_size == (session_info->record_size + sizeof(scc_cleartext_header_t)));
    
    //Section 5.5:
    //For AES-GCM, up to 2^24.5 full-size records (about 24 million)
    //may be encrypted on a given connection while keeping a safety margin
    //of approximately 2^-57 for Authenticated Encryption (AE) security
    //at most 2^32 invocations of AES-GCM according to NIST guidelines
    //but we stop at 2^24 because of TLS 1.3 spec
    if (session_info->local_seq_number > (1 << 24)) { return -1; }
    
    //allocate memory for ciphertext
    size_t dst_len = sizeof(scc_ciphertext_header_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + record_size;
    
    uint8_t *ciphertext = (uint8_t *) malloc(dst_len);
    assert (ciphertext != NULL);
    
    ((scc_ciphertext_header_t *) ciphertext)->type = APPLICATION_DATA;
    ((scc_ciphertext_header_t *) ciphertext)->length = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + record_size;
    
    uint8_t *payload = ciphertext + sizeof(scc_ciphertext_header_t);
    
    //compute the per-record nonce
    //(1) The 64-bit record sequence number is encoded in network byte order and padded to the left with zeroes to iv_length.
    for (size_t i = 0; i < sizeof(session_info->local_seq_number); i++)
    {
        payload[i] = (session_info->local_seq_number >> (56 - i * 8)) & 0xFF;
    }
    memset(payload + sizeof(session_info->local_seq_number), 0, SGX_AESGCM_IV_SIZE - sizeof(session_info->local_seq_number));
    //(2) The padded sequence number is XORed with the static client_write_iv or server_write_iv, depending on the role.
    for (size_t i = 0; i < SGX_AESGCM_IV_SIZE; i++)
    {
        payload[i] = payload[i] ^ (session_info->iv_constant)[i];
    }
    
    /* ciphertext: IV || MAC || encrypted */
    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) &(session_info->local_key),
                                        record, /* input */
                                        record_size, /* input length */
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        payload + 0, /* IV */
                                        SGX_AESGCM_IV_SIZE, /* 12 bytes of IV */
                                        (uint8_t *) &(session_info->local_seq_number), /* additional data */
                                        sizeof(session_info->local_seq_number), /* zero bytes of additional data */
                                        (sgx_aes_gcm_128bit_tag_t *) (payload + SGX_AESGCM_IV_SIZE)); /* mac */
    assert(status == SGX_SUCCESS);
    
    //so we don't reuse IVs
    session_info->local_seq_number = session_info->local_seq_number + 1;
    
    status = send_msg_ocall(&retstatus, ciphertext, dst_len, session_info->session_id);
    assert(status == SGX_SUCCESS && retstatus == 0);
    free(ciphertext);
    return 0;
}


size_t session_recv(dh_session_t *session_info, void *record, size_t record_size)
{
    sgx_status_t status;
    size_t retstatus;
    scc_ciphertext_header_t header;
    
    if (record_size > (1<<14)) { return -1; }
    assert(record_size == (session_info->record_size + sizeof(scc_cleartext_header_t)));
    
    //TODO: only one ocall is needed because we know the record_size
    //first fetch the header to understand what to do next
    status = recv_msg_ocall(&retstatus, &header, sizeof(scc_ciphertext_header_t), session_info->session_id);
    assert(status == SGX_SUCCESS && retstatus == 0);
    
    if (header.type != APPLICATION_DATA) { return -1; }
    if (header.length != (record_size + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)) { return -1; }
    
    uint8_t *ciphertext = (uint8_t *) malloc(header.length);
    assert(ciphertext != NULL);
    
    //fetch the ciphertext
    status = recv_msg_ocall(&retstatus, ciphertext, header.length, session_info->session_id);
    assert(status == SGX_SUCCESS && retstatus == 0);
    
    /* ciphertext: header || IV || MAC || encrypted */
    status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) &(session_info->remote_key), //key
                                        ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, //src
                                        record_size, //src_len
                                        record, //dst
                                        ciphertext, //iv
                                        SGX_AESGCM_IV_SIZE, //12 bytes
                                        (uint8_t *) &(session_info->remote_seq_number), //aad
                                        sizeof(session_info->remote_seq_number), //0 bytes of AAD
                                        (const sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE)); //mac
    assert(status == SGX_SUCCESS);
    
    session_info->remote_seq_number = session_info->remote_seq_number + 1;
    
    free(ciphertext);
    return 0;
}

