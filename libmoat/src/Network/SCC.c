//NIST guidelines: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
//TLS 1.3 Spec: https://tlswg.github.io/tls13-spec/

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

#include "../../api/libmoat.h"
#include "../../api/libmoat_untrusted.h"
#include "RecordChannel/api/RecordChannel.h"
#include "../Utils/api/Utils.h"

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
            PUBLIC API IMPLEMENTATION
 ***************************************************/

void _moat_scc_module_init()
{
    record_channel_module_init();
}

scc_handle_t *_moat_scc_create(bool is_server, sgx_measurement_t *measurement)
{
    size_t status;
    size_t session_id;

    dh_session_t *session_info = open_session();
    if (session_info == NULL) { return NULL; } //can't handle another session
    
    //fill session_info->AEK
    status = establish_shared_secret(is_server, measurement, session_info);
    assert(status == 0);

    //derive server and client keys
    uint8_t* okm = malloc(2 * sizeof(sgx_aes_gcm_128bit_key_t));
    assert(okm != NULL);

    static const char key_label[] = "key";
    status = hkdf(((uint8_t *) &(session_info->AEK)),
                  sizeof(sgx_aes_gcm_128bit_key_t),
                  (uint8_t *) key_label,
                  strlen(key_label),
                  okm,
                  2 * sizeof(sgx_aes_gcm_128bit_key_t));
    assert(status == 0);
    size_t local_key_offset = is_server ? sizeof(sgx_aes_gcm_128bit_key_t) : 0;
    size_t remote_key_offset = is_server ? 0 : sizeof(sgx_aes_gcm_128bit_key_t);
    memcpy(((uint8_t *) &(session_info->local_key)), okm + local_key_offset, sizeof(sgx_aes_gcm_128bit_key_t));
    memcpy(((uint8_t *) &(session_info->remote_key)), okm + remote_key_offset, sizeof(sgx_aes_gcm_128bit_key_t));

    free(okm);

    //derive iv constant
    uint8_t* iv_constant = malloc(2 * SGX_AESGCM_IV_SIZE);
    assert(iv_constant != NULL);

    static const char iv_label[] = "iv";
    status = hkdf(((uint8_t *) &(session_info->AEK)),
                  sizeof(sgx_aes_gcm_128bit_key_t),
                  (uint8_t *) iv_label,
                  strlen(iv_label),
                  iv_constant,
                  2 * SGX_AESGCM_IV_SIZE);
    assert(status == 0);
    size_t iv_offset = is_server ? SGX_AESGCM_IV_SIZE : 0;
    memcpy(((uint8_t *) &(session_info->iv_constant)), iv_constant + iv_offset, SGX_AESGCM_IV_SIZE);

    free(iv_constant);

    //local_seq_number is used as IV, and is incremented by 1 for each invocation of AES-GCM-128
    session_info->local_seq_number = 0;
    session_info->remote_seq_number = 0;
    session_info->recv_carryover_start = NULL;
    session_info->recv_carryover_ptr = NULL;
    session_info->recv_carryover_bytes = 0;

#ifndef RELEASE
    _moat_print_debug("master secret: ");
    for (size_t i = 0; i < sizeof(sgx_aes_gcm_128bit_key_t); i++)
    {
        _moat_print_debug("0x%02X,", ((uint8_t *) &(session_info->AEK))[i]);
    }
    _moat_print_debug("\n");
    _moat_print_debug("local key: ");
    for (size_t i = 0; i < sizeof(sgx_aes_gcm_128bit_key_t); i++)
    {
        _moat_print_debug("0x%02X,", ((uint8_t *) &(session_info->local_key))[i]);
    }
    _moat_print_debug("\n");
    _moat_print_debug("remote key: ");
    for (size_t i = 0; i < sizeof(sgx_aes_gcm_128bit_key_t); i++)
    {
        _moat_print_debug("0x%02X,", ((uint8_t *) &(session_info->remote_key))[i]);
    }
    _moat_print_debug("\n");
#endif

    //allocate memory for the context
    scc_handle_t *handle = (scc_handle_t *) malloc(sizeof(scc_handle_t));
    assert(handle != NULL);
    handle->session_id = session_info->session_id;
    
    //all ok if we got here
    return handle;
}

size_t _moat_scc_send(scc_handle_t *handle, void *buf, size_t len)
{
    sgx_status_t status;
    size_t retstatus;

    //a full size record cannot exceed 2^14 bytes in TLS 1.3
    if (len > (1<<14)) { return -1; }

    dh_session_t *session_info = find_session(handle->session_id);
    assert(session_info != NULL);

    //Section 5.5: 
    //For AES-GCM, up to 2^24.5 full-size records (about 24 million) 
    //may be encrypted on a given connection while keeping a safety margin 
    //of approximately 2^-57 for Authenticated Encryption (AE) security
    //at most 2^32 invocations of AES-GCM according to NIST guidelines
    //but we stop at 2^24 because of TLS 1.3 spec
    if (session_info->local_seq_number > (1 << 24)) { return -1; }

    //allocate memory for ciphertext
    size_t dst_len = sizeof(scc_ciphertext_header_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;
    //look for overflows
    assert(dst_len > len);
    uint8_t *ciphertext = (uint8_t *) malloc(dst_len);
    assert (ciphertext != NULL);

    ((scc_ciphertext_header_t *) ciphertext)->type = APPLICATION_DATA;
    ((scc_ciphertext_header_t *) ciphertext)->length = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;

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
                                        buf, /* input */
                                        len, /* input length */
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        payload + 0, /* IV */
                                        SGX_AESGCM_IV_SIZE, /* 12 bytes of IV */
                                        (uint8_t *) &(session_info->local_seq_number), /* additional data */
                                        sizeof(session_info->local_seq_number), /* zero bytes of additional data */
                                        (sgx_aes_gcm_128bit_tag_t *) (payload + SGX_AESGCM_IV_SIZE)); /* mac */
    assert(status == SGX_SUCCESS);

    //so we don't reuse IVs
    session_info->local_seq_number = session_info->local_seq_number + 1;

    status = send_msg_ocall(&retstatus, ciphertext, dst_len, handle->session_id);
    assert(status == SGX_SUCCESS && retstatus == 0);
    free(ciphertext);
    return 0;
}

size_t _moat_scc_recv(scc_handle_t *handle, void *buf, size_t len)
{
    sgx_status_t status;
    size_t retstatus;
    size_t len_completed = 0; //how many of the requested len bytes have we fulfilled?

    dh_session_t *session_info = find_session(handle->session_id);
    assert(session_info != NULL);
    
    //are there any bytes remaining from the previous invocation of recv?
    if (session_info->recv_carryover_ptr != NULL) {
        size_t bytes_to_copy = min(session_info->recv_carryover_bytes, len);
        memcpy(buf, session_info->recv_carryover_ptr, bytes_to_copy);
        _moat_print_debug("copying %" PRIu64 " bytes from previous message\n", bytes_to_copy);
        
        len_completed = len_completed + bytes_to_copy;
        session_info->recv_carryover_bytes = session_info->recv_carryover_bytes - bytes_to_copy;
        
        if (session_info->recv_carryover_bytes == 0) {
            free(session_info->recv_carryover_start);
            session_info->recv_carryover_start = NULL;
            session_info->recv_carryover_ptr = NULL;
        }
    }
    
    scc_ciphertext_header_t *header = (scc_ciphertext_header_t *) malloc(sizeof(scc_ciphertext_header_t));
    assert(header != NULL);
    
    while (len_completed < len) {
        //first fetch the header to understand what to do next
        status = recv_msg_ocall(&retstatus, header, sizeof(scc_ciphertext_header_t), handle->session_id);
        //the ocall succeeded, and the logic within the ocall says everything succeeded
        assert(status == SGX_SUCCESS && retstatus == 0);

        if (header->type != APPLICATION_DATA) { free(header); return -1; } //no bytes
        if (header->length > ((1<<14) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)) { free(header); return -1; }

        uint8_t *ciphertext = (uint8_t *) malloc(header->length);
        assert(ciphertext != NULL);

        size_t cleartext_length = header->length - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
        uint8_t *cleartext = (uint8_t *) malloc(cleartext_length);
        assert(cleartext != NULL);

        //fetch the ciphertext
        status = recv_msg_ocall(&retstatus, ciphertext, header->length, handle->session_id);
        assert(status == SGX_SUCCESS && retstatus == 0);

        /* ciphertext: header || IV || MAC || encrypted */
        status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) &(session_info->remote_key), //key
                                            ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, //src
                                            cleartext_length, //src_len
                                            cleartext, //dst
                                            ciphertext, //iv
                                            SGX_AESGCM_IV_SIZE, //12 bytes
                                            (uint8_t *) &(session_info->remote_seq_number), //aad
                                            sizeof(session_info->remote_seq_number), //0 bytes of AAD
                                            (const sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE)); //mac
        assert(status == SGX_SUCCESS);

        session_info->remote_seq_number = session_info->remote_seq_number + 1;

        size_t bytes_to_copy = min(cleartext_length, len - len_completed);
        memcpy(buf + len_completed, cleartext, bytes_to_copy);
        len_completed = len_completed + bytes_to_copy;

        if (bytes_to_copy < cleartext_length) {
            session_info->recv_carryover_start = cleartext;
            session_info->recv_carryover_ptr = cleartext + bytes_to_copy;
            session_info->recv_carryover_bytes = cleartext_length - bytes_to_copy;
        } else {
            free(cleartext);
        }
        
        free(ciphertext);
    }
    
    free(header);
    return 0;
    
}

size_t _moat_scc_destroy(scc_handle_t *handle)
{
    dh_session_t *session_info = find_session(handle->session_id);
    size_t status = close_session(session_info);
    assert(status == 0);
    free(handle);
    return 0;
}

