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

typedef struct
{
    size_t cleartext_length;
} scc_cleartext_header_t;

#define RECORD_CLEARTEXT_SIZE 128

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

//decomposes buf into record-sized chunks and sends it to the RecordChannel layer
size_t _moat_scc_send(scc_handle_t *handle, void *buf, size_t len)
{
    size_t status;

    dh_session_t *session_info = find_session(handle->session_id);
    if (session_info == NULL) { return -1; }

    uint8_t *record = malloc(sizeof(scc_cleartext_header_t) + RECORD_CLEARTEXT_SIZE);
    assert(record != NULL);

    size_t len_completed = 0; //how many of the requested len bytes have we fulfilled?

    while (len_completed < len) {
        size_t delta = len - len_completed;

        if (delta > RECORD_CLEARTEXT_SIZE) {
            ((scc_cleartext_header_t *) record)->cleartext_length = RECORD_CLEARTEXT_SIZE;
            memcpy(record + sizeof(scc_cleartext_header_t), buf + len_completed, RECORD_CLEARTEXT_SIZE);
            len_completed += RECORD_CLEARTEXT_SIZE;
        } else {
            //introduce zero pad
            ((scc_cleartext_header_t *) record)->cleartext_length = delta;
            memcpy(record + sizeof(scc_cleartext_header_t), buf + len_completed, delta);
            memset(record + sizeof(scc_cleartext_header_t) + delta, 0, RECORD_CLEARTEXT_SIZE - delta);
            len_completed += delta;
        }

        status = record_channel_send(session_info, record, sizeof(scc_cleartext_header_t) + RECORD_CLEARTEXT_SIZE);
        if (status != 0) { free(record); return -1; } //TODO: handle IV wraparound so we can do session rengotiation
    }

    free(record);
    return 0;
}

size_t _moat_scc_recv(scc_handle_t *handle, void *buf, size_t len)
{
    size_t status;

    dh_session_t *session_info = find_session(handle->session_id);
    if (session_info == NULL) { return -1; }

    size_t len_completed = 0; //how many of the requested len bytes have we fulfilled?
    
    //are there any left over bytes from the previous invocation of _moat_scc_recv?
    if (session_info->recv_carryover_ptr != NULL) {
        size_t bytes_to_copy = min(session_info->recv_carryover_bytes, len);

        _moat_print_debug("copying %" PRIu64 " bytes from previous message\n", bytes_to_copy);

        memcpy(buf, session_info->recv_carryover_ptr, bytes_to_copy);
        len_completed = len_completed + bytes_to_copy;
        session_info->recv_carryover_bytes = session_info->recv_carryover_bytes - bytes_to_copy;
        session_info->recv_carryover_ptr = session_info->recv_carryover_ptr + bytes_to_copy;

        //have we exhausted the left over bytes? If so, then free those resources.
        if (session_info->recv_carryover_bytes == 0) {
            free(session_info->recv_carryover_start);
            session_info->recv_carryover_start = NULL;
            session_info->recv_carryover_ptr = NULL;
        }
    }

    uint8_t *record = (uint8_t *) malloc(sizeof(scc_cleartext_header_t) + RECORD_CLEARTEXT_SIZE);
    assert(record != NULL);

    size_t cleartext_bytes_fetched = 0, bytes_to_copy = 0;

    while (len_completed < len) {
        //fetch the ciphertext
        status = record_channel_recv(session_info, record, sizeof(scc_cleartext_header_t) + RECORD_CLEARTEXT_SIZE);
        if (status != 0) { free(record); return -1; }

        cleartext_bytes_fetched = ((scc_cleartext_header_t *) record)->cleartext_length;
        bytes_to_copy = min(cleartext_bytes_fetched, len - len_completed);

        memcpy(buf + len_completed, record + sizeof(scc_cleartext_header_t), bytes_to_copy);
        len_completed = len_completed + bytes_to_copy;
    }
    
    if (bytes_to_copy < cleartext_bytes_fetched) {
        session_info->recv_carryover_start = record;
        session_info->recv_carryover_ptr = record + sizeof(scc_cleartext_header_t) + bytes_to_copy;
        session_info->recv_carryover_bytes = cleartext_bytes_fetched - bytes_to_copy;
    } else {
        free(record);
    }

    return 0;
    
}

size_t _moat_scc_destroy(scc_handle_t *handle)
{
    dh_session_t *session_info = find_session(handle->session_id);
    if (session_info == NULL) { return -1; }

    size_t status = close_session(session_info);
    assert(status == 0);

    free(handle);

    return 0;
}

