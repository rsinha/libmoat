//NIST guidelines: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
//TLS 1.3 Spec: https://tlswg.github.io/tls13-spec/

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

#include "../../api/libmoat.h"
#include "../../api/libbarbican.h"
#include "RecordChannel/api/RecordChannel.h"
#include "../Utils/api/Utils.h"


/***************************************************
            PUBLIC API IMPLEMENTATION
 ***************************************************/

void _moat_scc_module_init()
{
    record_channel_module_init();
}

int64_t _moat_scc_create(char *name, sgx_measurement_t *measurement)
{
    size_t status;

    dh_session_t *session_info = session_open(name, measurement);
    if (session_info == NULL) { return -1; } //can't handle another session

    //fill session_info->AEK
    status = session_info->role_is_server ?
        server_dh_exchange(measurement, session_info) :
        client_dh_exchange(measurement, session_info);
    assert(status == 0);

    //derive server and client keys
    uint8_t okm[2 * sizeof(sgx_aes_gcm_128bit_key_t)];

    static const char key_label[] = "key";
    status = hkdf(((uint8_t *) &(session_info->AEK)),
                  sizeof(sgx_aes_gcm_128bit_key_t),
                  (uint8_t *) key_label,
                  strlen(key_label),
                  okm,
                  2 * sizeof(sgx_aes_gcm_128bit_key_t));
    assert(status == 0);
    size_t local_key_offset = session_info->role_is_server ? sizeof(sgx_aes_gcm_128bit_key_t) : 0;
    size_t remote_key_offset = session_info->role_is_server ? 0 : sizeof(sgx_aes_gcm_128bit_key_t);
    memcpy(((uint8_t *) &(session_info->local_key)), okm + local_key_offset, sizeof(sgx_aes_gcm_128bit_key_t));
    memcpy(((uint8_t *) &(session_info->remote_key)), okm + remote_key_offset, sizeof(sgx_aes_gcm_128bit_key_t));

    //derive iv constant
    uint8_t iv_constant[2 * SGX_AESGCM_IV_SIZE];

    static const char iv_label[] = "iv";
    status = hkdf(((uint8_t *) &(session_info->AEK)),
                  sizeof(sgx_aes_gcm_128bit_key_t),
                  (uint8_t *) iv_label,
                  strlen(iv_label),
                  iv_constant,
                  2 * SGX_AESGCM_IV_SIZE);
    assert(status == 0);
    size_t iv_offset = session_info->role_is_server ? SGX_AESGCM_IV_SIZE : 0;
    memcpy(((uint8_t *) &(session_info->iv_constant)), iv_constant + iv_offset, SGX_AESGCM_IV_SIZE);

    //local_seq_number is used as IV, and is incremented by 1 for each invocation of AES-GCM-128
    session_info->local_seq_number = 0;
    session_info->remote_seq_number = 0;
    session_info->recv_carryover_start = NULL;
    session_info->recv_carryover_ptr = NULL;
    session_info->recv_carryover_bytes = 0;

    //parameter
    session_info->record_size = 128;


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
    
    //all ok if we got here
    return session_info->session_id;
}

//TODO: handle IV wraparound so we can do session rengotiation
//decomposes buf into record-sized chunks and sends it to the RecordChannel layer
int64_t _moat_scc_send(int64_t session_id, void *buf, size_t len)
{
    dh_session_t *session_info = find_session(session_id);
    if (session_info == NULL) { return -1; }

    /* each record has the form: record_size[64] || plaintext[record_size] */
    size_t record_len = sizeof(scc_cleartext_header_t) + session_info->record_size;
    uint8_t *record = malloc(record_len);
    assert(record != NULL);

    size_t len_completed = 0; //how many of the requested len bytes have we fulfilled?

    while (len_completed < len) {
        size_t delta = len - len_completed;

        if (delta > session_info->record_size) {
            ((scc_cleartext_header_t *) record)->cleartext_length = session_info->record_size;
            memcpy(record + sizeof(scc_cleartext_header_t), buf + len_completed, session_info->record_size);
            len_completed += session_info->record_size;
        } else {
            //introduce zero pad
            ((scc_cleartext_header_t *) record)->cleartext_length = delta;
            memcpy(record + sizeof(scc_cleartext_header_t), buf + len_completed, delta);
            memset(record + sizeof(scc_cleartext_header_t) + delta, 0, session_info->record_size - delta);
            len_completed += delta;
        }

        /* argument is a plaintext record of the form: record_size[64] || plaintext[record_size] */
        int64_t status = session_send(session_info, record, record_len);
        if (status != 0) {
            free(record);
            return -1;
        }
    }

    free(record);
    return 0;
}

int64_t _moat_scc_recv(int64_t session_id, void *buf, size_t len)
{
    size_t status;

    dh_session_t *session_info = find_session(session_id);
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

    uint8_t *record = (uint8_t *) malloc(sizeof(scc_cleartext_header_t) + session_info->record_size);
    assert(record != NULL);

    size_t cleartext_bytes_fetched = 0, bytes_to_copy = 0;

    while (len_completed < len) {
        //fetch the ciphertext
        status = session_recv(session_info, record, sizeof(scc_cleartext_header_t) + session_info->record_size);
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

int64_t _moat_scc_destroy(int64_t session_id)
{
    dh_session_t *session_info = find_session(session_id);
    if (session_info == NULL) { return -1; }

    size_t status = session_close(session_info);
    assert(status == 0);

    return 0;
}

