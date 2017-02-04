//NIST guidelines: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
//TLS 1.3 Spec: https://tlswg.github.io/tls13-spec/

#include <stddef.h> 

#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../api/libmoat.h"
#include "../api/libmoat_untrusted.h"
#include "attestation/local/dh_session_protocol.h"
#include "attestation/local/error_codes.h"
#include "attestation/local/EnclaveMessageExchange.h"

typedef enum { RESET = 0,
               TEARDOWN = 1,
               APPLICATION_DATA = 2
             } libmoat_ciphertext_type_t;

typedef struct
{
    size_t type;
    size_t length;
} libmoat_ciphertext_header_t;

size_t min(size_t a, size_t b) { return (a < b ? a : b); }

scc_ctx_t *_moat_scc_create(bool is_server, sgx_measurement_t *measurement)
{
    uint32_t session_id = create_session(is_server, measurement);
    assert(session_id != 0);

    dh_session_t *session_info = get_session_info(session_id);
    assert(session_info != NULL);

    //local_counter is used as IV, and is incremented by 2 for each invocation of AES-GCM-128
    session_info->local_counter = is_server ? 1 : 2; //server/client uses odd/even IVs
    session_info->remote_counter = 0; //haven't seen any remote IVs yet
    session_info->recv_carryover_bytes = 0;
    session_info->recv_carryover = NULL;

    //allocate memory for the context
    scc_ctx_t *ctx = (scc_ctx_t *) malloc(sizeof(scc_ctx_t));
    assert(ctx != NULL);
    ctx->session_id = session_id;
    
    //all ok if we got here
    return ctx;
}

size_t _moat_scc_send(scc_ctx_t *ctx, void *buf, size_t len)
{
    sgx_status_t status;
    uint32_t retstatus;

    //a full size record cannot exceed 2^14 bytes in TLS 1.3
    if (len > (1<<14)) { return 1; }

    dh_session_t *session_info = get_session_info(ctx->session_id);
    assert(session_info != NULL);

    //Section 5.5: 
    //For AES-GCM, up to 2^24.5 full-size records (about 24 million) 
    //may be encrypted on a given connection while keeping a safety margin 
    //of approximately 2^-57 for Authenticated Encryption (AE) security
    //at most 2^32 invocations of AES-GCM according to NIST guidelines
    //but we stop at 2^24 because of TLS 1.3 spec
    if (session_info->local_counter > (1 << 24)) { return 1; }

    //allocate memory for ciphertext
    size_t dst_len = sizeof(libmoat_ciphertext_header_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;
    //look for overflows
    assert(dst_len > len);
    uint8_t *ciphertext = (uint8_t *) malloc(dst_len);
    assert (ciphertext != NULL);

    ((libmoat_ciphertext_header_t *) ciphertext)->type = APPLICATION_DATA;
    ((libmoat_ciphertext_header_t *) ciphertext)->length = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;

    uint8_t *payload = ciphertext + sizeof(libmoat_ciphertext_header_t);

    uint32_t nonce = session_info->local_counter;
    //nonce is 64 bits of 0 followed by the message sequence number
    memcpy(payload + 0, &nonce, sizeof(nonce));
    memset(payload + sizeof(nonce), 0, SGX_AESGCM_IV_SIZE - sizeof(nonce));

    /* ciphertext: IV || MAC || encrypted */
    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) &(session_info->AEK),
                                        buf, /* input */
                                        len, /* input length */
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        payload + 0, /* IV */
                                        SGX_AESGCM_IV_SIZE, /* 12 bytes of IV */
                                        NULL, /* additional data */
                                        0, /* zero bytes of additional data */
                                        (sgx_aes_gcm_128bit_tag_t *) (payload + SGX_AESGCM_IV_SIZE)); /* mac */
    assert(status == SGX_SUCCESS);

    //so we don't reuse IVs
    session_info->local_counter = session_info->local_counter + 2;

    status = send_msg_ocall(&retstatus, ciphertext, dst_len, ctx->session_id);
    assert(status == SGX_SUCCESS && retstatus == 0);
    free(ciphertext);
    return 0;
}

size_t _moat_scc_recv(scc_ctx_t *ctx, void *buf, size_t len)
{
    sgx_status_t status;
    uint32_t retstatus;
    size_t actual_len; //how much data has the ocall given us?
    size_t len_completed = 0; //how many of the requested len bytes have we fulfilled?

    dh_session_t *session_info = get_session_info(ctx->session_id);
    assert(session_info != NULL);
    
    //are there any bytes remaining from the previous invocation of recv?
    if (session_info->recv_carryover != NULL) {
        size_t bytes_to_copy = min(session_info->recv_carryover_bytes, len);
        memcpy(buf, session_info->recv_carryover, bytes_to_copy);
        
        len_completed = len_completed + bytes_to_copy;
        session_info->recv_carryover_bytes = session_info->recv_carryover_bytes - bytes_to_copy;
        
        if (session_info->recv_carryover_bytes == 0) {
            free(session_info->recv_carryover);
            session_info->recv_carryover = NULL;
        }
    }
    
    libmoat_ciphertext_header_t *header = (libmoat_ciphertext_header_t *) malloc(sizeof(libmoat_ciphertext_header_t));
    assert(header != NULL);
    
    while (len_completed < len) {
        //first fetch the header to understand what to do next
        status = recv_msg_ocall(&retstatus, header, sizeof(libmoat_ciphertext_header_t), &actual_len, ctx->session_id);
        //the ocall succeeded, and the logic within the ocall says everything succeeded
        assert(status == SGX_SUCCESS && retstatus == 0);
        assert(actual_len == sizeof(libmoat_ciphertext_header_t));

        if (header->type != APPLICATION_DATA) { free(header); return len_completed; } //no bytes
        if (header->length > ((1<<14) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)) { free(header); return len_completed; }

        uint8_t *ciphertext = (uint8_t *) malloc(header->length);
        assert(ciphertext != NULL);

        size_t cleartext_length = header->length - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
        uint8_t *cleartext = (uint8_t *) malloc(cleartext_length);
        assert(cleartext != NULL);

        //fetch the ciphertext
        status = recv_msg_ocall(&retstatus, ciphertext, header->length, &actual_len, ctx->session_id);
        assert(status == SGX_SUCCESS && retstatus == 0);
        assert (actual_len == header->length);

        /* ciphertext: header || IV || MAC || encrypted */
        status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) &(session_info->AEK), //key
                                            ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, //src
                                            cleartext_length, //src_len
                                            cleartext, //dst
                                            ciphertext, //iv
                                            SGX_AESGCM_IV_SIZE, //12 bytes
                                            NULL, //aad
                                            0, //0 bytes of AAD
                                            (const sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE)); //mac
        assert(status == SGX_SUCCESS);
        
        uint32_t nonce;
        memcpy(&nonce, ciphertext, sizeof(nonce)); //iv (LSB 32-bits) is the nonce
        assert(nonce > session_info->remote_counter); //to prevent replay attacks
        session_info->remote_counter = nonce;

        size_t bytes_to_copy = min(cleartext_length, len - len_completed);
        memcpy(buf, cleartext, bytes_to_copy);
        len_completed = len_completed + bytes_to_copy;

        if (bytes_to_copy < cleartext_length) {
            session_info->recv_carryover = cleartext + bytes_to_copy;
            session_info->recv_carryover_bytes = cleartext_length - bytes_to_copy;
        } else {
            free(cleartext);
        }
        free(ciphertext);
    }
    
    free(header);
    return len_completed;
    
}

void _moat_scc_destroy(scc_ctx_t *ctx)
{
    attestation_status_t status;    
    status = close_session(0);
    assert(status == SUCCESS);
    free(ctx);
}

