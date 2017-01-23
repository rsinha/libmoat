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

//NIST guidelines: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

scc_ctx_t *_moat_scc_create(bool is_server, sgx_measurement_t *measurement)
{
    uint32_t session_id = create_session(is_server, measurement);
    assert(session_id != 0);

    dh_session_t *session_info = get_session_info(session_id);
    assert(session_info != NULL);

    //local_counter is used as IV, and is incremented by 2 for each invocation of AES-GCM-128
    session_info->local_counter = is_server ? 1 : 2; //server/client uses odd/even IVs
    session_info->remote_counter = 0; //haven't seen any remote IVs yet

    //allocate memory for the context
    scc_ctx_t *ctx = (scc_ctx_t *) malloc(sizeof(scc_ctx_t));
    assert(ctx != NULL);
    ctx->session_id = session_id;
    
    //all ok if we got here
    return ctx;
}

void _moat_scc_send(scc_ctx_t *ctx, void *buf, size_t len)
{
    sgx_status_t status;
    uint32_t retstatus;

    dh_session_t *session_info = get_session_info(ctx->session_id);
    assert(session_info != NULL);

    //at most 2^32 invocations of AES-GCM according to NIST guidelines
    if(session_info->local_counter > ((uint32_t) - 3)) {
        assert(false); //TODO: ideally tear down and recreate session
    }

    //allocate memory for ciphertext
    size_t dst_len = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;
    //look for overflows
    assert(dst_len > len);
    uint8_t *dst_buf = (uint8_t *) malloc(dst_len);
    assert (dst_buf != NULL);

    //status = sgx_read_rand((unsigned char *) dst_buf + 0, SGX_AESGCM_IV_SIZE);
    //assert(status == SGX_SUCCESS);
    memcpy(dst_buf + 0, &(session_info->local_counter), sizeof(session_info->local_counter));

    /* ciphertext: IV || MAC || encrypted */
    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) &(session_info->AEK),
                                        buf, /* input */
                                        len, /* input length */
                                        dst_buf + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        dst_buf + 0,
                                        SGX_AESGCM_IV_SIZE,
                                        NULL,
                                        0,
                                        (sgx_aes_gcm_128bit_tag_t *) (dst_buf + SGX_AESGCM_IV_SIZE));
    assert(status == SGX_SUCCESS);

    //so we don't reuse IVs
    session_info->local_counter = session_info->local_counter + 2;

    status = send_msg_ocall(&retstatus, dst_buf, dst_len, ctx->session_id);
    assert(status == SGX_SUCCESS && retstatus == 0);
    free(dst_buf);
}

size_t _moat_scc_recv(scc_ctx_t *ctx, void *buf, size_t len)
{
    sgx_status_t status;
    uint32_t retstatus;
    size_t actual_len;
    size_t max_len = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;

    uint8_t *ciphertext = (uint8_t *) malloc(max_len);
    assert(ciphertext != NULL);

    status = recv_msg_ocall(&retstatus, ciphertext, max_len, &actual_len, ctx->session_id);
    assert(status == SGX_SUCCESS && retstatus == 0);
    assert (actual_len <= max_len); //although the caller cannot write past len, it may set actual to be an arbitrary value

    dh_session_t *session_info = get_session_info(ctx->session_id);
    assert(session_info != NULL);

    /* ciphertext: IV || MAC || encrypted */
    status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) &(session_info->AEK),
                                        ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE,
                                        actual_len - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE),
                                        buf,
                                        ciphertext,
                                        SGX_AESGCM_IV_SIZE,
                                        NULL,
                                        0,
                                        (const sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE));
    assert(status == SGX_SUCCESS);

    uint32_t nonce;
    memcpy(&nonce, ciphertext, sizeof(nonce));
    assert(nonce > session_info->remote_counter); //to prevent replay attacks
    session_info->remote_counter = nonce;

    free(ciphertext);
    return actual_len - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
}

void _moat_scc_destroy(scc_ctx_t *ctx)
{
    attestation_status_t status;    
    status = close_session(0);
    assert(status == SUCCESS);
    free(ctx);
}

