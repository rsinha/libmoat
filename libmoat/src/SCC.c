#include <stddef.h> 

#include <assert.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../api/libmoat.h"
#include "../api/libmoat_untrusted.h"
#include "attestation/local/dh_session_protocol.h"
#include "attestation/local/error_codes.h"
#include "attestation/local/EnclaveMessageExchange.h"

scc_ctx_t *_moat_scc_create(bool is_server, sgx_measurement_t *measurement)
{
    uint32_t session_id = create_session(is_server, measurement);
    assert(session_id != 0);

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

    //allocate memory for ciphertext
    size_t dst_len = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;
    //look for overflows
    assert(dst_len > len);
    uint8_t *dst_buf = (uint8_t *) malloc(dst_len);
    assert (dst_buf != NULL);

    /* ciphertext: IV || MAC || encrypted */
    status = sgx_read_rand((unsigned char *) dst_buf + 0, SGX_AESGCM_IV_SIZE);
    assert(status == SGX_SUCCESS);

    dh_session_t *dh_session = get_session_info(ctx->session_id);
    assert(dh_session != NULL);

    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) &(dh_session->AEK),
                                        buf, /* input */
                                        len, /* input length */
                                        dst_buf + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        dst_buf + 0,
                                        SGX_AESGCM_IV_SIZE,
                                        NULL,
                                        0,
                                        (sgx_aes_gcm_128bit_tag_t *) (dst_buf + SGX_AESGCM_IV_SIZE));
    assert(status == SGX_SUCCESS);

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

    dh_session_t *dh_session = get_session_info(ctx->session_id);
    assert(dh_session != NULL);

    status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) &(dh_session->AEK),
                                        ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE,
                                        actual_len - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE),
                                        buf,
                                        ciphertext,
                                        SGX_AESGCM_IV_SIZE,
                                        NULL,
                                        0,
                                        (const sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE));
    assert(status == SGX_SUCCESS);

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

