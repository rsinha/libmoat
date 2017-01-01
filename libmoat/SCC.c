#include <stddef.h> 

#include <assert.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "api/libmoat.h"
#include "shal.h"

scc_ctx_t *_moat_scc_create()
{
    sgx_status_t status;
    //allocate memory for the context
    scc_ctx_t *ctx = (scc_ctx_t *) malloc(sizeof(scc_ctx_t));
    assert(ctx != NULL);
    //ask CPU for some random bits to create the AES key
    status = sgx_read_rand((unsigned char *) &(ctx->scc_key), sizeof(sgx_aes_gcm_128bit_key_t));
    assert(status == SGX_SUCCESS);
    //all ok if we got here
    return ctx;
}

void _moat_scc_send(scc_ctx_t *ctx, void *buf, size_t len)
{
    sgx_status_t status; 
    //allocate memory for ciphertext
    size_t dst_len = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;
    //look for overflows
    assert(dst_len > len);
    uint8_t *dst_buf = (uint8_t *) malloc(dst_len);
    assert (dst_buf != NULL);
    /* ciphertext: IV || MAC || encrypted */
    status = sgx_read_rand((unsigned char *) dst_buf + 0, SGX_AESGCM_IV_SIZE);
    assert(status == SGX_SUCCESS);
    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) &(ctx->scc_key),
                                        buf, /* input */
                                        len, /* input length */
                                        dst_buf + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        dst_buf + 0,
                                        SGX_AESGCM_IV_SIZE,
                                        NULL,
                                        0,
                                        (sgx_aes_gcm_128bit_tag_t *) (dst_buf + SGX_AESGCM_IV_SIZE));
    assert(status == SGX_SUCCESS);
    _shal_outputToHost(dst_buf, dst_len);
    free(dst_buf);
}

size_t _moat_scc_recv(scc_ctx_t *ctx, void *buf, size_t len)
{
    sgx_status_t status;
    size_t actual_len;
    size_t max_len = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;
    uint8_t *ciphertext = (uint8_t *) malloc(max_len);
    assert(ciphertext != NULL);
    _shal_inputFromHost(ciphertext, max_len, &actual_len);
    assert (actual_len <= max_len); //although the caller cannot write past len, it may set actual to be an arbitrary value
    status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) &(ctx->scc_key),
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

void _moat_scc_delete(scc_ctx_t *ctx)
{
    free(ctx);
}
