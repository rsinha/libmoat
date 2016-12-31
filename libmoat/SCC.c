#include <stddef.h> 

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "shal.h"

scc_ctx_t *_moat_scc_create()
{
  sgx_status_t status;
  //allocate memory for the context
  scc_ctx_t *ctx = (scc_ctx_t *) malloc(sizeof(scc_ctx_t));
  assert(ctx != NULL);
  //ask CPU for some random bits to create the AES key
  status = sgx_read_rand(&(ctx->scc_key), sizeof(sgx_aes_gcm_128bit_key_t));
  assert(status == SGX_SUCCESS);
  //all ok if we got here
  return ctx;
}

void _moat_scc_send(scc_ctx_t *ctx, void *buf, size_t len)
{
    sgx_status_t status; 
    //TODO: encrypt
    status = sgx_rijndael128GCM_encrypt(&(ctx->scc_key),
                                        
    _shal_outputToHost(buf, len);
}

size_t _moat_scc_recv(scc_ctx_t *ctx, void *buf, size_t len)
{
    size_t actual;
    _shal_inputFromHost(buf, len, &actual);
    //TODO: decrypt
    return actual;
}

void _moat_scc_delete(scc_ctx_t *ctx)
{

}
