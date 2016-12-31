#ifndef _LIBMOAT_H_
#define _LIBMOAT_H_

/* Secure Communication Channel */

typedef struct
{
  sgx_aes_gcm_128bit_key_t scc_key; //16 bytes
} scc_ctx_t;

scc_ctx_t *_moat_scc_create();
void _moat_scc_send(scc_ctx_t *ctx, void *buf, size_t len);
size_t _moat_scc_recv(void *buf, size_t len);
void _moat_scc_delete(scc_ctx_t *ctx);

/* Key Value Store */

#endif
