#ifndef _LIBMOAT_H_
#define _LIBMOAT_H_

#include "sgx_tcrypto.h"

/* Debugging */
void _moat_print_debug(const char *fmt, ...);

/* Secure Communication Channel */

typedef struct
{
  sgx_aes_gcm_128bit_key_t scc_key; //16 bytes
} scc_ctx_t;

scc_ctx_t *_moat_scc_create();
void _moat_scc_send(scc_ctx_t *ctx, void *buf, size_t len);
size_t _moat_scc_recv(scc_ctx_t *ctx, void *buf, size_t len);
void _moat_scc_delete(scc_ctx_t *ctx);

/* Key Value Store */

#endif
