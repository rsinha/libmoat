#ifndef _LIBMOAT_H_
#define _LIBMOAT_H_

#include "sgx_tcrypto.h"

//#define LIBMOAT_API __attribute__((visibility("default")))
#define LIBMOAT_API 

/* Debugging */
void LIBMOAT_API _moat_print_debug(const char *fmt, ...);

/* Secure Communication Channel */

typedef struct
{
    uint32_t session_id;
} scc_ctx_t;

scc_ctx_t * LIBMOAT_API _moat_scc_create();
void LIBMOAT_API _moat_scc_send(scc_ctx_t *ctx, void *buf, size_t len);
size_t LIBMOAT_API _moat_scc_recv(scc_ctx_t *ctx, void *buf, size_t len);
void LIBMOAT_API _moat_scc_destroy(scc_ctx_t *ctx);

/* Key Value Store */

#endif
