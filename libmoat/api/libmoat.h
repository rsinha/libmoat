#ifndef _LIBMOAT_H_
#define _LIBMOAT_H_

#include "sgx_tcrypto.h"
#include <stdbool.h>

//#define LIBMOAT_API __attribute__((visibility("default")))
#define LIBMOAT_API 

/* Debugging */
void LIBMOAT_API _moat_print_debug(const char *fmt, ...);

/* Secure Communication Channel */

typedef struct
{
    uint32_t session_id;
} scc_handle_t;

scc_handle_t * LIBMOAT_API _moat_scc_create(bool is_server, sgx_measurement_t *target_enclave);
size_t LIBMOAT_API _moat_scc_send(scc_handle_t *handle, void *buf, size_t len);
size_t LIBMOAT_API _moat_scc_recv(scc_handle_t *handle, void *buf, size_t len);
void LIBMOAT_API _moat_scc_destroy(scc_handle_t *handle);



#endif
