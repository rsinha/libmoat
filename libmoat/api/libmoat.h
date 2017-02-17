#ifndef _LIBMOAT_H_
#define _LIBMOAT_H_

#include "sgx_tcrypto.h"
#include <stdbool.h>

//#define LIBMOAT_API __attribute__((visibility("default")))
#define LIBMOAT_API 

/***************************************************
            DEBUGGING UTILITIES
 ***************************************************/

void LIBMOAT_API _moat_debug_module_init();
void LIBMOAT_API _moat_print_debug(const char *fmt, ...);

/***************************************************
        SECURE COMMUNICATION CHANNEL
 ***************************************************/

typedef struct {
    size_t session_id;
} scc_handle_t;

void LIBMOAT_API _moat_scc_module_init();
scc_handle_t * LIBMOAT_API _moat_scc_create(bool is_server, sgx_measurement_t *target_enclave);
size_t LIBMOAT_API _moat_scc_send(scc_handle_t *handle, void *buf, size_t len);
size_t LIBMOAT_API _moat_scc_recv(scc_handle_t *handle, void *buf, size_t len);
void LIBMOAT_API _moat_scc_destroy(scc_handle_t *handle);

/***************************************************
        SECURE FILE SYSTEM INTERFACE
 ***************************************************/

typedef struct {
    size_t file_descriptor;
} fs_handle_t;

void LIBMOAT_API _moat_fs_module_init();
fs_handle_t *_moat_fs_open(char *name);
size_t _moat_fs_read(fs_handle_t *handle, size_t offset, void* buf, size_t len);
size_t _moat_fs_write(fs_handle_t *handle, size_t offset, void* buf, size_t len);
void _moat_fs_close(fs_handle_t *handle);

#endif
