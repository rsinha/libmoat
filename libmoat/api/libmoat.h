#ifndef _LIBMOAT_H_
#define _LIBMOAT_H_

#include "sgx_tcrypto.h"
#include <stdbool.h>
#include <stdint.h>

//#define LIBMOAT_API __attribute__((visibility("default")))
#define LIBMOAT_API 

/***************************************************
            DEBUGGING UTILITIES
 ***************************************************/

void LIBMOAT_API _moat_debug_module_init();
size_t LIBMOAT_API _moat_print_debug(const char *fmt, ...);

/***************************************************
        SECURE COMMUNICATION CHANNEL
 ***************************************************/

typedef struct {
    size_t session_id;
} scc_handle_t;

typedef struct {
    size_t record_size;
    size_t side_channel_protection;
} scc_attributes_t;

void LIBMOAT_API _moat_scc_module_init();
scc_handle_t * LIBMOAT_API _moat_scc_create(bool is_server, sgx_measurement_t *measurement, scc_attributes_t *attr);
size_t LIBMOAT_API _moat_scc_send(scc_handle_t *handle, void *buf, size_t len);
size_t LIBMOAT_API _moat_scc_recv(scc_handle_t *handle, void *buf, size_t len);
size_t LIBMOAT_API _moat_scc_destroy(scc_handle_t *handle);

/***************************************************
        SECURE FILE SYSTEM INTERFACE
 ***************************************************/

#define O_RDONLY (1 << 0)
#define O_WRONLY (1 << 1)
#define O_RDWR (1 << 2)

#define SEEK_SET 0 /* beginning of file */
#define SEEK_CUR 1 /* current value of offset */
#define SEEK_END 2 /* end of file */

void LIBMOAT_API _moat_fs_module_init();
int64_t LIBMOAT_API _moat_fs_open(char *name, int oflag);
int64_t LIBMOAT_API _moat_fs_lseek(int64_t fd, int64_t offset, int base);
int64_t LIBMOAT_API _moat_fs_read(int64_t fd, void* buf, int64_t len);
int64_t LIBMOAT_API _moat_fs_write(int64_t fd, void* buf, int64_t len);
int64_t LIBMOAT_API _moat_fs_close(int64_t fd);

/***************************************************
        SECURE KV-STORE INTERFACE
 ***************************************************/

typedef struct kv_key_t {
    uint8_t k[32];
} kv_key_t;

void LIBMOAT_API _moat_kvs_module_init();
int64_t _moat_kvs_open(char *name, int oflag);
int64_t _moat_kvs_insert(int64_t fd, kv_key_t *k, uint64_t offset, void* buf, uint64_t len);
int64_t _moat_kvs_set(int64_t fd, kv_key_t *k, uint64_t offset, void* buf, uint64_t len);
int64_t _moat_kvs_set(int64_t fd, kv_key_t *k, uint64_t offset, void *buf, uint64_t len);
int64_t _moat_kvs_get(int64_t fd, kv_key_t *k, uint64_t offset, void* buf, uint64_t len);
//int64_t _moat_kvs_delete(int64_t handle, kv_key_t *k);
int64_t _moat_kvs_close(int64_t fd);

#endif
