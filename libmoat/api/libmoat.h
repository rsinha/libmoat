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
int64_t LIBMOAT_API _moat_print_debug(const char *fmt, ...);

/***************************************************
        SECURE COMMUNICATION CHANNEL
 ***************************************************/

void LIBMOAT_API _moat_scc_module_init();
int64_t LIBMOAT_API _moat_scc_create(char *name, sgx_measurement_t *measurement);
int64_t LIBMOAT_API _moat_scc_send(int64_t handle, void *buf, size_t len);
int64_t LIBMOAT_API _moat_scc_recv(int64_t handle, void *buf, size_t len);
int64_t LIBMOAT_API _moat_scc_destroy(int64_t handle);

/***************************************************
        STORAGE RELATED DEFINITIONS
 ***************************************************/

#define O_RDONLY (1 << 0)  /* only reads allowed, use this for inputs */
#define O_WRONLY (1 << 1)  /* only writes allowed */
#define O_RDWR (1 << 2)    /* both reads and writes allowed, use this for state */
#define O_CREAT (1 << 3)   /* not loaded but created, used for creating state or outputs */
#define O_TMPFILE (1 << 4) /* temporary state, not loaded nor saved */

/***************************************************
        SECURE FILE SYSTEM INTERFACE
 ***************************************************/

#define SEEK_SET 0 /* beginning of file */
#define SEEK_CUR 1 /* current value of offset */
#define SEEK_END 2 /* end of file */

void LIBMOAT_API _moat_fs_module_init();
int64_t LIBMOAT_API _moat_fs_open(char *name, int64_t oflag, sgx_aes_gcm_128bit_key_t *key);
int64_t LIBMOAT_API _moat_fs_lseek(int64_t fd, int64_t offset, int base);
int64_t LIBMOAT_API _moat_fs_tell(int64_t fd);
int64_t LIBMOAT_API _moat_fs_read(int64_t fd, void* buf, int64_t len);
int64_t LIBMOAT_API _moat_fs_write(int64_t fd, void* buf, int64_t len);
int64_t LIBMOAT_API _moat_fs_close(int64_t fd);
int64_t LIBMOAT_API _moat_fs_save(int64_t fd);

/***************************************************
        SECURE KV-STORE INTERFACE
 ***************************************************/

void LIBMOAT_API _moat_kvs_module_init();
int64_t LIBMOAT_API _moat_kvs_open(char *name, int64_t oflag, sgx_aes_gcm_128bit_key_t *key);
int64_t LIBMOAT_API _moat_kvs_set(int64_t fd, void *k, uint64_t k_len, void* buf, uint64_t buf_len);
int64_t LIBMOAT_API _moat_kvs_get(int64_t fd, void *k, uint64_t k_len, uint64_t offset, void* buf, uint64_t buf_len);
int64_t LIBMOAT_API _moat_kvs_insert(int64_t fd, void *k, uint64_t k_len, void* buf, uint64_t buf_len);
int64_t LIBMOAT_API _moat_kvs_delete(int64_t fd, void *k, uint64_t k_len);
int64_t LIBMOAT_API _moat_kvs_close(int64_t fd);
int64_t LIBMOAT_API _moat_kvs_save(int64_t fd);

/***************************************************
        KEY MANAGEMENT INTERFACE
 ***************************************************/

void _moat_generate_seal_key();

#endif
