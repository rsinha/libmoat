#ifndef _SHAL_H_
#define _SHAL_H_

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */
#include "sgx_eid.h"
#include "sgx_dh.h"

#include <stdlib.h>

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t SGX_CDECL recv_dh_msg1_ocall(size_t* retval, sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, int64_t session_id);
sgx_status_t SGX_CDECL send_dh_msg2_recv_dh_msg3_ocall(size_t* retval, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, int64_t session_id);
sgx_status_t SGX_CDECL send_dh_msg1_recv_dh_msg2_ocall(size_t* retval, sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, sgx_dh_msg2_t* dh_msg2, int64_t session_id);
sgx_status_t SGX_CDECL send_dh_msg3_ocall(size_t* retval, sgx_dh_msg3_t* dh_msg3, int64_t session_id);

sgx_status_t SGX_CDECL start_session_ocall(size_t* retval, const char *name, sgx_measurement_t *target_enclave, int64_t session_id, size_t *is_server);
sgx_status_t SGX_CDECL end_session_ocall(size_t* retval, int64_t session_id);

sgx_status_t SGX_CDECL send_msg_ocall(size_t* retval, void* buf, size_t len, int64_t session_id);
sgx_status_t SGX_CDECL recv_msg_ocall(size_t* retval, void* buf, size_t len, int64_t session_id);

sgx_status_t SGX_CDECL fs_init_service_ocall(size_t* retval);
sgx_status_t SGX_CDECL fs_create_ocall(size_t *retval, int64_t fd, const char *str);
sgx_status_t SGX_CDECL fs_destroy_ocall(size_t *retval, int64_t fd, const char *str);
sgx_status_t SGX_CDECL fs_save_ocall(size_t *retval, int64_t fd, const char *name, int64_t length);
sgx_status_t SGX_CDECL fs_load_ocall(size_t *retval, int64_t fd, const char *str, int64_t *length);
sgx_status_t SGX_CDECL fs_write_block_ocall(size_t* retval, int64_t fd, size_t addr, void* buf, size_t len);
sgx_status_t SGX_CDECL fs_read_block_ocall(size_t* retval, int64_t fd, size_t addr, void* buf, size_t len);
sgx_status_t SGX_CDECL fs_delete_block_ocall(size_t* retval, int64_t fd, size_t addr);

//sgx_status_t SGX_CDECL create_merkle_ocall(size_t* retval, sgx_sha256_hash_t* buf, size_t num_hashes, size_t num_blocks);
//sgx_status_t SGX_CDECL read_merkle_ocall(size_t* retval, size_t addr, sgx_sha256_hash_t* buf, size_t num_hashes);
//sgx_status_t SGX_CDECL write_merkle_ocall(size_t* retval, size_t addr, sgx_sha256_hash_t* buf, size_t num_hashes);

sgx_status_t SGX_CDECL kvs_init_service_ocall(size_t *retval);
sgx_status_t SGX_CDECL kvs_create_ocall(size_t *retval, int64_t fd, const char *str);
sgx_status_t SGX_CDECL kvs_load_ocall(size_t *retval, int64_t fd, const char *str);
sgx_status_t SGX_CDECL kvs_set_ocall(size_t *retval, int64_t fd, void *k, size_t k_len, void *buf, size_t buf_len);
sgx_status_t SGX_CDECL kvs_get_ocall(size_t *retval, int64_t fd, void *k, size_t k_len, void **untrusted_buf);
sgx_status_t SGX_CDECL kvs_delete_ocall(size_t *retval, int64_t fd, void *k, size_t k_len);
sgx_status_t SGX_CDECL kvs_destroy_ocall(size_t *retval, int64_t fd, const char *name);
sgx_status_t SGX_CDECL kvs_close_ocall(size_t *retval, int64_t fd);
sgx_status_t SGX_CDECL kvs_save_ocall(size_t *retval, int64_t fd, const char *name);

sgx_status_t SGX_CDECL malloc_ocall(size_t* retval, size_t num_bytes, void **untrusted_buf);
sgx_status_t SGX_CDECL free_ocall(size_t* retval, void *untrusted_buf);

sgx_status_t SGX_CDECL ledger_post_ocall(size_t* retval, void* buf, size_t len);
sgx_status_t SGX_CDECL ledger_get_ocall(size_t* retval, void **untrusted_buf, size_t *untrusted_buf_len);

sgx_status_t SGX_CDECL print_debug_on_host_ocall(size_t* retval, const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
