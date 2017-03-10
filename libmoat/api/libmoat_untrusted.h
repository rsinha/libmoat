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

sgx_status_t SGX_CDECL recv_dh_msg1_ocall(size_t* retval, sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, size_t session_id);
sgx_status_t SGX_CDECL send_dh_msg2_recv_dh_msg3_ocall(size_t* retval, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, size_t session_id);
sgx_status_t SGX_CDECL send_dh_msg1_recv_dh_msg2_ocall(size_t* retval, sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, sgx_dh_msg2_t* dh_msg2, size_t session_id);
sgx_status_t SGX_CDECL send_dh_msg3_ocall(size_t* retval, sgx_dh_msg3_t* dh_msg3, size_t session_id);

sgx_status_t SGX_CDECL end_session_ocall(size_t* retval, size_t session_id);

sgx_status_t SGX_CDECL send_msg_ocall(size_t* retval, void* buf, size_t len, size_t session_id);
sgx_status_t SGX_CDECL recv_msg_ocall(size_t* retval, void* buf, size_t len, size_t session_id);

sgx_status_t SGX_CDECL create_blockfs_ocall(size_t* retval, size_t num_blocks);
sgx_status_t SGX_CDECL write_block_ocall(size_t* retval, void* buf, size_t len, size_t addr);
sgx_status_t SGX_CDECL read_block_ocall(size_t* retval, void* buf, size_t len, size_t addr);

sgx_status_t SGX_CDECL create_merkle_ocall(size_t* retval, sgx_sha256_hash_t* buf, size_t num_hashes, size_t num_blocks);
sgx_status_t SGX_CDECL read_merkle_ocall(size_t* retval, size_t addr, sgx_sha256_hash_t* buf, size_t num_hashes);
sgx_status_t SGX_CDECL write_merkle_ocall(size_t* retval, size_t addr, sgx_sha256_hash_t* buf, size_t num_hashes);

sgx_status_t SGX_CDECL print_debug_on_host_ocall(size_t* retval, const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
