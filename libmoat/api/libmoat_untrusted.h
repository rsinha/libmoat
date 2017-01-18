#ifndef _SHAL_H_
#define _SHAL_H_

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */
#include "sgx_eid.h"
#include "sgx_dh.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t SGX_CDECL recv_dh_msg1_ocall(uint32_t* retval, sgx_measurement_t *target_enclave, sgx_dh_msg1_t* dh_msg1, uint32_t session_id);
sgx_status_t SGX_CDECL send_dh_msg2_recv_dh_msg3_ocall(uint32_t* retval, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
sgx_status_t SGX_CDECL send_dh_msg1_recv_dh_msg2_ocall(uint32_t* retval, sgx_dh_msg1_t* dh_msg1, sgx_dh_msg2_t* dh_msg2, uint32_t session_id);
sgx_status_t SGX_CDECL send_dh_msg3_ocall(uint32_t* retval, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
sgx_status_t SGX_CDECL end_session_ocall(uint32_t* retval, uint32_t session_id);
sgx_status_t SGX_CDECL send_msg_ocall(uint32_t* retval, void* buf, size_t len, uint32_t session_id);
sgx_status_t SGX_CDECL recv_msg_ocall(uint32_t* retval, void* buf, size_t len_max, size_t* len_actual, uint32_t session_id);
sgx_status_t SGX_CDECL print_debug_on_host_ocall(uint32_t* retval, const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
