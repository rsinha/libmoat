#ifndef _SHAL_H_
#define _SHAL_H_

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


uint64_t enclave_test();

sgx_status_t SGX_CDECL _shal_printDebugOnHost(const char* str);
sgx_status_t SGX_CDECL _shal_outputToHost(void* buf, size_t len);
sgx_status_t SGX_CDECL _shal_inputFromHost(void* buf, size_t len_max, size_t* len_actual);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
