#include <stddef.h>
#include <assert.h>
#include <string.h>

#include "sgx_tseal.h"
#include "sgx_utils.h"

#include "../../api/libmoat.h"


void _moat_generate_seal_key()
{
    sgx_key_id_t key_id;
    sgx_key_request_t key_request;
    sgx_report_t report;
    sgx_key_128bit_t seal_key;

    /* zero out critical data structures before asking SGX to populate fields */
    memset(&report, 0, sizeof(sgx_report_t));
    memset(&key_id, 0, sizeof(sgx_key_id_t));
    memset(&key_request, 0, sizeof(sgx_key_request_t));
    memset(&seal_key, 0, sizeof(sgx_key_128bit_t));

    sgx_status_t err = sgx_create_report(NULL, NULL, &report);
    assert(err == SGX_SUCCESS);

    memcpy(&(key_request.cpu_svn), &(report.body.cpu_svn), sizeof(sgx_cpu_svn_t));
    memcpy(&(key_request.isv_svn), &(report.body.isv_svn), sizeof(sgx_isv_svn_t));
    key_request.key_name = SGX_KEYSELECT_SEAL;
    key_request.key_policy = SGX_KEYPOLICY_MRENCLAVE;
    key_request.attribute_mask.flags = SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    key_request.attribute_mask.xfrm = 0x0;
    memcpy(&(key_request.key_id), &key_id, sizeof(sgx_key_id_t));
    key_request.misc_mask = (~(0x0FFFFFFF));
    
    err = sgx_get_key(&key_request, &seal_key);
    assert(err == SGX_SUCCESS);

#ifndef RELEASE
    _moat_print_debug("generated sealing key: ");
    for (size_t i = 0; i < sizeof(seal_key); i++)
    {
        _moat_print_debug("0x%02X,", seal_key[i]);
    }
    _moat_print_debug("\n");
#endif
}
