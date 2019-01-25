#include <stddef.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../api/libmoat.h"
#include "../../api/libbarbican.h"
#include "../Utils/api/Utils.h"

/***************************************************
 PUBLIC API IMPLEMENTATION
 ***************************************************/

bool _moat_l_post(void *buf, size_t len)
{
    size_t retstatus;
    sgx_status_t status = ledger_post_ocall(&retstatus, buf, len);
    assert(status == SGX_SUCCESS && retstatus == 0);
    //verify_L TODO
    return true;
}

bool _moat_l_get_content(uint64_t height, void **buf, size_t *len)
{
    void *untrusted_buf; size_t untrusted_buf_len;
    size_t retstatus;
    sgx_status_t status = ledger_get_content_ocall(&retstatus, height, &untrusted_buf, &untrusted_buf_len);
    assert(status == SGX_SUCCESS && retstatus == 0);

    *len = untrusted_buf_len;
    *buf = malloc(*len);
    assert(*buf != NULL);
    memcpy(*buf, untrusted_buf, *len);
    //verify_L TODO
    return true;
}

bool _moat_l_get_compute_record(uint64_t spec_id, void **buf, size_t *len)
{
    void *untrusted_buf; size_t untrusted_buf_len;
    size_t retstatus;
    sgx_status_t status = ledger_get_compute_record_ocall(&retstatus, spec_id, &untrusted_buf, &untrusted_buf_len);
    assert(status == SGX_SUCCESS && retstatus == 0);

    *len = untrusted_buf_len;
    *buf = malloc(*len);
    assert(*buf != NULL);
    memcpy(*buf, untrusted_buf, *len);
    //verify_L TODO
    return true;
}

bool _moat_l_get_policy(uint64_t spec_id, void **buf, size_t *len)
{
    void *untrusted_buf; size_t untrusted_buf_len;
    size_t retstatus;
    sgx_status_t status = ledger_get_policy_ocall(&retstatus, spec_id, &untrusted_buf, &untrusted_buf_len);
    assert(status == SGX_SUCCESS && retstatus == 0);

    *len = untrusted_buf_len;
    *buf = malloc(*len);
    assert(*buf != NULL);
    memcpy(*buf, untrusted_buf, *len);
    //verify_L TODO
    return true;
}

uint64_t _moat_l_get_current_counter()
{
    uint64_t height;
    size_t retstatus;
    sgx_status_t status = ledger_get_current_counter_ocall(&retstatus, &height);
    assert(status == SGX_SUCCESS && retstatus == 0);
    return height;
}