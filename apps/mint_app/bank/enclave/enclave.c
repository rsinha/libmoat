#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"
#include "common.h"

#include "sgx_dh.h"

uint64_t enclave_test()
{
    _moat_debug_module_init();
    _moat_scc_module_init();
    _moat_fs_module_init();
    _moat_kvs_module_init();

    //ideally some authority (e.g. CA) will tell us this
    sgx_measurement_t measurement = { .m = { 0x55,0xCF,0x87,0x7E,0xFF,0x2F,0xE4,0x09,
                                             0x6F,0x16,0x5B,0xC1,0x0D,0x06,0xCB,0x7A,
                                             0xAF,0x49,0xEF,0x4B,0xCE,0xBD,0xEA,0x90,
                                             0xD6,0x28,0x98,0xBC,0xBC,0x8F,0x50,0x36 } };
    scc_attributes_t attr = { .record_size = 128, .side_channel_protection = 0 };
    scc_handle_t *handle = _moat_scc_create(false, &measurement, &attr);
    assert(handle != NULL);
    _moat_print_debug("ECDHE+AES-GCM-128 channel established with server...\n");

    transaction_t tx1 = { .amt = 20, .gmr_id = 1, .timestamp = 60 },
                  tx2 = { .amt = 30, .gmr_id = 1, .timestamp = 120 },
                  tx3 = { .amt = 10, .gmr_id = 2, .timestamp = 180 };

    int64_t api_result;    
    //api_result = _moat_scc_send(handle, &blob1, sizeof(blob1)); assert(api_result == 0);
    bool next = true;
    api_result = _moat_scc_send(handle, &(next), sizeof(next)); assert(api_result == 0);
    api_result = _moat_scc_send(handle, &(tx1), sizeof(tx1)); assert(api_result == 0);
    api_result = _moat_scc_send(handle, &(next), sizeof(next)); assert(api_result == 0);
    api_result = _moat_scc_send(handle, &(tx2), sizeof(tx2)); assert(api_result == 0);
    api_result = _moat_scc_send(handle, &(next), sizeof(next)); assert(api_result == 0);
    api_result = _moat_scc_send(handle, &(tx3), sizeof(tx3)); assert(api_result == 0);
    next = false;
    api_result = _moat_scc_send(handle, &(next), sizeof(next)); assert(api_result == 0);

    api_result = _moat_scc_destroy(handle); assert(api_result == 0);

    api_result = _moat_print_debug("sent all transactions to Mint's enclave\n"); assert(api_result == 0);

    return 0;
}

