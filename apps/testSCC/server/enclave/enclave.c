#include <assert.h>
#include <stddef.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

#include "sgx_dh.h"

uint64_t enclave_test()
{
    //ideally some authority (e.g. CA) will tell us this
    sgx_measurement_t measurement = { .m = { 0x6A,0xD5,0x51,0xD6,0x40,0x9F,0xA1,0x9B,
                                             0x96,0x2A,0x5B,0x5B,0xCB,0x2E,0xD4,0x08,
                                             0x11,0xB8,0x86,0x5A,0x77,0x2A,0x53,0xEA,
                                             0x7D,0x56,0x45,0x10,0x51,0xD4,0x9C,0x52 } };
    scc_handle_t *handle = _moat_scc_create(true, &measurement);
    _moat_print_debug("ECDHE+AES-GCM-128 channel established with client...\n");

    blob_t blob;
    _moat_scc_recv(handle, &blob.x1, sizeof(blob.x1));
    _moat_scc_recv(handle, &blob.x2, sizeof(blob.x2));
    _moat_print_debug("Received input...\n");
    uint64_t result = blob.x1 + blob.x2;
    _moat_scc_send(handle, &result, sizeof(result));
    _moat_print_debug("Sent result...\n");
    _moat_scc_destroy(handle);
    return 0;
}

