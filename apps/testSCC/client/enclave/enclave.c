#include <assert.h>
#include <stddef.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

#include "sgx_dh.h"

uint64_t enclave_test()
{
    blob_t blob1, blob2;
    //ideally some authority (e.g. CA) will tell us this
    sgx_measurement_t measurement = { .m = { 0x55,0xCF,0x87,0x7E,0xFF,0x2F,0xE4,0x09,
                                             0x6F,0x16,0x5B,0xC1,0x0D,0x06,0xCB,0x7A,
                                             0xAF,0x49,0xEF,0x4B,0xCE,0xBD,0xEA,0x90,
                                             0xD6,0x28,0x98,0xBC,0xBC,0x8F,0x50,0x36 } };
    scc_ctx_t *ctx = _moat_scc_create(false, &measurement);
     _moat_print_debug("Channel Established with server...\n");

    blob1.x = 42;
    char x;
    _moat_scc_recv(ctx, &x, 1);
    _moat_scc_send(ctx, &blob1, sizeof(blob1));
    _moat_scc_recv(ctx, &blob2, sizeof(blob2));
    _moat_print_debug("result: %" PRIu64 "\n", blob2.x);

    return 0;
}

