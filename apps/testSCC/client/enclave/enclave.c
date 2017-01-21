#include <assert.h>
#include <stddef.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

#include "sgx_dh.h"

uint64_t enclave_test()
{
    blob_t blob1, blob2;

    sgx_measurement_t measurement;
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

