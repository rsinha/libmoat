#include <assert.h>
#include <stddef.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

uint64_t enclave_test()
{
    blob_t blob1, blob2, blob3;
    scc_ctx_t *ctx = _moat_scc_create();
    blob1.x = 42;
    _moat_scc_send(ctx, &blob1, sizeof(blob1));
    _moat_scc_recv(ctx, &blob2, sizeof(blob2));
    _moat_print_debug("blob contains %" PRIu64 "\n", blob2.x);
    //trusted increment
    blob2.x += 1;
    _moat_scc_send(ctx, &blob2, sizeof(blob2));
    _moat_scc_recv(ctx, &blob3, sizeof(blob3));
    _moat_print_debug("blob contains %" PRIu64 "\n", blob3.x);
    return 0;
}
