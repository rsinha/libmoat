#include <assert.h>
#include <stddef.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

uint64_t enclave_test()
{
    blob_t blob;
    scc_ctx_t *ctx = _moat_scc_create();
    blob.x = 42;
    _moat_scc_send(ctx, &blob, sizeof(blob));
    _moat_scc_recv(ctx, &blob, sizeof(blob));
    //trusted increment
    blob.x += 1;
    _moat_scc_send(ctx, &blob, sizeof(blob));        
    _moat_scc_recv(ctx, &blob, sizeof(blob));
    _moat_print_debug("test returned %" PRIu64 "\n", blob.x);
    return 0;
}
