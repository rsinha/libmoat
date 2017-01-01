#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

#define DEBUG 1

void debugf(const char *fmt, ...)
{
#if DEBUG == 1
    char buf[256] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    _shal_printDebugOnHost(buf);
#endif
}

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
    debugf("test returned %" PRIu64 "\n", blob.x);
    return 0;
}
