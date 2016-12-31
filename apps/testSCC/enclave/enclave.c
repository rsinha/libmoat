#include <assert.h>
#include <string.h>
#include <inttypes.h>

#include "libmoat.h"
#include "common.h"

void debugf(const char *fmt, ...)
{
#if DEBUG == 1
    char buf[256] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printDebugOnHost(buf);
#endif
}

uint64_t enclave_test()
{
    blob_t blob;
    moat_recv(&blob, sizeof(blob));
    //trusted increment
    blob.x += 1;
    moat_send(&blob, sizeof(blob));        

    return 0;
}
