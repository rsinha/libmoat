#include <stdarg.h>
#include <stdio.h>
#include <assert.h>

#include "../../api/libbarbican.h"

/***************************************************
 PUBLIC API IMPLEMENTATION
 ***************************************************/

void _moat_debug_module_init() { }

size_t _moat_print_debug(const char *fmt, ...)
{
    size_t retstatus;
    char buf[256] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    sgx_status_t status = print_debug_on_host_ocall(&retstatus, buf);
    assert(status == SGX_SUCCESS);
    assert(retstatus == 0);
    return 0;
}
