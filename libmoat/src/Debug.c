#include <stdarg.h>
#include <stdio.h>

#include "libmoat_untrusted.h"

void _moat_print_debug(const char *fmt, ...)
{
    char buf[256] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    print_debug_on_host_ocall(buf);
}
