#include "api/Utils.h"
#include <assert.h>

/***************************************************
 PUBLIC API
 ***************************************************/

size_t min(size_t a, size_t b)
{
    return (a < b ? a : b);
}

size_t max(size_t a, size_t b)
{
    return (a > b ? a : b);
}

size_t log_base_2(size_t x)
{
    assert ((x & (x - 1)) == 0); //assert power of 2
    size_t result = 0;
    while((x & 1) == 0) {
        x = x >> 1;
        result = result + 1;
    }
    return result;
}
