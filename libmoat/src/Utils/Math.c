#include "api/Utils.h"
#include <assert.h>

/***************************************************
 PUBLIC API
 ***************************************************/

uint64_t div_ceil(uint64_t x, uint64_t y)
{
    assert(x != 0);
    return 1 + ((x - 1) / y);
}

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

size_t exp_of_2(size_t x)
{
    assert (x >= 0);
    size_t result = 1;
    while (x > 0) {
        result = result * 2;
        x = x - 1;
    }
    return result;
}

bool addition_is_safe(uint64_t a, uint64_t b) {
    return (UINT64_MAX - a > b);
}