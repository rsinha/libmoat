#include "api/Utils.h"

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
