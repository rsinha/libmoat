#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"
#include "attempt.pb-c.h"

uint64_t enclave_test()
{
    _moat_debug_module_init();
    _moat_fs_module_init();



    return 0;
}

