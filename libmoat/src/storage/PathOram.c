#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../api/libmoat.h"
#include "../../api/libmoat_untrusted.h"
#include "api/BlockStorage.h"

/***************************************************
 PUBLIC API
 ***************************************************/

void path_oram_storage_module_init()
{
    return;
}

size_t path_oram_storage_access(size_t op, size_t addr, block_t data, sgx_aes_gcm_128bit_key_t *key)
{
    return -1;
}
