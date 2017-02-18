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

/*
size_t access(size_t op, size_t addr, block_t data, const sgx_aes_gcm_128bit_key_t *key)
{
    return 0;
}
*/
