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
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

void auth_enc_storage_module_init();
size_t auth_enc_storage_access(size_t op, size_t addr, block_t data, sgx_aes_gcm_128bit_key_t *key);

void path_oram_storage_module_init();
size_t path_oram_storage_access(size_t op, size_t addr, block_t data, sgx_aes_gcm_128bit_key_t *key);


/***************************************************
                    PUBLIC API
 ***************************************************/

void block_storage_module_init()
{
    auth_enc_storage_module_init(false);
    //path_oram_storage_module_init();
}

size_t block_storage_access(size_t op, size_t addr, block_t data, sgx_aes_gcm_128bit_key_t *key)
{
    auth_enc_storage_access(op, addr, data, key);
}
