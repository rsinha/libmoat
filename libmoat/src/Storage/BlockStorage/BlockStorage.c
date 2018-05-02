#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../../api/libmoat.h"
#include "../../../api/libmoat_untrusted.h"
#include "api/BlockStorage.h"

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

void auth_enc_storage_module_init();
size_t auth_enc_storage_access(size_t op, size_t addr, block_data_t data);

/***************************************************
                    PUBLIC API
 ***************************************************/

void block_storage_module_init()
{
    sgx_status_t status;
    size_t retstatus;

    status = create_blockfs_ocall(&retstatus, NUM_BLOCKS);
    assert(status == SGX_SUCCESS && retstatus == 0);

    auth_enc_storage_module_init(true);
}

size_t block_storage_access(size_t op, size_t addr, block_data_t data)
{
    auth_enc_storage_access(op, addr, data);
}
