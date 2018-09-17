#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../../api/libmoat.h"
#include "../../../api/libbarbican.h"

#include "api/BlockStorage.h"

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

void auth_enc_storage_module_init(size_t num_blocks);
size_t auth_enc_storage_read(cipher_ctx_t *ctx, size_t addr, block_data_t data);
size_t auth_enc_storage_write(cipher_ctx_t *ctx, size_t addr, block_data_t data);

/***************************************************
                    PUBLIC API
 ***************************************************/

void block_storage_module_init(size_t num_blocks)
{
    sgx_status_t status;
    size_t retstatus;

    status = fs_init_service_ocall(&retstatus, num_blocks);
    assert(status == SGX_SUCCESS && retstatus == 0);

    auth_enc_storage_module_init(num_blocks);
}

size_t block_storage_read(cipher_ctx_t *ctx, size_t addr, block_data_t data)
{
    return auth_enc_storage_read(ctx, addr, data);
}

size_t block_storage_write(cipher_ctx_t *ctx, size_t addr, block_data_t data)
{
    return auth_enc_storage_write(ctx, addr, data);
}
