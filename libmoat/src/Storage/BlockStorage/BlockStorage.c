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

void auth_enc_storage_module_init();
size_t auth_enc_storage_read(int64_t fd, cipher_ctx_t *ctx, size_t addr, block_data_t data);
size_t auth_enc_storage_write(int64_t fd, cipher_ctx_t *ctx, size_t addr, block_data_t data);

/***************************************************
                    PUBLIC API
 ***************************************************/

void block_storage_module_init()
{
    sgx_status_t status;
    size_t retstatus;

    status = fs_init_service_ocall(&retstatus);
    assert(status == SGX_SUCCESS && retstatus == 0);

    auth_enc_storage_module_init();
}

size_t block_storage_read(int64_t fd, cipher_ctx_t *ctx, size_t addr, block_data_t data)
{
    return auth_enc_storage_read(fd, ctx, addr, data);
}

size_t block_storage_write(int64_t fd, cipher_ctx_t *ctx, size_t addr, block_data_t data)
{
    return auth_enc_storage_write(fd, ctx, addr, data);
}
