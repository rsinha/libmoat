#ifndef _BLOCKSTORAGE_H_
#define _BLOCKSTORAGE_H_

#include <stddef.h>
#include "../../../Utils/api/Utils.h"

#define BLOCK_SIZE 4044
typedef uint8_t block_data_t[BLOCK_SIZE];

void block_storage_module_init();
size_t block_storage_load(int64_t fd, size_t num_blocks);
size_t block_storage_get_digest(int64_t fd, sgx_sha256_hash_t *hash);
size_t block_storage_read(int64_t fd, cipher_ctx_t *ctx, size_t addr, block_data_t data);
size_t block_storage_write(int64_t fd, cipher_ctx_t *ctx, size_t addr, block_data_t data);

#endif

