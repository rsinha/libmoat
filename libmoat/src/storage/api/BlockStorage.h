#ifndef _BLOCKSTORAGE_H_
#define _BLOCKSTORAGE_H_

#include <stddef.h>

#define NUM_BLOCKS 8
#define BLOCK_SIZE 4096
typedef uint8_t block_t[BLOCK_SIZE];

#define READ 1
#define WRITE 2

void block_storage_module_init();
size_t block_storage_access(size_t op, size_t addr, block_t data, sgx_aes_gcm_128bit_key_t *key);

#endif

