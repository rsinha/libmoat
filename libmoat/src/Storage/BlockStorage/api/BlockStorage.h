#ifndef _BLOCKSTORAGE_H_
#define _BLOCKSTORAGE_H_

#include <stddef.h>

#define BLOCK_SIZE 4044
typedef uint8_t block_data_t[BLOCK_SIZE];

void block_storage_module_init();
size_t block_storage_read(size_t addr, block_data_t data);
size_t block_storage_write(size_t addr, block_data_t data);

#endif

