#ifndef _BLOCKSTORAGE_H_
#define _BLOCKSTORAGE_H_

#include <stddef.h>

#define NUM_BLOCKS 15
#define BLOCK_SIZE 4096
typedef uint8_t block_t[BLOCK_SIZE];

#define READ 1
#define WRITE 2

size_t access(size_t op, size_t addr, block_t data);

#endif

