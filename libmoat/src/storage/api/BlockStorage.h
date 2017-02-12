#ifndef _BLOCKSTORAGE_H_
#define _BLOCKSTORAGE_H_

#include <stddef.h>

typedef uint8_t block_t[4096];
#define READ 1
#define WRITE 2

size_t access(size_t op, size_t addr, block_t data);

#endif

