#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"

void cache_init(void);
void cache_block_read(void * buffer, block_sector_t target);
void cache_block_write(void * buffer, block_sector_t target);

#endif // FILESYS_CACHE_H
